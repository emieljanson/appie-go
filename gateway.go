package appie

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	srt "github.com/juzeon/spoofed-round-tripper"
)

const (
	hostedAttemptCookie  = "appie_gateway_attempt"
	maxGatewayBodyBytes  = 1 << 20
	maxGatewayAttemptTTL = 10 * time.Minute
	hostedLoginCSP       = "default-src 'self'; img-src 'self' data: https://login.ah.nl https://static.ah.nl https://hcaptcha.com https://*.hcaptcha.com; font-src 'self' data: https://static.ah.nl; style-src 'self' 'unsafe-inline' https://login.ah.nl https://static.ah.nl https://hcaptcha.com https://*.hcaptcha.com; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://login.ah.nl https://hcaptcha.com https://*.hcaptcha.com; connect-src 'self' https://login.ah.nl https://hcaptcha.com https://*.hcaptcha.com; frame-src https://hcaptcha.com https://*.hcaptcha.com; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
	hostedLoginNotice    = `<style id="betergekozen-login-notice-style">html,body{margin:0!important;padding:0!important}#betergekozen-login-notice{box-sizing:border-box;width:100%;flex:none;background:#f3e7d9;border-bottom:1px solid rgba(20,20,20,.12);color:#171717;font-family:Arial,sans-serif}#betergekozen-login-notice p{box-sizing:border-box;max-width:1120px;margin:0 auto;padding:13px 20px;font-size:14px;line-height:1.45}@media(max-width:600px){#betergekozen-login-notice p{padding:11px 16px;font-size:13px}}</style><aside id="betergekozen-login-notice" aria-label="Uitleg over de koppeling"><p>Je blijft op Beter Gekozen om de koppeling af te ronden; je wachtwoord gaat alleen naar Albert Heijn en wordt niet door ons opgeslagen.</p></aside>`
)

var hostedStylesheetPattern = regexp.MustCompile(`href="/login/_next/static/[^"]+\.css(?:\?[^"]*)?"`)

// HostedGatewayConfig configures the narrow HTTPS gateway used to complete AH login.
type HostedGatewayConfig struct {
	PublicOrigin          string
	AppOrigin             string
	HandoffURL            string
	SharedSecret          []byte
	LoginBaseURL          string
	APIBaseURL            string
	Logger                *log.Logger
	HTTPClient            *http.Client
	Now                   func() time.Time
	MaxActiveAttempts     int
	AllowInsecureForTests bool
}

type hostedAttempt struct {
	id             string
	capabilityHash [32]byte
	returnPath     string
	expiresAt      time.Time
	consumed       bool
}

// HostedLoginGateway is an http.Handler. It keeps only short-lived attempt
// capabilities in memory; AH credentials and tokens are never retained.
type HostedLoginGateway struct {
	publicOrigin   *url.URL
	appOrigin      *url.URL
	handoffURL     *url.URL
	loginTarget    *url.URL
	apiBaseURL     string
	secret         []byte
	client         *http.Client
	apiClient      *http.Client
	proxyTransport http.RoundTripper
	logger         *log.Logger
	now            func() time.Time
	maxAttempts    int

	mu       sync.Mutex
	attempts map[string]*hostedAttempt
}

// NewHostedLoginGateway validates the trust boundaries before serving traffic.
func NewHostedLoginGateway(cfg HostedGatewayConfig) (*HostedLoginGateway, error) {
	publicOrigin, err := parseGatewayOrigin(cfg.PublicOrigin, cfg.AllowInsecureForTests)
	if err != nil {
		return nil, fmt.Errorf("public origin: %w", err)
	}
	appOrigin, err := parseGatewayOrigin(cfg.AppOrigin, cfg.AllowInsecureForTests)
	if err != nil {
		return nil, fmt.Errorf("app origin: %w", err)
	}
	handoffURL, err := url.Parse(cfg.HandoffURL)
	if err != nil || handoffURL.Scheme != appOrigin.Scheme || handoffURL.Host != appOrigin.Host || handoffURL.User != nil {
		return nil, errors.New("handoff URL must use the configured app origin")
	}
	if len(cfg.SharedSecret) < 32 {
		return nil, errors.New("shared secret must contain at least 32 bytes")
	}
	loginBaseURL := cfg.LoginBaseURL
	if loginBaseURL == "" {
		loginBaseURL = "https://login.ah.nl"
	}
	loginTarget, err := url.Parse(loginBaseURL)
	if err != nil || loginTarget.Scheme == "" || loginTarget.Host == "" || loginTarget.User != nil || loginTarget.RawQuery != "" {
		return nil, errors.New("invalid AH login base URL")
	}
	if !cfg.AllowInsecureForTests && (loginTarget.Scheme != "https" || loginTarget.Hostname() != "login.ah.nl") {
		return nil, errors.New("AH login target must be https://login.ah.nl")
	}
	apiBaseURL := cfg.APIBaseURL
	if apiBaseURL == "" {
		apiBaseURL = defaultBaseURL
	}
	client := cfg.HTTPClient
	usingDefaultClient := client == nil
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	clientCopy := *client
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if clientCopy.Timeout == 0 {
		clientCopy.Timeout = 20 * time.Second
	}
	client = &clientCopy
	proxyTransport := client.Transport
	if proxyTransport == nil {
		proxyTransport = http.DefaultTransport
	}
	if usingDefaultClient && !cfg.AllowInsecureForTests {
		proxyTransport, err = srt.NewSpoofedRoundTripper(
			tlsclient.WithRandomTLSExtensionOrder(),
			tlsclient.WithClientProfile(profiles.Chrome_120),
			tlsclient.WithNotFollowRedirects(),
			tlsclient.WithTimeoutSeconds(20),
		)
		if err != nil {
			return nil, fmt.Errorf("create browser-compatible AH transport: %w", err)
		}
	}
	apiClientCopy := *client
	apiClientCopy.Transport = proxyTransport
	apiClient := &apiClientCopy
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	maxAttempts := cfg.MaxActiveAttempts
	if maxAttempts == 0 {
		maxAttempts = 1000
	}
	if maxAttempts < 1 || maxAttempts > 10000 {
		return nil, errors.New("max active attempts must be between 1 and 10000")
	}
	return &HostedLoginGateway{
		publicOrigin:   publicOrigin,
		appOrigin:      appOrigin,
		handoffURL:     handoffURL,
		loginTarget:    loginTarget,
		apiBaseURL:     strings.TrimRight(apiBaseURL, "/"),
		secret:         append([]byte(nil), cfg.SharedSecret...),
		client:         client,
		apiClient:      apiClient,
		proxyTransport: proxyTransport,
		logger:         logger,
		now:            now,
		maxAttempts:    maxAttempts,
		attempts:       make(map[string]*hostedAttempt),
	}, nil
}

func parseGatewayOrigin(raw string, allowInsecure bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("must be an origin without path, query, fragment, or credentials")
	}
	if !allowInsecure && u.Scheme != "https" {
		return nil, errors.New("must use HTTPS")
	}
	if allowInsecure && u.Scheme != "https" && u.Scheme != "http" {
		return nil, errors.New("unsupported scheme")
	}
	u.Path = ""
	return u, nil
}

// SignHostedGatewayStart returns the signature expected by /start.
func SignHostedGatewayStart(secret []byte, attemptID string, expiresUnix int64, returnPath string) string {
	return gatewayMAC(secret, attemptID+"\n"+strconv.FormatInt(expiresUnix, 10)+"\n"+returnPath)
}

func gatewayMAC(secret []byte, value string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = io.WriteString(mac, value)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (g *HostedLoginGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.pruneAttempts()
	g.setSecurityHeaders(w)
	if r.Host != g.publicOrigin.Host {
		http.Error(w, "invalid host", http.StatusMisdirectedRequest)
		return
	}
	switch r.URL.Path {
	case "/health":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			methodNotAllowed(w, "GET, HEAD")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case "/start":
		g.handleStart(w, r)
	case "/callback":
		g.handleCallback(w, r)
	default:
		g.handleProxy(w, r)
	}
}

func (g *HostedLoginGateway) setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", hostedLoginCSP)
}

func (g *HostedLoginGateway) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	q := r.URL.Query()
	attemptID, returnPath := q.Get("attempt"), q.Get("return_path")
	expiresUnix, err := strconv.ParseInt(q.Get("expires"), 10, 64)
	if err != nil || !validGatewayAttemptID(attemptID) || !validGatewayReturnPath(returnPath) {
		http.Error(w, "invalid login attempt", http.StatusBadRequest)
		return
	}
	now := g.now()
	expiresAt := time.Unix(expiresUnix, 0)
	if !expiresAt.After(now) || expiresAt.After(now.Add(maxGatewayAttemptTTL)) {
		http.Error(w, "expired login attempt", http.StatusGone)
		return
	}
	expected := SignHostedGatewayStart(g.secret, attemptID, expiresUnix, returnPath)
	if subtle.ConstantTimeCompare([]byte(q.Get("signature")), []byte(expected)) != 1 {
		http.Error(w, "invalid login attempt", http.StatusForbidden)
		return
	}
	capability, err := randomGatewayCapability()
	if err != nil {
		http.Error(w, "could not start login", http.StatusInternalServerError)
		return
	}
	g.mu.Lock()
	if _, exists := g.attempts[attemptID]; exists {
		g.mu.Unlock()
		http.Error(w, "login attempt already exists", http.StatusConflict)
		return
	}
	if len(g.attempts) >= g.maxAttempts {
		g.mu.Unlock()
		http.Error(w, "too many active login attempts", http.StatusTooManyRequests)
		return
	}
	g.attempts[attemptID] = &hostedAttempt{
		id: attemptID, capabilityHash: sha256.Sum256([]byte(capability)), returnPath: returnPath, expiresAt: expiresAt,
	}
	g.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: hostedAttemptCookie, Value: attemptID + "." + capability, Path: "/", HttpOnly: true,
		Secure: g.publicOrigin.Scheme == "https", SameSite: http.SameSiteLaxMode,
		MaxAge: int(expiresAt.Sub(now).Seconds()),
	})
	loginPath := fmt.Sprintf("/login?client_id=%s&response_type=code&redirect_uri=appie://login-exit", defaultClientID)
	http.Redirect(w, r, loginPath, http.StatusSeeOther)
}

func (g *HostedLoginGateway) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	attempt, ok := g.authorizeAttempt(r, true)
	if !ok {
		http.Error(w, "login attempt unavailable", http.StatusUnauthorized)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" || len(code) > 4096 {
		g.finishAttempt(attempt.id)
		g.redirectResult(w, r, attempt, "failed")
		return
	}
	client := New(WithBaseURL(g.apiBaseURL), WithHTTPClient(g.apiClient), WithLogger(g.logger))
	if err := client.exchangeCode(r.Context(), code); err != nil {
		g.logger.Printf("gateway callback attempt=%s result=exchange_failed", redactedAttemptID(attempt.id))
		g.finishAttempt(attempt.id)
		g.redirectResult(w, r, attempt, "failed")
		return
	}
	session, ok := client.AuthSession()
	if !ok {
		g.logger.Printf("gateway callback attempt=%s result=session_incomplete", redactedAttemptID(attempt.id))
		g.finishAttempt(attempt.id)
		g.redirectResult(w, r, attempt, "failed")
		return
	}
	if session.MemberID == "" {
		member, err := client.GetMember(r.Context())
		if err != nil || member.ID == "" {
			g.logger.Printf("gateway callback attempt=%s result=member_lookup_failed", redactedAttemptID(attempt.id))
			g.finishAttempt(attempt.id)
			g.redirectResult(w, r, attempt, "failed")
			return
		}
		session.MemberID = member.ID
	}
	if err := g.handoff(r.Context(), attempt.id, session); err != nil {
		g.logger.Printf("gateway callback attempt=%s result=handoff_failed", redactedAttemptID(attempt.id))
		g.finishAttempt(attempt.id)
		g.redirectResult(w, r, attempt, "failed")
		return
	}
	g.logger.Printf("gateway callback attempt=%s result=complete", redactedAttemptID(attempt.id))
	g.finishAttempt(attempt.id)
	g.redirectResult(w, r, attempt, "complete")
}

func (g *HostedLoginGateway) handoff(ctx context.Context, attemptID string, session AuthSession) error {
	body, err := json.Marshal(struct {
		AttemptID string      `json:"attempt_id"`
		Session   AuthSession `json:"session"`
	}{AttemptID: attemptID, Session: session})
	if err != nil {
		return err
	}
	timestamp := strconv.FormatInt(g.now().Unix(), 10)
	signature := gatewayMAC(g.secret, timestamp+"\n"+attemptID+"\n"+string(body))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.handoffURL.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Appie-Timestamp", timestamp)
	req.Header.Set("X-Appie-Attempt", attemptID)
	req.Header.Set("X-Appie-Signature", signature)
	resp, err := g.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("handoff returned status %d", resp.StatusCode)
	}
	return nil
}

func (g *HostedLoginGateway) handleProxy(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if recovered := recover(); recovered != nil {
			classification := "unexpected_panic"
			if recovered == http.ErrAbortHandler {
				classification = "abort_handler"
			}
			g.logger.Printf("gateway proxy result=panic classification=%s detail=%q", classification, recovered)
			w.Header().Set("X-Appie-Gateway-Error", classification)
			http.Error(w, "AH login is temporarily unavailable", http.StatusBadGateway)
		}
	}()
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPost {
		methodNotAllowed(w, "GET, HEAD, POST")
		return
	}
	if !isPublicHostedLoginAsset(r) {
		if _, ok := g.authorizeAttempt(r, false); !ok {
			http.Error(w, "login attempt unavailable", http.StatusUnauthorized)
			return
		}
	}
	if r.Method == http.MethodPost && r.Header.Get("Origin") != g.publicOrigin.String() {
		http.Error(w, "invalid origin", http.StatusForbidden)
		return
	}
	if r.ContentLength > maxGatewayBodyBytes {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxGatewayBodyBytes)
	upstream := r.Clone(r.Context())
	upstream.RequestURI = ""
	upstream.URL.Scheme = g.loginTarget.Scheme
	upstream.URL.Host = g.loginTarget.Host
	upstream.Host = g.loginTarget.Host
	upstream.Header = r.Header.Clone()
	upstream.Header.Del("Accept-Encoding")
	normalizeHostedBrowserHeaders(upstream.Header)
	removeCookie(upstream, hostedAttemptCookie)
	if upstream.Header.Get("Origin") == g.publicOrigin.String() {
		upstream.Header.Set("Origin", strings.TrimRight(g.loginTarget.String(), "/"))
	}
	if referer := upstream.Header.Get("Referer"); strings.HasPrefix(referer, g.publicOrigin.String()) {
		upstream.Header.Set("Referer", strings.Replace(referer, g.publicOrigin.String(), strings.TrimRight(g.loginTarget.String(), "/"), 1))
	}

	resp, err := g.proxyTransport.RoundTrip(upstream)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		g.logger.Printf("gateway proxy result=upstream_failed error=%q", err.Error())
		http.Error(w, "AH login is temporarily unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if err := rewriteHostedLoginResponse(resp, g.publicOrigin.String(), strings.TrimRight(g.loginTarget.String(), "/")); err != nil {
		g.logger.Printf("gateway proxy result=response_rewrite_failed error=%q", err.Error())
		http.Error(w, "AH login is temporarily unavailable", http.StatusBadGateway)
		return
	}
	const maxUpstreamResponseBytes = 8 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamResponseBytes+1))
	if err != nil {
		g.logger.Printf("gateway proxy result=response_read_failed error=%q", err.Error())
		http.Error(w, "AH login is temporarily unavailable", http.StatusBadGateway)
		return
	}
	if len(body) > maxUpstreamResponseBytes {
		g.logger.Printf("gateway proxy result=response_too_large")
		http.Error(w, "AH login is temporarily unavailable", http.StatusBadGateway)
		return
	}
	resp.Header.Del("Transfer-Encoding")
	resp.Header.Del("Content-Length")
	resp.Header.Del("Connection")
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if r.Method != http.MethodHead {
		if _, err := w.Write(body); err != nil {
			g.logger.Printf("gateway proxy result=response_copy_failed error=%q", err.Error())
		}
	}
}

func normalizeHostedBrowserHeaders(header http.Header) {
	userAgent := header.Get("User-Agent")
	if strings.Contains(userAgent, "HeadlessChrome/") {
		header.Set("User-Agent", strings.ReplaceAll(userAgent, "HeadlessChrome/", "Chrome/"))
	}
	clientHints := header.Get("Sec-CH-UA")
	if strings.Contains(clientHints, "HeadlessChrome") {
		header.Set("Sec-CH-UA", strings.ReplaceAll(clientHints, "HeadlessChrome", "Google Chrome"))
	}
}

func isPublicHostedLoginAsset(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	return strings.HasPrefix(r.URL.Path, "/login/_next/static/") ||
		strings.HasPrefix(r.URL.Path, "/login/static/")
}

func (g *HostedLoginGateway) authorizeAttempt(r *http.Request, consume bool) (*hostedAttempt, bool) {
	cookie, err := r.Cookie(hostedAttemptCookie)
	if err != nil {
		return nil, false
	}
	parts := strings.SplitN(cookie.Value, ".", 2)
	if len(parts) != 2 || !validGatewayAttemptID(parts[0]) {
		return nil, false
	}
	hash := sha256.Sum256([]byte(parts[1]))
	g.mu.Lock()
	defer g.mu.Unlock()
	attempt := g.attempts[parts[0]]
	if attempt == nil || attempt.consumed || !attempt.expiresAt.After(g.now()) || subtle.ConstantTimeCompare(hash[:], attempt.capabilityHash[:]) != 1 {
		return nil, false
	}
	if consume {
		attempt.consumed = true
	}
	copy := *attempt
	return &copy, true
}

func (g *HostedLoginGateway) finishAttempt(attemptID string) {
	g.mu.Lock()
	delete(g.attempts, attemptID)
	g.mu.Unlock()
}

func (g *HostedLoginGateway) redirectResult(w http.ResponseWriter, r *http.Request, attempt *hostedAttempt, status string) {
	http.SetCookie(w, &http.Cookie{Name: hostedAttemptCookie, Value: "", Path: "/", HttpOnly: true, Secure: g.publicOrigin.Scheme == "https", SameSite: http.SameSiteLaxMode, MaxAge: -1})
	destination := *g.appOrigin
	returnURL, _ := url.ParseRequestURI(attempt.returnPath)
	destination.Path = returnURL.Path
	destination.RawPath = returnURL.RawPath
	destination.RawQuery = returnURL.RawQuery
	q := destination.Query()
	q.Set("ah_attempt", attempt.id)
	q.Set("ah_status", status)
	destination.RawQuery = q.Encode()
	http.Redirect(w, r, destination.String(), http.StatusSeeOther)
}

func (g *HostedLoginGateway) pruneAttempts() {
	now := g.now()
	g.mu.Lock()
	for id, attempt := range g.attempts {
		if attempt.consumed || !attempt.expiresAt.After(now) {
			delete(g.attempts, id)
		}
	}
	g.mu.Unlock()
}

func rewriteHostedLoginResponse(resp *http.Response, publicOrigin, targetOrigin string) error {
	if location := resp.Header.Get("Location"); location != "" {
		switch {
		case strings.HasPrefix(location, "appie://"):
			u, err := url.Parse(location)
			if err != nil {
				return err
			}
			resp.Header.Set("Location", publicOrigin+"/callback?"+u.Query().Encode())
		case strings.HasPrefix(location, targetOrigin):
			resp.Header.Set("Location", strings.Replace(location, targetOrigin, publicOrigin, 1))
		}
	}
	if cookies := resp.Header.Values("Set-Cookie"); len(cookies) > 0 {
		resp.Header.Del("Set-Cookie")
		for _, cookie := range cookies {
			resp.Header.Add("Set-Cookie", sanitizeHostedCookie(cookie))
		}
	}
	resp.Header.Set("Cache-Control", "no-store")
	resp.Header.Set("Referrer-Policy", "no-referrer")
	resp.Header.Set("X-Content-Type-Options", "nosniff")
	resp.Header.Set("X-Frame-Options", "DENY")
	resp.Header.Set("Content-Security-Policy", hostedLoginCSP)
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") && !strings.Contains(contentType, "javascript") && !strings.Contains(contentType, "json") {
		return nil
	}
	body, err := readResponseBody(resp)
	if err != nil {
		return err
	}
	body = bytes.ReplaceAll(body, []byte("appie://login-exit"), []byte(publicOrigin+"/callback"))
	body = bytes.ReplaceAll(body, []byte(targetOrigin), []byte(publicOrigin))
	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices && strings.Contains(contentType, "text/html") {
		body = routeHostedStylesheetsDirectly(body, targetOrigin)
		body = injectHostedLoginNotice(body)
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Del("Content-Encoding")
	return nil
}

func routeHostedStylesheetsDirectly(body []byte, targetOrigin string) []byte {
	return hostedStylesheetPattern.ReplaceAllFunc(body, func(match []byte) []byte {
		return bytes.Replace(match, []byte(`href="/`), []byte(`href="`+targetOrigin+`/`), 1)
	})
}

func injectHostedLoginNotice(body []byte) []byte {
	lower := bytes.ToLower(body)
	bodyStart := bytes.Index(lower, []byte("<body"))
	if bodyStart == -1 {
		return body
	}
	bodyTagEnd := bytes.IndexByte(body[bodyStart:], '>')
	if bodyTagEnd == -1 {
		return body
	}
	insertAt := bodyStart + bodyTagEnd + 1
	result := make([]byte, 0, len(body)+len(hostedLoginNotice))
	result = append(result, body[:insertAt]...)
	result = append(result, hostedLoginNotice...)
	result = append(result, body[insertAt:]...)
	return result
}

func sanitizeHostedCookie(cookie string) string {
	parts := strings.Split(cookie, ";")
	out := parts[:1]
	for _, part := range parts[1:] {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(part)), "domain=") {
			continue
		}
		out = append(out, part)
	}
	return strings.Join(out, ";")
}

func removeCookie(r *http.Request, name string) {
	var kept []string
	for _, cookie := range r.Cookies() {
		if cookie.Name != name {
			kept = append(kept, cookie.Name+"="+cookie.Value)
		}
	}
	if len(kept) == 0 {
		r.Header.Del("Cookie")
		return
	}
	r.Header.Set("Cookie", strings.Join(kept, "; "))
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func validGatewayAttemptID(value string) bool {
	if len(value) < 32 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '_' && char != '-' {
			return false
		}
	}
	return true
}

func validGatewayReturnPath(value string) bool {
	if !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.ContainsAny(value, "\r\n") || len(value) > 2048 {
		return false
	}
	parsed, err := url.ParseRequestURI(value)
	return err == nil && parsed.IsAbs() == false && parsed.Host == "" && parsed.Fragment == ""
}

func randomGatewayCapability() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func redactedAttemptID(value string) string {
	if len(value) < 8 {
		return "invalid"
	}
	return value[:8]
}
