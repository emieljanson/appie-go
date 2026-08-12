package appie

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const gatewayTestSecret = "0123456789abcdef0123456789abcdef"

type gatewayFixture struct {
	gateway        *HostedLoginGateway
	server         *httptest.Server
	loginServer    *httptest.Server
	apiServer      *httptest.Server
	appServer      *httptest.Server
	handoffs       chan []byte
	upstreamCookie chan string
	upstreamOrigin chan string
	upstreamAgent  chan string
	upstreamCHUA   chan string
	logs           *bytes.Buffer
	now            time.Time
}

type panicRoundTripper struct{ value any }

func (transport panicRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	panic(transport.value)
}

func newGatewayFixture(t *testing.T) *gatewayFixture {
	t.Helper()
	fixture := &gatewayFixture{
		handoffs:       make(chan []byte, 8),
		upstreamCookie: make(chan string, 8),
		upstreamOrigin: make(chan string, 8),
		upstreamAgent:  make(chan string, 8),
		upstreamCHUA:   make(chan string, 8),
		logs:           &bytes.Buffer{},
		now:            time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC),
	}
	fixture.appServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ah/connect/complete" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		timestamp := r.Header.Get("X-Appie-Timestamp")
		attempt := r.Header.Get("X-Appie-Attempt")
		expected := gatewayMAC([]byte(gatewayTestSecret), timestamp+"\n"+attempt+"\n"+string(body))
		if subtle.ConstantTimeCompare([]byte(expected), []byte(r.Header.Get("X-Appie-Signature"))) != 1 {
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		fixture.handoffs <- body
		w.WriteHeader(http.StatusNoContent)
	}))
	fixture.loginServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.upstreamCookie <- r.Header.Get("Cookie")
		fixture.upstreamOrigin <- r.Header.Get("Origin")
		fixture.upstreamAgent <- r.Header.Get("User-Agent")
		fixture.upstreamCHUA <- r.Header.Get("Sec-CH-UA")
		switch r.URL.Path {
		case "/login":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><link rel="stylesheet" href="/login/_next/static/login.css"><script src="/login/_next/static/login.js"></script></head><body><a href="%s/next">next</a><a href="appie://login-exit?code=from-body">done</a></body></html>`, fixture.loginServer.URL)
		case "/login/_next/static/login.css":
			w.Header().Set("Content-Type", "text/css")
			_, _ = io.WriteString(w, "body{color:#111}")
		case "/submit":
			_, err := io.Copy(io.Discard, r.Body)
			if err != nil {
				http.Error(w, "too large", http.StatusRequestEntityTooLarge)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	fixture.apiServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mobile-auth/v1/auth/token" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(token{AccessToken: "secret-access", RefreshToken: "secret-refresh", MemberID: "member-123", ExpiresIn: 3600})
	}))

	unstarted := httptest.NewUnstartedServer(nil)
	publicOrigin := "http://" + unstarted.Listener.Addr().String()
	gateway, err := NewHostedLoginGateway(HostedGatewayConfig{
		PublicOrigin:          publicOrigin,
		AppOrigin:             fixture.appServer.URL,
		HandoffURL:            fixture.appServer.URL + "/api/ah/connect/complete",
		SharedSecret:          []byte(gatewayTestSecret),
		LoginBaseURL:          fixture.loginServer.URL,
		APIBaseURL:            fixture.apiServer.URL,
		Logger:                log.New(fixture.logs, "", 0),
		Now:                   func() time.Time { return fixture.now },
		AllowInsecureForTests: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.gateway = gateway
	unstarted.Config.Handler = gateway
	unstarted.Start()
	fixture.server = unstarted
	t.Cleanup(func() {
		fixture.server.Close()
		fixture.loginServer.Close()
		fixture.apiServer.Close()
		fixture.appServer.Close()
	})
	return fixture
}

func gatewayClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func startGatewayAttempt(t *testing.T, fixture *gatewayFixture, client *http.Client, attemptID string) *http.Response {
	t.Helper()
	expires := fixture.now.Add(5 * time.Minute).Unix()
	values := url.Values{
		"attempt":     {attemptID},
		"expires":     {strconv.FormatInt(expires, 10)},
		"return_path": {"/instellen"},
		"signature":   {SignHostedGatewayStart([]byte(gatewayTestSecret), attemptID, expires, "/instellen")},
	}
	resp, err := client.Get(fixture.server.URL + "/start?" + values.Encode())
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestHostedGatewayCompletesOneTimeSignedHandoff(t *testing.T) {
	fixture := newGatewayFixture(t)
	client := gatewayClient(t)
	attemptID := strings.Repeat("a", 32)

	start := startGatewayAttempt(t, fixture, client, attemptID)
	start.Body.Close()
	if start.StatusCode != http.StatusSeeOther || !strings.HasPrefix(start.Header.Get("Location"), "/login?") {
		t.Fatalf("unexpected start response: %d %s", start.StatusCode, start.Header.Get("Location"))
	}
	login, err := client.Get(fixture.server.URL + start.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(login.Body)
	login.Body.Close()
	if strings.Contains(string(body), fixture.loginServer.URL+"/next") || strings.Contains(string(body), "appie://") {
		t.Fatalf("hosted response was not rewritten: %s", body)
	}
	if !strings.Contains(string(body), fixture.server.URL+"/callback") {
		t.Fatalf("hosted callback missing: %s", body)
	}
	if !strings.Contains(string(body), "Je blijft op Beter Gekozen") || strings.Count(string(body), "betergekozen-login-notice") < 1 {
		t.Fatalf("hosted login notice missing: %s", body)
	}
	if !strings.Contains(string(body), fixture.loginServer.URL+"/login/_next/static/login.css") ||
		!strings.Contains(string(body), fixture.loginServer.URL+"/login/_next/static/login.js") {
		t.Fatalf("hosted static assets were not routed directly to AH: %s", body)
	}
	if upstreamCookie := <-fixture.upstreamCookie; strings.Contains(upstreamCookie, hostedAttemptCookie) {
		t.Fatal("gateway capability leaked to AH upstream")
	}

	callback, err := client.Get(fixture.server.URL + "/callback?code=auth-code")
	if err != nil {
		t.Fatal(err)
	}
	callback.Body.Close()
	if callback.StatusCode != http.StatusSeeOther {
		t.Fatalf("unexpected callback status: %d", callback.StatusCode)
	}
	destination, _ := url.Parse(callback.Header.Get("Location"))
	if destination.Path != "/instellen" || destination.Query().Get("ah_status") != "complete" || destination.Query().Get("ah_attempt") != attemptID {
		t.Fatalf("unexpected completion redirect: %s", destination)
	}

	var payload struct {
		AttemptID string      `json:"attempt_id"`
		Session   AuthSession `json:"session"`
	}
	if err := json.Unmarshal(<-fixture.handoffs, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.AttemptID != attemptID || payload.Session.MemberID != "member-123" || payload.Session.AccessToken != "secret-access" {
		t.Fatalf("unexpected handoff payload: %+v", payload)
	}

	replay, err := client.Get(fixture.server.URL + "/callback?code=auth-code")
	if err != nil {
		t.Fatal(err)
	}
	replay.Body.Close()
	if replay.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected callback replay rejection, got %d", replay.StatusCode)
	}
	if strings.Contains(fixture.logs.String(), "secret-access") || strings.Contains(fixture.logs.String(), "secret-refresh") || strings.Contains(fixture.logs.String(), "auth-code") {
		t.Fatalf("secret material reached gateway logs: %s", fixture.logs)
	}
}

func TestHostedGatewayKeepsPublicStylesAvailableWithoutAttempt(t *testing.T) {
	fixture := newGatewayFixture(t)

	resp, err := http.Get(fixture.server.URL + "/login/_next/static/login.css")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "body{color:#111}" {
		t.Fatalf("unexpected public stylesheet response: %d %q", resp.StatusCode, body)
	}

	login, err := http.Get(fixture.server.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	login.Body.Close()
	if login.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected login document to remain protected, got %d", login.StatusCode)
	}
}

func TestInjectHostedLoginNoticeOnlyTouchesHTMLBody(t *testing.T) {
	body := []byte(`<html><body class="login"><main>AH login</main></body></html>`)
	got := injectHostedLoginNotice(body)
	if !bytes.Contains(got, []byte(hostedLoginNotice)) {
		t.Fatalf("notice was not injected: %s", got)
	}
	if bytes.Count(got, []byte(`id="betergekozen-login-notice"`)) != 1 {
		t.Fatalf("notice was not injected exactly once: %s", got)
	}
	if gotWithoutBody := injectHostedLoginNotice([]byte("body{color:#111}")); !bytes.Equal(gotWithoutBody, []byte("body{color:#111}")) {
		t.Fatalf("non-HTML body was changed: %s", gotWithoutBody)
	}
}

func TestRouteHostedStaticAssetsDirectlyLeavesApplicationRoutesHosted(t *testing.T) {
	body := []byte(`<link href="/login/_next/static/login.css"><form action="/login"><a href="/login/passkeys">Passkeys</a></form>`)
	got := routeHostedStaticAssetsDirectly(body, "https://login.ah.nl")
	if !bytes.Contains(got, []byte(`href="https://login.ah.nl/login/_next/static/login.css"`)) {
		t.Fatalf("static asset was not routed directly: %s", got)
	}
	for _, hosted := range []string{`action="/login"`, `href="/login/passkeys"`} {
		if !bytes.Contains(got, []byte(hosted)) {
			t.Fatalf("application route was unexpectedly changed: %s", got)
		}
	}
}

func TestHostedLoginNoticeIsNotAddedToUpstreamErrors(t *testing.T) {
	response := &http.Response{
		StatusCode: http.StatusForbidden,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader("<html><body>Access Denied</body></html>")),
	}
	if err := rewriteHostedLoginResponse(response, "https://login.app.test", "https://login.ah.test"); err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	if bytes.Contains(body, []byte("betergekozen-login-notice")) {
		t.Fatalf("notice was added to an upstream error: %s", body)
	}
}

func TestHostedGatewayIsolatesConcurrentBrowserAttempts(t *testing.T) {
	fixture := newGatewayFixture(t)
	clients := []*http.Client{gatewayClient(t), gatewayClient(t)}
	attempts := []string{strings.Repeat("a", 32), strings.Repeat("b", 32)}
	var wg sync.WaitGroup
	for i := range clients {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp := startGatewayAttempt(t, fixture, clients[i], attempts[i])
			resp.Body.Close()
		}(i)
	}
	wg.Wait()

	for i := range clients {
		resp, err := clients[i].Get(fixture.server.URL + "/callback?code=code-" + strconv.Itoa(i))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("attempt %d failed with %d", i, resp.StatusCode)
		}
	}
	received := map[string]bool{}
	for range attempts {
		var payload struct {
			AttemptID string `json:"attempt_id"`
		}
		if err := json.Unmarshal(<-fixture.handoffs, &payload); err != nil {
			t.Fatal(err)
		}
		received[payload.AttemptID] = true
	}
	for _, attempt := range attempts {
		if !received[attempt] {
			t.Fatalf("missing isolated handoff for %s", attempt)
		}
	}
}

func TestHostedGatewayRejectsInvalidBoundaries(t *testing.T) {
	fixture := newGatewayFixture(t)
	attemptID := strings.Repeat("a", 32)
	expires := fixture.now.Add(5 * time.Minute).Unix()

	t.Run("bad signature", func(t *testing.T) {
		resp, err := http.Get(fixture.server.URL + "/start?attempt=" + attemptID + "&expires=" + strconv.FormatInt(expires, 10) + "&return_path=%2Finstellen&signature=bad")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("got %d", resp.StatusCode)
		}
	})

	t.Run("expired", func(t *testing.T) {
		past := fixture.now.Add(-time.Minute).Unix()
		signature := SignHostedGatewayStart([]byte(gatewayTestSecret), attemptID, past, "/instellen")
		resp, err := http.Get(fixture.server.URL + "/start?attempt=" + attemptID + "&expires=" + strconv.FormatInt(past, 10) + "&return_path=%2Finstellen&signature=" + url.QueryEscape(signature))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusGone {
			t.Fatalf("got %d", resp.StatusCode)
		}
	})

	t.Run("wrong host", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fixture.server.URL+"/health", nil)
		req.Host = "malicious.example"
		response := httptest.NewRecorder()
		fixture.gateway.ServeHTTP(response, req)
		if response.Code != http.StatusMisdirectedRequest {
			t.Fatalf("got %d", response.Code)
		}
	})

	t.Run("wrong origin", func(t *testing.T) {
		client := gatewayClient(t)
		start := startGatewayAttempt(t, fixture, client, strings.Repeat("c", 32))
		start.Body.Close()
		req, _ := http.NewRequest(http.MethodPost, fixture.server.URL+"/submit", strings.NewReader("email=private@example.com"))
		req.Header.Set("Origin", "https://malicious.example")
		for _, cookie := range client.Jar.Cookies(mustParseURL(t, fixture.server.URL)) {
			req.AddCookie(cookie)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("got %d", resp.StatusCode)
		}
		if strings.Contains(fixture.logs.String(), "private@example.com") {
			t.Fatal("request body reached gateway logs")
		}
	})

	t.Run("unsupported method", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPut, fixture.server.URL+"/anything", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("got %d", resp.StatusCode)
		}
	})
}

func TestHostedGatewayRejectsOversizedRequestBody(t *testing.T) {
	for index, chunked := range []bool{false, true} {
		t.Run(map[bool]string{false: "known length", true: "chunked"}[chunked], func(t *testing.T) {
			fixture := newGatewayFixture(t)
			client := gatewayClient(t)
			start := startGatewayAttempt(t, fixture, client, strings.Repeat(string(rune('d'+index)), 32))
			start.Body.Close()

			req, err := http.NewRequest(
				http.MethodPost,
				fixture.server.URL+"/submit",
				strings.NewReader(strings.Repeat("x", maxGatewayBodyBytes+1)),
			)
			if err != nil {
				t.Fatal(err)
			}
			if chunked {
				req.ContentLength = -1
				req.TransferEncoding = []string{"chunked"}
			}
			req.Header.Set("Origin", fixture.server.URL)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusRequestEntityTooLarge {
				t.Fatalf("expected oversized request rejection, got %d", resp.StatusCode)
			}
		})
	}
}

func TestHostedGatewayRejectsCrossAttemptCapability(t *testing.T) {
	fixture := newGatewayFixture(t)
	firstClient := gatewayClient(t)
	secondClient := gatewayClient(t)
	firstAttempt := strings.Repeat("e", 32)
	secondAttempt := strings.Repeat("f", 32)

	first := startGatewayAttempt(t, fixture, firstClient, firstAttempt)
	first.Body.Close()
	second := startGatewayAttempt(t, fixture, secondClient, secondAttempt)
	second.Body.Close()

	var firstCookie *http.Cookie
	for _, cookie := range firstClient.Jar.Cookies(mustParseURL(t, fixture.server.URL)) {
		if cookie.Name == hostedAttemptCookie {
			firstCookie = cookie
			break
		}
	}
	if firstCookie == nil {
		t.Fatal("attempt cookie missing")
	}
	parts := strings.SplitN(firstCookie.Value, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("unexpected attempt cookie shape")
	}

	req, err := http.NewRequest(http.MethodGet, fixture.server.URL+"/next", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: hostedAttemptCookie, Value: secondAttempt + "." + parts[1]})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected cross-attempt capability rejection, got %d", resp.StatusCode)
	}
}

func TestHostedGatewayValidatesProductionOrigins(t *testing.T) {
	_, err := NewHostedLoginGateway(HostedGatewayConfig{
		PublicOrigin: "http://gateway.example", AppOrigin: "https://app.example",
		HandoffURL: "https://app.example/api/ah/connect/complete", SharedSecret: []byte(gatewayTestSecret),
	})
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected insecure origin rejection, got %v", err)
	}
	_, err = NewHostedLoginGateway(HostedGatewayConfig{
		PublicOrigin: "https://gateway.example", AppOrigin: "https://app.example",
		HandoffURL: "https://evil.example/collect", SharedSecret: []byte(gatewayTestSecret),
	})
	if err == nil || !strings.Contains(err.Error(), "app origin") {
		t.Fatalf("expected handoff origin rejection, got %v", err)
	}
}

func TestHostedGatewayNeverFollowsTokenHandoffRedirects(t *testing.T) {
	leaked := make(chan bool, 1)
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked <- true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer evil.Close()
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL, http.StatusTemporaryRedirect)
	}))
	defer app.Close()
	gateway, err := NewHostedLoginGateway(HostedGatewayConfig{
		PublicOrigin:          "http://gateway.test",
		AppOrigin:             app.URL,
		HandoffURL:            app.URL + "/api/ah/connect/complete",
		SharedSecret:          []byte(gatewayTestSecret),
		LoginBaseURL:          app.URL,
		APIBaseURL:            app.URL,
		AllowInsecureForTests: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = gateway.handoff(context.Background(), strings.Repeat("a", 32), AuthSession{
		AccessToken: "secret-access", RefreshToken: "secret-refresh", MemberID: "member-123",
	})
	if err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("expected redirect to remain a failed handoff, got %v", err)
	}
	select {
	case <-leaked:
		t.Fatal("token handoff followed a redirect to another origin")
	default:
	}
}

func TestGatewayReturnPathValidation(t *testing.T) {
	for _, valid := range []string{"/instellen", "/instellen?from=ah"} {
		if !validGatewayReturnPath(valid) {
			t.Fatalf("expected valid return path %q", valid)
		}
	}
	for _, invalid := range []string{"https://evil.example", "//evil.example", "/bad\nheader", ""} {
		if validGatewayReturnPath(invalid) {
			t.Fatalf("expected invalid return path %q", invalid)
		}
	}
}

func TestHostedGatewayBoundsActiveAttempts(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	gateway, err := NewHostedLoginGateway(HostedGatewayConfig{
		PublicOrigin: "http://gateway.test", AppOrigin: "http://app.test",
		HandoffURL: "http://app.test/api/ah/connect/complete", SharedSecret: []byte(gatewayTestSecret),
		LoginBaseURL: "http://login.test", APIBaseURL: "http://api.test",
		Now: func() time.Time { return now }, MaxActiveAttempts: 1, AllowInsecureForTests: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := func(attempt string) *http.Request {
		expires := now.Add(5 * time.Minute).Unix()
		values := url.Values{
			"attempt": {attempt}, "expires": {strconv.FormatInt(expires, 10)}, "return_path": {"/instellen"},
			"signature": {SignHostedGatewayStart([]byte(gatewayTestSecret), attempt, expires, "/instellen")},
		}
		return httptest.NewRequest(http.MethodGet, "http://gateway.test/start?"+values.Encode(), nil)
	}
	first := httptest.NewRecorder()
	gateway.ServeHTTP(first, request(strings.Repeat("a", 32)))
	if first.Code != http.StatusSeeOther {
		t.Fatalf("first attempt failed with %d", first.Code)
	}
	second := httptest.NewRecorder()
	gateway.ServeHTTP(second, request(strings.Repeat("b", 32)))
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("expected capacity rejection, got %d", second.Code)
	}
}

func TestHostedGatewayRewritesValidatedBrowserHeaders(t *testing.T) {
	fixture := newGatewayFixture(t)
	client := gatewayClient(t)
	start := startGatewayAttempt(t, fixture, client, strings.Repeat("d", 32))
	start.Body.Close()
	req, _ := http.NewRequest(http.MethodPost, fixture.server.URL+"/submit", strings.NewReader("email=private@example.com"))
	req.Header.Set("Origin", fixture.server.URL)
	req.Header.Set("Referer", fixture.server.URL+"/login")
	req.Header.Set("User-Agent", "Mozilla/5.0 HeadlessChrome/140.0.0.0 Safari/537.36")
	req.Header.Set("Sec-CH-UA", `"Chromium";v="140", "HeadlessChrome";v="140"`)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected status %d", resp.StatusCode)
	}
	if origin := <-fixture.upstreamOrigin; origin != fixture.loginServer.URL {
		t.Fatalf("origin was not rewritten for AH: %q", origin)
	}
	if upstreamCookie := <-fixture.upstreamCookie; strings.Contains(upstreamCookie, hostedAttemptCookie) {
		t.Fatal("gateway capability leaked in proxied cookie header")
	}
	if userAgent := <-fixture.upstreamAgent; strings.Contains(userAgent, "HeadlessChrome") || !strings.Contains(userAgent, "Chrome/140") {
		t.Fatalf("automation marker was not normalized in user agent: %q", userAgent)
	}
	if clientHints := <-fixture.upstreamCHUA; strings.Contains(clientHints, "HeadlessChrome") || !strings.Contains(clientHints, "Google Chrome") {
		t.Fatalf("automation marker was not normalized in client hints: %q", clientHints)
	}
}

func TestHostedGatewayTurnsProxyPanicsIntoSafeErrors(t *testing.T) {
	fixture := newGatewayFixture(t)
	client := gatewayClient(t)
	start := startGatewayAttempt(t, fixture, client, strings.Repeat("p", 32))
	start.Body.Close()
	fixture.gateway.proxyTransport = panicRoundTripper{value: http.ErrAbortHandler}

	resp, err := client.Get(fixture.server.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected safe gateway error, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Appie-Gateway-Error"); got != "abort_handler" {
		t.Fatalf("unexpected panic classification %q", got)
	}
}

func TestSanitizeHostedCookiePreservesHTTPSAttributes(t *testing.T) {
	got := sanitizeHostedCookie("session=abc; Domain=.ah.nl; Path=/; Secure; HttpOnly; SameSite=None")
	if strings.Contains(strings.ToLower(got), "domain=") {
		t.Fatalf("hosted cookie retained upstream domain: %s", got)
	}
	for _, required := range []string{"Path=/", "Secure", "HttpOnly", "SameSite=None"} {
		if !strings.Contains(got, required) {
			t.Fatalf("hosted cookie dropped %s: %s", required, got)
		}
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
