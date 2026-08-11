package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	appie "github.com/gwillem/appie-go"
)

type gatewayCommand struct {
	Listen       string `long:"listen" default:"127.0.0.1:8080" description:"HTTP listen address"`
	PublicOrigin string `long:"public-origin" required:"true" description:"Public HTTPS gateway origin"`
	AppOrigin    string `long:"app-origin" required:"true" description:"Allowed Boodschappencoach HTTPS origin"`
	HandoffURL   string `long:"handoff-url" required:"true" description:"Fixed server-to-server token handoff URL"`
	MaxAttempts  int    `long:"max-active-attempts" default:"1000" description:"Maximum concurrent login attempts"`
}

func (cmd *gatewayCommand) Execute(_ []string) error {
	secret := os.Getenv("APPIE_GATEWAY_SHARED_SECRET")
	if len(secret) < 32 {
		return errors.New("APPIE_GATEWAY_SHARED_SECRET must contain at least 32 bytes")
	}
	logger := log.New(os.Stdout, "gateway ", log.LstdFlags|log.LUTC)
	gateway, err := appie.NewHostedLoginGateway(appie.HostedGatewayConfig{
		PublicOrigin:      cmd.PublicOrigin,
		AppOrigin:         cmd.AppOrigin,
		HandoffURL:        cmd.HandoffURL,
		SharedSecret:      []byte(secret),
		Logger:            logger,
		MaxActiveAttempts: cmd.MaxAttempts,
	})
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              cmd.Listen,
		Handler:           gateway,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	logger.Printf("listening address=%s", cmd.Listen)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve gateway: %w", err)
	}
	return nil
}
