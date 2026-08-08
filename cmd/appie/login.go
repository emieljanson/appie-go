package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	appie "github.com/gwillem/appie-go"
)

type loginCommand struct {
	NoBrowser bool `long:"no-browser" description:"Print the local login URL without opening a browser"`
}

func (cmd *loginCommand) Execute(args []string) error {
	configPath := globalOpts.Config

	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	opts := clientOpts()
	if cmd.NoBrowser {
		opts = append(opts, appie.WithBrowserOpener(func(loginURL string) {
			fmt.Println(loginURL)
		}))
	}
	client := appie.New(opts...)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if cmd.NoBrowser {
		fmt.Println("AH login URL:")
	} else {
		fmt.Println("Opening browser for AH login. If it doesn't open, visit:")
	}

	if err := client.Login(ctx); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	fmt.Printf("Login successful! Tokens saved to %s\n", configPath)
	fmt.Println("After you have been authorized, the access keys will be automatically refreshed.")
	return nil
}
