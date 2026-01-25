package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/techmore/nmapui/internal/server"
)

func main() {
	srv := server.NewServer()
	if err := srv.Initialize(); err != nil {
		log.Fatalf("server init failed: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(":9000")
	}()

	shutdownCh := make(chan os.Signal, 1)
	signal.Notify(shutdownCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		if err != nil {
			log.Fatalf("server start failed: %v", err)
		}
	case sig := <-shutdownCh:
		log.Printf("shutdown signal received: %s", sig.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("server shutdown error: %v", err)
	}
}
