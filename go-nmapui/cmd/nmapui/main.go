package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/techmore/nmapui/internal/config"
	"github.com/techmore/nmapui/internal/database"
	"github.com/techmore/nmapui/internal/fingerprint"
	"github.com/techmore/nmapui/internal/reports"
	"github.com/techmore/nmapui/internal/scanner"
	"github.com/techmore/nmapui/internal/server"
	"github.com/techmore/nmapui/pkg/websocket"
)

func main() {
	cfg := config.Load()
	log.Printf("NmapUI Go Edition v%s", cfg.AppVersion)

	db, err := database.NewDB(cfg.DatabasePath)
	if err != nil {
		log.Fatalf("database init failed: %v", err)
	}
	defer db.Close()
	log.Printf("Database initialized: %s", cfg.DatabasePath)

	wsHub := websocket.NewHub()
	go wsHub.Run()
	log.Printf("WebSocket hub started")

	nmapScanner := scanner.NewNmapScanner(cfg.NmapPath)
	scanEngine := scanner.NewScanEngine(nmapScanner, nil, cfg.MaxConcurrent)
	log.Printf("Scanner engine initialized (max concurrent: %d)", cfg.MaxConcurrent)

	fpEngine := fingerprint.NewCustomerFingerprinter(cfg.CustomersYAML)
	log.Printf("Fingerprint engine initialized: %s", cfg.CustomersYAML)

	reportGen := reports.NewReportGenerator(cfg.XSLPath, cfg.TempDir, cfg.AppVersion)
	log.Printf("Report generator initialized")

	deps := &server.Dependencies{
		DB:            db,
		ScanEngine:    scanEngine,
		Fingerprinter: fpEngine,
		ReportGen:     reportGen,
		WSHub:         wsHub,
	}

	srv := server.NewServer(deps)
	if err := srv.Initialize(); err != nil {
		log.Fatalf("server init failed: %v", err)
	}

	addr := fmt.Sprintf(":%d", cfg.Port)
	errCh := make(chan error, 1)
	go func() {
		log.Printf("Server listening on http://localhost%s", addr)
		errCh <- srv.Start(addr)
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

	log.Printf("Server stopped gracefully")
}
