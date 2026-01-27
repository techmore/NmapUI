# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NmapUI is a network scanner with a real-time web interface. The project is migrating from Python (Flask/SocketIO) to Go (Fiber/WebSocket) for easier deployment - particularly in hospital environments where Docker is prohibited.

**Active development is on the `go-migration` branch** in the `go-nmapui/` directory.

## Build & Development Commands

All commands run from `go-nmapui/` directory:

```bash
# Build
make build              # Build for current platform → bin/nmapui
make build-all          # Cross-compile for darwin/linux/windows (amd64/arm64)

# Run
make run                # go run cmd/nmapui/main.go
make dev                # Live reload with air (auto-installs)

# Test
make test               # All tests with coverage
make test-race          # Race condition detection
make test-coverage      # Generate coverage.html
go test -v ./internal/scanner/...  # Single package

# Code Quality
make fmt                # Format + goimports
make lint               # golangci-lint (auto-installs)
make vet                # go vet
make security           # gosec security scan

# Utilities
make clean              # Remove artifacts
make tools              # Install air, golangci-lint, goimports
```

## Architecture

```
Browser ←→ Socket.IO Client ←→ Fiber HTTP :9000
                                    ├→ REST API (15+ endpoints)
                                    └→ WebSocket Hub (54 events)
                                         ├→ Scanner Engine → nmap CLI
                                         ├→ Customer Fingerprinter → traceroute
                                         ├→ Report Generator → xsltproc/wkhtmltopdf
                                         └→ SQLite Database (WAL mode)
```

### Package Structure

- `cmd/nmapui/main.go` - Entry point only
- `internal/server/` - HTTP handlers, routes, WebSocket handlers
- `internal/scanner/` - Nmap wrapper, concurrent scan pool, engine orchestration
- `internal/fingerprint/` - Customer identification via network topology
- `internal/database/` - SQLite layer with migrations
- `internal/reports/` - PDF/HTML generation pipeline
- `internal/models/` - Data structures
- `pkg/websocket/` - Hub pattern for real-time communication

### Key Patterns

**Concurrent scanning** uses goroutine pool with semaphore (`internal/scanner/concurrent.go`):
```go
pool := NewPool(maxConcurrent)
errList := pool.Run(ctx, tasks)
```

**WebSocket hub** manages client connections and broadcasts (`pkg/websocket/hub.go`):
```go
router.Register("event_name", handlerFunc)
hub.Broadcast(Message{Event: "scan_progress", Data: data})
```

**Error wrapping** uses `%w` for context:
```go
return fmt.Errorf("scan failed: %w", err)
```

## System Dependencies

Required: `nmap`, `xsltproc`
Optional: `wkhtmltopdf` (PDF reports), `arp-scan` (ARP discovery)

## Code Style

- Imports: stdlib → external → internal (blank lines between groups)
- JSON tags: `snake_case` with `omitempty` for optional fields
- Exported function comments start with function name
- Concurrency: always use `sync.WaitGroup`, `sync.Mutex`, and handle `ctx.Done()`
- Receiver names: 1-2 letters (`s *Scanner`, `h *Hub`)

## WebSocket Events

Main event categories:
- Scans: `quick_scan_start/complete`, `deep_scan_start/host_complete/complete`, `arp_scan_start/complete`
- Progress: `scan_progress`, `scan_feedback`, `scan_error`
- Customer: `get_customers`, `assign_customer`, `get_customer_traceroutes`
- Network: `get_network_key`, `get_local_ip`

## Configuration

Environment variables:
- `PORT` (default: 9000)
- `DB_PATH` (default: data/nmapui.db)
- `NMAP_PATH` (default: nmap)
- `CUSTOMERS_YAML` (default: config/customers.yaml)
- `MAX_CONCURRENT` (default: 10)

## Branch Strategy

- `main` - Python version (legacy)
- `go-migration` - Go version (production-ready, active development)
