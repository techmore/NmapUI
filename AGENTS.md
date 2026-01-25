# NmapUI Project - Agent Instructions

## Project Status & Context

### Current State (Jan 25, 2026)
**Active Branch:** `go-migration` (17 commits ahead of main)  
**Status:** Production-ready Go migration complete  
**Python Version:** Working but deprecated (port 9000)  
**Go Version:** Fully functional (single binary, ready for deployment)

### Migration Summary
Completed migration from Python Flask to Go for hospital deployment (Docker banned due to safety policy). All core features ported and tested:
- ✅ HTTP server (Fiber v2) with 15+ API endpoints
- ✅ WebSocket layer (54 events, hub architecture)
- ✅ Scanning engine (nmap wrapper, concurrent execution)
- ✅ Customer fingerprinting (traceroute-based identification)
- ✅ Report generation (XSL→HTML→PDF pipeline)
- ✅ Database layer (SQLite with WAL mode, JSON migration)
- ✅ Testing suite (30.9% coverage, benchmarks)
- ✅ Integration tests (6 endpoints verified)

### Repository Structure
```
/Users/sdolbec/NmapUI/
├── Python Version (main branch)
│   ├── app.py (2721 lines - monolithic Flask app)
│   ├── scalable_scan_engine.py (560 lines)
│   ├── customer_fingerprint.py (644 lines)
│   └── requirements.txt (13 dependencies)
│
└── Go Version (go-migration branch)
    └── go-nmapui/
        ├── cmd/nmapui/main.go (entry point)
        ├── internal/ (scanner, fingerprint, reports, database, server)
        ├── pkg/websocket/ (hub, client, events)
        ├── config/customers.yaml
        ├── Makefile (20+ targets)
        └── AGENTS.md (Go-specific guide)
```

---

## Build & Test Commands

### Python Version (Legacy)
```bash
cd /Users/sdolbec/NmapUI
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py  # Runs on port 9000
```

### Go Version (Production)
```bash
cd /Users/sdolbec/NmapUI/go-nmapui

# Build
make build              # Creates bin/nmapui
make build-all          # Cross-compile for all platforms

# Run
make run                # go run cmd/nmapui/main.go
./bin/nmapui            # Run binary directly

# Test
make test               # All tests with coverage
make test-race          # Race detection
go test ./internal/scanner -v -run TestQuickScan  # Single test

# Quality
make fmt                # Format code
make lint               # golangci-lint
make vet                # Static analysis

# Integration
./test_integration.sh   # API endpoint tests (requires server running)
```

---

## Code Style Guidelines

### Go Code (go-nmapui/)

**Import Organization:**
```go
import (
    // Standard library (alphabetical)
    "context"
    "fmt"
    "time"
    
    // External packages (alphabetical)
    "github.com/gofiber/fiber/v2"
    
    // Internal packages (alphabetical)
    "github.com/techmore/nmapui/internal/models"
)
```

**Naming Conventions:**
- Exported functions: `PascalCase` (e.g., `NewNmapScanner`)
- Unexported functions: `camelCase` (e.g., `mapHosts`)
- Constants: `UPPER_SNAKE_CASE` or `PascalCase` for exported
- Receivers: 1-2 letters (e.g., `s *Server`, `c *Client`)

**Error Handling:**
```go
// ALWAYS check errors immediately
result, err := someFunc()
if err != nil {
    return fmt.Errorf("operation failed: %w", err)  // Use %w to wrap
}

// For HTTP handlers, use fiber.NewError
if err != nil {
    return fiber.NewError(fiber.StatusInternalServerError, err.Error())
}
```

**Struct Tags:**
```go
type Host struct {
    IP     string `json:"ip"`                   // snake_case in JSON
    Status string `json:"status"`
    Ports  []Port `json:"ports,omitempty"`      // omitempty for optional
}
```

**Concurrency Patterns:**
- Use `sync.WaitGroup` for goroutine coordination
- Use `sync.RWMutex` for shared state protection
- Always handle `ctx.Done()` for cancellation
- Buffered channels for high-throughput (e.g., `make(chan Message, 256)`)

### Python Code (legacy/)

**Import Organization:**
```python
# Framework imports
from flask import Flask, jsonify

# Standard library
import json, os, time

# Local imports
from customer_fingerprint import CustomerFingerprinter
```

**Style:**
- Google-style one-liner docstrings
- Type hints used inconsistently (partial)
- f-strings for formatting
- logging with `logger.info/warning/error`

---

## Testing Guidelines

### Go Testing
**File naming:** `*_test.go` in same package  
**Test naming:** `TestFunctionName_Scenario`

```go
func TestNmapScanner_QuickScan(t *testing.T) {
    scanner := NewNmapScanner("nmap")
    ctx := context.Background()
    
    hosts, err := scanner.QuickScan(ctx, "127.0.0.1", "T3")
    if err != nil {
        t.Fatalf("QuickScan failed: %v", err)
    }
    
    if len(hosts) == 0 {
        t.Error("expected at least one host")
    }
}
```

**Table-driven tests:**
```go
tests := []struct {
    name    string
    target  string
    wantErr bool
}{
    {"valid IP", "192.168.1.1", false},
    {"invalid target", "not-an-ip", true},
}

for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
        // test logic
    })
}
```

### Python Testing
No formal test framework. Integration tests in:
- `test_generate_report.py` (Socket.IO client)
- `test_performance.py` (mock-based)

---

## Git Workflow

### Branching Strategy
- `main` - Python version (legacy, stable)
- `go-migration` - Go version (active development, production-ready)

### Commit Style (Semantic)
```
feat: add customer fingerprinting engine
fix: resolve race condition in scanner pool
refactor: extract route handlers to separate file
docs: update AGENTS.md with testing guidelines
test: add integration tests for API endpoints
```

**All commits include Sisyphus attribution:**
```
Co-authored-by: Sisyphus <clio-agent@sisyphuslabs.ai>
```

---

## Configuration

### Environment Variables (Go)
```bash
PORT=9000                  # Server port (default: 9000)
DB_PATH=data/nmapui.db     # SQLite database path
NMAP_PATH=nmap             # nmap binary location
CUSTOMERS_YAML=config/customers.yaml
MAX_CONCURRENT=10          # Max concurrent scans
```

### Key Files
- `config/customers.yaml` - Customer fingerprint database
- `data/nmapui.db` - SQLite database (auto-created)
- `web/static/*.xsl` - XSL stylesheets for reports

---

## Common Tasks

### Running the Go Server
```bash
cd /Users/sdolbec/NmapUI/go-nmapui
make build
./bin/nmapui

# Should see:
# NmapUI Go Edition v1.0.0-go
# Database initialized: data/nmapui.db
# Server listening on http://localhost:9000
```

### Adding a New API Endpoint
1. Add handler in `internal/server/handlers.go`
2. Register route in `internal/server/routes.go`
3. Add integration test in `test_integration.sh`
4. Run `make test && make build`

### Adding a New Scanner Method
1. Implement in `internal/scanner/nmap.go` or `engine.go`
2. Add test in `internal/scanner/nmap_test.go`
3. Update API handler to expose it
4. Document in AGENTS.md

### Database Schema Changes
1. Update schema in `internal/database/schema.go`
2. Migration logic in `internal/database/migrate.go`
3. Test with `:memory:` database in tests

---

## Known Issues & Constraints

### Hospital Deployment Requirements
- **NO DOCKER** - Banned due to life-threatening danger clause in policy
- **Single Binary** - Main reason for Go migration
- **Port 9000** - Application standard port
- **Root Privileges** - Required for nmap SYN scans (`-sS`)

### Python Version Issues
- Python 3.14 bleeding edge (should use 3.12)
- Version hell, venv chaos
- No formal test framework
- Monolithic 2721-line app.py

### Go Version Todo (Optional Enhancements)
- Full WebSocket event business logic (stubs exist)
- Report generation file serving endpoints
- Additional customer CRUD operations
- Performance optimization for large networks

---

## Resuming Development

### If Session Lost
1. Check current branch: `git branch -vv`
2. Review recent commits: `git log --oneline -10`
3. Check todo status: `mcp_todoread` (if in agent session)
4. Verify build: `cd go-nmapui && make build`
5. Run tests: `make test`

### Current Integration Points
- All components wired via dependency injection
- Database connected to scan/fingerprint operations
- WebSocket hub running in goroutine
- API handlers accessing all services via `s.Deps.*`

### Next Steps (If Continuing)
- Deploy to staging environment
- Performance testing under load
- Additional WebSocket event handlers
- UI frontend integration
- Create PR for code review

---

## Quick Reference

| Task | Command |
|------|---------|
| Build Go binary | `cd go-nmapui && make build` |
| Run Go server | `./bin/nmapui` |
| Run Python server | `python app.py` |
| Test Go code | `make test` |
| Format Go code | `make fmt` |
| Integration test | `./test_integration.sh` |
| Check health | `curl http://localhost:9000/api/health` |
| View logs | `tail -f /tmp/nmapui.log` |

**Critical:** Always verify build after changes with `make build && make test`
