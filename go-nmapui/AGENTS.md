# Agent Instructions: NmapUI Go Edition

## Build & Test Commands

### Development
```bash
# Build for current platform
make build              # Output: bin/nmapui

# Run directly (no build)
make run                # go run cmd/nmapui/main.go

# Live reload (auto-installs air)
make dev                # Watch for changes, auto-rebuild
```

### Testing
```bash
# Run all tests with coverage
make test               # go test -v -cover ./...

# Race condition detection
make test-race          # go test -v -race ./...

# Coverage report (HTML)
make test-coverage      # Opens coverage.html in browser

# Benchmarks
make bench              # go test -bench=. -benchmem ./...
```

### Code Quality
```bash
# Format code (gofmt + goimports)
make fmt                # Auto-installs goimports if missing

# Lint (auto-installs golangci-lint)
make lint               # golangci-lint run

# Static analysis
make vet                # go vet ./...

# Security scan (auto-installs gosec)
make security           # gosec ./...
```

### Deployment
```bash
# Cross-compile for all platforms
make build-all          # darwin/amd64, darwin/arm64, linux/amd64, linux/arm64, windows/amd64

# Install to system (requires sudo)
make install            # Copies to /usr/local/bin/nmapui

# Create release artifacts
make release            # tar.gz + SHA256 checksums
```

### Cleanup & Maintenance
```bash
make clean              # Remove build artifacts
make mod-update         # Update all dependencies
make tools              # Install dev tools (air, golangci-lint, goimports)
```

---

## Code Style Guidelines

### Import Organization
```go
import (
    // Standard library (alphabetical)
    "context"
    "fmt"
    "log"
    "sync"
    
    // External packages (alphabetical)
    "github.com/gofiber/fiber/v2"
    "github.com/google/uuid"
    
    // Internal packages (alphabetical)
    "github.com/techmore/nmapui/internal/models"
    "github.com/techmore/nmapui/pkg/websocket"
)
```
**Rules:**
- Blank lines between groups (stdlib → external → internal)
- Alphabetical within each group
- Run `make fmt` to auto-organize

### Naming Conventions
| Type | Pattern | Example |
|------|---------|---------|
| **Exported functions** | PascalCase | `NewNmapScanner()` |
| **Unexported functions** | camelCase | `mapHosts()`, `selectIP()` |
| **Types/Structs** | PascalCase | `NmapScanner`, `ScanConfig` |
| **Constants** | UPPER_SNAKE_CASE | `EventConnect`, `maxMessageSize` |
| **Exported fields** | PascalCase | `IP`, `Status`, `Ports` |
| **Unexported fields** | camelCase | `binaryPath`, `clients` |
| **Receiver names** | 1-2 letters | `s *NmapScanner`, `h *Hub`, `c *Client` |

### Struct Tags
```go
type Host struct {
    IP        string   `json:"ip"`                    // Required field
    Status    string   `json:"status"`                // Required field
    Ports     []Port   `json:"ports,omitempty"`       // Optional (omit if empty)
    OS        *OSInfo  `json:"os_info,omitempty"`     // Optional (pointer + omitempty)
}

type Customer struct {
    ID   string `yaml:"id" json:"id"`      // Both YAML (config) and JSON (API)
    Name string `yaml:"name" json:"name"`
}
```
**Rules:**
- JSON tags: `snake_case` for API responses
- YAML tags: for configuration files
- Use `omitempty` for optional fields
- Use pointers + `omitempty` for nested structs

### Comments & Documentation
```go
// Package scanner provides nmap scanning functionality for network discovery.
package scanner

// NewNmapScanner creates a new scanner instance with the specified nmap binary path.
// Returns a configured scanner ready to execute scans.
func NewNmapScanner(binaryPath string) *NmapScanner {
    return &NmapScanner{binaryPath: binaryPath}
}

// QuickScan performs a fast scan of the target using the specified timing profile.
// Returns hosts found and any errors encountered during scanning.
func (s *NmapScanner) QuickScan(ctx context.Context, target string, timingProfile string) ([]models.Host, error) {
    // Implementation...
}
```
**Rules:**
- Package-level comment required at top of each package
- Exported functions MUST have comment starting with function name
- Comments are sentences (capital letter, period at end)
- Inline comments for complex logic only

---

## Error Handling Patterns

### Pattern 1: Immediate Check & Return
```go
func (s *NmapScanner) QuickScan(ctx context.Context, target string) ([]models.Host, error) {
    result, _, err := s.run(ctx, target)
    if err != nil {
        return nil, err  // Return early on error
    }
    return mapHosts(result.Hosts, true), nil
}
```

### Pattern 2: Error with Context
```go
func main() {
    srv := server.NewServer()
    if err := srv.Initialize(); err != nil {
        log.Fatalf("server init failed: %v", err)  // Fatal errors only in main
    }
}
```

### Pattern 3: Error Aggregation (Concurrent Operations)
```go
type AggregateError struct {
    Errors []error
}

func (e AggregateError) Error() string {
    parts := make([]string, 0, len(e.Errors))
    for _, err := range e.Errors {
        if err == nil {
            continue
        }
        parts = append(parts, err.Error())
    }
    return strings.Join(parts, "; ")
}

// Use in goroutine pools
func (p *Pool) addError(err error) {
    p.errMu.Lock()
    p.errs = append(p.errs, err)
    p.errMu.Unlock()
}
```

### Pattern 4: Type Assertion with Check
```go
func handleError(err error) int {
    if fiberErr, ok := err.(*fiber.Error); ok {
        return fiberErr.Code  // Custom error code
    }
    return 500  // Default to internal server error
}
```

### Pattern 5: Nil Checks Before Use
```go
if len(result.Hosts) == 0 {
    return models.Host{IP: target, Status: "down"}, nil
}
```

**NEVER:**
- Ignore errors: `result, _ := someFunc()` (unless truly irrelevant)
- Panic in library code (only main package can panic)
- Return generic errors without context

---

## Concurrency Patterns

### Pattern 1: Goroutine Pool with Semaphore
```go
type Pool struct {
    max   int
    sem   chan struct{}  // Semaphore for max concurrency
    wg    sync.WaitGroup
    errMu sync.Mutex
    errs  []error
}

func (p *Pool) Run(ctx context.Context, tasks []Task) []error {
    for _, task := range tasks {
        select {
        case p.sem <- struct{}{}:  // Acquire slot
            p.wg.Add(1)
            go func(t Task) {
                defer p.wg.Done()
                defer func() { <-p.sem }()  // Release slot
                
                if err := t(ctx); err != nil {
                    p.addError(err)
                }
            }(task)
        case <-ctx.Done():  // Handle cancellation
            p.addError(ctx.Err())
            break
        }
    }
    p.wg.Wait()
    return p.errs
}
```

### Pattern 2: Hub Pattern (WebSocket)
```go
type Hub struct {
    clients     map[*Client]bool
    clientsByID map[string]*Client
    broadcast   chan Message
    register    chan *Client
    unregister  chan *Client
    mu          sync.RWMutex  // Protects maps
}

func (h *Hub) Run() {
    for {
        select {
        case client := <-h.register:
            h.mu.Lock()
            h.clients[client] = true
            h.clientsByID[client.id] = client
            h.mu.Unlock()
            
        case client := <-h.unregister:
            h.mu.Lock()
            delete(h.clients, client)
            delete(h.clientsByID, client.id)
            h.mu.Unlock()
            
        case message := <-h.broadcast:
            h.broadcastToClients(message)
        }
    }
}
```

### Pattern 3: Read/Write Pumps
```go
// Read from WebSocket (blocking)
func (c *Client) readPump() {
    defer c.hub.Unregister(c)
    
    for {
        var message Message
        if err := c.conn.ReadJSON(&message); err != nil {
            break  // Exit on any read error
        }
        
        if err := c.router.Handle(c, message); err != nil {
            log.Printf("handle error client=%s event=%s err=%v", c.id, message.Event, err)
        }
    }
}

// Write to WebSocket (non-blocking)
func (c *Client) writePump() {
    ticker := time.NewTicker(pingPeriod)
    defer ticker.Stop()
    
    for {
        select {
        case message, ok := <-c.send:
            if !ok {
                return  // Channel closed
            }
            if err := c.conn.WriteJSON(message); err != nil {
                return  // Exit on write error
            }
            
        case <-ticker.C:
            // Send periodic ping
            if err := c.conn.WriteMessage(fiberws.PingMessage, nil); err != nil {
                return
            }
        }
    }
}
```

### Pattern 4: Sync.Once for Cleanup
```go
type Client struct {
    closeOnce sync.Once
    done      chan struct{}
    send      chan Message
}

func (c *Client) Close() {
    c.closeOnce.Do(func() {
        close(c.done)
        close(c.send)
        if err := c.conn.Close(); err != nil {
            log.Printf("close error client=%s err=%v", c.id, err)
        }
    })
}
```

**Best Practices:**
- Always use `sync.WaitGroup` to wait for goroutines
- Always use `sync.Mutex` or `sync.RWMutex` for shared state
- Always handle `ctx.Done()` for cancellation
- Use buffered channels for high-throughput scenarios
- Use `sync.Once` for one-time initialization/cleanup

---

## Logging Style

### Structured Logging with Context
```go
// Include relevant context (client ID, event, target, etc.)
log.Printf("websocket read error client=%s err=%v", c.id, err)
log.Printf("websocket handle error client=%s event=%s err=%v", c.id, message.Event, err)
log.Printf("scan started target=%s timing=%s", target, timing)
log.Printf("scan completed target=%s hosts=%d duration=%s", target, len(hosts), duration)
```

### Log Levels (stdlib log package)
```go
log.Printf("info: server listening on %s", addr)       // Info
log.Printf("warn: scan timeout target=%s", target)     // Warning
log.Printf("error: database query failed: %v", err)    // Error
log.Fatalf("fatal: server init failed: %v", err)       // Fatal (main only)
```

**Format:**
- Use `%v` for errors and complex types
- Use `%s` for strings
- Use `%d` for integers
- Use key=value pairs for structured data
- Always include error variable name: `err=%v`

---

## HTTP Handler Patterns (Fiber v2)

### Basic Handler
```go
func handleHealth(c *fiber.Ctx) error {
    return c.JSON(fiber.Map{
        "status": "ok",
        "version": version,
    })
}
```

### Handler with Request Body
```go
type ScanRequest struct {
    Target string `json:"target" validate:"required"`
    Timing string `json:"timing" validate:"required"`
}

func handleScan(c *fiber.Ctx) error {
    var req ScanRequest
    if err := c.BodyParser(&req); err != nil {
        return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
    }
    
    // Process request...
    return c.JSON(fiber.Map{"scan_id": scanID})
}
```

### Handler with Path Parameters
```go
func handleGetScan(c *fiber.Ctx) error {
    scanID := c.Params("id")
    
    scan, err := getScan(scanID)
    if err != nil {
        return fiber.NewError(fiber.StatusNotFound, "scan not found")
    }
    
    return c.JSON(scan)
}
```

### Error Response
```go
func handleError(c *fiber.Ctx, err error) error {
    code := fiber.StatusInternalServerError
    message := "internal server error"
    
    if fiberErr, ok := err.(*fiber.Error); ok {
        code = fiberErr.Code
        message = fiberErr.Message
    }
    
    return c.Status(code).JSON(fiber.Map{
        "error": message,
    })
}
```

---

## Testing Guidelines

### Test File Naming
- **Unit tests**: `scanner_test.go` (same package)
- **Integration tests**: `integration_test.go` (separate package)
- **Benchmarks**: `scanner_bench_test.go`

### Test Function Naming
```go
func TestNmapScanner_QuickScan(t *testing.T)          // Unit test
func TestNmapScanner_QuickScan_EmptyTarget(t *testing.T)  // Edge case
func BenchmarkNmapScanner_QuickScan(b *testing.B)     // Benchmark
```

### Table-Driven Tests
```go
func TestEstimateHostCount(t *testing.T) {
    tests := []struct {
        name   string
        target string
        want   int
    }{
        {"single IP", "192.168.1.1", 1},
        {"CIDR /24", "192.168.1.0/24", 256},
        {"CIDR /16", "10.0.0.0/16", 65536},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := estimateHostCount(tt.target)
            if got != tt.want {
                t.Errorf("estimateHostCount(%s) = %d, want %d", tt.target, got, tt.want)
            }
        })
    }
}
```

### Mocking
```go
type mockScanner struct {
    hosts []models.Host
    err   error
}

func (m *mockScanner) Scan(ctx context.Context, target string) ([]models.Host, error) {
    return m.hosts, m.err
}
```

---

## Project Structure

```
go-nmapui/
├── cmd/
│   └── nmapui/
│       └── main.go              # Entry point only (initialize, run, cleanup)
├── internal/                    # Private packages (not importable externally)
│   ├── fingerprint/
│   │   ├── matcher.go          # Customer identification logic
│   │   └── traceroute.go       # Traceroute analysis
│   ├── models/
│   │   ├── scan.go             # Scan data structures
│   │   └── customer.go         # Customer config structures
│   ├── scanner/
│   │   ├── nmap.go             # Nmap wrapper
│   │   ├── concurrent.go       # Goroutine pool
│   │   └── engine.go           # Scan engine orchestration
│   └── server/
│       ├── server.go           # HTTP server setup
│       ├── routes.go           # Route registration
│       └── websocket.go        # WebSocket handlers
├── pkg/                        # Public packages (importable externally)
│   └── websocket/
│       ├── hub.go              # Connection hub
│       ├── client.go           # Client connection
│       └── events.go           # Event definitions
├── web/
│   ├── static/                 # CSS, JS, images
│   └── templates/              # HTML templates
├── config/
│   └── customers.yaml          # Customer configuration
├── Makefile
├── go.mod
├── go.sum
├── README.md
└── AGENTS.md                   # This file
```

**Placement Rules:**
- `cmd/` — Executable entry points (minimal code, just initialize & run)
- `internal/` — Private packages (business logic, not importable by external projects)
- `pkg/` — Public packages (reusable utilities, importable by external projects)
- `web/` — Static assets and templates
- Root — Configuration files, documentation, build scripts

---

## Common Anti-Patterns to Avoid

### ❌ Don't
```go
// Ignoring errors
result, _ := someFunc()

// Generic error without context
return errors.New("failed")

// Goroutine without WaitGroup
go doWork()

// Shared state without mutex
type Server struct {
    count int  // Accessed by multiple goroutines
}

// Panic in library code
if err != nil {
    panic(err)
}

// Magic numbers
time.Sleep(30 * time.Second)

// Multiple return types without names
func GetData() (string, int, error)
```

### ✅ Do
```go
// Check all errors
result, err := someFunc()
if err != nil {
    return fmt.Errorf("someFunc failed: %w", err)
}

// Error with context using %w
return fmt.Errorf("failed to parse config: %w", err)

// Goroutine with WaitGroup
var wg sync.WaitGroup
wg.Add(1)
go func() {
    defer wg.Done()
    doWork()
}()
wg.Wait()

// Shared state with mutex
type Server struct {
    mu    sync.RWMutex
    count int
}

// Return errors, let caller decide
if err != nil {
    return err
}

// Named constants
const defaultTimeout = 30 * time.Second
time.Sleep(defaultTimeout)

// Named return values for clarity
func GetData() (name string, age int, err error)
```

---

## Dependencies

### Core Libraries
- `github.com/gofiber/fiber/v2` — HTTP framework (Express-like API)
- `github.com/Ullaakut/nmap/v3` — Nmap wrapper with structured parsing
- `github.com/mattn/go-sqlite3` — SQLite database driver
- `github.com/gofiber/contrib/websocket` — WebSocket support for Fiber
- `gopkg.in/yaml.v3` — YAML parsing for config files

### Utilities
- `github.com/google/uuid` — UUID generation
- `golang.org/x/sync` — Advanced synchronization primitives
- `golang.org/x/net` — Network utilities

### Development Tools (installed via `make tools`)
- `github.com/cosmtrek/air` — Live reload for development
- `github.com/golangci/golangci-lint` — Comprehensive linter
- `golang.org/x/tools/cmd/goimports` — Import formatter
- `github.com/securego/gosec` — Security vulnerability scanner

---

## Quick Reference

### Before Committing
```bash
make fmt        # Format code
make lint       # Check code quality
make vet        # Static analysis
make test       # Run all tests
make build      # Verify build works
```

### Common Commands
```bash
# Development cycle
make dev        # Live reload (edit code, auto-rebuild)

# Testing cycle
make test       # Run tests
make test-race  # Check for race conditions
make bench      # Performance benchmarks

# Deployment
make build-all  # Cross-compile for all platforms
make release    # Create release artifacts
```

### Debugging
```bash
# Build with race detector
go build -race ./...

# Run with verbose logging
LOG_LEVEL=debug go run cmd/nmapui/main.go

# Profile CPU usage
go test -cpuprofile=cpu.prof -bench=.
go tool pprof cpu.prof
```

---

## Additional Resources

- **Go Documentation**: https://go.dev/doc/
- **Fiber Documentation**: https://docs.gofiber.io/
- **Nmap Library**: https://github.com/Ullaakut/nmap
- **Effective Go**: https://go.dev/doc/effective_go
- **Go Code Review Comments**: https://github.com/golang/go/wiki/CodeReviewComments
