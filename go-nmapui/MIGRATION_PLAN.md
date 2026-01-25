# Go Migration Plan for NmapUI

## Overview
Complete migration from Python/Flask to Go/Fiber for improved deployment and maintainability.

**Timeline**: 10-14 weeks  
**Go Version**: 1.25.6  
**Target Port**: 9000 (matching Python)

---

## Project Structure

```
go-nmapui/
├── cmd/
│   └── nmapui/
│       └── main.go              # Application entry point
├── internal/
│   ├── server/
│   │   ├── server.go            # HTTP server setup
│   │   ├── routes.go            # Route definitions
│   │   └── middleware.go        # Custom middleware
│   ├── scanner/
│   │   ├── engine.go            # Scan orchestration
│   │   ├── nmap.go              # Nmap wrapper
│   │   └── concurrent.go        # Goroutine pool management
│   ├── fingerprint/
│   │   ├── matcher.go           # Customer identification
│   │   ├── traceroute.go        # Network path analysis
│   │   └── scorer.go            # Match scoring algorithm
│   ├── models/
│   │   ├── scan.go              # Scan data structures
│   │   ├── customer.go          # Customer configuration
│   │   └── network.go           # Network key structures
│   └── db/
│       ├── sqlite.go            # SQLite connection
│       └── migrations.go        # Schema migrations
├── pkg/
│   ├── nmap/
│   │   └── wrapper.go           # Nmap CLI wrapper
│   └── websocket/
│       ├── hub.go               # WebSocket connection hub
│       ├── client.go            # Client connection
│       └── events.go            # Event definitions
├── web/
│   ├── static/                  # CSS/JS/images
│   └── templates/
│       └── index.html           # Main UI (copied from Python)
├── go.mod                       # Go module definition
├── go.sum                       # Dependency checksums
├── Makefile                     # Build automation
├── Dockerfile                   # Container build
└── README.md                    # Go-specific docs
```

---

## Dependencies

### Core Framework
- **gofiber/fiber/v2** - Fast HTTP framework
- **gofiber/contrib/websocket** - WebSocket support
- **gofiber/template/html** - HTML templating

### Nmap Integration
- **Ullaakut/nmap/v3** - Nmap wrapper library

### Database
- **mattn/go-sqlite3** - SQLite driver
- **gorm.io/gorm** - ORM (optional)

### Utilities
- **gopkg.in/yaml.v3** - YAML parsing
- **logrus** - Structured logging
- **viper** - Configuration management

### Testing
- **stretchr/testify** - Testing toolkit
- **DATA-DOG/go-sqlmock** - Database mocking

---

## Migration Phases

### Phase 1: Foundation (Week 1-2)
**Goal**: Basic HTTP server + WebSocket infrastructure

**Tasks**:
- [x] Install Go 1.25.6
- [x] Initialize go.mod
- [ ] Create project structure
- [ ] HTTP server with Fiber
- [ ] WebSocket hub implementation
- [ ] Static file serving
- [ ] Health check endpoints

**Deliverable**: Server starts, serves frontend, WebSocket connects

---

### Phase 2: Scanning Engine (Week 3-4)
**Goal**: Core nmap scanning functionality

**Tasks**:
- [ ] Nmap wrapper using Ullaakut/nmap
- [ ] Goroutine pool for concurrent scans
- [ ] Quick scan (-sn)
- [ ] Deep scan (-sS -T4 -A -sC --script vulners)
- [ ] ARP scan integration
- [ ] Real-time progress updates via WebSocket
- [ ] Timeout handling with context.Context

**Deliverable**: All scan types working with live progress

---

### Phase 3: Customer Fingerprinting (Week 5-6)
**Goal**: Network identification algorithm

**Tasks**:
- [ ] Traceroute execution
- [ ] Network key generation
- [ ] YAML customer config loading
- [ ] Multi-factor matching algorithm:
  - [ ] Exit IP scoring (30%)
  - [ ] Hop pattern matching (40%)
  - [ ] Latency profiling (20%)
  - [ ] Network size estimation (10%)
- [ ] Confidence threshold calculation
- [ ] Traceroute history persistence

**Deliverable**: Customer auto-identification working

---

### Phase 4: Report Generation (Week 7-8)
**Goal**: Scan reports in XML/HTML/PDF

**Tasks**:
- [ ] XSL stylesheet integration (xsltproc)
- [ ] XML → HTML transformation
- [ ] PDF generation (wkhtmltopdf or chromedp)
- [ ] Report metadata generation
- [ ] File organization (Customer/Date/Time)
- [ ] Report history API
- [ ] Download endpoints

**Deliverable**: Full report generation pipeline

---

### Phase 5: Database Migration (Week 9)
**Goal**: Move from JSON to SQLite

**Tasks**:
- [ ] SQLite schema design
- [ ] Migration script (JSON → SQLite)
- [ ] CRUD operations for:
  - [ ] Scans
  - [ ] Customers
  - [ ] Traceroute history
  - [ ] Scan results
- [ ] Query optimization
- [ ] Concurrent access handling

**Deliverable**: All data in SQLite, JSON deprecated

---

### Phase 6: WebSocket Events (Week 10-11)
**Goal**: Implement all 54 real-time events

**Python Events to Port**:
```
connect, disconnect
get_network_key, get_customer_info, get_network_statistics
start_scan, generate_report
add_customer, assign_customer, get_customers, delete_customer
assign_report_to_customer, get_customer_traceroutes, add_labeled_public_ip
check_resumable_scan, resume_from_last_scan
check_app_updates, perform_app_update, cancel_auto_update, start_auto_update_countdown
update_auto_scan, search_scan_history, get_history_counts, get_versions
scan_feedback, scan_progress, deep_scan_start, deep_scan_host_complete, deep_scan_complete
quick_scan_start, quick_scan_complete, scan_error, cve_array
```

**Tasks**:
- [ ] Event handler registration
- [ ] Event routing to goroutines
- [ ] Response serialization
- [ ] Error handling per event
- [ ] Event ordering guarantees
- [ ] Reconnection handling

**Deliverable**: All UI features working via WebSocket

---

### Phase 7: Testing & Hardening (Week 12-13)
**Goal**: Production-ready quality

**Tasks**:
- [ ] Unit tests (>80% coverage)
- [ ] Integration tests
- [ ] Load testing (concurrent scans)
- [ ] Memory leak testing
- [ ] Concurrent access testing
- [ ] Error recovery testing
- [ ] Cross-platform testing (Linux/macOS/Windows)

**Deliverable**: Test suite passing, benchmarks documented

---

### Phase 8: Deployment (Week 14)
**Goal**: Ship production binary

**Tasks**:
- [ ] Cross-compilation setup
- [ ] Build for Linux (amd64, arm64)
- [ ] Build for macOS (amd64, arm64)
- [ ] Build for Windows (amd64)
- [ ] Release documentation
- [ ] Installation scripts
- [ ] Docker image (optional)
- [ ] GitHub Actions CI/CD

**Deliverable**: Release artifacts on GitHub

---

## Key Technical Decisions

### WebSocket Protocol
**Decision**: Keep Socket.IO-compatible protocol  
**Reason**: Frontend already uses Socket.IO client  
**Library**: gofiber/contrib/websocket with custom event layer

### Database
**Decision**: SQLite for single-server deployment  
**Reason**: No external dependencies, easy backup  
**Future**: PostgreSQL for multi-server

### Concurrency Model
**Decision**: Semaphore pattern with buffered channels  
**Reason**: Matches ThreadPoolExecutor behavior  
**Implementation**:
```go
sem := make(chan struct{}, maxConcurrent)
for _, target := range targets {
    sem <- struct{}{}
    go func(t string) {
        defer func() { <-sem }()
        scanHost(t)
    }(target)
}
```

### Error Handling
**Decision**: Explicit error returns, no panics  
**Reason**: Go idiom, better error messages  
**Pattern**:
```go
if err != nil {
    log.WithError(err).Error("scan failed")
    return nil, fmt.Errorf("scanning %s: %w", target, err)
}
```

---

## Migration Validation

### Feature Parity Checklist
- [ ] Quick scan (-sn)
- [ ] ARP scan (arp-scan)
- [ ] Deep scan with CVE detection
- [ ] Real-time progress updates
- [ ] Customer auto-identification
- [ ] Report generation (XML/HTML/PDF)
- [ ] Scan history viewer
- [ ] Customer management
- [ ] Auto-scan scheduling
- [ ] Network key fingerprinting
- [ ] Traceroute history
- [ ] Asset resume feature
- [ ] App update checking

### Performance Benchmarks
Compare Python vs Go:
- [ ] Scan execution time (should be same - both use nmap)
- [ ] Memory usage (Go should be lower)
- [ ] Concurrent scan handling (Go should be better)
- [ ] WebSocket latency (should be comparable)
- [ ] Binary size (Go ~10-20MB)
- [ ] Startup time (Go should be faster)

### Deployment Success Metrics
- [ ] Single binary works on all platforms
- [ ] No Python installation required
- [ ] System tools still documented (nmap, wkhtmltopdf, etc.)
- [ ] Cross-compilation from macOS works
- [ ] Binary runs without external dependencies (except system tools)

---

## Risk Mitigation

### High-Risk Areas

**1. WebSocket Event Ordering**
- **Risk**: Goroutines may reorder events
- **Mitigation**: Single event channel per connection, sequence numbers
- **Test**: Rapid-fire events in integration tests

**2. Customer Fingerprinting Accuracy**
- **Risk**: Floating-point precision differences
- **Mitigation**: Comprehensive test suite with Python reference data
- **Test**: 1000+ test cases comparing Go vs Python scores

**3. Concurrent File Access**
- **Risk**: Multiple scans writing simultaneously
- **Mitigation**: SQLite with WAL mode, transaction isolation
- **Test**: Concurrent scan stress test

**4. Subprocess Management**
- **Risk**: Zombie processes, timeout handling
- **Mitigation**: context.Context with timeouts, defer cleanup
- **Test**: Kill tests, timeout tests

### Rollback Plan
- Keep Python version running in parallel
- Feature flag new endpoints
- Gradual traffic migration
- Monitor error rates

---

## Success Criteria

**Go version is production-ready when**:
1. ✅ All 54 WebSocket events working
2. ✅ All scan types produce identical results to Python
3. ✅ Customer fingerprinting matches Python within 1% accuracy
4. ✅ Load test: 100 concurrent scans without crashes
5. ✅ Cross-platform binaries tested on Linux/macOS/Windows
6. ✅ No memory leaks after 24-hour stress test
7. ✅ Documentation complete
8. ✅ CI/CD pipeline passing

---

## Post-Migration

### Deprecation of Python Version
- Announce Go version availability
- Run both in parallel for 1-2 months
- Collect user feedback
- Fix Go-specific bugs
- Eventually archive Python version

### Future Enhancements (Go-specific)
- **Multi-tenancy**: User authentication + isolated scans
- **Clustering**: Distributed scanning across multiple nodes
- **Plugins**: Go plugin system for custom scanners
- **gRPC API**: For programmatic access
- **Prometheus metrics**: Observability

---

## Resources

### Documentation
- [Fiber v2 Docs](https://docs.gofiber.io/)
- [Ullaakut/nmap](https://github.com/Ullaakut/nmap)
- [Go SQLite](https://github.com/mattn/go-sqlite3)
- [WebSocket Protocol](https://datatracker.ietf.org/doc/html/rfc6455)

### Team Training
- Go Tour: https://go.dev/tour/
- Effective Go: https://go.dev/doc/effective_go
- Go by Example: https://gobyexample.com/

---

**Last Updated**: 2026-01-24  
**Status**: Foundation phase in progress
