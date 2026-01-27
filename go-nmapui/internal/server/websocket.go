package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	fiberws "github.com/gofiber/contrib/websocket"
	nmapws "github.com/techmore/nmapui/pkg/websocket"

	"github.com/gofiber/fiber/v2"
	"github.com/techmore/nmapui/internal/database"
	"github.com/techmore/nmapui/internal/models"
	"github.com/techmore/nmapui/internal/reports"
	"github.com/techmore/nmapui/internal/scanner"
)

func RegisterWebSocket(s *Server) {
	hub := s.Deps.WSHub
	router := nmapws.NewRouter()
	registerWebSocketHandlers(s, router)
	app := s.App

	app.Use("/socket.io/", func(c *fiber.Ctx) error {
		if fiberws.IsWebSocketUpgrade(c) {
			return c.Next()
		}
		return fiber.ErrUpgradeRequired
	})

	app.Get("/socket.io/", fiberws.New(func(conn *fiberws.Conn) {
		log.Printf("[WS-CONN] new connection from remote=%s", conn.RemoteAddr())
		client := nmapws.NewClient(hub, conn, router)
		log.Printf("[WS-CONN] client created id=%s", client.ID())
		hub.Register(client)
		log.Printf("[WS-CONN] client registered id=%s", client.ID())
		client.Start()
		log.Printf("[WS-CONN] client started id=%s", client.ID())

		if err := handleConnect(client); err != nil {
			log.Printf("[WS-CONN] connect handler error client=%s err=%v", client.ID(), err)
		}

		<-client.Done()
		log.Printf("[WS-CONN] client done id=%s", client.ID())
		_ = handleDisconnect(client)
	}))
}

func registerWebSocketHandlers(s *Server, router *nmapws.Router) {
	router.Register(nmapws.EventConnect, func(client *nmapws.Client, data interface{}) error {
		return nil
	})
	router.Register(nmapws.EventDisconnect, func(client *nmapws.Client, data interface{}) error {
		return nil
	})

	router.Register(nmapws.EventGetNetworkKey, func(client *nmapws.Client, data interface{}) error {
		return handleGetNetworkKeyWS(s, client, data)
	})
	router.Register(nmapws.EventGetCustomerInfo, func(client *nmapws.Client, data interface{}) error {
		return handleGetCustomerInfoWS(s, client, data)
	})
	router.Register(nmapws.EventStartScan, func(client *nmapws.Client, data interface{}) error {
		return handleStartScanEventWS(s, client, data)
	})
	router.Register(nmapws.EventScanFeedback, handleScanFeedback)
	router.Register(nmapws.EventScanProgress, handleScanProgress)
	router.Register(nmapws.EventGetCustomers, func(client *nmapws.Client, data interface{}) error {
		return handleGetCustomersWS(s, client, data)
	})
	router.Register(nmapws.EventAssignCustomer, func(client *nmapws.Client, data interface{}) error {
		return handleAssignCustomerWS(s, client, data)
	})
	router.Register(nmapws.EventGetLocalIP, func(client *nmapws.Client, data interface{}) error {
		return handleGetLocalIPWS(s, client, data)
	})

	router.Register(nmapws.EventGenerateReport, func(client *nmapws.Client, data interface{}) error {
		return handleGenerateReportWS(s, client, data)
	})
	router.Register(nmapws.EventCheckResumableScan, func(client *nmapws.Client, data interface{}) error {
		return handleCheckResumableScanWS(s, client, data)
	})
	router.Register("resume_from_last_scan", func(client *nmapws.Client, data interface{}) error {
		return handleResumeFromLastScanWS(s, client, data)
	})
	router.Register(nmapws.EventAddCustomer, func(client *nmapws.Client, data interface{}) error {
		return handleAddCustomerWS(s, client, data)
	})
	router.Register(nmapws.EventDeleteCustomer, func(client *nmapws.Client, data interface{}) error {
		return handleDeleteCustomerWS(s, client, data)
	})
	registerStub(router, nmapws.EventDeepScanStart)
	registerStub(router, nmapws.EventDeepScanComplete)
	registerStub(router, nmapws.EventQuickScanStart)
	registerStub(router, nmapws.EventQuickScanComplete)

	registerStub(router, nmapws.EventCheckAppUpdates)
	registerStub(router, nmapws.EventPerformAppUpdate)
	router.Register(nmapws.EventSearchScanHistory, func(client *nmapws.Client, data interface{}) error {
		return handleSearchScanHistoryWS(s, client, data)
	})
	router.Register(nmapws.EventGetHistoryCounts, func(client *nmapws.Client, data interface{}) error {
		return handleGetHistoryCountsWS(s, client, data)
	})
	registerStub(router, nmapws.EventCVEArray)
	registerStub(router, nmapws.EventScanError)

}

func registerStub(router *nmapws.Router, event string) {
	router.Register(event, func(client *nmapws.Client, data interface{}) error {
		log.Printf("websocket stub event=%s client=%s", event, client.ID())
		return nil
	})
}

func handleConnect(client *nmapws.Client) error {
	client.Send(nmapws.Message{
		Event: nmapws.EventConnect,
		Data: nmapws.ConnectPayload{
			ID: client.ID(),
		},
	})
	return nil
}

func handleDisconnect(client *nmapws.Client) error {
	log.Printf("websocket disconnect client=%s", client.ID())
	return nil
}

func handleGetNetworkKeyWS(s *Server, client *nmapws.Client, data interface{}) error {
	ctx := context.Background()

	nk, err := s.Deps.Fingerprinter.RunTraceroute(ctx, "1.1.1.1")
	if err != nil {
		log.Printf("traceroute failed client=%s err=%v", client.ID(), err)
		client.Send(nmapws.Message{
			Event: nmapws.EventNetworkKey,
			Data: nmapws.NetworkKeyResponse{
				Hops: []string{},
			},
		})
		return nil
	}

	hops := make([]string, len(nk.Hops))
	for i, hop := range nk.Hops {
		hops[i] = hop.IP
	}

	client.Send(nmapws.Message{
		Event: nmapws.EventNetworkKey,
		Data: nmapws.NetworkKeyResponse{
			Hops: hops,
		},
	})
	return nil
}

func handleGetCustomerInfoWS(s *Server, client *nmapws.Client, data interface{}) error {
	ctx := context.Background()

	nk, err := s.Deps.Fingerprinter.RunTraceroute(ctx, "1.1.1.1")
	if err != nil {
		log.Printf("traceroute failed for customer info client=%s err=%v", client.ID(), err)
		client.Send(nmapws.Message{
			Event: nmapws.EventCustomerInfo,
			Data: nmapws.CustomerInfoResponse{
				Customer: nmapws.Customer{},
			},
		})
		return nil
	}

	customerID, confidence, err := s.Deps.Fingerprinter.IdentifyCustomer(ctx, nk)
	if err != nil || customerID == "Unknown" {
		client.Send(nmapws.Message{
			Event: nmapws.EventCustomerInfo,
			Data: nmapws.CustomerInfoResponse{
				Customer: nmapws.Customer{},
			},
		})
		return nil
	}

	client.Send(nmapws.Message{
		Event: nmapws.EventCustomerInfo,
		Data: nmapws.CustomerInfoResponse{
			Customer: nmapws.Customer{
				ID:   customerID,
				Name: customerID,
			},
		},
	})

	log.Printf("identified customer=%s confidence=%.2f client=%s", customerID, confidence, client.ID())
	return nil
}

func handleStartScanEventWS(s *Server, client *nmapws.Client, data interface{}) error {
	// Parse target from data
	var target string
	switch v := data.(type) {
	case string:
		target = v
	case map[string]interface{}:
		if t, ok := v["target"].(string); ok {
			target = t
		}
	}

	if target == "" {
		client.Send(nmapws.Message{
			Event: nmapws.EventScanError,
			Data: nmapws.ScanFeedback{
				Status:  "error",
				Message: "target is required",
			},
		})
		return nil
	}

	sendFeedback := func(msg string) {
		client.Send(nmapws.Message{
			Event: nmapws.EventScanFeedback,
			Data:  msg,
		})
	}

	sendFeedback(fmt.Sprintf("🎯 Scan received for target: %s", target))
	log.Printf("scan starting target=%s client=%s", target, client.ID())

	// Run scan in goroutine to not block WebSocket handler
	go func() {
		ctx := context.Background()
		scanStart := time.Now()

		// Phase 1: Quick scan to discover live hosts
		hosts, err := s.Deps.ScanEngine.QuickScan(ctx, target)
		if err != nil {
			sendFeedback(fmt.Sprintf("❌ Quick scan failed: %s", err.Error()))
			log.Printf("quick scan failed target=%s err=%v", target, err)
			return
		}

		if len(hosts) == 0 {
			sendFeedback("⚠️ No live hosts found on target network")
			log.Printf("no hosts found target=%s", target)
			return
		}

		// Phase 2: ARP scan for MAC/vendor info
		_, err = s.Deps.ScanEngine.ARPScan(ctx, target)
		if err != nil {
			log.Printf("arp scan failed (continuing) target=%s err=%v", target, err)
		}

		// Phase 3: Deep scan on discovered hosts
		var targets []string
		for _, host := range hosts {
			if host.Status == "up" {
				targets = append(targets, host.IP)
			}
		}

		if len(targets) > 0 {
			_, err = s.Deps.ScanEngine.DeepScan(ctx, targets)
			if err != nil {
				sendFeedback(fmt.Sprintf("⚠️ Deep scan encountered errors: %s", err.Error()))
				log.Printf("deep scan failed target=%s err=%v", target, err)
			}
		}

		totalDuration := time.Since(scanStart)
		sendFeedback(fmt.Sprintf("🏁 Scan complete! Total time: %s", formatDurationWS(totalDuration)))
		log.Printf("scan complete target=%s hosts=%d duration=%s", target, len(hosts), totalDuration)
	}()

	return nil
}

func formatDurationWS(d time.Duration) string {
	seconds := int(d.Seconds())
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	if seconds < 3600 {
		return fmt.Sprintf("%dm %ds", seconds/60, seconds%60)
	}
	return fmt.Sprintf("%dh %dm", seconds/3600, (seconds%3600)/60)
}

func handleScanFeedback(client *nmapws.Client, data interface{}) error {
	log.Printf("websocket scan feedback client=%s", client.ID())
	return nil
}

func handleScanProgress(client *nmapws.Client, data interface{}) error {
	log.Printf("websocket scan progress client=%s", client.ID())
	return nil
}

func handleGetCustomersWS(s *Server, client *nmapws.Client, data interface{}) error {
	customers := s.Deps.Fingerprinter.Customers

	wsCustomers := make([]nmapws.Customer, len(customers))
	for i, c := range customers {
		wsCustomers[i] = nmapws.Customer{
			ID:   c.ID,
			Name: c.Name,
		}
	}

	client.Send(nmapws.Message{
		Event: nmapws.EventCustomers,
		Data: nmapws.CustomersResponse{
			Customers: wsCustomers,
		},
	})
	return nil
}

func handleAssignCustomerWS(s *Server, client *nmapws.Client, data interface{}) error {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		log.Printf("invalid assign customer data client=%s", client.ID())
		return nil
	}

	customerID, ok := dataMap["customer_id"].(string)
	if !ok {
		log.Printf("missing customer_id client=%s", client.ID())
		return nil
	}

	assignment := database.Assignment{
		CustomerID:   customerID,
		CustomerName: customerID,
		Timestamp:    time.Now(),
		Confidence:   1.0,
		NetworkKey:   make(map[string]interface{}),
	}

	if err := s.Deps.DB.SetCurrentAssignment(assignment); err != nil {
		log.Printf("save assignment failed customer=%s client=%s err=%v", customerID, client.ID(), err)
		return nil
	}

	log.Printf("customer assigned customer=%s client=%s", customerID, client.ID())
	return nil
}

func handleSearchScanHistoryWS(s *Server, client *nmapws.Client, data interface{}) error {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		dataMap = make(map[string]interface{})
	}

	customerID, _ := dataMap["customer_id"].(string)
	limit := 50
	if limitFloat, ok := dataMap["limit"].(float64); ok {
		limit = int(limitFloat)
	}

	history, err := s.Deps.DB.GetScanHistory(customerID, limit)
	if err != nil {
		log.Printf("get scan history failed client=%s err=%v", client.ID(), err)
		return nil
	}

	client.Send(nmapws.Message{
		Event: nmapws.EventScanHistoryResults,
		Data:  map[string]interface{}{"history": history},
	})
	return nil
}

func handleGetHistoryCountsWS(s *Server, client *nmapws.Client, data interface{}) error {
	count, err := s.Deps.DB.GetScanHistoryCount()
	if err != nil {
		log.Printf("get history counts failed client=%s err=%v", client.ID(), err)
		return nil
	}

	counts := map[string]interface{}{
		"total":    count,
		"by_day":   make(map[string]int),
		"by_month": make(map[string]int),
	}

	client.Send(nmapws.Message{
		Event: nmapws.EventHistoryCounts,
		Data:  counts,
	})
	return nil
}

func handleGetLocalIPWS(s *Server, client *nmapws.Client, data interface{}) error {
	log.Printf("[HANDLER] get_local_ip called client=%s", client.ID())

	localIP := getLocalIP()
	log.Printf("[HANDLER] get_local_ip localIP=%s", localIP)

	subnetMask := getSubnetMask()
	log.Printf("[HANDLER] get_local_ip subnetMask=%s", subnetMask)

	cidr := calculateFullCIDR(localIP, subnetMask)
	log.Printf("[HANDLER] get_local_ip cidr=%s", cidr)

	publicIP := getPublicIP()
	log.Printf("[HANDLER] get_local_ip publicIP=%s", publicIP)

	response := nmapws.LocalIPResponse{
		LocalIP:    localIP,
		SubnetMask: subnetMask,
		PublicIP:   publicIP,
		CIDR:       cidr,
	}
	log.Printf("[HANDLER] get_local_ip sending response=%+v", response)

	client.Send(nmapws.Message{
		Event: nmapws.EventLocalIP,
		Data:  response,
	})
	return nil
}

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func getSubnetMask() string {
	localIP := getLocalIP()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "255.255.255.0"
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipNet.Contains(net.ParseIP(localIP)) {
			return net.IP(ipNet.Mask).String()
		}
	}
	return "255.255.255.0"
}

func calculateFullCIDR(ip, subnet string) string {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return "24"
	}

	// Parse subnet as IPv4 mask using dot notation
	parts := strings.Split(subnet, ".")
	if len(parts) != 4 {
		return "24"
	}

	var maskBytes [4]byte
	for i, part := range parts {
		if val, err := strconv.Atoi(part); err == nil {
			maskBytes[i] = byte(val)
		} else {
			return "24"
		}
	}

	mask := net.IPv4Mask(maskBytes[0], maskBytes[1], maskBytes[2], maskBytes[3])
	network := ipAddr.Mask(mask)
	ones, _ := mask.Size()

	return fmt.Sprintf("%s/%d", network.String(), ones)
}

func getPublicIP() string {
	client := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := client.Dial("tcp", "ifconfig.me:80")
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Send HTTP request
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: ifconfig.me\r\nUser-Agent: curl\r\nAccept: */*\r\n\r\n")

	// Read response (simple parsing for IP)
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}

	// Find the body after headers (double CRLF)
	response := string(buf[:n])
	parts := strings.Split(response, "\r\n\r\n")
	if len(parts) < 2 {
		return ""
	}

	// The body should be just the IP
	ip := strings.TrimSpace(parts[1])
	if net.ParseIP(ip) != nil {
		return ip
	}
	return ""
}

func handleAddCustomerWS(s *Server, client *nmapws.Client, data interface{}) error {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		client.Send(nmapws.Message{
			Event: nmapws.EventScanError,
			Data:  nmapws.ScanFeedback{Status: "error", Message: "invalid data format"},
		})
		return nil
	}

	id, _ := dataMap["id"].(string)
	name, _ := dataMap["name"].(string)
	confidence := 0.7
	if conf, ok := dataMap["confidence"].(float64); ok {
		confidence = conf
	}

	if id == "" || name == "" {
		client.Send(nmapws.Message{
			Event: nmapws.EventScanError,
			Data:  nmapws.ScanFeedback{Status: "error", Message: "id and name are required"},
		})
		return nil
	}

	customer := models.Customer{
		ID:         id,
		Name:       name,
		Confidence: confidence,
	}

	if err := s.Deps.Fingerprinter.AddCustomer(customer); err != nil {
		client.Send(nmapws.Message{
			Event: nmapws.EventScanError,
			Data:  nmapws.ScanFeedback{Status: "error", Message: err.Error()},
		})
		return nil
	}

	// Send updated customer list
	return handleGetCustomersWS(s, client, nil)
}

func handleDeleteCustomerWS(s *Server, client *nmapws.Client, data interface{}) error {
	var customerID string
	switch v := data.(type) {
	case string:
		customerID = v
	case map[string]interface{}:
		customerID, _ = v["id"].(string)
		if customerID == "" {
			customerID, _ = v["customer_id"].(string)
		}
	}

	if customerID == "" {
		client.Send(nmapws.Message{
			Event: nmapws.EventScanError,
			Data:  nmapws.ScanFeedback{Status: "error", Message: "customer id is required"},
		})
		return nil
	}

	if err := s.Deps.Fingerprinter.DeleteCustomer(customerID); err != nil {
		client.Send(nmapws.Message{
			Event: nmapws.EventScanError,
			Data:  nmapws.ScanFeedback{Status: "error", Message: err.Error()},
		})
		return nil
	}

	// Send updated customer list
	return handleGetCustomersWS(s, client, nil)
}

func handleGenerateReportWS(s *Server, client *nmapws.Client, data interface{}) error {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		client.Send(nmapws.Message{
			Event: nmapws.EventScanError,
			Data:  nmapws.ScanFeedback{Status: "error", Message: "invalid data format"},
		})
		return nil
	}

	xmlPath, _ := dataMap["xml_path"].(string)
	customerName, _ := dataMap["customer_name"].(string)
	target, _ := dataMap["target"].(string)

	if customerName == "" {
		customerName = "Unknown"
	}

	sendFeedback := func(msg string) {
		client.Send(nmapws.Message{
			Event: nmapws.EventScanFeedback,
			Data:  msg,
		})
	}

	log.Printf("[REPORT] generate_report called: target=%s customer=%s xmlPath=%s", target, customerName, xmlPath)
	sendFeedback(fmt.Sprintf("📋 Generating report for %s...", customerName))

	// Run report generation in background
	go func() {
		startTime := time.Now()
		ctx := context.Background()

		sendFeedback("📁 Creating scan folder...")
		scanDir := createScanDirectoryWS(customerName, target)

		// If no XML path provided, we need to run a scan first
		if xmlPath == "" {
			if target == "" {
				sendFeedback("❌ Error: No target specified")
				client.Send(nmapws.Message{
					Event: "report_error",
					Data:  map[string]interface{}{"error": "No target specified"},
				})
				return
			}

			sendFeedback(fmt.Sprintf("🔍 Running nmap scan on %s...", target))

			// Run nmap and save XML output
			xmlPath = filepath.Join(scanDir, "scan.xml")
			cmd := fmt.Sprintf("nmap -sV -sC --script=vulners -oX %s %s", xmlPath, target)
			sendFeedback(fmt.Sprintf("⚡ Executing: %s", cmd))

			result, err := runNmapCommand(ctx, target, xmlPath)
			if err != nil {
				sendFeedback(fmt.Sprintf("❌ Scan failed: %s", err.Error()))
				client.Send(nmapws.Message{
					Event: "report_error",
					Data:  map[string]interface{}{"error": err.Error()},
				})
				return
			}
			sendFeedback(fmt.Sprintf("✅ Scan completed in %.1fs", result.Duration.Seconds()))
		}

		sendFeedback("📄 Converting XML to HTML (web view)...")

		reportReq := reports.ReportRequest{
			XMLPath:      xmlPath,
			CustomerName: customerName,
			Target:       target,
			ScanDir:      scanDir,
		}

		result, err := s.Deps.ReportGen.GenerateReport(ctx, reportReq)
		if err != nil {
			log.Printf("report generation failed: %v", err)
			sendFeedback(fmt.Sprintf("❌ Report generation failed: %s", err.Error()))
			client.Send(nmapws.Message{
				Event: "report_error",
				Data:  map[string]interface{}{"error": err.Error()},
			})
			return
		}

		sendFeedback("📑 Generating PDF report...")

		duration := time.Since(startTime)
		sendFeedback(fmt.Sprintf("✅ Report generation completed in %.1fs", duration.Seconds()))

		client.Send(nmapws.Message{
			Event: "report_generated",
			Data: map[string]interface{}{
				"html_path":     result.HTMLPath,
				"pdf_path":      result.PDFPath,
				"metadata_path": result.MetadataPath,
				"duration_ms":   result.Duration.Milliseconds(),
			},
		})
	}()

	return nil
}

type nmapResult struct {
	Duration time.Duration
}

func runNmapCommand(ctx context.Context, target, xmlPath string) (*nmapResult, error) {
	start := time.Now()

	args := []string{"-sV", "-sC", "--script=vulners", "-oX", xmlPath, target}
	cmd := exec.CommandContext(ctx, "nmap", args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nmap failed: %v - %s", err, string(output))
	}

	return &nmapResult{Duration: time.Since(start)}, nil
}

func createScanDirectoryWS(customerName, target string) string {
	now := time.Now()
	datePart := now.Format("2006-01-02")
	timePart := now.Format("150405")

	safeCustomer := sanitizeFilenameWS(customerName)
	safeTarget := sanitizeFilenameWS(target)

	scanDir := filepath.Join("data", "scans", safeCustomer, datePart, "scan_"+timePart+"_"+safeTarget)
	os.MkdirAll(scanDir, 0755)

	return scanDir
}

func sanitizeFilenameWS(s string) string {
	if s == "" {
		return "unknown"
	}
	result := ""
	for _, ch := range s {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '.' {
			result += string(ch)
		} else {
			result += "_"
		}
	}
	return result
}

func handleCheckResumableScanWS(s *Server, client *nmapws.Client, data interface{}) error {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		dataMap = make(map[string]interface{})
	}

	customerID, _ := dataMap["customer_id"].(string)
	maxDays := 7
	if days, ok := dataMap["max_days"].(float64); ok {
		maxDays = int(days)
	}

	if customerID == "" || customerID == "unknown" {
		client.Send(nmapws.Message{
			Event: "resumable_scan_check",
			Data:  map[string]interface{}{"available": false},
		})
		return nil
	}

	// Find customer name from ID
	customerName := customerID
	for _, c := range s.Deps.Fingerprinter.Customers {
		if c.ID == customerID {
			customerName = c.Name
			break
		}
	}

	// Search for recent scans
	scansDir := filepath.Join("data", "scans")
	scan, err := scanner.FindMostRecentScan(scansDir, customerName, maxDays)
	if err != nil || scan == nil {
		client.Send(nmapws.Message{
			Event: "resumable_scan_check",
			Data:  map[string]interface{}{"available": false},
		})
		return nil
	}

	client.Send(nmapws.Message{
		Event: "resumable_scan_check",
		Data: map[string]interface{}{
			"available":             true,
			"scan_date":             scan.Metadata.Timestamp,
			"target":                scan.Metadata.Target,
			"total_hosts":           scan.TotalHosts,
			"total_vulnerabilities": scan.TotalVulns,
			"age_days":              scan.AgeDays,
			"age_seconds":           scan.AgeSeconds,
		},
	})
	return nil
}

func handleResumeFromLastScanWS(s *Server, client *nmapws.Client, data interface{}) error {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		dataMap = make(map[string]interface{})
	}

	customerID, _ := dataMap["customer_id"].(string)
	maxDays := 7
	if days, ok := dataMap["max_days"].(float64); ok {
		maxDays = int(days)
	}

	if customerID == "" {
		client.Send(nmapws.Message{
			Event: "resume_scan_error",
			Data:  map[string]interface{}{"error": "No customer ID provided"},
		})
		return nil
	}

	// Find customer name from ID
	customerName := customerID
	for _, c := range s.Deps.Fingerprinter.Customers {
		if c.ID == customerID {
			customerName = c.Name
			break
		}
	}

	// Search for recent scans
	scansDir := filepath.Join("data", "scans")
	scan, err := scanner.FindMostRecentScan(scansDir, customerName, maxDays)
	if err != nil || scan == nil {
		client.Send(nmapws.Message{
			Event: "resume_scan_error",
			Data:  map[string]interface{}{"error": "No recent scan found"},
		})
		return nil
	}

	// Parse the XML file
	hosts, err := scanner.ParseNmapXML(scan.XMLPath)
	if err != nil || len(hosts) == 0 {
		client.Send(nmapws.Message{
			Event: "resume_scan_error",
			Data:  map[string]interface{}{"error": "No assets found in scan"},
		})
		return nil
	}

	// Calculate statistics
	totalVulns := 0
	totalExploits := 0
	for _, host := range hosts {
		totalVulns += len(host.Vulnerabilities)
		for _, vuln := range host.Vulnerabilities {
			if isExploit, ok := vuln["is_exploit"].(bool); ok && isExploit {
				totalExploits++
			}
		}
	}

	// Format age string
	var ageStr string
	switch {
	case scan.AgeDays == 0:
		ageStr = "today"
	case scan.AgeDays == 1:
		ageStr = "yesterday"
	default:
		ageStr = fmt.Sprintf("%d days ago", scan.AgeDays)
	}

	// Send scan results
	client.Send(nmapws.Message{
		Event: nmapws.EventScanResults,
		Data: map[string]interface{}{
			"hosts":                 hosts,
			"total":                 len(hosts),
			"is_historical":         true,
			"scan_date":             scan.Metadata.Timestamp,
			"target":                scan.Metadata.Target,
			"age_days":              scan.AgeDays,
			"total_vulnerabilities": totalVulns,
			"total_exploits":        totalExploits,
		},
	})

	// Send feedback message
	client.Send(nmapws.Message{
		Event: nmapws.EventScanFeedback,
		Data: nmapws.ScanFeedback{
			Status:  "loaded",
			Message: fmt.Sprintf("Loaded %d assets from scan %s (%d vulnerabilities, %d exploits)", len(hosts), ageStr, totalVulns, totalExploits),
		},
	})

	return nil
}
