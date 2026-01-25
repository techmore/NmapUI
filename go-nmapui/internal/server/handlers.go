package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/techmore/nmapui/internal/database"
	"github.com/techmore/nmapui/internal/models"
)

func (s *Server) handleQuickScan(c *fiber.Ctx) error {
	var req struct {
		Target string `json:"target"`
		Timing string `json:"timing"`
	}

	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}

	if req.Target == "" {
		return fiber.NewError(fiber.StatusBadRequest, "target is required")
	}

	if req.Timing == "" {
		req.Timing = "T3"
	}

	ctx := context.Background()

	hosts, err := s.Deps.ScanEngine.QuickScan(ctx, req.Target)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("scan failed: %v", err))
	}

	networkKey, err := s.Deps.Fingerprinter.RunTraceroute(ctx, req.Target)
	if err != nil {
		networkKey = &models.NetworkKey{}
	}

	customerID, confidence, err := s.Deps.Fingerprinter.IdentifyCustomer(ctx, networkKey)
	if err != nil {
		customerID = "unknown"
		confidence = 0.0
	}

	customerName := "Unknown"
	for _, cust := range s.Deps.Fingerprinter.Customers {
		if cust.ID == customerID {
			customerName = cust.Name
			break
		}
	}

	networkKeyMap := map[string]interface{}{
		"exit_ip": networkKey.ExitIP,
		"hops":    networkKey.Hops,
	}

	entry := database.ScanHistoryEntry{
		Timestamp:       time.Now(),
		CustomerID:      customerID,
		CustomerName:    customerName,
		ConfidenceScore: confidence,
		NetworkKey:      networkKeyMap,
	}
	if err := s.Deps.DB.InsertScanHistory(entry); err != nil {
		c.Context().Logger().Printf("failed to save scan: %v", err)
	}

	assignment := database.Assignment{
		CustomerID:   customerID,
		CustomerName: customerName,
		Timestamp:    time.Now(),
		Confidence:   confidence,
		NetworkKey:   networkKeyMap,
	}
	s.Deps.DB.SetCurrentAssignment(assignment)

	return c.JSON(fiber.Map{
		"hosts":      hosts,
		"customer_id": customerID,
		"customer_name": customerName,
		"confidence": confidence,
	})
}

func (s *Server) handleDeepScan(c *fiber.Ctx) error {
	var req struct {
		Targets []string `json:"targets"`
	}

	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}

	if len(req.Targets) == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "targets is required")
	}

	ctx := context.Background()

	result, err := s.Deps.ScanEngine.DeepScan(ctx, req.Targets)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("scan failed: %v", err))
	}

	return c.JSON(fiber.Map{
		"result": result,
		"hosts": result.Hosts,
		"count": len(result.Hosts),
	})
}

func (s *Server) handleGetCustomers(c *fiber.Ctx) error {
	customers := s.Deps.Fingerprinter.Customers
	return c.JSON(fiber.Map{
		"customers": customers,
		"total":     len(customers),
	})
}

func (s *Server) handleGetCustomer(c *fiber.Ctx) error {
	id := c.Params("id")
	
	for _, customer := range s.Deps.Fingerprinter.Customers {
		if customer.ID == id {
			return c.JSON(customer)
		}
	}

	return fiber.NewError(fiber.StatusNotFound, "customer not found")
}

func (s *Server) handleIdentifyCustomer(c *fiber.Ctx) error {
	var req struct {
		Target string `json:"target"`
	}

	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}

	ctx := context.Background()
	networkKey, err := s.Deps.Fingerprinter.RunTraceroute(ctx, req.Target)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	customerID, confidence, err := s.Deps.Fingerprinter.IdentifyCustomer(ctx, networkKey)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(fiber.Map{
		"customer_id": customerID,
		"confidence":  confidence,
		"network_key": networkKey,
	})
}

func (s *Server) handleAssignCustomer(c *fiber.Ctx) error {
	var req struct {
		CustomerID string `json:"customer_id"`
	}

	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}

	var customerName string
	found := false
	for _, customer := range s.Deps.Fingerprinter.Customers {
		if customer.ID == req.CustomerID {
			customerName = customer.Name
			found = true
			break
		}
	}

	if !found {
		return fiber.NewError(fiber.StatusNotFound, "customer not found")
	}

	assignment := database.Assignment{
		CustomerID:   req.CustomerID,
		CustomerName: customerName,
		Timestamp:    time.Now(),
		Confidence:   1.0,
		NetworkKey:   map[string]interface{}{},
	}

	if err := s.Deps.DB.SetCurrentAssignment(assignment); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(fiber.Map{
		"customer_id":   req.CustomerID,
		"customer_name": customerName,
	})
}

func (s *Server) handleGetNetworkKey(c *fiber.Ctx) error {
	ctx := context.Background()
	networkKey, err := s.Deps.Fingerprinter.RunTraceroute(ctx, "8.8.8.8")
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(fiber.Map{
		"network_key": networkKey,
	})
}

func (s *Server) handleTraceroute(c *fiber.Ctx) error {
	target := c.Query("target", "8.8.8.8")

	ctx := context.Background()
	networkKey, err := s.Deps.Fingerprinter.RunTraceroute(ctx, target)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(networkKey)
}

func (s *Server) handleVersion(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"app_version": "1.0.0-go",
		"status":      "running",
	})
}

func (s *Server) handleAddCustomer(c *fiber.Ctx) error {
	return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{
		"error": "add customer not implemented",
	})
}

func (s *Server) handleDeleteCustomer(c *fiber.Ctx) error {
	return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{
		"error": "delete customer not implemented",
	})
}

func (s *Server) handleGenerateReport(c *fiber.Ctx) error {
	return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{
		"error": "report generation not implemented",
	})
}

func (s *Server) handleGetScanHTML(c *fiber.Ctx) error {
	return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{
		"error": "scan HTML retrieval not implemented",
	})
}

func (s *Server) handleGetScanPDF(c *fiber.Ctx) error {
	return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{
		"error": "scan PDF retrieval not implemented",
	})
}

func (s *Server) handleGetScanXML(c *fiber.Ctx) error {
	return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{
		"error": "scan XML retrieval not implemented",
	})
}

func (s *Server) handleDeleteScan(c *fiber.Ctx) error {
	return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{
		"error": "scan deletion not implemented",
	})
}

func extractNetworkKey(hosts []models.Host) map[string]interface{} {
	if len(hosts) > 0 {
		return map[string]interface{}{
			"exit_ip": hosts[0].IP,
			"hops":    []string{},
		}
	}
	return map[string]interface{}{}
}

func sanitizeFilename(s string) string {
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

func createScanDirectory(customerName, target string) string {
	now := time.Now()
	datePart := now.Format("2006-01-02")
	timePart := now.Format("150405")

	safeCustomer := sanitizeFilename(customerName)
	safeTarget := sanitizeFilename(target)

	scanDir := filepath.Join("data", "scans", safeCustomer, datePart, "scan_"+timePart+"_"+safeTarget)
	os.MkdirAll(scanDir, 0755)

	return scanDir
}

func (s *Server) handleListScans(c *fiber.Ctx) error {
	limit := 100
	if limitStr := c.Query("limit"); limitStr != "" {
		fmt.Sscanf(limitStr, "%d", &limit)
	}

	scans, err := s.Deps.DB.GetScanHistory("", limit)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	type ScanInfo struct {
		ID              int64     `json:"id"`
		Timestamp       time.Time `json:"timestamp"`
		CustomerName    string    `json:"customer_name"`
		ConfidenceScore float64   `json:"confidence_score"`
		ExitIP          string    `json:"exit_ip"`
	}

	var scanList []ScanInfo
	for _, scan := range scans {
		scanList = append(scanList, ScanInfo{
			ID:              scan.ID,
			Timestamp:       scan.Timestamp,
			CustomerName:    scan.CustomerName,
			ConfidenceScore: scan.ConfidenceScore,
			ExitIP:          scan.ExitIP,
		})
	}

	return c.JSON(fiber.Map{
		"scans": scanList,
		"total": len(scanList),
	})
}

func (s *Server) handleGetScanByID(c *fiber.Ctx) error {
	id := c.Params("id")
	var scanID int64
	if _, err := fmt.Sscanf(id, "%d", &scanID); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid scan ID")
	}

	scan, err := s.Deps.DB.GetScanHistoryByID(scanID)
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "scan not found")
	}

	return c.JSON(scan)
}

func (s *Server) handleGetCurrentAssignment(c *fiber.Ctx) error {
	assignment, err := s.Deps.DB.GetCurrentAssignment()
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	if assignment == nil {
		return c.JSON(fiber.Map{
			"customer": nil,
		})
	}

	return c.JSON(fiber.Map{
		"customer":   assignment.CustomerName,
		"confidence": assignment.Confidence,
		"timestamp":  assignment.Timestamp,
	})
}

func (s *Server) handleScanHistory(c *fiber.Ctx) error {
	customerID := c.Query("customer_id", "")
	limit := 100
	if limitStr := c.Query("limit"); limitStr != "" {
		fmt.Sscanf(limitStr, "%d", &limit)
	}

	scans, err := s.Deps.DB.GetScanHistory(customerID, limit)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(fiber.Map{
		"history": scans,
		"total":   len(scans),
	})
}

func (s *Server) handleStartScan(c *fiber.Ctx) error {
	var req struct {
		Target   string `json:"target"`
		ScanType string `json:"scan_type"`
		Timing   string `json:"timing"`
	}

	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}

	if req.Target == "" {
		return fiber.NewError(fiber.StatusBadRequest, "target is required")
	}

	scanType := strings.ToLower(req.ScanType)
	if scanType == "" {
		scanType = "quick"
	}

	ctx := context.Background()

	switch scanType {
	case "quick":
		hosts, err := s.Deps.ScanEngine.QuickScan(ctx, req.Target)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("scan failed: %v", err))
		}
		return c.JSON(fiber.Map{
			"hosts":     hosts,
			"count":     len(hosts),
			"scan_type": scanType,
		})
	case "deep":
		result, err := s.Deps.ScanEngine.DeepScan(ctx, []string{req.Target})
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("scan failed: %v", err))
		}
		return c.JSON(fiber.Map{
			"result":    result,
			"hosts":     result.Hosts,
			"count":     len(result.Hosts),
			"scan_type": scanType,
		})
	default:
		return fiber.NewError(fiber.StatusBadRequest, "invalid scan_type (use 'quick' or 'deep')")
	}
}
