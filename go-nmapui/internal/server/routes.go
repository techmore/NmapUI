package server

import (
	"github.com/gofiber/fiber/v2"
)

func RegisterRoutes(s *Server) {
	app := s.App

	app.Get("/", s.handleIndex)
	app.Get("/api/health", s.handleHealth)
	app.Get("/api/version", s.handleVersion)

	app.Get("/api/scans", s.handleListScans)
	app.Get("/api/scans/:id", s.handleGetScanByID)
	app.Get("/api/scan/history", s.handleScanHistory)
	app.Post("/api/scan/start", s.handleStartScan)
	app.Post("/api/scan/quick", s.handleQuickScan)
	app.Post("/api/scan/deep", s.handleDeepScan)

	app.Get("/api/customers", s.handleGetCustomers)
	app.Get("/api/customers/:id", s.handleGetCustomer)
	app.Post("/api/customer/identify", s.handleIdentifyCustomer)
	app.Post("/api/customer/assign", s.handleAssignCustomer)
	app.Get("/api/customer/current", s.handleGetCurrentAssignment)

	app.Get("/api/network/key", s.handleGetNetworkKey)
	app.Get("/api/network/traceroute", s.handleTraceroute)

	RegisterWebSocket(s)
}

func (s *Server) handleIndex(c *fiber.Ctx) error {
	return c.Render("index", fiber.Map{
		"Title": "NmapUI",
	})
}

func (s *Server) handleHealth(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status": "ok",
	})
}


