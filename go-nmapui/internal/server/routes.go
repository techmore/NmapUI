package server

import (
	"github.com/gofiber/fiber/v2"
)

func RegisterRoutes(s *Server) {
	app := s.App

	app.Get("/", s.handleIndex)
	app.Get("/api/health", s.handleHealth)

	app.Get("/api/scans", s.handleListScans)
	app.Post("/api/scan/start", s.handleStartScan)
	app.Get("/api/scan/:id", s.handleGetScan)

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

func (s *Server) handleListScans(c *fiber.Ctx) error {
	return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{
		"error": "scan listing not implemented",
	})
}

func (s *Server) handleStartScan(c *fiber.Ctx) error {
	return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{
		"error": "scan start not implemented",
	})
}

func (s *Server) handleGetScan(c *fiber.Ctx) error {
	return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{
		"error": "scan lookup not implemented",
		"id":    c.Params("id"),
	})
}
