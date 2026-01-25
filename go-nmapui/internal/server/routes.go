package server

import (
	"github.com/gofiber/fiber/v2"
)

func RegisterRoutes(app *fiber.App) {
	app.Get("/", handleIndex)
	app.Get("/api/health", handleHealth)

	app.Get("/api/scans", handleListScans)
	app.Post("/api/scan/start", handleStartScan)
	app.Get("/api/scan/:id", handleGetScan)

	RegisterWebSocket(app)
}

func handleIndex(c *fiber.Ctx) error {
	return c.Render("index", fiber.Map{
		"Title": "NmapUI",
	})
}

func handleHealth(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status": "ok",
	})
}

func handleListScans(c *fiber.Ctx) error {
	return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{
		"error": "scan listing not implemented",
	})
}

func handleStartScan(c *fiber.Ctx) error {
	return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{
		"error": "scan start not implemented",
	})
}

func handleGetScan(c *fiber.Ctx) error {
	return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{
		"error": "scan lookup not implemented",
		"id":    c.Params("id"),
	})
}
