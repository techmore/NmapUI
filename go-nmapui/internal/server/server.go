package server

import (
	"context"
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/template/html/v2"
	"github.com/techmore/nmapui/internal/database"
	"github.com/techmore/nmapui/internal/fingerprint"
	"github.com/techmore/nmapui/internal/reports"
	"github.com/techmore/nmapui/internal/scanner"
	"github.com/techmore/nmapui/pkg/websocket"
)

// Dependencies holds all components needed by the server
type Dependencies struct {
	DB            *database.DB
	ScanEngine    *scanner.ScanEngine
	Fingerprinter *fingerprint.CustomerFingerprinter
	ReportGen     *reports.ReportGenerator
	WSHub         *websocket.Hub
}

type Server struct {
	App  *fiber.App
	Deps *Dependencies
}

func NewServer(deps *Dependencies) *Server {
	return &Server{
		Deps: deps,
	}
}

func (s *Server) Initialize() error {
	views := html.New("./web/templates", ".html")

	s.App = fiber.New(fiber.Config{
		Views:        views,
		ErrorHandler: errorHandler,
		AppName:      "NmapUI Go Edition",
		ServerHeader: "NmapUI",
	})

	s.App.Use(logger.New())
	s.App.Use(cors.New())
	s.App.Static("/static", "./web/static")

	RegisterRoutes(s)
	return nil
}

func (s *Server) Start(address string) error {
	if s.App == nil {
		return errors.New("server not initialized")
	}

	return s.App.Listen(address)
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.App == nil {
		return nil
	}

	return s.App.ShutdownWithContext(ctx)
}

func errorHandler(c *fiber.Ctx, err error) error {
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
