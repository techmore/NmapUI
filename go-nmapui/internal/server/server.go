package server

import (
	"context"
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/template/html/v2"
)

type Server struct {
	App *fiber.App
}

func NewServer() *Server {
	return &Server{}
}

func (s *Server) Initialize() error {
	views := html.New("./web/templates", ".html")

	s.App = fiber.New(fiber.Config{
		Views:        views,
		ErrorHandler: errorHandler,
	})

	s.App.Use(logger.New())
	s.App.Use(cors.New())
	s.App.Static("/static", "./web/static")

	RegisterRoutes(s.App)
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
