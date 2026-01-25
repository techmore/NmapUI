package server

import (
	"log"

	fiberws "github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
	nmapws "github.com/techmore/nmapui/pkg/websocket"
)

func RegisterWebSocket(app *fiber.App) {
	hub := nmapws.NewHub()
	router := nmapws.NewRouter()
	registerWebSocketHandlers(router)

	go hub.Run()

	app.Use("/socket.io/", func(c *fiber.Ctx) error {
		if fiberws.IsWebSocketUpgrade(c) {
			return c.Next()
		}
		return fiber.ErrUpgradeRequired
	})

	app.Get("/socket.io/", fiberws.New(func(conn *fiberws.Conn) {
		client := nmapws.NewClient(hub, conn, router)
		hub.Register(client)
		client.Start()

		if err := handleConnect(client); err != nil {
			log.Printf("websocket connect handler error client=%s err=%v", client.ID(), err)
		}

		<-client.Done()
		_ = handleDisconnect(client)
	}))
}

func registerWebSocketHandlers(router *nmapws.Router) {
	router.Register(nmapws.EventConnect, func(client *nmapws.Client, data interface{}) error {
		return nil
	})
	router.Register(nmapws.EventDisconnect, func(client *nmapws.Client, data interface{}) error {
		return nil
	})
	router.Register(nmapws.EventGetNetworkKey, handleGetNetworkKey)
	router.Register(nmapws.EventGetCustomerInfo, handleGetCustomerInfo)
	router.Register(nmapws.EventStartScan, handleStartScanEvent)
	router.Register(nmapws.EventScanFeedback, handleScanFeedback)
	router.Register(nmapws.EventScanProgress, handleScanProgress)
	router.Register(nmapws.EventGetCustomers, handleGetCustomers)
	router.Register(nmapws.EventAssignCustomer, handleAssignCustomer)

	registerStub(router, nmapws.EventGenerateReport)
	registerStub(router, nmapws.EventCheckResumableScan)
	registerStub(router, nmapws.EventAddCustomer)
	registerStub(router, nmapws.EventDeleteCustomer)
	registerStub(router, nmapws.EventDeepScanStart)
	registerStub(router, nmapws.EventDeepScanComplete)
	registerStub(router, nmapws.EventQuickScanStart)
	registerStub(router, nmapws.EventQuickScanComplete)

	registerStub(router, nmapws.EventCheckAppUpdates)
	registerStub(router, nmapws.EventPerformAppUpdate)
	registerStub(router, nmapws.EventSearchScanHistory)
	registerStub(router, nmapws.EventGetHistoryCounts)
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

func handleGetNetworkKey(client *nmapws.Client, data interface{}) error {
	client.Send(nmapws.Message{
		Event: nmapws.EventNetworkKey,
		Data: nmapws.NetworkKeyResponse{
			Hops: []string{},
		},
	})
	return nil
}

func handleGetCustomerInfo(client *nmapws.Client, data interface{}) error {
	client.Send(nmapws.Message{
		Event: nmapws.EventCustomerInfo,
		Data: nmapws.CustomerInfoResponse{
			Customer: nmapws.Customer{},
		},
	})
	return nil
}

func handleStartScanEvent(client *nmapws.Client, data interface{}) error {
	client.Send(nmapws.Message{
		Event: nmapws.EventScanFeedback,
		Data: nmapws.ScanFeedback{
			Status:  "received",
			Message: "start_scan queued",
		},
	})
	return nil
}

func handleScanFeedback(client *nmapws.Client, data interface{}) error {
	log.Printf("websocket scan feedback client=%s", client.ID())
	return nil
}

func handleScanProgress(client *nmapws.Client, data interface{}) error {
	log.Printf("websocket scan progress client=%s", client.ID())
	return nil
}

func handleGetCustomers(client *nmapws.Client, data interface{}) error {
	client.Send(nmapws.Message{
		Event: nmapws.EventCustomers,
		Data: nmapws.CustomersResponse{
			Customers: []nmapws.Customer{},
		},
	})
	return nil
}

func handleAssignCustomer(client *nmapws.Client, data interface{}) error {
	log.Printf("websocket assign customer client=%s", client.ID())
	return nil
}
