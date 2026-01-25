package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	fiberws "github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/techmore/nmapui/internal/database"
	nmapws "github.com/techmore/nmapui/pkg/websocket"
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
	client.Send(nmapws.Message{
		Event: nmapws.EventScanFeedback,
		Data: nmapws.ScanFeedback{
			Status:  "received",
			Message: "start_scan queued",
		},
	})

	log.Printf("scan queued client=%s", client.ID())
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
		Event: "scan_history_results",
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
		Event: "history_counts",
		Data:  counts,
	})
	return nil
}

func handleGetLocalIPWS(s *Server, client *nmapws.Client, data interface{}) error {
	localIP := getLocalIP()
	subnet := getSubnetMask()
	cidr := calculateCIDR(subnet)
	publicIP := getPublicIP()

	client.Send(nmapws.Message{
		Event: nmapws.EventLocalIP,
		Data: nmapws.LocalIPResponse{
			IP:       localIP,
			Subnet:   subnet,
			CIDR:     cidr,
			PublicIP: publicIP,
		},
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
		if ipNet.IP.String() == localIP {
			return ipNet.Mask.String()
		}
	}
	return "255.255.255.0"
}

func calculateCIDR(subnet string) string {
	mask := net.ParseIP(subnet)
	if mask == nil {
		return "24"
	}
	ones, _ := net.IPMask(mask).Size()
	return fmt.Sprintf("%d", ones)
}

func getPublicIP() string {
	return ""
}
