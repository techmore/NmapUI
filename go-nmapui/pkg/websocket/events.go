package websocket

import (
	"log"
	"sync"
)

const (
	EventConnect         = "connect"
	EventDisconnect      = "disconnect"
	EventGetNetworkKey   = "get_network_key"
	EventNetworkKey      = "network_key"
	EventGetCustomerInfo = "get_customer_info"
	EventCustomerInfo    = "customer_info"
	EventStartScan       = "start_scan"
	EventScanFeedback    = "scan_feedback"
	EventScanProgress    = "scan_progress"
	EventGetCustomers    = "get_customers"
	EventCustomers       = "customers"
	EventAssignCustomer  = "assign_customer"
	EventGetLocalIP      = "get_local_ip"
	EventLocalIP         = "local_ip"

	EventGenerateReport     = "generate_report"
	EventCheckResumableScan = "check_resumable_scan"
	EventAddCustomer        = "add_customer"
	EventDeleteCustomer     = "delete_customer"
	EventDeepScanStart      = "deep_scan_start"
	EventDeepScanComplete   = "deep_scan_complete"
	EventQuickScanStart     = "quick_scan_start"
	EventQuickScanComplete  = "quick_scan_complete"

	EventCheckAppUpdates   = "check_app_updates"
	EventPerformAppUpdate  = "perform_app_update"
	EventSearchScanHistory = "search_scan_history"
	EventGetHistoryCounts  = "get_history_counts"
	EventCVEArray          = "cve_array"
	EventScanError         = "scan_error"
)

// Message defines the websocket event envelope.
type Message struct {
	Event string      `json:"event"`
	Data  interface{} `json:"data"`
	To    string      `json:"to,omitempty"`
}

type EventHandler func(client *Client, data interface{}) error

type Router struct {
	handlers map[string]EventHandler
	mu       sync.RWMutex
}

func NewRouter() *Router {
	return &Router{
		handlers: make(map[string]EventHandler),
	}
}

func (r *Router) Register(event string, handler EventHandler) {
	r.mu.Lock()
	r.handlers[event] = handler
	r.mu.Unlock()
}

func (r *Router) Handle(client *Client, message Message) error {
	r.mu.RLock()
	handler := r.handlers[message.Event]
	r.mu.RUnlock()

	if handler == nil {
		log.Printf("websocket unhandled event=%s client=%s", message.Event, client.id)
		return nil
	}

	return handler(client, message.Data)
}

type ConnectPayload struct {
	ID string `json:"id"`
}

type NetworkKeyResponse struct {
	Hops []string `json:"hops"`
}

type Customer struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type CustomersResponse struct {
	Customers []Customer `json:"customers"`
}

type CustomerInfoResponse struct {
	Customer Customer `json:"customer"`
}

type ScanFeedback struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

type LocalIPResponse struct {
	IP       string `json:"ip"`
	Subnet   string `json:"subnet"`
	CIDR     string `json:"cidr"`
	PublicIP string `json:"public_ip"`
}
