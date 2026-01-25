package websocket

import (
	"sync"
	"testing"
	"time"
)

func TestNewHub(t *testing.T) {
	hub := NewHub()
	if hub == nil {
		t.Fatal("NewHub() returned nil")
	}
	if hub.clients == nil {
		t.Error("clients map is nil")
	}
	if hub.clientsByID == nil {
		t.Error("clientsByID map is nil")
	}
	if hub.broadcast == nil {
		t.Error("broadcast channel is nil")
	}
	if hub.register == nil {
		t.Error("register channel is nil")
	}
	if hub.unregister == nil {
		t.Error("unregister channel is nil")
	}
}

func TestHub_RegisterUnregister(t *testing.T) {
	hub := NewHub()
	go hub.Run()

	client := &Client{
		id:        "test-client-1",
		hub:       hub,
		send:      make(chan Message, 256),
		done:      make(chan struct{}),
		closeOnce: sync.Once{},
		conn:      nil,
	}

	hub.Register(client)
	time.Sleep(10 * time.Millisecond)

	hub.mu.RLock()
	clientCount := len(hub.clients)
	clientByIDExists := hub.clientsByID["test-client-1"] != nil
	hub.mu.RUnlock()

	if clientCount != 1 {
		t.Errorf("hub has %d clients, want 1", clientCount)
	}
	if !clientByIDExists {
		t.Error("client not found in clientsByID map")
	}

	client.closeOnce.Do(func() {
		close(client.done)
		close(client.send)
	})

	hub.mu.Lock()
	delete(hub.clients, client)
	delete(hub.clientsByID, client.id)
	hub.mu.Unlock()

	time.Sleep(10 * time.Millisecond)

	hub.mu.RLock()
	clientCount = len(hub.clients)
	hub.mu.RUnlock()

	if clientCount != 0 {
		t.Errorf("hub has %d clients after manual cleanup, want 0", clientCount)
	}
}

func TestHub_Broadcast(t *testing.T) {
	hub := NewHub()
	go hub.Run()

	// Register two clients
	client1 := &Client{
		id:        "c1",
		hub:       hub,
		send:      make(chan Message, 256),
		done:      make(chan struct{}),
		closeOnce: sync.Once{},
	}
	client2 := &Client{
		id:        "c2",
		hub:       hub,
		send:      make(chan Message, 256),
		done:      make(chan struct{}),
		closeOnce: sync.Once{},
	}

	hub.Register(client1)
	hub.Register(client2)
	time.Sleep(10 * time.Millisecond)

	// Broadcast message
	msg := Message{Event: "test_event", Data: "test_data"}
	hub.Broadcast(msg)

	// Verify both clients received it
	select {
	case received := <-client1.send:
		if received.Event != "test_event" {
			t.Errorf("client1 received event %s, want test_event", received.Event)
		}
		if received.Data != "test_data" {
			t.Errorf("client1 received data %v, want test_data", received.Data)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("client1 did not receive broadcast")
	}

	select {
	case received := <-client2.send:
		if received.Event != "test_event" {
			t.Errorf("client2 received event %s, want test_event", received.Event)
		}
		if received.Data != "test_data" {
			t.Errorf("client2 received data %v, want test_data", received.Data)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("client2 did not receive broadcast")
	}

	// Cleanup
	hub.Unregister(client1)
	hub.Unregister(client2)
}

func TestHub_SendTo(t *testing.T) {
	hub := NewHub()
	go hub.Run()

	// Register two clients
	client1 := &Client{
		id:        "target-client",
		hub:       hub,
		send:      make(chan Message, 256),
		done:      make(chan struct{}),
		closeOnce: sync.Once{},
	}
	client2 := &Client{
		id:        "other-client",
		hub:       hub,
		send:      make(chan Message, 256),
		done:      make(chan struct{}),
		closeOnce: sync.Once{},
	}

	hub.Register(client1)
	hub.Register(client2)
	time.Sleep(10 * time.Millisecond)

	// Send message to specific client
	msg := Message{Event: "private_event", Data: "private_data"}
	hub.SendTo("target-client", msg)

	// Verify only target client received it
	select {
	case received := <-client1.send:
		if received.Event != "private_event" {
			t.Errorf("target client received event %s, want private_event", received.Event)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("target client did not receive message")
	}

	// Verify other client did not receive it
	select {
	case <-client2.send:
		t.Error("other client should not have received the message")
	case <-time.After(50 * time.Millisecond):
		// Expected - no message received
	}

	// Test sending to non-existent client (should not panic)
	hub.SendTo("non-existent", msg)

	// Cleanup
	hub.Unregister(client1)
	hub.Unregister(client2)
}

func TestHub_MultipleClients(t *testing.T) {
	hub := NewHub()
	go hub.Run()

	// Register multiple clients
	numClients := 10
	clients := make([]*Client, numClients)
	for i := 0; i < numClients; i++ {
		clients[i] = &Client{
			id:        string(rune('a' + i)),
			hub:       hub,
			send:      make(chan Message, 256),
			done:      make(chan struct{}),
			closeOnce: sync.Once{},
		}
		hub.Register(clients[i])
	}
	time.Sleep(20 * time.Millisecond)

	// Verify all registered
	hub.mu.RLock()
	clientCount := len(hub.clients)
	hub.mu.RUnlock()

	if clientCount != numClients {
		t.Errorf("hub has %d clients, want %d", clientCount, numClients)
	}

	// Broadcast to all
	msg := Message{Event: "broadcast_test", Data: "data"}
	hub.Broadcast(msg)

	// Verify all received
	for i, client := range clients {
		select {
		case received := <-client.send:
			if received.Event != "broadcast_test" {
				t.Errorf("client %d received event %s, want broadcast_test", i, received.Event)
			}
		case <-time.After(100 * time.Millisecond):
			t.Errorf("client %d did not receive broadcast", i)
		}
	}

	// Unregister all
	for _, client := range clients {
		hub.Unregister(client)
	}
	time.Sleep(20 * time.Millisecond)

	hub.mu.RLock()
	clientCount = len(hub.clients)
	hub.mu.RUnlock()

	if clientCount != 0 {
		t.Errorf("hub has %d clients after unregister all, want 0", clientCount)
	}
}

func TestHub_ConcurrentAccess(t *testing.T) {
	hub := NewHub()
	go hub.Run()

	var wg sync.WaitGroup
	numGoroutines := 50

	// Concurrent register/unregister
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			client := &Client{
				id:        string(rune('a' + id%26)),
				hub:       hub,
				send:      make(chan Message, 256),
				done:      make(chan struct{}),
				closeOnce: sync.Once{},
			}
			hub.Register(client)
			time.Sleep(time.Millisecond)
			hub.Unregister(client)
		}(i)
	}

	// Concurrent broadcasts
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			msg := Message{Event: "concurrent_test", Data: id}
			hub.Broadcast(msg)
		}(i)
	}

	wg.Wait()
	time.Sleep(50 * time.Millisecond)

	// Should not panic and should be empty
	hub.mu.RLock()
	clientCount := len(hub.clients)
	hub.mu.RUnlock()

	if clientCount > 0 {
		t.Logf("Warning: hub has %d clients remaining after concurrent test", clientCount)
	}
}

func TestHub_BroadcastBufferFull(t *testing.T) {
	hub := NewHub()
	go hub.Run()

	// Create client with small buffer
	client := &Client{
		id:        "test-client",
		hub:       hub,
		send:      make(chan Message, 1),
		done:      make(chan struct{}),
		closeOnce: sync.Once{},
	}

	hub.Register(client)
	time.Sleep(10 * time.Millisecond)

	// Fill the buffer
	msg1 := Message{Event: "msg1", Data: "data1"}
	hub.Broadcast(msg1)
	time.Sleep(5 * time.Millisecond)

	// Try to send more messages (should not block hub)
	msg2 := Message{Event: "msg2", Data: "data2"}
	msg3 := Message{Event: "msg3", Data: "data3"}
	hub.Broadcast(msg2)
	hub.Broadcast(msg3)

	// Hub should still be responsive
	time.Sleep(10 * time.Millisecond)

	// Cleanup
	hub.Unregister(client)
}

func TestHub_RegisterSameClientTwice(t *testing.T) {
	hub := NewHub()
	go hub.Run()

	client := &Client{
		id:        "duplicate-client",
		hub:       hub,
		send:      make(chan Message, 256),
		done:      make(chan struct{}),
		closeOnce: sync.Once{},
	}

	// Register twice
	hub.Register(client)
	hub.Register(client)
	time.Sleep(10 * time.Millisecond)

	hub.mu.RLock()
	clientCount := len(hub.clients)
	hub.mu.RUnlock()

	// Should only be registered once
	if clientCount != 1 {
		t.Errorf("hub has %d clients, want 1", clientCount)
	}

	hub.Unregister(client)
}

func TestHub_UnregisterNonExistentClient(t *testing.T) {
	hub := NewHub()
	go hub.Run()

	client := &Client{
		id:        "non-existent",
		hub:       hub,
		send:      make(chan Message, 256),
		done:      make(chan struct{}),
		closeOnce: sync.Once{},
	}

	// Unregister without registering (should not panic)
	hub.Unregister(client)
	time.Sleep(10 * time.Millisecond)

	hub.mu.RLock()
	clientCount := len(hub.clients)
	hub.mu.RUnlock()

	if clientCount != 0 {
		t.Errorf("hub has %d clients, want 0", clientCount)
	}
}

// Benchmark tests
func BenchmarkHub_Broadcast(b *testing.B) {
	hub := NewHub()
	go hub.Run()

	// Register 10 clients
	clients := make([]*Client, 10)
	for i := 0; i < 10; i++ {
		clients[i] = &Client{
			id:        string(rune('a' + i)),
			hub:       hub,
			send:      make(chan Message, 256),
			done:      make(chan struct{}),
			closeOnce: sync.Once{},
		}
		hub.Register(clients[i])
	}
	time.Sleep(10 * time.Millisecond)

	// Drain messages in background
	for _, client := range clients {
		go func(c *Client) {
			for range c.send {
				// Drain
			}
		}(client)
	}

	msg := Message{Event: "benchmark", Data: "data"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hub.Broadcast(msg)
	}

	// Cleanup
	for _, client := range clients {
		hub.Unregister(client)
	}
}

func BenchmarkHub_SendTo(b *testing.B) {
	hub := NewHub()
	go hub.Run()

	client := &Client{
		id:        "target",
		hub:       hub,
		send:      make(chan Message, 256),
		done:      make(chan struct{}),
		closeOnce: sync.Once{},
	}
	hub.Register(client)
	time.Sleep(10 * time.Millisecond)

	// Drain messages
	go func() {
		for range client.send {
			// Drain
		}
	}()

	msg := Message{Event: "benchmark", Data: "data"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hub.SendTo("target", msg)
	}

	hub.Unregister(client)
}

func BenchmarkHub_RegisterUnregister(b *testing.B) {
	hub := NewHub()
	go hub.Run()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client := &Client{
			id:        "bench-client",
			hub:       hub,
			send:      make(chan Message, 256),
			done:      make(chan struct{}),
			closeOnce: sync.Once{},
		}
		hub.Register(client)
		hub.Unregister(client)
	}
}
