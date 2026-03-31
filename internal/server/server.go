package server

import (
	"fmt"
	"log"
	"log/slog"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/listeners"

	"github.com/lincomatic/meshcore-mqtt-broker-go/internal/config"
	"github.com/lincomatic/meshcore-mqtt-broker-go/internal/ratelimit"
)

// Broker wraps the mochi-mqtt server with our configuration
type Broker struct {
	mqtt    *mqtt.Server
	cfg     *config.Config
	limiter *ratelimit.Limiter
}

// New creates and starts the MQTT broker with a WebSocket listener
func New(cfg *config.Config) (*Broker, error) {
	server := mqtt.New(&mqtt.Options{
		Logger: slog.Default(),
	})

	limiter := ratelimit.New(60000, 10, 300000)

	b := &Broker{
		mqtt:    server,
		cfg:     cfg,
		limiter: limiter,
	}

	// Register auth + ACL hook
	if err := server.AddHook(&authHook{broker: b}, nil); err != nil {
		return nil, fmt.Errorf("failed to add auth hook: %w", err)
	}

	// WebSocket listener
	addr := fmt.Sprintf("%s:%d", cfg.MQTT.Host, cfg.MQTT.Port)
	ws := listeners.NewWebsocket(listeners.Config{
		ID:      "ws1",
		Address: addr,
	})
	if err := server.AddListener(ws); err != nil {
		return nil, fmt.Errorf("failed to add websocket listener: %w", err)
	}

	// Start serving (non-blocking)
	go func() {
		if err := server.Serve(); err != nil {
			log.Printf("[SERVER] MQTT server stopped: %v", err)
		}
	}()

	log.Println("╔════════════════════════════════════════════════════════════╗")
	log.Println("║         MeshCore MQTT Broker (WebSocket / Go)             ║")
	log.Println("╚════════════════════════════════════════════════════════════╝")
	log.Printf("[SERVER] WebSocket MQTT listening on: ws://%s", addr)
	log.Printf("[SERVER] Subscribers configured: %d", len(cfg.Subscriber.Users))
	if cfg.MQTT.ExpectedAudience != "" {
		log.Printf("[SERVER] Audience validation: %s", cfg.MQTT.ExpectedAudience)
	} else {
		log.Println("[SERVER] Audience validation: disabled")
	}
	log.Println("[SERVER] Ready to accept connections...")

	return b, nil
}

// Close gracefully shuts down the broker
func (b *Broker) Close() error {
	return b.mqtt.Close()
}
