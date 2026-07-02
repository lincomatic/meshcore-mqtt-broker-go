package server

import (
	"crypto/tls"
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

const (
	listenerWS    = "ws1"
	listenerWSS   = "wss1"
	listenerMQTT  = "mqtt1"
	listenerMQTTS = "mqtts1"
)

// New creates and starts the MQTT broker with any configured listeners.
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

	var tlsConfig *tls.Config
	if cfg.MQTT.WSSPort > 0 || cfg.MQTT.MQTTSPort > 0 {
		pair, err := tls.LoadX509KeyPair(cfg.MQTT.CertPath, cfg.MQTT.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{pair}}
	}

	addedListeners := 0
	if cfg.MQTT.WSPort > 0 {
		addr := fmt.Sprintf("%s:%d", cfg.MQTT.Host, cfg.MQTT.WSPort)
		if err := server.AddListener(listeners.NewWebsocket(listeners.Config{ID: listenerWS, Address: addr})); err != nil {
			return nil, fmt.Errorf("failed to add WS listener: %w", err)
		}
		addedListeners++
		log.Printf("[SERVER] WebSocket MQTT listening on: ws://%s", addr)
	}

	if cfg.MQTT.WSSPort > 0 {
		addr := fmt.Sprintf("%s:%d", cfg.MQTT.Host, cfg.MQTT.WSSPort)
		if err := server.AddListener(listeners.NewWebsocket(listeners.Config{ID: listenerWSS, Address: addr, TLSConfig: tlsConfig})); err != nil {
			return nil, fmt.Errorf("failed to add WSS listener: %w", err)
		}
		addedListeners++
		log.Printf("[SERVER] Secure WebSocket MQTT listening on: wss://%s", addr)
	}

	if cfg.MQTT.MQTTPort > 0 {
		addr := fmt.Sprintf("%s:%d", cfg.MQTT.Host, cfg.MQTT.MQTTPort)
		if err := server.AddListener(listeners.NewTCP(listeners.Config{ID: listenerMQTT, Address: addr})); err != nil {
			return nil, fmt.Errorf("failed to add MQTT listener: %w", err)
		}
		addedListeners++
		log.Printf("[SERVER] Native MQTT listening on: mqtt://%s", addr)
	}

	if cfg.MQTT.MQTTSPort > 0 {
		addr := fmt.Sprintf("%s:%d", cfg.MQTT.Host, cfg.MQTT.MQTTSPort)
		if err := server.AddListener(listeners.NewTCP(listeners.Config{ID: listenerMQTTS, Address: addr, TLSConfig: tlsConfig})); err != nil {
			return nil, fmt.Errorf("failed to add MQTTS listener: %w", err)
		}
		addedListeners++
		log.Printf("[SERVER] Secure native MQTT listening on: mqtts://%s", addr)
	}

	if addedListeners == 0 {
		return nil, fmt.Errorf("no listeners configured")
	}

	// Start serving (non-blocking)
	go func() {
		if err := server.Serve(); err != nil {
			log.Printf("[SERVER] MQTT server stopped: %v", err)
		}
	}()

	log.Println("╔════════════════════════════════════════════════════════════╗")
	log.Println("║        MeshCore MQTT Broker (Native + WebSocket)          ║")
	log.Println("╚════════════════════════════════════════════════════════════╝")
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
