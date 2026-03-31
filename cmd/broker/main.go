package main

import (
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/lincomatic/meshcore-mqtt-broker-go/internal/config"
	"github.com/lincomatic/meshcore-mqtt-broker-go/internal/server"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Configure log level from LOG_LEVEL env var (DEBUG, INFO, WARN, ERROR)
	var level slog.Level
	switch cfg.LogLevel {
	case "DEBUG":
		level = slog.LevelDebug
	case "WARN":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)
	// Also redirect the standard log package to slog
	log.SetFlags(0)
	log.SetOutput(os.Stdout)
	slog.Info("Log level set", "level", cfg.LogLevel)

	broker, err := server.New(cfg)
	if err != nil {
		slog.Error("Failed to start broker", "err", err)
		os.Exit(1)
	}
	defer broker.Close()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	slog.Info("Shutting down broker...")
}
