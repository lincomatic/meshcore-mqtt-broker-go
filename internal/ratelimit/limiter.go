package ratelimit

import (
	"log"
	"sync"
	"time"

	"github.com/lincomatic/meshcore-mqtt-broker-go/internal/models"
)

// Limiter implements rate limiting for failed connection attempts by IP address
type Limiter struct {
	mu                    sync.RWMutex
	failedConnectionsByIP map[string]*models.RateLimitRecord
	windowMs              int64
	maxFailedConnections  int
	blockDurationMs       int64
}

// New creates a new rate limiter
// windowMs: time window to count failures (default 60000 = 1 minute)
// maxFailedConnections: number of failures to trigger a block (default 10)
// blockDurationMs: how long to block an IP (default 300000 = 5 minutes)
func New(windowMs int64, maxFailedConnections int, blockDurationMs int64) *Limiter {
	return &Limiter{
		failedConnectionsByIP: make(map[string]*models.RateLimitRecord),
		windowMs:              windowMs,
		maxFailedConnections:  maxFailedConnections,
		blockDurationMs:       blockDurationMs,
	}
}

// IsBlocked checks if an IP address is currently blocked
func (l *Limiter) IsBlocked(ip string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()

	record, exists := l.failedConnectionsByIP[ip]
	if !exists {
		return false
	}

	now := time.Now()

	// Check if blocked
	if record.BlockedUntil != nil && now.Before(*record.BlockedUntil) {
		return true
	}

	// Reset if window expired
	if now.Sub(record.FirstFailure) > time.Duration(l.windowMs)*time.Millisecond {
		// Will be cleaned up on next operation
		return false
	}

	return false
}

// RecordFailure records a failed connection attempt from an IP
// Returns true if the IP should now be blocked
func (l *Limiter) RecordFailure(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	record, exists := l.failedConnectionsByIP[ip]

	if !exists {
		l.failedConnectionsByIP[ip] = &models.RateLimitRecord{
			Count:        1,
			FirstFailure: now,
		}
		return false
	}

	// Reset if window expired
	if now.Sub(record.FirstFailure) > time.Duration(l.windowMs)*time.Millisecond {
		l.failedConnectionsByIP[ip] = &models.RateLimitRecord{
			Count:        1,
			FirstFailure: now,
		}
		return false
	}

	record.Count++

	// Block if threshold exceeded
	if record.Count >= l.maxFailedConnections && record.BlockedUntil == nil {
		blockUntil := now.Add(time.Duration(l.blockDurationMs) * time.Millisecond)
		record.BlockedUntil = &blockUntil
		log.Printf("[RATE_LIMIT] Blocking IP %s for %d seconds (%d failed connections in %d seconds)",
			ip, l.blockDurationMs/1000, record.Count, l.windowMs/1000)
		return true
	}

	return false
}

// Cleanup removes expired entries to prevent memory leaks
func (l *Limiter) Cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	for ip, record := range l.failedConnectionsByIP {
		// Remove if window expired and not blocked, or if block expired
		windowExpired := now.Sub(record.FirstFailure) > time.Duration(l.windowMs)*time.Millisecond
		blockExpired := record.BlockedUntil != nil && now.After(*record.BlockedUntil)

		if (windowExpired && record.BlockedUntil == nil) || blockExpired {
			delete(l.failedConnectionsByIP, ip)
		}
	}
}
