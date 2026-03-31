package utils

import (
	"net/http"
	"strings"
)

// GetClientIP extracts the real client IP from an HTTP request,
// considering Cloudflare headers and other proxy headers
func GetClientIP(r *http.Request) string {
	// Cloudflare provides the real IP in CF-Connecting-IP header
	if cfConnectingIP := r.Header.Get("CF-Connecting-IP"); cfConnectingIP != "" {
		return cfConnectingIP
	}

	// Fallback to X-Forwarded-For (take first IP in chain)
	if xForwardedFor := r.Header.Get("X-Forwarded-For"); xForwardedFor != "" {
		// X-Forwarded-For can contain multiple IPs separated by commas
		ips := strings.Split(xForwardedFor, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Fallback to X-Real-IP
	if xRealIP := r.Header.Get("X-Real-IP"); xRealIP != "" {
		return xRealIP
	}

	// Last resort: socket remote address
	if remoteAddr := r.RemoteAddr; remoteAddr != "" {
		// RemoteAddr includes the port, extract just the IP
		if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
			return remoteAddr[:idx]
		}
		return remoteAddr
	}

	return "unknown"
}
