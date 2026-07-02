package config

import (
	"testing"

	"github.com/lincomatic/meshcore-mqtt-broker-go/internal/models"
)

func TestParseSubscriberUserRequiresRole(t *testing.T) {
	_, err := parseSubscriberUser("viewer:secret", 2)
	if err == nil {
		t.Fatal("expected missing role to fail")
	}
}

func TestParseSubscriberUserRejectsInvalidRole(t *testing.T) {
	_, err := parseSubscriberUser("viewer:secret:99", 2)
	if err == nil {
		t.Fatal("expected invalid role to fail")
	}
}

func TestParseSubscriberUserParsesWriteOnlyRole(t *testing.T) {
	user, err := parseSubscriberUser("writer:secret:3:D", 7)
	if err != nil {
		t.Fatalf("expected valid subscriber user, got error: %v", err)
	}

	if user.Role != models.SubscriberRoleWriteOnly {
		t.Fatalf("expected role 3, got %d", user.Role)
	}

	if user.MaxConnections != 7 {
		t.Fatalf("expected default max connections 7, got %d", user.MaxConnections)
	}
}
