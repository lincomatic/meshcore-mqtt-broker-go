package server

import (
	"testing"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"

	"github.com/lincomatic/meshcore-mqtt-broker-go/internal/models"
)

func TestOnACLCheckSubscriberReadRules(t *testing.T) {
	hook := &authHook{}

	tests := []struct {
		name  string
		role  models.SubscriberRole
		topic string
		want  bool
	}{
		{name: "admin can read internal", role: models.SubscriberRoleAdmin, topic: "meshcore/SEA/ABC/internal", want: true},
		{name: "role 2 can subscribe broad wildcard", role: models.SubscriberRoleFullAccess, topic: "#", want: true},
		{name: "role 2 can read meshcore wildcard scope", role: models.SubscriberRoleFullAccess, topic: "meshcore/#", want: true},
		{name: "role 2 can read concrete meshcore topic", role: models.SubscriberRoleFullAccess, topic: "meshcore/SEA/ABC/status", want: true},
		{name: "role 2 cannot explicitly read internal", role: models.SubscriberRoleFullAccess, topic: "meshcore/SEA/ABC/internal", want: false},
		{name: "role 2 cannot read outside meshcore", role: models.SubscriberRoleFullAccess, topic: "$SYS/broker/uptime", want: false},
		{name: "role 3 wildcard subscribe allowed to avoid client errors", role: models.SubscriberRoleWriteOnly, topic: "meshcore/#", want: true},
		{name: "role 3 still cannot read concrete topic", role: models.SubscriberRoleWriteOnly, topic: "meshcore/SEA/ABC/status", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newSubscriberTestClient(test.role)
			got := hook.OnACLCheck(client, test.topic, false)
			if got != test.want {
				t.Fatalf("OnACLCheck(read) for topic %q returned %v, want %v", test.topic, got, test.want)
			}
		})
	}
}

func TestAuthorizeSubscriberPublishRoleThree(t *testing.T) {
	hook := &authHook{}

	tests := []struct {
		name  string
		topic string
		want  bool
	}{
		{name: "role 3 can publish meshcore child topic", topic: "meshcore/SEA/ABC123/status", want: true},
		{name: "role 3 cannot publish internal topic", topic: "meshcore/SEA/ABC123/internal", want: false},
		{name: "role 3 cannot publish outside meshcore", topic: "$SYS/broker/uptime", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := hook.authorizeSubscriberPublish("[C:test]", "writer", "3", test.topic)
			if got != test.want {
				t.Fatalf("authorizeSubscriberPublish(%q) = %v, want %v", test.topic, got, test.want)
			}
		})
	}
}

func newSubscriberTestClient(role models.SubscriberRole) *mqtt.Client {
	return &mqtt.Client{
		ID: "test-client",
		Properties: mqtt.ClientProperties{
			Username: []byte("subscriber"),
			Props: packets.Properties{
				User: []packets.UserProperty{
					{Key: "clientType", Val: string(models.ClientTypeSubscriber)},
					{Key: "role", Val: string(rune('0' + role))},
				},
			},
		},
	}
}
