package server

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"

	"github.com/lincomatic/meshcore-mqtt-broker-go/internal/auth"
	"github.com/lincomatic/meshcore-mqtt-broker-go/internal/models"
)

var pubKeyRegex = regexp.MustCompile(`^[0-9A-Fa-f]{64}$`)
var iataRegex = regexp.MustCompile(`^[A-Z]{3}$`)

// authHook implements mochi-mqtt's HookBase for auth and ACL
type authHook struct {
	mqtt.HookBase
	broker *Broker
}

func (h *authHook) ID() string { return "meshcore-auth" }

func (h *authHook) Provides(b byte) bool {
	return b == mqtt.OnConnectAuthenticate || b == mqtt.OnACLCheck
}

// OnConnectAuthenticate handles CONNECT packet authentication
func (h *authHook) OnConnectAuthenticate(cl *mqtt.Client, pk packets.Packet) bool {
	username := string(pk.Connect.Username)
	password := string(pk.Connect.Password)
	logPrefix := fmt.Sprintf("[C:%s]", cl.ID)

	log.Printf("%s [AUTH] Authentication attempt - Username: %s", logPrefix, username)

	// --- Subscriber auth ---
	if user, ok := h.broker.cfg.Subscriber.Users[username]; ok {
		if password != user.Password {
			log.Printf("%s [AUTH] ✗ Subscriber invalid password (%s)", logPrefix, username)
			return false
		}
		// Connection limit check
		// TODO: track active connections per subscriber (Phase 3)
		log.Printf("%s [AUTH] ✓ Subscriber authenticated (%s)", logPrefix, username)
		cl.Properties.Username = []byte(username)
		// Store role on client session props for ACL use
		cl.Properties.Props.User = append(cl.Properties.Props.User, packets.UserProperty{
			Key: "clientType", Val: string(models.ClientTypeSubscriber),
		}, packets.UserProperty{
			Key: "role", Val: fmt.Sprintf("%d", user.Role),
		})
		return true
	}

	// --- Publisher auth (v1_{PUBLIC_KEY}) ---
	if !strings.HasPrefix(username, "v1_") {
		log.Printf("%s [AUTH] ✗ Invalid username format: %s", logPrefix, username)
		return false
	}

	publicKey := strings.ToUpper(strings.TrimSpace(username[3:]))
	if !pubKeyRegex.MatchString(publicKey) {
		log.Printf("%s [AUTH] ✗ Invalid public key format: %s", logPrefix, publicKey)
		return false
	}

	if password == "" {
		log.Printf("%s [AUTH] ✗ No password provided", logPrefix)
		return false
	}

	payload, err := auth.VerifyToken(password, publicKey, h.broker.cfg.MQTT.ExpectedAudience)
	if err != nil {
		log.Printf("%s [AUTH] ✗ Token verification failed: %v", logPrefix, err)
		return false
	}

	if err := auth.ValidateTokenPayload(payload, h.broker.cfg.MQTT.ExpectedAudience); err != nil {
		log.Printf("%s [AUTH] ✗ Token claims invalid: %v", logPrefix, err)
		return false
	}

	log.Printf("[O:%s] [AUTH] ✓ Publisher authenticated%s",
		publicKey[:8],
		func() string {
			if payload.Aud != "" {
				return " [aud: " + payload.Aud + "]"
			}
			return ""
		}(),
	)

	cl.Properties.Props.User = append(cl.Properties.Props.User, packets.UserProperty{
		Key: "clientType", Val: string(models.ClientTypePublisher),
	}, packets.UserProperty{
		Key: "publicKey", Val: publicKey,
	})

	return true
}

// OnACLCheck handles publish/subscribe authorization
func (h *authHook) OnACLCheck(cl *mqtt.Client, topic string, write bool) bool {
	logPrefix := fmt.Sprintf("[C:%s]", cl.ID)
	clientType := getUserProp(cl, "clientType")
	publicKey := getUserProp(cl, "publicKey")
	username := string(cl.Properties.Username)

	if write {
		// --- Publisher publish rules ---
		if clientType == string(models.ClientTypePublisher) {
			return h.authorizePublish(logPrefix, publicKey, topic)
		}
		// --- Subscriber publish rules ---
		if clientType == string(models.ClientTypeSubscriber) {
			roleStr := getUserProp(cl, "role")
			return h.authorizeSubscriberPublish(logPrefix, username, roleStr, topic)
		}
		log.Printf("%s [AUTHZ] ✗ Publish denied (unknown client type) -> %s", logPrefix, topic)
		return false
	}

	// --- Subscribe rules ---
	if clientType == string(models.ClientTypePublisher) {
		// Publishers may only subscribe to their own serial/commands
		if strings.HasSuffix(topic, "/serial/commands") {
			parts := strings.Split(topic, "/")
			if len(parts) == 5 && parts[0] == "meshcore" && parts[3] == "serial" {
				topicKey := strings.ToUpper(parts[2])
				if topicKey == publicKey {
					log.Printf("%s [AUTHZ] ✓ Subscribe authorized (own serial/commands) -> %s", logPrefix, topic)
					return true
				}
			}
		}
		log.Printf("%s [AUTHZ] ✗ Subscribe denied (publisher) -> %s", logPrefix, topic)
		return false
	}

	if clientType == string(models.ClientTypeSubscriber) {
		role := parseSubscriberRole(getUserProp(cl, "role"))

		if role == models.SubscriberRoleFullAccess {
			if isExplicitInternalTopicFilter(topic) {
				log.Printf("%s [AUTHZ] ✗ Subscribe denied (role 2 internal topics hidden) -> %s", logPrefix, topic)
				return false
			}

			if topic == "meshcore" || strings.HasPrefix(topic, "meshcore/") {
				log.Printf("%s [AUTHZ] ✓ Subscribe authorized (role 2 meshcore scope) -> %s", logPrefix, topic)
				return true
			}

			log.Printf("%s [AUTHZ] ✗ Subscribe denied (role 2 limited to meshcore/*) -> %s", logPrefix, topic)
			return false
		}

		log.Printf("%s [AUTHZ] ✓ Subscribe authorized -> %s", logPrefix, topic)
		return true
	}

	log.Printf("%s [AUTHZ] ✗ Subscribe denied (unknown client type) -> %s", logPrefix, topic)
	return false
}

func (h *authHook) authorizePublish(logPrefix, publicKey, topic string) bool {
	if !strings.HasPrefix(topic, "meshcore/") {
		log.Printf("%s [AUTHZ] ✗ Publish denied -> %s (not meshcore/*)", logPrefix, topic)
		return false
	}

	parts := strings.Split(topic, "/")
	if len(parts) < 4 {
		log.Printf("%s [AUTHZ] ✗ Publish denied -> %s (need meshcore/IATA/PUBKEY/subtopic)", logPrefix, topic)
		return false
	}

	locationCode := parts[1]
	isTest := strings.ToLower(locationCode) == "test"

	if locationCode == "XXX" {
		log.Printf("%s [AUTHZ] ✗ Publish denied -> %s (XXX is placeholder)", logPrefix, topic)
		return false
	}

	if !isTest {
		if !iataRegex.MatchString(locationCode) {
			log.Printf("%s [AUTHZ] ✗ Publish denied -> %s (invalid IATA format)", logPrefix, topic)
			return false
		}
	}

	topicKey := strings.ToUpper(parts[2])
	if !pubKeyRegex.MatchString(topicKey) {
		log.Printf("%s [AUTHZ] ✗ Publish denied -> %s (invalid pubkey in topic)", logPrefix, topic)
		return false
	}

	if topicKey != publicKey {
		log.Printf("%s [AUTHZ] ✗ Publish denied -> %s (pubkey mismatch)", logPrefix, topic)
		return false
	}

	log.Printf("%s [AUTHZ] ✓ Publish authorized -> %s", logPrefix, topic)
	return true
}

func (h *authHook) authorizeSubscriberPublish(logPrefix, username, roleStr, topic string) bool {
	role := parseSubscriberRole(roleStr)

	// Admin can delete retained messages (empty payload to retained topic)
	// Admin can publish to serial/commands
	if role == models.SubscriberRoleAdmin {
		if strings.HasSuffix(topic, "/serial/commands") {
			parts := strings.Split(topic, "/")
			if len(parts) == 5 && parts[0] == "meshcore" && parts[3] == "serial" {
				log.Printf("%s [AUTHZ] ✓ Admin serial command authorized -> %s", logPrefix, topic)
				return true
			}
		}
		// Allow admin to publish empty retained (delete)
		log.Printf("%s [AUTHZ] ✓ Admin publish authorized -> %s", logPrefix, topic)
		return true
	}

	log.Printf("%s [AUTHZ] ✗ Publish denied (subscriber) -> %s", logPrefix, topic)
	return false
}

func parseSubscriberRole(roleStr string) models.SubscriberRole {
	switch roleStr {
	case "1":
		return models.SubscriberRoleAdmin
	case "2":
		return models.SubscriberRoleFullAccess
	default:
		return models.SubscriberRoleFullAccess
	}
}

func isExplicitInternalTopicFilter(topic string) bool {
	return topic == "internal" ||
		strings.HasSuffix(topic, "/internal") ||
		strings.Contains(topic, "/internal/")
}

// getUserProp retrieves a user property from client session
func getUserProp(cl *mqtt.Client, key string) string {
	for _, p := range cl.Properties.Props.User {
		if p.Key == key {
			return p.Val
		}
	}
	return ""
}
