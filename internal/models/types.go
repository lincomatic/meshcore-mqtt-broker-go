package models

import "time"

// ClientType represents the type of MQTT client
type ClientType string

const (
	ClientTypeSubscriber ClientType = "subscriber"
	ClientTypePublisher  ClientType = "publisher"
)

// SubscriberRole represents the access level of a subscriber
type SubscriberRole int

const (
	SubscriberRoleAdmin      SubscriberRole = 1 // Full access + can delete retained messages
	SubscriberRoleFullAccess SubscriberRole = 2 // Meshcore-only access with internal topics hidden
	SubscriberRoleWriteOnly  SubscriberRole = 3 // Write-only access to meshcore topics, excluding internal
)

// ClientTrustState represents the trust and behavioral state of a connected client
type ClientTrustState struct {
	// Identity
	PublicKey   string
	Username    string
	ConnectedAt time.Time
	ClientType  ClientType

	// Network tracking
	RecentIPs []IPHistory

	// Status
	Status     string // "allowed", "muted", "would_mute"
	MutedAt    *time.Time
	MuteReason string

	// Rate limiting (leaky bucket)
	TokenBucket TokenBucket

	// Duplicate detection
	RecentPacketHashes  []PacketHash
	DuplicateCount      int64
	DuplicateRateWindow DuplicateRateWindow

	// Counters (lifetime)
	TotalPacketsReceived int64
	TotalPacketsSilenced int64
	TotalPacketsRelayed  int64

	// Behavioral metrics
	UniqueTopics map[string]bool
	TopicHistory []TopicEvent

	// IATA location tracking
	IATAHistory        []IATAEvent
	CurrentIATA        string
	IATAChangeCount24h int

	// Clock tracking
	ClockTracking ClockTracking

	// Anomaly tracking
	AnomalyCount int
	Anomalies    []Anomaly

	// Performance/debugging
	LastPacketAt     time.Time
	AvgPacketSize    float64
	PeakRateObserved float64
}

// IPHistory tracks client IP addresses
type IPHistory struct {
	IP              string
	FirstSeen       time.Time
	LastSeen        time.Time
	ConnectionCount int
}

// TokenBucket for rate limiting
type TokenBucket struct {
	Tokens     float64
	LastRefill time.Time
	Capacity   float64
	RefillRate float64
}

// PacketHash tracks recently seen packet hashes
type PacketHash struct {
	Hash      string
	Timestamp time.Time
	Count     int // How many times this packet was seen
}

// DuplicateRateWindow tracks duplicate rate over time
type DuplicateRateWindow struct {
	TotalPackets     int
	DuplicatePackets int
	WindowStart      time.Time
	WindowMs         int64
}

// TopicEvent tracks topic subscriptions/publishes
type TopicEvent struct {
	Topic     string
	Timestamp time.Time
}

// IATAEvent tracks IATA location history
type IATAEvent struct {
	IATA      string
	FirstSeen time.Time
	LastSeen  time.Time
}

// ClockTracking for detecting clock anomalies
type ClockTracking struct {
	Version             int
	EstimatedOffset     *int64
	LastDeviceTimestamp *int64
	LastBrokerTimestamp *int64
	ErraticJumps        []ClockJump
}

// ClockJump represents a suspicious clock jump
type ClockJump struct {
	From         int64
	To           int64
	OffsetChange int64
	Timestamp    time.Time
}

// Anomaly represents a detected anomalous behavior
type Anomaly struct {
	Type      string
	Details   string
	Timestamp time.Time
}

// SubscriberUser represents a configured subscriber
type SubscriberUser struct {
	Username       string
	Password       string
	Role           SubscriberRole
	MaxConnections int
}

// RateLimitRecord tracks failed connection attempts from an IP
type RateLimitRecord struct {
	Count        int
	FirstFailure time.Time
	BlockedUntil *time.Time
}
