package config

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
	"github.com/lincomatic/meshcore-mqtt-broker-go/internal/models"
)

// Config holds all application configuration
type Config struct {
	MQTT       MQTTConfig
	Auth       AuthConfig
	Subscriber SubscriberConfig
	Abuse      AbuseConfig
	LogLevel   string
}

// MQTTConfig holds MQTT server configuration
type MQTTConfig struct {
	Port             int
	Host             string
	ExpectedAudience string
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	ExpectedAudience string
}

// SubscriberConfig holds subscriber configuration
type SubscriberConfig struct {
	DefaultMaxConnections int
	Users                 map[string]*models.SubscriberUser
}

// AbuseConfig holds abuse detection configuration
type AbuseConfig struct {
	DuplicateWindowSize    int
	DuplicateWindowMs      int
	DuplicateThreshold     int
	MaxDuplicatesPerPacket int
	DuplicateRateThreshold float64
	DuplicateRateWindowMs  int
	BucketCapacity         int
	BucketRefillRate       float64
	MaxPacketSize          int
	MaxTopicsPerDay        int
	AnomalyThreshold       int
	MaxIATAChanges24h      int
	TopicHistorySize       int
	TopicHistoryWindowMs   int
	PersistencePath        string
	PersistenceIntervalMs  int
	EnforcementEnabled     bool
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	// Load .env file if it exists
	_ = godotenv.Load()

	cfg := &Config{}

	// Load MQTT configuration
	if err := cfg.loadMQTTConfig(); err != nil {
		return nil, err
	}

	// Load Auth configuration
	if err := cfg.loadAuthConfig(); err != nil {
		return nil, err
	}

	// Load Subscriber configuration
	if err := cfg.loadSubscriberConfig(); err != nil {
		return nil, err
	}

	// Load Abuse detection configuration
	if err := cfg.loadAbuseConfig(); err != nil {
		return nil, err
	}

	cfg.LogLevel = strings.ToUpper(os.Getenv("LOG_LEVEL"))
	if cfg.LogLevel == "" {
		cfg.LogLevel = "INFO"
	}

	return cfg, nil
}

func (c *Config) loadMQTTConfig() error {
	port, err := getRequiredInt("MQTT_WS_PORT")
	if err != nil {
		return err
	}

	host, err := getRequiredString("MQTT_HOST")
	if err != nil {
		return err
	}

	c.MQTT = MQTTConfig{
		Port:             port,
		Host:             host,
		ExpectedAudience: os.Getenv("AUTH_EXPECTED_AUDIENCE"),
	}

	return nil
}

func (c *Config) loadAuthConfig() error {
	c.Auth = AuthConfig{
		ExpectedAudience: os.Getenv("AUTH_EXPECTED_AUDIENCE"),
	}

	return nil
}

func (c *Config) loadSubscriberConfig() error {
	defaultMaxConn, err := getRequiredInt("SUBSCRIBER_MAX_CONNECTIONS_DEFAULT")
	if err != nil {
		return err
	}

	c.Subscriber = SubscriberConfig{
		DefaultMaxConnections: defaultMaxConn,
		Users:                 make(map[string]*models.SubscriberUser),
	}

	// Load subscriber users from environment
	for i := 1; i <= 100; i++ { // Support up to 100 subscribers
		envVar := os.Getenv(fmt.Sprintf("SUBSCRIBER_%d", i))
		if envVar == "" {
			break
		}

		user, err := parseSubscriberUser(envVar, defaultMaxConn)
		if err != nil {
			log.Printf("[CONFIG] Invalid format for SUBSCRIBER_%d: %v", i, err)
			continue
		}

		c.Subscriber.Users[user.Username] = user
		role := map[models.SubscriberRole]string{
			models.SubscriberRoleAdmin:      "admin",
			models.SubscriberRoleFullAccess: "full_access",
			models.SubscriberRoleLimited:    "limited",
		}
		log.Printf("[CONFIG] Loaded subscriber user: %s (role: %s, maxConnections: %d)",
			user.Username, role[user.Role], user.MaxConnections)
	}

	if len(c.Subscriber.Users) == 0 {
		log.Println("[CONFIG] No subscriber users configured")
	} else {
		log.Printf("[CONFIG] Default max connections per subscriber: %d", defaultMaxConn)
	}

	return nil
}

func (c *Config) loadAbuseConfig() error {
	// Validate all required abuse detection environment variables
	requiredVars := []string{
		"ABUSE_DUPLICATE_WINDOW_SIZE",
		"ABUSE_DUPLICATE_WINDOW_MS",
		"ABUSE_DUPLICATE_THRESHOLD",
		"ABUSE_BUCKET_CAPACITY",
		"ABUSE_BUCKET_REFILL_RATE",
		"ABUSE_MAX_PACKET_SIZE",
		"ABUSE_MAX_TOPICS_PER_DAY",
		"ABUSE_ANOMALY_THRESHOLD",
		"ABUSE_MAX_IATA_CHANGES_24H",
		"ABUSE_TOPIC_HISTORY_SIZE",
		"ABUSE_TOPIC_HISTORY_WINDOW_MS",
		"ABUSE_PERSISTENCE_PATH",
		"ABUSE_PERSISTENCE_INTERVAL_MS",
	}

	for _, envVar := range requiredVars {
		if os.Getenv(envVar) == "" {
			return fmt.Errorf("missing required environment variable: %s", envVar)
		}
	}

	// Parse all required integer values
	dupWindowSize, err := getRequiredInt("ABUSE_DUPLICATE_WINDOW_SIZE")
	if err != nil {
		return err
	}

	dupWindowMs, err := getRequiredInt("ABUSE_DUPLICATE_WINDOW_MS")
	if err != nil {
		return err
	}

	dupThreshold, err := getRequiredInt("ABUSE_DUPLICATE_THRESHOLD")
	if err != nil {
		return err
	}

	bucketCapacity, err := getRequiredInt("ABUSE_BUCKET_CAPACITY")
	if err != nil {
		return err
	}

	maxPacketSize, err := getRequiredInt("ABUSE_MAX_PACKET_SIZE")
	if err != nil {
		return err
	}

	maxTopicsPerDay, err := getRequiredInt("ABUSE_MAX_TOPICS_PER_DAY")
	if err != nil {
		return err
	}

	anomalyThreshold, err := getRequiredInt("ABUSE_ANOMALY_THRESHOLD")
	if err != nil {
		return err
	}

	maxIATAChanges24h, err := getRequiredInt("ABUSE_MAX_IATA_CHANGES_24H")
	if err != nil {
		return err
	}

	topicHistorySize, err := getRequiredInt("ABUSE_TOPIC_HISTORY_SIZE")
	if err != nil {
		return err
	}

	topicHistoryWindowMs, err := getRequiredInt("ABUSE_TOPIC_HISTORY_WINDOW_MS")
	if err != nil {
		return err
	}

	persistenceIntervalMs, err := getRequiredInt("ABUSE_PERSISTENCE_INTERVAL_MS")
	if err != nil {
		return err
	}

	persistencePath, err := getRequiredString("ABUSE_PERSISTENCE_PATH")
	if err != nil {
		return err
	}

	// Parse optional float values with defaults
	bucketRefillRate := getOptionalFloat("ABUSE_BUCKET_REFILL_RATE", 1.0)

	c.Abuse = AbuseConfig{
		DuplicateWindowSize:    dupWindowSize,
		DuplicateWindowMs:      dupWindowMs,
		DuplicateThreshold:     dupThreshold,
		MaxDuplicatesPerPacket: getOptionalInt("ABUSE_MAX_DUPLICATES_PER_PACKET", 5),
		DuplicateRateThreshold: getOptionalFloat("ABUSE_DUPLICATE_RATE_THRESHOLD", 0.3),
		DuplicateRateWindowMs:  getOptionalInt("ABUSE_DUPLICATE_RATE_WINDOW_MS", 300000),
		BucketCapacity:         bucketCapacity,
		BucketRefillRate:       bucketRefillRate,
		MaxPacketSize:          maxPacketSize,
		MaxTopicsPerDay:        maxTopicsPerDay,
		AnomalyThreshold:       anomalyThreshold,
		MaxIATAChanges24h:      maxIATAChanges24h,
		TopicHistorySize:       topicHistorySize,
		TopicHistoryWindowMs:   topicHistoryWindowMs,
		PersistencePath:        persistencePath,
		PersistenceIntervalMs:  persistenceIntervalMs,
		EnforcementEnabled:     getOptionalBool("ABUSE_ENFORCEMENT_ENABLED", false),
	}

	return nil

}

func parseSubscriberUser(envVar string, defaultMaxConn int) (*models.SubscriberUser, error) {
	parts := strings.Split(envVar, ":")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid format: expected at least username:password")
	}

	username := strings.TrimSpace(parts[0])
	password := strings.TrimSpace(parts[1])

	role := models.SubscriberRoleLimited // default
	if len(parts) > 2 && parts[2] != "" {
		roleNum, err := strconv.Atoi(strings.TrimSpace(parts[2]))
		if err == nil {
			if roleNum == 1 || roleNum == 2 || roleNum == 3 {
				role = models.SubscriberRole(roleNum)
			}
		}
	}

	maxConn := defaultMaxConn
	if len(parts) > 3 && parts[3] != "" {
		maxConnStr := strings.TrimSpace(parts[3])
		if strings.ToUpper(maxConnStr) != "D" {
			if parsed, err := strconv.Atoi(maxConnStr); err == nil && parsed > 0 {
				maxConn = parsed
			}
		}
	}

	return &models.SubscriberUser{
		Username:       username,
		Password:       password,
		Role:           role,
		MaxConnections: maxConn,
	}, nil
}

// Helper functions for environment variables

func getRequiredString(key string) (string, error) {
	val := os.Getenv(key)
	if val == "" {
		return "", fmt.Errorf("missing required environment variable: %s", key)
	}
	return val, nil
}

func getRequiredInt(key string) (int, error) {
	val := os.Getenv(key)
	if val == "" {
		return 0, fmt.Errorf("missing required environment variable: %s", key)
	}
	num, err := strconv.Atoi(val)
	if err != nil {
		return 0, fmt.Errorf("invalid integer for %s: %v", key, err)
	}
	return num, nil
}

func getOptionalInt(key string, defaultVal int) int {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	num, err := strconv.Atoi(val)
	if err != nil {
		log.Printf("WARNING: Invalid integer for %s, using default %d", key, defaultVal)
		return defaultVal
	}
	return num
}

func getOptionalFloat(key string, defaultVal float64) float64 {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	num, err := strconv.ParseFloat(val, 64)
	if err != nil {
		log.Printf("WARNING: Invalid float for %s, using default %f", key, defaultVal)
		return defaultVal
	}
	return num
}

func getOptionalBool(key string, defaultVal bool) bool {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	return strings.ToLower(val) == "true"
}
