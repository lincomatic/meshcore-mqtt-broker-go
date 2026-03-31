package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type tokenHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// TokenPayload represents the JWT payload
type TokenPayload struct {
	PublicKey string `json:"publicKey"`
	Aud       string `json:"aud"`
	Iat       int64  `json:"iat"`
	Exp       *int64 `json:"exp,omitempty"`
}

// VerifyToken verifies a JWT token signed with Ed25519.
// Token format: header.payload.signature where header/payload are base64url
// and signature is hex-encoded (MeshCore-specific format).
func VerifyToken(tokenStr, publicKeyHex, expectedAudience string) (*TokenPayload, error) {
	// Parse token into its three parts
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format: expected 3 parts separated by dots, got %d", len(parts))
	}

	headerEncoded, payloadEncoded, signatureHex := parts[0], parts[1], parts[2]

	// Decode and validate header
	headerBytes, err := base64urlDecode(headerEncoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var header tokenHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	if header.Alg != "Ed25519" || header.Typ != "JWT" {
		return nil, fmt.Errorf("invalid token header: alg=%s typ=%s", header.Alg, header.Typ)
	}

	// Decode payload (second part)
	payload, err := base64urlDecode(payloadEncoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	// Decode signature (third part, hex-encoded in meshcore-decoder)
	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	if len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid signature size: expected %d bytes, got %d", ed25519.SignatureSize, len(signature))
	}

	// Convert public key from hex to ed25519.PublicKey
	pubKey, err := hexToEd25519PublicKey(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key: %w", err)
	}

	// Reconstruct the signing input (header.payload in base64url form)
	// This is what was signed: "base64url(header).base64url(payload)"
	signingInput := []byte(headerEncoded + "." + payloadEncoded)

	// Verify Ed25519 signature
	if !ed25519.Verify(pubKey, signingInput, signature) {
		return nil, fmt.Errorf("invalid token signature")
	}

	// Parse payload JSON
	var tokenPayload TokenPayload
	if err := json.Unmarshal(payload, &tokenPayload); err != nil {
		return nil, fmt.Errorf("failed to parse payload: %w", err)
	}

	if tokenPayload.PublicKey == "" {
		return nil, fmt.Errorf("token payload missing public_key")
	}

	if !strings.EqualFold(tokenPayload.PublicKey, publicKeyHex) {
		return nil, fmt.Errorf("token payload public_key does not match expected key")
	}

	// Validate the payload claims
	if err := ValidateTokenPayload(&tokenPayload, expectedAudience); err != nil {
		return nil, err
	}

	return &tokenPayload, nil
}

// ValidateTokenPayload validates the claims in a token payload
func ValidateTokenPayload(payload *TokenPayload, expectedAudience string) error {
	if payload == nil {
		return fmt.Errorf("payload is nil")
	}

	// Validate audience
	if expectedAudience != "" && payload.Aud != expectedAudience {
		return fmt.Errorf("invalid audience: expected %s, got %s", expectedAudience, payload.Aud)
	}

	// Validate expiration
	if payload.Exp != nil {
		if time.Now().Unix() > *payload.Exp {
			return fmt.Errorf("token has expired")
		}
	}

	// Validate iat is not too far in the future (allow 60 seconds clock skew)
	if payload.Iat > time.Now().Unix()+60 {
		return fmt.Errorf("token iat is in the future")
	}

	return nil
}

// hexToEd25519PublicKey converts a hex-encoded public key to ed25519.PublicKey
// Ed25519 public keys are 32 bytes, which is 64 hexadecimal characters
func hexToEd25519PublicKey(hexKey string) (ed25519.PublicKey, error) {
	// Ed25519 public keys must be exactly 32 bytes (64 hex characters)
	if len(hexKey) != 64 {
		return nil, fmt.Errorf("invalid public key length: expected 64 hex characters (32 bytes), got %d", len(hexKey))
	}

	// Decode hex string to bytes
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex public key: %w", err)
	}

	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("invalid public key size: expected 32 bytes, got %d", len(keyBytes))
	}

	return ed25519.PublicKey(keyBytes), nil
}

// base64urlDecode decodes a base64url-encoded string
// Base64url uses - instead of + and _ instead of /
// Reference: RFC 4648 Section 5
func base64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
