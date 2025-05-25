package test

import (
	"altica_node/core"
	"crypto/ed25519"
	"testing"
	"time"
)

func TestNewRecord(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	r := &core.Record{
		Domain:   "example.alt",
		Mappings: make(map[string]interface{}),
		TTL:      time.Minute,
		Metadata: map[string]interface{}{},
	}
	if err := r.Sign(priv); err != nil {
		t.Fatalf("Failed to sign record: %v", err)
	}
	if !r.Verify() {
		t.Error("Record signature failed to verify")
	}
	if r.Domain != "example.alt" || r.TTL != time.Minute {
		t.Error("Record did not set fields correctly")
	}
	if r.Mappings == nil {
		t.Error("Mappings should be initialized")
	}
}

func TestRecordSigningAndVerification(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	r := &core.Record{
		Domain:   "example.alt",
		Mappings: map[string]interface{}{"A": "1.2.3.4"},
		TTL:      time.Minute,
		Metadata: map[string]interface{}{},
	}
	if err := r.Sign(priv); err != nil {
		t.Fatalf("Failed to sign record: %v", err)
	}
	if !r.Verify() {
		t.Error("Record signature failed to verify")
	}
}

func TestInvalidSignatureFails(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(nil)
	_, priv2, _ := ed25519.GenerateKey(nil)

	r := &core.Record{
		Domain:   "example.alt",
		Mappings: map[string]interface{}{"A": "1.2.3.4"},
		TTL:      time.Minute,
		Metadata: map[string]interface{}{},
	}
	if err := r.Sign(priv1); err != nil {
		t.Fatalf("Failed to sign record: %v", err)
	}

	// Manually override the public key with mismatched one
	r.PublicKey = priv2.Public().(ed25519.PublicKey)

	if r.Verify() {
		t.Error("Verification should have failed with mismatched public key")
	}
}

func TestSerializationAndDeserialization(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	r1 := &core.Record{
		Domain:   "example.alt",
		Mappings: map[string]interface{}{"A": "1.2.3.4"},
		TTL:      time.Minute,
		Metadata: map[string]interface{}{},
	}
	r1.Sign(priv)

	data, err := r1.Serialize()
	if err != nil {
		t.Fatalf("Failed to serialize: %v", err)
	}

	r2, err := core.DeserializeRecord(data)
	if err != nil {
		t.Fatalf("Failed to deserialize: %v", err)
	}

	if !r2.Verify() {
		t.Error("Deserialized record failed to verify")
	}
}

func TestExpiration(t *testing.T) {
	r := &core.Record{
		Domain:   "expired.alt",
		Mappings: make(map[string]interface{}),
		TTL:      -1 * time.Second,
		Metadata: map[string]interface{}{},
	}
	r.Metadata["created_at"] = time.Now().Add(-2 * time.Second).UTC().Format(time.RFC3339)
	if r.IsExpired() == false {
		t.Error("Record should be expired")
	}

	r2 := &core.Record{
		Domain:   "valid.alt",
		Mappings: make(map[string]interface{}),
		TTL:      time.Minute,
		Metadata: map[string]interface{}{},
	}
	r2.Metadata["created_at"] = time.Now().UTC().Format(time.RFC3339)
	if r2.IsExpired() {
		t.Error("Record should not be expired")
	}
}

func TestUpdateRecord(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	r := &core.Record{
		Domain:   "example.alt",
		Mappings: map[string]interface{}{"A": "1.2.3.4"},
		TTL:      time.Minute,
		Metadata: map[string]interface{}{},
	}
	if err := r.Sign(priv); err != nil {
		t.Fatalf("Failed to sign record: %v", err)
	}
	r.Mappings["A"] = "0.9.8.7"
	if err := r.Sign(priv); err != nil {
		t.Fatalf("Failed to re-sign record: %v", err)
	}
	if !r.Verify() {
		t.Error("Updated record signature failed to verify")
	}
}
