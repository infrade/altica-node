package test

import (
	"altica_node/core"
	"crypto/ed25519"
	"testing"
	"time"
)

func TestNewRecord(t *testing.T) {
	r := core.NewRecord("example.alt", "1.2.3.4", time.Minute)
	if r.Domain != "example.alt" || r.Value != "1.2.3.4" || r.TTL != time.Minute {
		t.Error("NewRecord did not set fields correctly")
	}
}

func TestRecordSigningAndVerification(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	r := core.NewRecord("example.alt", "1.2.3.4", time.Minute)

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

	r := core.NewRecord("example.alt", "1.2.3.4", time.Minute)
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
	r1 := core.NewRecord("example.alt", "1.2.3.4", time.Minute)
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
	r := core.NewRecord("expired.alt", "4.3.2.1", -1*time.Second)
	if !r.IsExpired() {
		t.Error("Record should be expired")
	}

	r2 := core.NewRecord("valid.alt", "4.3.2.1", time.Minute)
	if r2.IsExpired() {
		t.Error("Record should not be expired")
	}
}

func TestUpdateRecord(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	r := core.NewRecord("example.alt", "1.2.3.4", time.Minute)
	if err := r.Sign(priv); err != nil {
		t.Fatalf("Failed to sign record: %v", err)
	}
	r.Value = "0.9.8.7"
	if err := r.Sign(priv); err != nil {
		t.Fatalf("Failed to re-sign record: %v", err)
	}
	if !r.Verify() {
		t.Error("Updated record signature failed to verify")
	}
}
