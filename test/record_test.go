package test

import (
	"altica_node/core"
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

func generateTestKey(t *testing.T) *ecdsa.PrivateKey {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	return privateKey
}

func TestNewRecord(t *testing.T) {
	priv := generateTestKey(t)
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

	// Verify signer address is set correctly
	signerAddr, err := r.GetSignerAddress()
	if err != nil {
		t.Fatalf("Failed to get signer address: %v", err)
	}
	expectedAddr := crypto.PubkeyToAddress(priv.PublicKey)
	if signerAddr != expectedAddr {
		t.Errorf("Signer address mismatch. Got %s, want %s", signerAddr.Hex(), expectedAddr.Hex())
	}
}

func TestRecordSigningAndVerification(t *testing.T) {
	priv := generateTestKey(t)
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
	priv1 := generateTestKey(t)
	priv2 := generateTestKey(t)

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
	r.PublicKey = crypto.FromECDSAPub(&priv2.PublicKey)

	if r.Verify() {
		t.Error("Verification should have failed with mismatched public key")
	}
}

func TestSerializationAndDeserialization(t *testing.T) {
	priv := generateTestKey(t)
	r1 := &core.Record{
		Domain:   "example.alt",
		Mappings: map[string]interface{}{"A": "1.2.3.4"},
		TTL:      time.Minute,
		Metadata: map[string]interface{}{},
	}
	if err := r1.Sign(priv); err != nil {
		t.Fatalf("Failed to sign record: %v", err)
	}

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

	// Verify signer address is preserved after serialization
	addr1, err := r1.GetSignerAddress()
	if err != nil {
		t.Fatalf("Failed to get signer address from r1: %v", err)
	}
	addr2, err := r2.GetSignerAddress()
	if err != nil {
		t.Fatalf("Failed to get signer address from r2: %v", err)
	}
	if addr1 != addr2 {
		t.Errorf("Signer address mismatch after serialization. Got %s, want %s", addr2.Hex(), addr1.Hex())
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
	priv := generateTestKey(t)
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

func TestGetSignerAddress(t *testing.T) {
	priv := generateTestKey(t)
	r := &core.Record{
		Domain:   "example.alt",
		Mappings: make(map[string]interface{}),
		TTL:      time.Minute,
		Metadata: map[string]interface{}{},
	}
	if err := r.Sign(priv); err != nil {
		t.Fatalf("Failed to sign record: %v", err)
	}

	// Test getting address from public key
	addr, err := r.GetSignerAddress()
	if err != nil {
		t.Fatalf("Failed to get signer address: %v", err)
	}
	expectedAddr := crypto.PubkeyToAddress(priv.PublicKey)
	if addr != expectedAddr {
		t.Errorf("Signer address mismatch. Got %s, want %s", addr.Hex(), expectedAddr.Hex())
	}

	// Test getting address from stored signer field
	r.Signer = addr.Hex()
	addr2, err := r.GetSignerAddress()
	if err != nil {
		t.Fatalf("Failed to get signer address: %v", err)
	}
	if addr2 != addr {
		t.Errorf("Signer address mismatch. Got %s, want %s", addr2.Hex(), addr.Hex())
	}
}
