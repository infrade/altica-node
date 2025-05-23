package core

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"
)

type Record struct {
	Domain    string        `json:"domain"`
	Value     string        `json:"value"` // IP, CID, etc.
	Timestamp time.Time     `json:"timestamp"`
	TTL       time.Duration `json:"ttl"`
	Signature []byte        `json:"signature,omitempty"`
	PublicKey []byte        `json:"public_key,omitempty"`
	Version   int64         `json:"version"`
	Status    string        `json:"status"`            // "pending", "confirmed", "rejected"
	LockID    string        `json:"lock_id,omitempty"` // For distributed locking
}

// NewRecord creates a new unsigned record
func NewRecord(domain, value string, ttl time.Duration) *Record {
	return &Record{
		Domain:    domain,
		Value:     value,
		Timestamp: time.Now().UTC(),
		TTL:       ttl,
	}
}

// Sign signs the record with the provided private key
func (r *Record) Sign(privateKey ed25519.PrivateKey) error {
	data, err := r.serializeForSigning()
	if err != nil {
		return err
	}
	r.Signature = ed25519.Sign(privateKey, data)
	r.PublicKey = privateKey.Public().(ed25519.PublicKey)
	return nil
}

// Verify checks the signature of the record
func (r *Record) Verify() bool {
	if r.Signature == nil || r.PublicKey == nil {
		return false
	}
	data, err := r.serializeForSigning()
	if err != nil {
		return false
	}
	return ed25519.Verify(r.PublicKey, data, r.Signature)
}

// Serialize encodes the full record
func (r *Record) Serialize() ([]byte, error) {
	return json.Marshal(r)
}

// DeserializeRecord parses a serialized record
func DeserializeRecord(data []byte) (*Record, error) {
	var r Record
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("failed to deserialize record: %w", err)
	}
	return &r, nil
}

// IsExpired returns whether the record is past its TTL
func (r *Record) IsExpired() bool {
	return time.Since(r.Timestamp) > r.TTL
}

// Helper to prepare deterministic signing payload
func (r *Record) serializeForSigning() ([]byte, error) {
	type unsignedRecord struct {
		Domain    string        `json:"domain"`
		Value     string        `json:"value"`
		Timestamp time.Time     `json:"timestamp"`
		TTL       time.Duration `json:"ttl"`
	}
	unsigned := unsignedRecord{
		Domain:    r.Domain,
		Value:     r.Value,
		Timestamp: r.Timestamp,
		TTL:       r.TTL,
	}
	return json.Marshal(unsigned)
}
