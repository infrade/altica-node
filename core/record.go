package core

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Record represents a robust, extensible DNS record that can support multi-chain, multi-use-case mappings.
type Record struct {
	Domain    string                 `json:"domain"`   // The domain name (e.g., 'sorxcode')
	Mappings  map[string]interface{} `json:"mappings"` // Arbitrary key-value pairs: chain names, DNS types, etc.
	TTL       time.Duration          `json:"ttl"`
	Signature []byte                 `json:"signature"`
	PublicKey []byte                 `json:"public_key"`
	Version   int64                  `json:"version"`
	Status    string                 `json:"status"`             // 'pending', 'confirmed', 'rejected'
	LockID    string                 `json:"lock_id,omitempty"`  // For distributed locking
	Metadata  map[string]interface{} `json:"metadata,omitempty"` // For future extensibility (e.g., owner, timestamps, etc.)
}

// NewRecord creates a new unsigned record
func NewRecord(domain string, ttl time.Duration, signature []byte, pubKey []byte) (*Record, error) {
	record := &Record{
		Domain:    domain,
		Mappings:  make(map[string]interface{}),
		TTL:       ttl,
		Signature: signature,
		PublicKey: pubKey,
		Metadata:  make(map[string]interface{}),
	}
	if !record.Verify() {
		return nil, fmt.Errorf("Record verification failed")
	}
	record.Metadata["created_at"] = time.Now().UTC().Format(time.RFC3339)
	return record, nil
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

// IsExpired returns whether the record is past its TTL based on Metadata["created_at"]
func (r *Record) IsExpired() bool {
	createdRaw, ok := r.Metadata["created_at"]
	if !ok {
		return false
	}
	var createdAt time.Time
	switch v := createdRaw.(type) {
	case time.Time:
		createdAt = v
	case string:
		parsed, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return false
		}
		createdAt = parsed
	default:
		return false
	}
	return time.Since(createdAt) > r.TTL
}

// Helper to prepare deterministic signing payload
func (r *Record) serializeForSigning() ([]byte, error) {
	type unsignedRecord struct {
		Domain string        `json:"domain"`
		TTL    time.Duration `json:"ttl"`
	}
	unsigned := unsignedRecord{
		Domain: r.Domain,
		TTL:    r.TTL,
	}
	return json.Marshal(unsigned)
}

// MarshalJSON customizes JSON output for Record to encode Signature and PublicKey as hex strings
func (r *Record) MarshalJSON() ([]byte, error) {
	type Alias Record
	return json.Marshal(&struct {
		Signature string `json:"signature,omitempty"`
		PublicKey string `json:"public_key,omitempty"`
		*Alias
	}{
		Signature: hex.EncodeToString(r.Signature),
		PublicKey: hex.EncodeToString(r.PublicKey),
		Alias:     (*Alias)(r),
	})
}

// UnmarshalJSON customizes JSON input for Record to decode Signature and PublicKey from hex strings
func (r *Record) UnmarshalJSON(data []byte) error {
	type Alias Record
	temp := &struct {
		Signature string `json:"signature,omitempty"`
		PublicKey string `json:"public_key,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}
	if temp.Signature != "" {
		b, err := hex.DecodeString(temp.Signature)
		if err != nil {
			return err
		}
		r.Signature = b
	}
	if temp.PublicKey != "" {
		b, err := hex.DecodeString(temp.PublicKey)
		if err != nil {
			return err
		}
		r.PublicKey = b
	}
	return nil
}
