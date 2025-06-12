package core

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Record represents a robust, extensible DNS record that can support multi-chain, multi-use-case mappings.
type Record struct {
	Domain    string                   `json:"domain"`
	Mappings  map[string]interface{}   `json:"mappings"`           // Flexible mapping structure
	TTL       time.Duration            `json:"ttl"`                // Time-to-live for the record
	Signature []byte                   `json:"signature"`          // ECDSA signature
	PublicKey []byte                   `json:"public_key"`         // secp256k1 public key
	Version   int64                    `json:"version"`            // Current version number
	Status    string                   `json:"status"`             // Record status (active, locked, etc.)
	LockID    string                   `json:"lock_id,omitempty"`  // ID of the lock if locked
	Metadata  map[string]interface{}   `json:"metadata"`           // Additional metadata
	Versions  map[string]RecordVersion `json:"versions,omitempty"` // peerID -> version
	Latest    RecordVersion            `json:"latest,omitempty"`   // Latest version info
	Signer    string                   `json:"signer"`             // EVM-like address of the signer
}

// RecordVersion represents a version of a record
type RecordVersion struct {
	Version   uint64 `json:"version"`
	Timestamp int64  `json:"timestamp"`
	PeerID    string `json:"peer_id"`
	Hash      string `json:"hash"` // Hash of the record content
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

	// Initialize versioning
	record.Versions = make(map[string]RecordVersion)
	record.Metadata["created_at"] = time.Now().UTC().Format(time.RFC3339)

	if !record.Verify() {
		return nil, fmt.Errorf("Record verification failed")
	}
	record.Metadata["created_at"] = time.Now().UTC().Format(time.RFC3339)
	return record, nil
}

// Sign signs the record with the provided private key
func (r *Record) Sign(privateKey *ecdsa.PrivateKey) error {
	data, err := r.serializeForSigning()
	if err != nil {
		return err
	}

	// Hash the data using Keccak256 (same as Ethereum)
	hash := crypto.Keccak256(data)

	// Sign the hash
	signature, err := crypto.Sign(hash, privateKey)
	if err != nil {
		return fmt.Errorf("failed to sign record: %w", err)
	}

	r.Signature = signature
	r.PublicKey = crypto.FromECDSAPub(&privateKey.PublicKey)

	// Set the signer address
	r.Signer = crypto.PubkeyToAddress(privateKey.PublicKey).Hex()

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

	// Hash the data using Keccak256
	hash := crypto.Keccak256(data)

	// Recover the public key from the signature
	pubKey, err := crypto.SigToPub(hash, r.Signature)
	if err != nil {
		return false
	}

	// Compare the recovered public key with the stored one
	recoveredPubKeyBytes := crypto.FromECDSAPub(pubKey)
	return hex.EncodeToString(recoveredPubKeyBytes) == hex.EncodeToString(r.PublicKey)
}

// GetSignerAddress returns the Ethereum address of the signer
func (r *Record) GetSignerAddress() (common.Address, error) {
	if r.Signer != "" {
		return common.HexToAddress(r.Signer), nil
	}

	// If Signer is not set, derive it from the public key
	pubKey, err := crypto.UnmarshalPubkey(r.PublicKey)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	return crypto.PubkeyToAddress(*pubKey), nil
}

// Serialize serializes the record to bytes
func (r *Record) Serialize() ([]byte, error) {
	return json.Marshal(r)
}

// DeserializeRecord deserializes bytes into a Record
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
