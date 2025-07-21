package utils

import (
	"time"

	"github.com/ethereum/go-ethereum/common"
)

type Record interface {
	GetDomain() string
	GetSigner() common.Address
	GetNamehash() []byte
	GetSignedTx() []byte
	Verify() bool
}

type RecordStore interface {
	GetByNamehash(namehash []byte) (Record, bool)
}

type NameBoundEvent struct {
	Namehash  [32]byte       `json:"namehash"`
	Resolver  common.Address `json:"resolver"`
	ExpiresAt uint64         `json:"expires_at"`
	ChainID   uint64         `json:"chain_id"` // e.g. 1 for Ethereum mainnet
	EventID   string         `json:"event_id"` // e.g. block:logIndex or hash
	Timestamp time.Time      `json:"timestamp"`
}

type RecordMessage struct {
	Type       string          `json:"type"` // "update", "delete", "batch", "snapshot", "registration_intent", "registration_confirm", "registration_reject"
	Records    []Record        `json:"records,omitempty"`
	StateRoot  []byte          `json:"state_root,omitempty"`
	Version    int64           `json:"version"`
	Filter     []byte          `json:"filter,omitempty"` // Bloom filter for record existence
	BatchRange [2]int64        `json:"batch_range,omitempty"`
	PeerID     string          `json:"peer_id,omitempty"`
	Consensus  map[string]bool `json:"consensus,omitempty"`
	Timestamp  time.Time       `json:"timestamp,omitempty"`
	MessageID  string          `json:"message_id,omitempty"` // For deduplication
}

// type Node interface {
// 	handleRegistrationIntent(recordMsg RecordMessage)
// }

type GossipManager interface {
	PublishRecordMessage(msg RecordMessage) error
	PublishNameBound(evt NameBoundEvent) error
}
