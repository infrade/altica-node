// core/sync.go
package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/sirupsen/logrus"
)

const (
	RecordsTopic     = "altica-records"
	BatchSize        = 1000
	BloomFilterSize  = 100000
	SnapshotInterval = time.Minute * 1
)

// StateSnapshot represents a point-in-time state
type StateSnapshot struct {
	StateRoot []byte             `json:"state_root"`
	Timestamp time.Time          `json:"timestamp"`
	Version   int64              `json:"version"`
	Filter    *bloom.BloomFilter `json:"filter"`
}

// RecordMessage with version control
type RecordMessage struct {
	Type       string          `json:"type"` // "update", "delete", "batch", "snapshot", "registration_intent", "registration_confirm", "registration_reject"
	Records    []Record        `json:"records,omitempty"`
	StateRoot  []byte          `json:"state_root,omitempty"`
	Version    int64           `json:"version"`
	Filter     []byte          `json:"filter,omitempty"` // Bloom filter for record existence
	BatchRange [2]int64        `json:"batch_range,omitempty"`
	PeerID     string          `json:"peer_id,omitempty"`   // ID of the sending peer
	Consensus  map[string]bool `json:"consensus,omitempty"` // Map of peer IDs to their vote (true=confirm, false=reject)
}

// SyncState represents the current state of synchronization
type SyncState struct {
	Version     int64
	LastSync    time.Time
	IsSyncing   bool
	CurrentPeer string
}

// SyncManager manages the synchronization of records between peers
type SyncManager struct {
	store      *RecordStore
	state      *SyncState
	stateMutex sync.RWMutex
	log        *logrus.Logger
}

// NewSyncManager creates a new sync manager
func NewSyncManager(store *RecordStore) *SyncManager {
	return &SyncManager{
		store: store,
		state: &SyncState{
			Version:   0,
			LastSync:  time.Time{},
			IsSyncing: false,
		},
		log: logrus.New(),
	}
}

func (s *RecordStore) computeStateRoot() []byte {
	hash := sha256.New()
	records := s.List()

	// Sort records by domain for consistent hashing
	sort.Slice(records, func(i, j int) bool {
		return records[i].Domain < records[j].Domain
	})

	for _, record := range records {
		data, _ := record.Serialize()
		hash.Write(data)
	}

	return hash.Sum(nil)
}

func (n *Node) StartRecordSync() error {
	// Use the already joined records topic
	topic := n.RecordsTopic

	// Subscribe to the topic
	sub, err := topic.Subscribe()
	if err != nil {
		return err
	}

	// Handle incoming record updates
	go n.handleRecordUpdates(sub)

	// // Periodically sync our records to other peers
	// go n.periodicRecordSync(topic)

	return nil
}

func (n *Node) handleRecordUpdates(sub *pubsub.Subscription) {
	fmt.Println("Listening for record updates...")
	for {
		msg, err := sub.Next(n.Context)
		fmt.Println("Receiving record update...")
		if err != nil {
			n.log.WithError(err).Error("Failed to read update")
			continue
		}
		fmt.Println("!Receiving record update...")

		var recordMsg RecordMessage
		if err := json.Unmarshal(msg.Data, &recordMsg); err != nil {
			n.log.WithError(err).Error("Failed to unmarshal record message")
			continue
		}
		fmt.Println("successfully unmarshalled", recordMsg.Version, n.Store.GetCurrentVersion())

		// Check if we need this update based on version and state root
		for _, record := range recordMsg.Records {
			if existingRecord, err := n.Store.GetLatestRecord(record.Domain); err == nil {
				if existingRecord.Version >= record.Version {
					n.log.WithFields(logrus.Fields{
						"domain":         record.Domain,
						"local_version":  existingRecord.Version,
						"remote_version": record.Version,
					}).Debug("Ignoring outdated record update")
					continue
				}
			}
			fmt.Println("Processing record update:", record.Version, record.Domain)
		}

		switch recordMsg.Type {
		case "snapshot":
			// Fast sync if we're far behind
			if recordMsg.Version > n.Store.GetCurrentVersion()+1000 {
				n.syncFromSnapshot(recordMsg)
			}
		case "registration_intent":
			// Each peer votes on the record
			n.handleRegistrationIntent(recordMsg)
		case "vote":
			continue
		case "batch":
			fmt.Println("Processing batch update")
			// Check bloom filter first
			filter := bloom.New(BloomFilterSize, 5)
			if err := filter.UnmarshalBinary(recordMsg.Filter); err != nil {
				n.log.WithError(err).Error("Failed to unmarshal bloom filter")
				continue
			}

			needsUpdate := false
			for _, record := range recordMsg.Records {
				if !filter.Test([]byte(record.Domain)) {
					needsUpdate = true
					break
				}
			}
			fmt.Println("Needs update:", needsUpdate)

			if !needsUpdate {
				continue
			}

			// Process batch
			for _, record := range recordMsg.Records {
				if record.Verify() {
					n.Store.Add(&record)
				}
			}

			// Verify state after batch
			if bytes.Equal(n.Store.computeStateRoot(), recordMsg.StateRoot) {
				// Update the version through accessor method
				for n.Store.GetCurrentVersion() < recordMsg.Version {
					n.Store.IncrementVersion()
				}
			}
		}
	}
}

// PublishRecord publishes a record update to the network
func (n *Node) PublishRecord(record *Record) error {
	topic := n.RecordsTopic

	msg := RecordMessage{
		Type:      "registration_intent",
		Records:   []Record{*record},
		Version:   record.Version,
		StateRoot: n.Store.computeStateRoot(),
		PeerID:    n.getID(),
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	return topic.Publish(n.Context, data)
}

func (n *Node) syncFromSnapshot(msg RecordMessage) error {
	// Verify snapshot integrity
	if !bytes.Equal(msg.StateRoot, n.Store.computeStateRoot()) {
		return fmt.Errorf("invalid state root")
	}

	// Update filter if provided
	if len(msg.Filter) > 0 {
		filter := bloom.New(BloomFilterSize, 5)
		if err := filter.UnmarshalBinary(msg.Filter); err != nil {
			return fmt.Errorf("failed to unmarshal filter: %w", err)
		}
		n.Store.filter = filter
	}

	// Update version through accessor method
	for n.Store.GetCurrentVersion() < msg.Version {
		n.Store.IncrementVersion()
	}
	return nil
}

func (n *Node) publishSnapshot(topic *pubsub.Topic, snapshot StateSnapshot) error {
	// This function is called with a topic argument, but we want to use n.RecordsTopic
	topic = n.RecordsTopic
	var mfilter []byte
	if snapshot.Filter == nil {
		// Initialize empty filter if none exists
		snapshot.Filter = bloom.New(BloomFilterSize, 5)
	}
	var err error
	mfilter, err = snapshot.Filter.MarshalBinary()
	if err != nil {
		n.log.WithError(err).Error("Failed to marshal bloom filter")
		return err
	}
	msg := RecordMessage{
		Type:      "snapshot",
		StateRoot: snapshot.StateRoot,
		Version:   snapshot.Version,
		Filter:    mfilter,
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	return topic.Publish(n.Context, data)
}

func (n *Node) publishBatch(topic *pubsub.Topic, msg RecordMessage) error {
	topic = n.RecordsTopic
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	return topic.Publish(n.Context, data)
}

func (n *Node) handleRegistrationIntent(msg RecordMessage) {
	for _, entry := range msg.Records {
		// Each peer validates the record
		accept := false
		record, found := n.Store.Get(entry.Domain)
		if !found {
			n.log.Error("record not found")
		} else if record.Status != "pending" {
			n.log.Error("Record is not pending")
		} else if !record.Verify() {
			n.log.Error("Invalid record signature")
		} else {
			accept = true
		}

		// Submit vote using voting manager
		if n.Store.votingManager != nil {
			if err := n.Store.votingManager.SubmitVote(record.Domain, accept); err != nil {
				n.log.WithError(err).Error("Failed to submit vote")
			}
		}
	}
}
