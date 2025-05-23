// core/sync.go
package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
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

	// Periodically sync our records to other peers
	go n.periodicRecordSync(topic)

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
		if recordMsg.Version <= n.Store.GetCurrentVersion() {
			n.log.WithField("version", recordMsg.Version).Debug("Ignoring outdated record update")
			continue
		}
		fmt.Println("Processing record update:", recordMsg.Version)

		switch recordMsg.Type {
		case "snapshot":
			// Fast sync if we're far behind
			if recordMsg.Version > n.Store.GetCurrentVersion()+1000 {
				n.syncFromSnapshot(recordMsg)
			}

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

func (n *Node) periodicRecordSync(topic *pubsub.Topic) {
	syncTicker := time.NewTicker(time.Second * 10)
	snapshotTicker := time.NewTicker(SnapshotInterval)
	defer syncTicker.Stop()
	defer snapshotTicker.Stop()

	for {
		select {
		case <-n.Context.Done():
			fmt.Println("Context done, stopping periodic sync")
			return

		case <-snapshotTicker.C:
			// Create and publish state snapshot
			fmt.Println("Creating snapshot")
			filter := n.Store.filter
			if filter == nil {
				filter = bloom.New(BloomFilterSize, 5)
				n.Store.filter = filter
			}
			snapshot := StateSnapshot{
				StateRoot: n.Store.computeStateRoot(),
				Timestamp: time.Now(),
				Version:   n.Store.GetCurrentVersion(),
				Filter:    filter,
			}

			if err := n.publishSnapshot(topic, snapshot); err != nil {
				n.log.WithError(err).Error("Failed to publish snapshot")
			}

		case <-syncTicker.C:
			fmt.Println("Syncing records")
			// Regular sync with optimizations
			newRecords, err := n.Store.ListModifiedSince(n.lastSync)
			if err != nil {
				n.log.WithError(err).Error("Failed to list modified records")
				continue
			}
			fmt.Println("New records to sync:", len(newRecords))
			if len(newRecords) == 0 {
				continue
			}

			// Create bloom filter for this batch
			filter := bloom.New(BloomFilterSize, 5)
			for _, record := range newRecords {
				filter.Add([]byte(record.Domain))
			}

			// Send records in optimized batches
			for i := 0; i < len(newRecords); i += BatchSize {
				end := i + BatchSize
				if end > len(newRecords) {
					end = len(newRecords)
				}

				batch := newRecords[i:end]
				mfilter, err := filter.MarshalBinary()
				if err != nil {
					n.log.WithError(err).Error("Failed to marshal bloom filter")
					continue
				}
				// Convert []*Record to []Record
				records := make([]Record, len(batch))
				for j, rec := range batch {
					records[j] = *rec
				}
				msg := RecordMessage{
					Type:       "batch",
					Records:    records,
					StateRoot:  n.Store.computeStateRoot(),
					Version:    n.Store.GetCurrentVersion(),
					Filter:     mfilter,
					BatchRange: [2]int64{int64(i), int64(end)},
				}

				// Compress and publish
				if err := n.publishBatch(topic, msg); err != nil {
					n.log.WithError(err).Error("Failed to publish batch")
				}

				// Exponential backoff between batches
				time.Sleep(time.Millisecond * 100 * time.Duration(1<<uint(i/BatchSize)))
			}
			// Update last sync time after successful batch sync
			now := time.Now()
			n.lastSync = now
			if err := n.Store.SetLastSyncTime(now); err != nil {
				n.log.WithError(err).Error("Failed to save last sync time")
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

// func (n *Node) handleRegistrationIntent(msg RecordMessage) {
// 	for _, record := range msg.Records {
// 		// Verify the record
// 		if !record.Verify() {
// 			n.log.Error("Invalid record signature")
// 			continue
// 		}

// 		// Check if we already have this record
// 		if !n.Store.IsDomainAvailable(record.Domain) {
// 			n.publishRegistrationReject(record)
// 			continue
// 		}

// 		// Try to acquire the lock
// 		lockID, acquired := n.Store.TryAcquireLock(record.Domain)
// 		if !acquired {
// 			n.publishRegistrationReject(record)
// 			continue
// 		}

// 		// Add to pending records
// 		record.LockID = lockID
// 		if err := n.Store.Add(&record); err != nil {
// 			n.Store.ReleaseLock(record.Domain, lockID)
// 			n.publishRegistrationReject(record)
// 			continue
// 		}

// 		// Initialize consensus tracking
// 		msg.Consensus = make(map[string]bool)
// 		msg.Consensus[n.Host.ID().String()] = true

// 		// Publish confirmation
// 		n.publishRegistrationConfirm(record)
// 	}
// }

// func (n *Node) publishRegistrationConfirm(record Record) error {
// 	topic := n.RecordsTopic

// 	msg := RecordMessage{
// 		Type:      "registration_confirm",
// 		Records:   []Record{record},
// 		Version:   record.Version,
// 		StateRoot: n.Store.computeStateRoot(),
// 	}

// 	data, err := json.Marshal(msg)
// 	if err != nil {
// 		return err
// 	}

// 	return topic.Publish(n.Context, data)
// }

// func (n *Node) publishRegistrationReject(record Record) error {
// 	topic := n.RecordsTopic

// 	msg := RecordMessage{
// 		Type:      "registration_reject",
// 		Records:   []Record{record},
// 		Version:   record.Version,
// 		StateRoot: n.Store.computeStateRoot(),
// 	}

// 	data, err := json.Marshal(msg)
// 	if err != nil {
// 		return err
// 	}

// 	return topic.Publish(n.Context, data)
// }
