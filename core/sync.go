// core/sync.go
package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/ipfs/go-datastore"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/peer"
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

		// // skip if node is publisher
		// if recordMsg.PeerID == n.getID() {
		// 	fmt.Println("publisher skipping self-published record")
		// 	continue
		// }

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

// StartSync starts the sync process
func (sm *SyncManager) StartSync() {
	sm.stateMutex.Lock()
	if sm.state.IsSyncing {
		sm.stateMutex.Unlock()
		return
	}
	sm.state.IsSyncing = true
	sm.stateMutex.Unlock()

	go sm.syncLoop()
}

// StopSync stops the sync process
func (sm *SyncManager) StopSync() {
	sm.stateMutex.Lock()
	sm.state.IsSyncing = false
	sm.stateMutex.Unlock()
}

// syncLoop is the main sync loop
func (sm *SyncManager) syncLoop() {
	for {
		sm.stateMutex.RLock()
		if !sm.state.IsSyncing {
			sm.stateMutex.RUnlock()
			return
		}
		sm.stateMutex.RUnlock()

		// Select peer with highest version
		peer, err := sm.selectSyncPeer()
		if err != nil {
			sm.log.WithError(err).Error("Failed to select sync peer")
			time.Sleep(5 * time.Second)
			continue
		}

		// Sync from selected peer
		if err := sm.syncFromPeer(peer); err != nil {
			sm.log.WithError(err).WithField("peer", peer).Error("Sync failed")
			time.Sleep(5 * time.Second)
			continue
		}

		// Update sync state
		sm.stateMutex.Lock()
		sm.state.LastSync = time.Now()
		sm.state.CurrentPeer = peer
		sm.stateMutex.Unlock()

		time.Sleep(30 * time.Second)
	}
}

// selectSyncPeer selects a peer with the highest version
func (sm *SyncManager) selectSyncPeer() (string, error) {
	peers := sm.store.dht.RoutingTable().ListPeers()
	if len(peers) == 0 {
		return "", fmt.Errorf("no peers available")
	}

	var highestVersion int64
	var selectedPeer string

	for _, p := range peers {
		version, err := sm.getPeerVersion(p)
		if err != nil {
			continue
		}

		if version > highestVersion {
			highestVersion = version
			selectedPeer = p.String()
		}
	}

	if selectedPeer == "" {
		return "", fmt.Errorf("no valid peers found")
	}

	return selectedPeer, nil
}

// getPeerVersion gets the version of a peer
func (sm *SyncManager) getPeerVersion(p peer.ID) (int64, error) {
	versionKey := "/store/version"
	data, err := sm.store.dht.GetValue(sm.store.ctx, versionKey)
	if err != nil {
		return 0, err
	}

	return int64(binary.BigEndian.Uint64(data)), nil
}

// syncFromPeer syncs records from a specific peer
func (sm *SyncManager) syncFromPeer(peerID string) error {
	// Get peer's version
	peerVersion, err := sm.getPeerVersion(peer.ID(peerID))
	if err != nil {
		return fmt.Errorf("failed to get peer version: %w", err)
	}

	// Get our version
	ourVersion, err := sm.store.GetStoreVersion()
	if err != nil {
		return fmt.Errorf("failed to get our version: %w", err)
	}

	// Only sync if peer has higher version
	if peerVersion <= ourVersion {
		return nil
	}

	// Get all records from peer
	records, err := sm.store.getAllRecordsFromPeer(peerID)
	if err != nil {
		return fmt.Errorf("failed to get records from peer: %w", err)
	}

	// Verify and store records
	for _, record := range records {
		if !record.Verify() {
			sm.log.WithField("domain", record.Domain).Error("Invalid record signature during sync")
			continue
		}

		// Store record
		data, err := record.Serialize()
		if err != nil {
			sm.log.WithError(err).WithField("domain", record.Domain).Error("Failed to serialize record during sync")
			continue
		}

		key := datastore.NewKey(makeRecordKey(record.Domain))
		if err := sm.store.db.Put(context.Background(), key, data); err != nil {
			sm.log.WithError(err).WithField("domain", record.Domain).Error("Failed to store record during sync")
			continue
		}
	}

	// Update our version
	sm.store.version = peerVersion
	versionData := make([]byte, 8)
	binary.BigEndian.PutUint64(versionData, uint64(sm.store.version))
	if err := sm.store.db.Put(context.Background(), datastore.NewKey("/store/version"), versionData); err != nil {
		return fmt.Errorf("failed to update store version after sync: %w", err)
	}

	return nil
}

// GetSyncState returns the current sync state
func (sm *SyncManager) GetSyncState() *SyncState {
	sm.stateMutex.RLock()
	defer sm.stateMutex.RUnlock()
	return sm.state
}
