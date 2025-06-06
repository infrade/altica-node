package core

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"strings"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/ipfs/go-datastore"
	"github.com/ipfs/go-datastore/query"
	leveldb "github.com/ipfs/go-ds-leveldb"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/routing"
	"github.com/sirupsen/logrus"
)

type PendingRecord struct {
	Record *Record
}

type RecordStore struct {
	db             *leveldb.Datastore
	dht            *dht.IpfsDHT
	ctx            context.Context
	hostID         string
	log            *logrus.Logger
	pendingLocks   map[string]string // domain -> lockID
	lockMutex      sync.RWMutex
	recordsMutex   sync.RWMutex       // For operations on confirmed records
	version        int64              // Current version number
	filter         *bloom.BloomFilter // Bloom filter for fast lookups
	votingManager  *VotingManager     // Added for voting functionality
	privKey        kyber.Scalar       // Node's private key for voting
	pendingRecords map[string]*Record // Local cache of pending records
	pendingMutex   sync.RWMutex       // Mutex for pending records
	syncManager    *SyncManager       // Sync manager for record synchronization
}

// convertCryptoPrivKeyToKyber converts a crypto private key to a Kyber scalar
func convertCryptoPrivKeyToKyber(privKey crypto.PrivKey) (kyber.Scalar, error) {
	if privKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}

	// Get the raw private key bytes
	rawKey, err := privKey.Raw()
	if err != nil {
		return nil, fmt.Errorf("failed to get raw private key: %w", err)
	}

	// Create a new Kyber suite with proper initialization
	suite := bn256.NewSuiteG2()

	// Create a new scalar
	scalar := suite.Scalar()

	// Convert the raw key bytes to a scalar
	// We need to ensure the bytes are the right length for the scalar
	keyBytes := make([]byte, scalar.MarshalSize())
	copy(keyBytes, rawKey)

	// Unmarshal the bytes into the scalar
	if err := scalar.UnmarshalBinary(keyBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
	}

	return scalar, nil
}

// NewRecordStore creates a new record store
func NewRecordStore(db *leveldb.Datastore, dht *dht.IpfsDHT, ctx context.Context, hostID string, privKey crypto.PrivKey) *RecordStore {
	// Convert libp2p private key to Kyber scalar
	kyberPrivKey, err := convertCryptoPrivKeyToKyber(privKey)
	if err != nil {
		// Log error but continue with nil voting manager
		logrus.WithError(err).Error("Failed to convert private key for voting")
	}

	store := &RecordStore{
		db:             db,
		dht:            dht,
		ctx:            ctx,
		hostID:         hostID,
		log:            logrus.New(),
		pendingLocks:   make(map[string]string),
		version:        0,
		pendingRecords: make(map[string]*Record),
	}

	// Initialize voting manager with converted private key
	if kyberPrivKey != nil {
		votingManager, err := NewVotingManager(store, kyberPrivKey)
		if err != nil {
			store.log.WithError(err).Error("Failed to initialize voting manager")
		} else {
			store.votingManager = votingManager
		}
	}

	// Initialize sync manager
	store.syncManager = NewSyncManager(store)
	store.syncManager.StartSync()

	// Start periodic sync of pending records
	store.StartSync(30 * time.Second) // Sync every 30 seconds

	// Initial sync from highest version peer
	go func() {
		// Wait for DHT to be ready
		time.Sleep(5 * time.Second)

		// Get all peers
		peers := store.dht.RoutingTable().ListPeers()
		if len(peers) == 0 {
			return
		}

		// Find peer with highest version
		var highestVersion int64
		var highestVersionPeer string
		for _, peer := range peers {
			versionKey := "/store/version"
			data, err := store.dht.GetValue(store.ctx, versionKey)
			if err != nil {
				continue
			}
			version := int64(binary.BigEndian.Uint64(data))
			if version > highestVersion {
				highestVersion = version
				highestVersionPeer = peer.String()
			}
		}

		// Sync from highest version peer
		if highestVersionPeer != "" {
			if err := store.SyncFromPeer(highestVersionPeer); err != nil {
				store.log.WithError(err).Error("Failed to sync from highest version peer")
			}
		}
	}()

	return store
}

// will try to get domain from localstore, and dht.
func (s *RecordStore) Get(domain string) (*Record, bool) {
	s.lockMutex.RLock()
	defer s.lockMutex.RUnlock()

	// First check local database
	key := datastore.NewKey(makeRecordKey(domain))
	data, err := s.db.Get(context.Background(), key)
	if err == nil && data != nil {
		record, err := DeserializeRecord(data)
		if err == nil && record != nil {
			return record, true
		}
	}

	// If not found locally, check pending records
	pending, err := s.GetPendingRecordFromDHT(domain)
	if err == nil && pending != nil && pending.Record != nil {
		return pending.Record, true
	}

	// If still not found, try getting latest from DHT
	record, err := s.GetLatestRecord(domain)
	if err == nil && record != nil {
		return record, true
	}

	return nil, false
}

const (
	// Use a custom namespace for our lock records to avoid IPNS validation
	lockNamespace   = "/altica/locks" // Custom DHT namespace for Altica locks
	indexKey        = "_index"
	recordNamespace = "/altica/records" // Custom DHT namespace for Altica records
)

// makeLockKey creates a valid DHT key for locks in the custom namespace
func makeLockKey(domain string) string {
	return fmt.Sprintf("%s/%s", lockNamespace, strings.ToLower(domain))
}

// IsLockValid checks if a lock is still valid in the DHT
func (s *RecordStore) IsLockValid(domain, lockID string) bool {
	lockKey := makeLockKey(domain)
	storedValue, err := s.dht.GetValue(s.ctx, lockKey)
	return err == nil && string(storedValue) == lockID
}

// TryAcquireLock attempts to acquire a distributed lock for a domain using DHT
func (s *RecordStore) TryAcquireLock(domain string) (string, bool) {
	s.lockMutex.Lock()
	defer s.lockMutex.Unlock()

	// Create DHT key with proper namespace and encoding
	lockKey := makeLockKey(domain)
	lockID := fmt.Sprintf("%s-%d", s.hostID, time.Now().UnixNano())

	// First check if a lock already exists
	existingValue, err := s.dht.GetValue(s.ctx, lockKey)
	if err == nil && len(existingValue) > 0 {
		// Lock already exists
		return "", false
	}

	// Attempt to put our lock value
	if err := s.dht.PutValue(s.ctx, lockKey, []byte(lockID)); err != nil {
		s.log.WithError(err).WithFields(logrus.Fields{
			"domain":  domain,
			"lockKey": lockKey,
		}).Error("Failed to acquire DHT lock")
		return "", false
	}

	// Verify we got the lock by reading it back
	if !s.IsLockValid(domain, lockID) {
		s.log.WithFields(logrus.Fields{
			"domain":   domain,
			"lockKey":  lockKey,
			"expected": lockID,
		}).Error("Lock verification failed - value mismatch")
		return "", false
	}
	// Store locally as well
	s.pendingLocks[domain] = lockID
	return lockID, true
}

// ReleaseLock releases a domain lock from both local store and DHT
func (s *RecordStore) ReleaseLock(domain, lockID string) bool {
	s.lockMutex.Lock()
	defer s.lockMutex.Unlock()

	lockKey := makeLockKey(domain)

	// Check if we own the lock
	if !s.IsLockValid(domain, lockID) {
		return false
	}

	// Remove from DHT
	_ = s.dht.PutValue(s.ctx, lockKey, []byte{})

	// Remove from local store
	if currentLockID, exists := s.pendingLocks[domain]; exists && currentLockID == lockID {
		delete(s.pendingLocks, domain)
		return true
	}
	return false
}

// Add adds a new record with transaction validation
func (s *RecordStore) Add(record *Record) error {

	// Check for existing records first
	if _, found := s.Get(record.Domain); found {
		return fmt.Errorf("record already exists")
	}

	// Try to acquire a lock
	lockID, acquired := s.TryAcquireLock(record.Domain)
	if !acquired {
		return fmt.Errorf("domain is currently locked for registration")
	}

	// Add to DHT as pending record
	record.Status = "pending"
	record.LockID = lockID

	if err := s.SavePendingRecordToDHT(PendingRecord{Record: record}); err != nil {
		s.ReleaseLock(record.Domain, lockID)
		return fmt.Errorf("Failed to save as pending records to dht: %w", err)
	}

	// Submit vote for the record
	if s.votingManager != nil {
		if err := s.votingManager.SubmitVote(record.Domain, true); err != nil {
			s.ReleaseLock(record.Domain, lockID)
			return fmt.Errorf("failed to submit vote: %w", err)
		}
	}

	// Add to local pending records cache
	s.pendingMutex.Lock()
	s.pendingRecords[record.Domain] = record
	s.pendingMutex.Unlock()

	// Return immediately, actual registration will happen after consensus
	return nil
}

// DHT key for pending records
func makePendingKey(domain string) string {
	return fmt.Sprintf("/altica/pending/%s", strings.ToLower(domain))
}

// SavePendingRecordToDHT saves a pending record to DHT and updates the index
func (s *RecordStore) SavePendingRecordToDHT(record PendingRecord) error {
	// First acquire lock on the index

	lockID, acquired := s.TryAcquireLock(indexKey)
	if !acquired {
		return fmt.Errorf("failed to acquire lock for pending index")
	}
	defer s.ReleaseLock(indexKey, lockID)

	// Get current index
	domains, ok := s.GetPendingDomains()
	if !ok {
		s.log.WithField("domains", domains).Info("No pending record found")
	}

	// Add domain to index if not present
	found := false
	for _, d := range domains {
		if d == record.Record.Domain {
			found = true
			break
		}
	}
	if !found {
		domains = append(domains, record.Record.Domain)
		// Update index
		domains_, err := json.Marshal(domains)
		if err != nil {
			return fmt.Errorf("failed to marshal pending index: %w", err)
		}
		if err := s.dht.PutValue(s.ctx, makePendingKey(indexKey), domains_); err != nil {
			return fmt.Errorf("failed to update pending index: %w", err)
		}
	}

	// Save the actual record
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	key := makePendingKey(record.Record.Domain)
	return s.dht.PutValue(s.ctx, key, data)
}

// GetPendingRecordFromDHT gets a pending record from DHT
func (s *RecordStore) GetPendingRecordFromDHT(domain string) (*PendingRecord, error) {
	// First try to get from our local cache
	s.pendingMutex.RLock()
	if record, exists := s.pendingRecords[domain]; exists {
		s.pendingMutex.RUnlock()
		return &PendingRecord{Record: record}, nil
	}
	s.pendingMutex.RUnlock()

	// If not in cache, query DHT
	key := makePendingKey(domain)
	data, err := s.dht.GetValue(s.ctx, key)
	if err != nil {
		if errors.Is(err, routing.ErrNotFound) {
			return nil, err
		}
		s.log.WithError(err).WithField("domain", domain).Error("Failed to get pending record from DHT")
		return nil, err
	}

	var pending PendingRecord
	if err := json.Unmarshal(data, &pending); err != nil {
		s.log.WithError(err).Error("Failed to unmarshal pending record")
		return nil, err
	}

	if pending.Record != nil {
		// Add to local cache
		s.pendingMutex.Lock()
		s.pendingRecords[domain] = pending.Record
		s.pendingMutex.Unlock()
		return &pending, nil
	}

	return nil, routing.ErrNotFound
}

func (s *RecordStore) GetPendingDomains() ([]string, bool) {
	indexData, err := s.dht.GetValue(s.ctx, makePendingKey(indexKey))
	if err != nil {
		if !errors.Is(err, routing.ErrNotFound) {
			s.log.WithError(err).Error("Failed to get pending records index")
		}
		return nil, false
	}
	if indexData == nil {
		return nil, false
	}
	var domains []string
	if err := json.Unmarshal(indexData, &domains); err != nil {
		s.log.WithError(err).Error("Failed to unmarshal pending records index")
		return nil, false
	}
	return domains, true

}

// OnlineNodes returns all online peers excluding bootstrap nodes
func (s *RecordStore) OnlineNodes() []peer.ID {
	allPeers := s.dht.RoutingTable().ListPeers()
	var filteredPeers []peer.ID

	// Filter out bootstrap nodes
	for _, peer := range allPeers {
		isBootstrap := false
		for _, bootstrapAddr := range bootstrapPeers {
			if strings.Contains(bootstrapAddr, peer.String()) {
				isBootstrap = true
				break
			}
		}
		if !isBootstrap {
			filteredPeers = append(filteredPeers, peer)
		}
	}

	return filteredPeers
}

func (s *RecordStore) OnlineNodesCount() int {
	return len(s.OnlineNodes())
}

// UpdateRecord updates a record with versioning
func (rs *RecordStore) UpdateRecord(domain string, content []byte) error {
	rs.recordsMutex.Lock()
	defer rs.recordsMutex.Unlock()

	// Get existing record
	record, err := rs.GetRecord(domain)
	if err != nil && !errors.Is(err, routing.ErrNotFound) {
		return err
	}

	// Calculate content hash
	hash := sha256.Sum256(content)
	hashStr := hex.EncodeToString(hash[:])

	// Create or update record
	if record == nil {
		record = &Record{
			Domain:   domain,
			Mappings: make(map[string]interface{}),
			TTL:      time.Hour * 24, // Default TTL
			Metadata: make(map[string]interface{}),
			Versions: make(map[string]RecordVersion),
		}
	}

	// Update content in mappings
	record.Mappings["content"] = content
	record.Metadata["updated_at"] = time.Now().UTC().Format(time.RFC3339)

	// Update version
	version := RecordVersion{
		Version:   uint64(record.Version + 1),
		Timestamp: time.Now().UnixNano(),
		PeerID:    rs.hostID,
		Hash:      hashStr,
	}

	// Update versions
	if record.Versions == nil {
		record.Versions = make(map[string]RecordVersion)
	}
	record.Versions[rs.hostID] = version
	record.Latest = version
	record.Version = int64(version.Version)

	// Save record
	key := makeRecordKey(domain)
	data, err := record.Serialize()
	if err != nil {
		return err
	}
	if err := rs.dht.PutValue(rs.ctx, key, data); err != nil {
		return err
	}

	// Save metadata separately for quick version checks
	metadataKey := makeMetadataKey(domain)
	metadataData, err := json.Marshal(map[string]interface{}{
		"latest":   version,
		"versions": record.Versions,
	})
	if err != nil {
		return err
	}
	return rs.dht.PutValue(rs.ctx, metadataKey, metadataData)
}

// GetRecord retrieves a record with version checking
func (rs *RecordStore) GetRecord(domain string) (*Record, error) {
	// First get metadata to check versions
	metadataKey := makeMetadataKey(domain)
	metadataData, err := rs.dht.GetValue(rs.ctx, metadataKey)
	if err != nil && !errors.Is(err, routing.ErrNotFound) {
		return nil, err
	}

	var metadata struct {
		Latest   RecordVersion            `json:"latest"`
		Versions map[string]RecordVersion `json:"versions"`
	}
	if metadataData != nil {
		if err := json.Unmarshal(metadataData, &metadata); err != nil {
			return nil, err
		}
	}

	// Get full record
	key := makeRecordKey(domain)
	data, err := rs.dht.GetValue(rs.ctx, key)
	if err != nil {
		return nil, err
	}

	record, err := DeserializeRecord(data)
	if err != nil {
		return nil, err
	}

	// If we have metadata, check if we need to sync
	if metadataData != nil {
		localVersion := record.Versions[rs.hostID]
		if metadata.Latest.Timestamp > localVersion.Timestamp {
			// We have a newer version, trigger sync
			go rs.syncRecord(domain, metadata.Latest.PeerID)
		}
	}

	return record, nil
}

// syncRecord syncs a record from a specific peer
func (rs *RecordStore) syncRecord(domain, peerID string) error {
	// Get record from peer
	key := makeRecordKey(domain)
	data, err := rs.dht.GetValue(rs.ctx, key)
	if err != nil {
		return err
	}

	record, err := DeserializeRecord(data)
	if err != nil {
		return err
	}

	// Verify hash
	content, ok := record.Mappings["content"].([]byte)
	if !ok {
		return fmt.Errorf("record content not found")
	}
	hash := sha256.Sum256(content)
	hashStr := hex.EncodeToString(hash[:])
	if hashStr != record.Latest.Hash {
		return fmt.Errorf("record hash mismatch")
	}

	// Update local record
	return rs.UpdateRecord(domain, content)
}

// GetLatestVersion gets the latest version information for a record
func (rs *RecordStore) GetLatestVersion(domain string) (*RecordVersion, error) {
	metadataKey := makeMetadataKey(domain)
	data, err := rs.dht.GetValue(rs.ctx, metadataKey)
	if err != nil {
		return nil, err
	}

	var metadata struct {
		Latest RecordVersion `json:"latest"`
	}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, err
	}

	return &metadata.Latest, nil
}

// GetLatestRecord gets the latest version of a record from the peer with the most recent version
func (rs *RecordStore) GetLatestRecord(domain string) (*Record, error) {
	metadata, err := rs.GetLatestVersion(domain)
	if err != nil {
		return nil, err
	}

	// Get record from peer with latest version
	key := makeRecordKey(domain)
	data, err := rs.dht.GetValue(rs.ctx, key)
	if err != nil {
		return nil, err
	}

	record, err := DeserializeRecord(data)
	if err != nil {
		return nil, err
	}

	// Verify hash
	content, ok := record.Mappings["content"].([]byte)
	if !ok {
		return nil, fmt.Errorf("record content not found")
	}
	hash := sha256.Sum256(content)
	hashStr := hex.EncodeToString(hash[:])
	if hashStr != metadata.Hash {
		return nil, fmt.Errorf("record hash mismatch")
	}

	return record, nil
}

// makeRecordKey creates a DHT key for a record
func makeRecordKey(domain string) string {
	return fmt.Sprintf("%s/%s", recordNamespace, domain)
}

// makeMetadataKey creates a DHT key for record metadata
func makeMetadataKey(domain string) string {
	return fmt.Sprintf("%s/%s/metadata", recordNamespace, domain)
}

// GetVoteResult retrieves vote result for a domain
func (s *RecordStore) GetVoteResult(domain string) (*VoteResult, error) {
	if s.votingManager == nil {
		return nil, fmt.Errorf("voting manager not initialized")
	}
	return s.votingManager.getVoteResult(domain)
}

// syncPendingRecords syncs pending records from DHT using the index
func (s *RecordStore) syncPendingRecords() {
	// Get the index of pending domains
	domains, ok := s.GetPendingDomains()
	if !ok {
		s.log.WithField("domains", domains).Info("No pending record found")
		return
	}

	// Get each pending record
	for _, domain := range domains {
		key := makePendingKey(domain)
		data, err := s.dht.GetValue(s.ctx, key)
		if err != nil {
			if !errors.Is(err, routing.ErrNotFound) {
				s.log.WithError(err).WithField("domain", domain).Error("Failed to get pending record")
				if s.pendingRecords[domain] == nil {
					continue
				}
				s.pendingMutex.Lock()
				delete(s.pendingRecords, domain)
				s.pendingMutex.Unlock()
			}
			continue
		}
		var pending PendingRecord
		if err := json.Unmarshal(data, &pending); err != nil {
			s.log.WithError(err).Error("Failed to unmarshal pending record")
			continue
		}

		if pending.Record != nil {
			// Add to local cache if not already present
			s.pendingMutex.Lock()
			if _, exists := s.pendingRecords[pending.Record.Domain]; !exists {
				s.pendingRecords[pending.Record.Domain] = pending.Record
			}
			s.pendingMutex.Unlock()
		}
	}
}

// StartSync starts periodic sync of pending records
func (s *RecordStore) StartSync(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.syncPendingRecords()
			case <-s.ctx.Done():
				return
			}
		}
	}()
}

// GetStoreVersion returns the current version of the store
func (s *RecordStore) GetStoreVersion() (int64, error) {
	s.recordsMutex.RLock()
	defer s.recordsMutex.RUnlock()

	versionKey := datastore.NewKey("/store/version")
	data, err := s.db.Get(context.Background(), versionKey)
	if err != nil {
		if err == datastore.ErrNotFound {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to get store version: %w", err)
	}

	return int64(binary.BigEndian.Uint64(data)), nil
}

// SyncFromPeer syncs all records from a specific peer
func (s *RecordStore) SyncFromPeer(peerID string) error {
	// Get peer's store version
	versionKey := "/store/version"
	data, err := s.dht.GetValue(s.ctx, versionKey)
	if err != nil {
		return fmt.Errorf("failed to get peer's store version: %w", err)
	}
	peerVersion := int64(binary.BigEndian.Uint64(data))

	// Get our version
	ourVersion, err := s.GetStoreVersion()
	if err != nil {
		return fmt.Errorf("failed to get our store version: %w", err)
	}

	// Only sync if peer has a higher version
	if peerVersion <= ourVersion {
		return nil
	}

	// Get all records from peer
	records, err := s.getAllRecordsFromPeer(peerID)
	if err != nil {
		return fmt.Errorf("failed to get records from peer: %w", err)
	}

	// Verify and store records
	for _, record := range records {
		if !record.Verify() {
			s.log.WithField("domain", record.Domain).Error("Invalid record signature during sync")
			continue
		}

		// Store record
		data, err := record.Serialize()
		if err != nil {
			s.log.WithError(err).WithField("domain", record.Domain).Error("Failed to serialize record during sync")
			continue
		}

		key := datastore.NewKey(makeRecordKey(record.Domain))
		if err := s.db.Put(context.Background(), key, data); err != nil {
			s.log.WithError(err).WithField("domain", record.Domain).Error("Failed to store record during sync")
			continue
		}
	}

	// Update our version
	s.version = peerVersion
	versionData := make([]byte, 8)
	binary.BigEndian.PutUint64(versionData, uint64(s.version))
	if err := s.db.Put(context.Background(), datastore.NewKey(versionKey), versionData); err != nil {
		return fmt.Errorf("failed to update store version after sync: %w", err)
	}

	return nil
}

// getAllRecordsFromPeer gets all records from a specific peer
func (s *RecordStore) getAllRecordsFromPeer(peerID string) ([]*Record, error) {
	var records []*Record

	// Get confirmed records from peer
	_, err := peer.Decode(peerID)
	if err != nil {
		return nil, fmt.Errorf("invalid peer ID: %w", err)
	}

	// Get all records from the peer's DHT
	// First get the list of all record keys from our local database
	q := query.Query{
		Prefix: recordNamespace,
	}
	results, err := s.db.Query(context.Background(), q)
	if err != nil {
		return nil, fmt.Errorf("failed to query local records: %w", err)
	}
	defer results.Close()

	// For each record key, try to get it from the specific peer
	for result := range results.Next() {
		if result.Error != nil {
			continue
		}

		// Get the record value from the peer
		data, err := s.dht.GetValue(s.ctx, result.Key)
		if err != nil {
			s.log.WithError(err).WithField("key", result.Key).Error("Failed to get record value from peer")
			continue
		}

		record, err := DeserializeRecord(data)
		if err != nil {
			s.log.WithError(err).WithField("key", result.Key).Error("Failed to deserialize record")
			continue
		}

		// Verify the record is from our target peer by checking the signature
		if len(record.Signature) > 0 {
			// TODO: Implement signature verification to ensure record is from the correct peer
			// For now, we'll trust the DHT routing
			records = append(records, record)
		}
	}

	// Get pending records from peer
	pendingKey := makePendingKey("*")
	data, err := s.dht.GetValue(s.ctx, pendingKey)
	if err == nil {
		var pending PendingRecord
		if err := json.Unmarshal(data, &pending); err == nil && pending.Record != nil {
			// Verify the pending record is from our target peer
			if pending.Record.LockID != "" && strings.HasPrefix(pending.Record.LockID, peerID) {
				records = append(records, pending.Record)
			}
		}
	}

	return records, nil
}

// GetSyncState returns the current sync state
func (s *RecordStore) GetSyncState() *SyncState {
	return s.syncManager.GetSyncState()
}

// ConfirmRecord finalizes a pending record registration and updates the index
func (s *RecordStore) ConfirmRecord(domain string) error {
	fmt.Println("Confirming Record")
	pending, err := s.GetPendingRecordFromDHT(domain)
	if err != nil {
		return fmt.Errorf("no pending record found for domain")
	}
	fmt.Println("Found pending record")
	record := pending.Record

	// Acquire lock on the index
	lockID, acquired := s.TryAcquireLock(indexKey)
	if !acquired {
		return fmt.Errorf("failed to acquire lock for pending index")
	}
	defer s.ReleaseLock(indexKey, lockID)

	// Get current index
	domains, ok := s.GetPendingDomains()
	if !ok {
		s.log.WithField("domains", domains).Info("No pending record found")
	}

	// Remove domain from index
	newDomains := make([]string, 0, len(domains))
	for _, d := range domains {
		if d != domain {
			newDomains = append(newDomains, d)
		}
	}

	// Update index
	domains_, err := json.Marshal(newDomains)
	if err != nil {
		return fmt.Errorf("failed to marshal pending index: %w", err)
	}
	if err := s.dht.PutValue(s.ctx, makePendingKey(indexKey), domains_); err != nil {
		return fmt.Errorf("failed to update pending index: %w", err)
	}

	// Finalize the record
	record.Status = "confirmed"
	s.recordsMutex.Lock()
	defer s.recordsMutex.Unlock()

	data, err := record.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize record: %w", err)
	}

	// Store the confirmed record
	key := datastore.NewKey(makeRecordKey(record.Domain))
	if err := s.db.Put(context.Background(), key, data); err != nil {
		return fmt.Errorf("failed to store record: %w", err)
	}

	// Increment store version
	s.version++
	versionKey := datastore.NewKey("/store/version")
	versionData := make([]byte, 8)
	binary.BigEndian.PutUint64(versionData, uint64(s.version))
	if err := s.db.Put(context.Background(), versionKey, versionData); err != nil {
		return fmt.Errorf("failed to update store version: %w", err)
	}

	// Cleanup
	_ = s.dht.PutValue(s.ctx, makePendingKey(domain), []byte{}) // Remove from DHT
	s.ReleaseLock(domain, record.LockID)

	// Remove from local pending records cache
	s.pendingMutex.Lock()
	delete(s.pendingRecords, domain)
	s.pendingMutex.Unlock()

	return nil
}

// RejectRecord cancels a pending record registration and updates the index
func (s *RecordStore) RejectRecord(domain string) error {
	pending, err := s.GetPendingRecordFromDHT(domain)
	if err != nil {
		return fmt.Errorf("no pending record found for domain")
	}
	record := pending.Record

	// Acquire lock on the index
	lockID, acquired := s.TryAcquireLock(indexKey)
	if !acquired {
		return fmt.Errorf("failed to acquire lock for pending index")
	}
	defer s.ReleaseLock(indexKey, lockID)

	// Get current index
	domains, ok := s.GetPendingDomains()
	if !ok {
		s.log.WithField("domains", domains).Info("No pending record found")
	}

	// Remove domain from index
	domain = strings.ToLower(domain)
	newDomains := make([]string, 0, len(domains))
	for _, d := range domains {
		if d != domain {
			newDomains = append(newDomains, d)
		}
	}

	// Update index
	domains_, err := json.Marshal(newDomains)
	if err != nil {
		return fmt.Errorf("failed to marshal pending index: %w", err)
	}
	if err := s.dht.PutValue(s.ctx, makePendingKey(indexKey), domains_); err != nil {
		return fmt.Errorf("failed to update pending index: %w", err)
	}

	// Cleanup
	_ = s.dht.PutValue(s.ctx, makePendingKey(domain), []byte{}) // Remove from DHT
	s.ReleaseLock(domain, record.LockID)

	// Remove from local pending records cache
	s.pendingMutex.Lock()
	delete(s.pendingRecords, domain)
	s.pendingMutex.Unlock()

	return nil
}
