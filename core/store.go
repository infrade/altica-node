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
	db            *leveldb.Datastore
	dht           *dht.IpfsDHT
	ctx           context.Context
	hostID        string
	log           *logrus.Logger
	pendingLocks  map[string]string // domain -> lockID
	lockMutex     sync.RWMutex
	recordsMutex  sync.RWMutex       // For operations on confirmed records
	version       int64              // Current version number
	filter        *bloom.BloomFilter // Bloom filter for fast lookups
	votingManager *VotingManager     // Added for voting functionality
	privKey       kyber.Scalar       // Node's private key for voting
	syncManager   *SyncManager       // Sync manager for record synchronization
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
		db:           db,
		dht:          dht,
		ctx:          ctx,
		hostID:       hostID,
		log:          logrus.New(),
		pendingLocks: make(map[string]string),
		version:      0,
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
	// store.syncManager = NewSyncManager(store)

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
	getLatestVersion := func() (*Record, bool) {
		// If still not found, try getting latest from DHT
		record, err := s.GetLatestRecord(domain)
		if err == nil && record != nil {
			s.SaveRecord(*record)
			return record, true
		}
		return nil, false
	}

	s.lockMutex.RLock()
	defer s.lockMutex.RUnlock()

	// First check local database
	key := datastore.NewKey(makeRecordKey(domain))
	data, err := s.db.Get(context.Background(), key)
	if err == nil && data != nil {
		record, err := DeserializeRecord(data)
		if err == nil && record != nil {
			if record.Status == "pending" {
				return getLatestVersion()
			}
			return record, true
		}
	}

	// If not found locally, check pending records
	pending, err := s.GetPendingRecordFromDHT(domain)
	if err == nil && pending != nil && pending.Record != nil {
		return pending.Record, true
	}

	return getLatestVersion()
}

func (s *RecordStore) List() []*Record {
	s.recordsMutex.RLock()
	defer s.recordsMutex.RUnlock()

	q := query.Query{
		Prefix: "/record/", // Fixed prefix to match other methods
	}
	results, err := s.db.Query(context.Background(), q)
	if err != nil {
		return nil
	}
	defer results.Close()

	var records []*Record
	for result := range results.Next() {
		if result.Error != nil {
			continue
		}
		record, err := DeserializeRecord(result.Value)
		if err != nil {
			continue
		}
		records = append(records, record)
	}

	return records
}

// IsDomainAvailable checks if a domain is available for registration
func (s *RecordStore) IsDomainAvailable(domain string) (bool, error) {
	// Check confirmed records
	if _, found := s.Get(domain); found {
		return false, nil
	}

	// Check pending records in DHT
	pending, err := s.GetPendingRecordFromDHT(domain)
	if err != nil {
		// If the error is a DHT not found error, treat as available
		if errors.Is(err, routing.ErrNotFound) {
			return true, nil
		}
		return false, err
	}
	if pending != nil {
		return false, fmt.Errorf("domain locked for registration")
	}
	return true, nil

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

	// Return immediately, actual registration will happen after consensus
	return nil
}

// TryAcquireIndexLock attempts to acquire the index lock with exponential backoff
func (s *RecordStore) TryAcquireIndexLock() (string, bool) {

	// Exponential backoff parameters
	maxAttempts := 5
	initialBackoff := 100 * time.Millisecond
	maxBackoff := 2 * time.Second
	timeout := 10 * time.Second
	startTime := time.Now()
	var lockID string
	var acquired bool

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Check if we've exceeded the timeout
		if time.Since(startTime) > timeout {
			s.log.Error("Index lock acquisition timed out")
			return "", false
		}

		lockID, acquired = s.TryAcquireLock(indexKey)
		// First check if a lock already exists
		if !acquired {
			// Calculate backoff duration with exponential increase
			backoff := initialBackoff * time.Duration(1<<uint(attempt))
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			time.Sleep(backoff)
			continue
		}

		// Store locally as well
		s.pendingLocks[indexKey] = lockID
		return lockID, true
	}

	s.log.Error("Failed to acquire index lock after maximum attempts")
	return "", false
}

// SavePendingRecordToDHT saves a pending record to DHT and updates the index
func (s *RecordStore) SavePendingRecordToDHT(record PendingRecord) error {
	// First acquire lock on the index with backoff
	lockID, acquired := s.TryAcquireIndexLock()
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
	return &pending, nil
}

// TODO: implement pending records cache so that we don't hit the dht always when record is pending
func (s *RecordStore) GetPendingDomains() ([]string, bool) {
	indexData, err := s.dht.GetValue(s.ctx, makePendingKey(indexKey))
	if err != nil {
		if !errors.Is(err, routing.ErrNotFound) {
			s.log.WithError(err).Error("Failed to get pending records index")
		}
		return nil, false
	}

	var domains []string
	if err := json.Unmarshal(indexData, &domains); err != nil {
		s.log.WithError(err).Error("Failed to unmarshal pending records index")
		return nil, false
	}
	s.log.WithField("domains", domains).Info("pending domains")
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
	return record, nil
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
	// metadata, err := rs.GetLatestVersion(domain)
	// if err != nil {
	// 	return nil, err
	// }

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

	// // Verify hash
	// content, ok := record.Mappings["content"].([]byte)
	// if !ok {
	// 	return nil, fmt.Errorf("record content not found")
	// }
	// hash := sha256.Sum256(content)
	// hashStr := hex.EncodeToString(hash[:])
	// if hashStr != metadata.Hash {
	// 	return nil, fmt.Errorf("record hash mismatch")
	// }

	return record, nil
}

// makeRecordKey creates a DHT key for a record
func makeRecordKey(domain string) string {
	return fmt.Sprintf("%s/%s", recordNamespace, domain)
}

// DHT key for pending records
func makePendingKey(domain string) string {
	return fmt.Sprintf("/altica/pending/%s", strings.ToLower(domain))
}

// makeMetadataKey creates a DHT key for record metadata
func makeMetadataKey(domain string) string {
	return fmt.Sprintf("%s/%s/metadata", recordNamespace, domain)
}

// makeNamehashKey creates a DHT key for namehash mappings
func makeNamehashKey(namehash []byte) string {
	return fmt.Sprintf("%s/namehash/%x", recordNamespace, namehash)
}

// GetVoteResult retrieves vote result for a domain
func (s *RecordStore) GetVoteResult(domain string) (*VoteResult, error) {
	if s.votingManager == nil {
		return nil, fmt.Errorf("voting manager not initialized")
	}
	return s.votingManager.getVoteResult(domain)
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

// ConfirmRecord finalizes a pending record registration and updates the index
func (s *RecordStore) ConfirmRecord(domain string) error {
	fmt.Println("Confirming Record")
	pending, err := s.GetPendingRecordFromDHT(domain)
	if err != nil {
		return fmt.Errorf("no pending record found for domain")
	}
	fmt.Println("Found pending record")
	record := pending.Record

	// Acquire lock on the index with backoff
	lockID, acquired := s.TryAcquireIndexLock()
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

	// Store the confirmed record to datastore
	err = s.SaveRecord(*record)
	if err != nil {
		return err
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

	return nil
}

// SaveRecord saves a record to both DHT and local storage
func (s *RecordStore) SaveRecord(record Record) error {
	// Save the record
	data, err := record.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize record: %w", err)
	}
	key := makeRecordKey(record.Domain)
	if err := s.dht.PutValue(s.ctx, key, data); err != nil {
		return fmt.Errorf("failed to store record to dht: %w", err)
	}
	datastoreKey := datastore.NewKey(key)
	if err := s.db.Put(context.Background(), datastoreKey, data); err != nil {
		return fmt.Errorf("failed to store record: %w", err)
	}

	// Save namehash mapping
	namehash := Namehash(record.Domain)
	namehashKey := makeNamehashKey(namehash)
	if err := s.dht.PutValue(s.ctx, namehashKey, []byte(record.Domain)); err != nil {
		return fmt.Errorf("failed to store namehash mapping to dht: %w", err)
	}
	if err := s.db.Put(context.Background(), datastore.NewKey(namehashKey), []byte(record.Domain)); err != nil {
		return fmt.Errorf("failed to store namehash mapping: %w", err)
	}

	return nil
}

// GetByNamehash looks up a domain name by its namehash
func (s *RecordStore) GetByNamehash(namehash []byte) (*Record, bool) {
	// First try local storage
	namehashKey := makeNamehashKey(namehash)
	domain, err := s.db.Get(context.Background(), datastore.NewKey(namehashKey))
	if err == nil && domain != nil {
		return s.Get(string(domain))
	}

	// If not found locally, try DHT
	domain, err = s.dht.GetValue(s.ctx, namehashKey)
	if err == nil && domain != nil {
		return s.Get(string(domain))
	}

	return nil, false
}

// RejectRecord cancels a pending record registration and updates the index
func (s *RecordStore) RejectRecord(domain string) error {
	pending, err := s.GetPendingRecordFromDHT(domain)
	if err != nil {
		return fmt.Errorf("no pending record found for domain")
	}
	record := pending.Record

	// Acquire lock on the index with backoff
	lockID, acquired := s.TryAcquireIndexLock()
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

	// Cleanup
	_ = s.dht.PutValue(s.ctx, makePendingKey(domain), []byte{}) // Remove from DHT
	s.ReleaseLock(domain, record.LockID)

	return nil
}

// GetCurrentVersion returns the current version number
func (s *RecordStore) GetCurrentVersion() int64 {
	s.recordsMutex.RLock()
	defer s.recordsMutex.RUnlock()
	return s.version
}

// IncrementVersion increases the current version and returns the new value
func (s *RecordStore) IncrementVersion() int64 {
	s.recordsMutex.Lock()
	defer s.recordsMutex.Unlock()
	s.version++
	return s.version
}

const lastSyncKey = "/sync/last_sync_time"

// GetLastSyncTime returns the last sync time from the datastore
func (s *RecordStore) GetLastSyncTime() (time.Time, error) {
	s.recordsMutex.RLock()
	defer s.recordsMutex.RUnlock()

	data, err := s.db.Get(context.Background(), datastore.NewKey(lastSyncKey))
	if err != nil {
		if err == datastore.ErrNotFound {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}

	var t time.Time
	if err := t.UnmarshalBinary(data); err != nil {
		return time.Time{}, err
	}
	return t, nil
}

// SetLastSyncTime stores the last sync time in the datastore
func (s *RecordStore) SetLastSyncTime(t time.Time) error {
	s.recordsMutex.Lock()
	defer s.recordsMutex.Unlock()

	data, err := t.MarshalBinary()
	if err != nil {
		return err
	}
	return s.db.Put(context.Background(), datastore.NewKey(lastSyncKey), data)
}
