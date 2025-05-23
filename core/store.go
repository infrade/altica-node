package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"strings"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/ipfs/go-datastore"
	"github.com/ipfs/go-datastore/query"
	leveldb "github.com/ipfs/go-ds-leveldb"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/routing"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

type PendingRecord struct {
	Record        *Record
	Confirmations int
	Rejections    int
}

type RecordStore struct {
	db           *leveldb.Datastore
	dht          *dht.IpfsDHT
	ctx          context.Context
	hostID       string
	log          *logrus.Logger
	pendingLocks map[string]string // domain -> lockID
	lockMutex    sync.RWMutex
	recordsMutex sync.RWMutex       // For operations on confirmed records
	version      int64              // Current version number
	filter       *bloom.BloomFilter // Bloom filter for fast lookups
}

func NewRecordStore(db *leveldb.Datastore, dht *dht.IpfsDHT, ctx context.Context, hostID string) *RecordStore {
	return &RecordStore{
		db:           db,
		dht:          dht,
		ctx:          ctx,
		hostID:       hostID,
		log:          logrus.New(),
		pendingLocks: make(map[string]string),
		version:      0,
	}
}

func (s *RecordStore) Get(domain string) (*Record, bool) {
	s.lockMutex.RLock()
	defer s.lockMutex.RUnlock()

	key := datastore.NewKey("/record/" + domain)
	data, err := s.db.Get(context.Background(), key)
	if err != nil {
		return nil, false
	}

	record, err := DeserializeRecord(data)
	if err != nil {
		return nil, false
	}

	return record, true
}

const (
	// Use a custom namespace for our lock records to avoid IPNS validation
	lockNamespace    = "/altica/locks" // Custom DHT namespace for Altica locks
	minConfirmations = 3               // Minimum number of peer confirmations required
)

// makeLockKey creates a valid DHT key for locks in the custom namespace
func makeLockKey(domain string) string {
	return fmt.Sprintf("%s/%s", lockNamespace, strings.ToLower(domain))
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
	storedValue, err := s.dht.GetValue(s.ctx, lockKey)
	if err != nil {
		s.log.WithError(err).WithFields(logrus.Fields{
			"domain":  domain,
			"lockKey": lockKey,
		}).Error("Failed to verify DHT lock")
		return "", false
	}

	if string(storedValue) != lockID {
		s.log.WithFields(logrus.Fields{
			"domain":      domain,
			"lockKey":     lockKey,
			"expected":    lockID,
			"storedValue": string(storedValue),
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
	storedValue, err := s.dht.GetValue(s.ctx, lockKey)
	if err != nil || string(storedValue) != lockID {
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

// IsLockValid checks if a lock is still valid in the DHT
func (s *RecordStore) IsLockValid(domain, lockID string) bool {
	lockKey := makeLockKey(domain)
	storedValue, err := s.dht.GetValue(s.ctx, lockKey)
	return err == nil && string(storedValue) == lockID
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
	pending := PendingRecord{
		Record:        record,
		Confirmations: 0,
		Rejections:    0,
	}
	if err := s.SavePendingRecordToDHT(record.Domain, pending); err != nil {
		return fmt.Errorf("failed to save pending record to DHT: %w", err)
	}

	// Return immediately, actual registration will happen after consensus
	return nil
}

// ConfirmRecord finalizes a pending record registration
func (s *RecordStore) ConfirmRecord(domain string, lockID string) error {
	pending, err := s.GetPendingRecordFromDHT(domain)
	if err != nil {
		return fmt.Errorf("no pending record found for domain")
	}
	record := pending.Record
	if record.LockID != lockID {
		return fmt.Errorf("invalid lock ID")
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
	key := datastore.NewKey("/record/" + record.Domain)
	if err := s.db.Put(context.Background(), key, data); err != nil {
		return fmt.Errorf("failed to store record: %w", err)
	}

	// Cleanup
	_ = s.dht.PutValue(s.ctx, makePendingKey(domain), []byte{}) // Remove from DHT
	s.ReleaseLock(domain, lockID)

	return nil
}

// RejectRecord cancels a pending record registration
func (s *RecordStore) RejectRecord(domain string, lockID string) error {
	pending, err := s.GetPendingRecordFromDHT(domain)
	if err != nil {
		return fmt.Errorf("no pending record found for domain")
	}
	record := pending.Record
	if record.LockID != lockID {
		return fmt.Errorf("invalid lock ID")
	}

	// Cleanup
	_ = s.dht.PutValue(s.ctx, makePendingKey(domain), []byte{}) // Remove from DHT
	s.ReleaseLock(domain, lockID)

	return nil
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

func (s *RecordStore) Delete(domain string) error {
	s.recordsMutex.Lock()
	defer s.recordsMutex.Unlock()

	key := datastore.NewKey("/record/" + domain)
	return s.db.Delete(context.Background(), key)
}

func (s *RecordStore) ListModifiedSince(timestamp time.Time) ([]*Record, error) {
	s.recordsMutex.RLock()
	defer s.recordsMutex.RUnlock()

	q := query.Query{
		Prefix:   "/record/", // Use forward slashes for datastore key prefix
		KeysOnly: false,      // We need values too
	}

	results, err := s.db.Query(context.Background(), q)
	if err != nil {
		return nil, fmt.Errorf("failed to query records: %w", err)
	}
	defer results.Close()

	var records []*Record
	entries, err := results.Rest()
	if err != nil {
		return nil, fmt.Errorf("failed to get query results: %w", err)
	}

	for _, entry := range entries {
		record, err := DeserializeRecord(entry.Value)
		if err != nil {
			s.log.WithError(err).Error("Failed to deserialize record")
			continue
		}
		if record.Timestamp.After(timestamp) {
			records = append(records, record)
		}
	}

	return records, nil
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

// DHT key for pending records
func makePendingKey(domain string) string {
	return fmt.Sprintf("/altica/pending/%s", strings.ToLower(domain))
}

func (s *RecordStore) SavePendingRecordToDHT(domain string, pending PendingRecord) error {
	data, err := json.Marshal(pending)
	if err != nil {
		return err
	}
	key := makePendingKey(domain)
	return s.dht.PutValue(s.ctx, key, data)
}

func (s *RecordStore) GetPendingRecordFromDHT(domain string) (*PendingRecord, error) {
	key := makePendingKey(domain)
	data, err := s.dht.GetValue(s.ctx, key)
	if err != nil {
		return nil, err
	}
	var pending PendingRecord
	if err := json.Unmarshal(data, &pending); err != nil {
		return nil, err
	}
	return &pending, nil
}
