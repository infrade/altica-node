package test

import (
	"altica_node/core"
	"context"
	"testing"
	"time"

	leveldb "github.com/ipfs/go-ds-leveldb"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
)

func setupTestStore(t *testing.T) (*core.RecordStore, func()) {
	// Create a temporary directory for the database
	db, err := leveldb.NewDatastore("", nil)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	// Create a test host
	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, 0)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create a test DHT
	ctx := context.Background()
	dht, err := dht.New(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to create test DHT: %v", err)
	}

	// Create the store
	store := core.NewRecordStore(db, dht, ctx, "test-peer", priv)

	// Return cleanup function
	cleanup := func() {
		db.Close()
		dht.Close()
	}

	return store, cleanup
}

func TestDomainRegistration(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	// Test domain availability
	available, err := store.IsDomainAvailable("test.alt")
	if err != nil {
		t.Fatalf("Failed to check domain availability: %v", err)
	}
	if !available {
		t.Error("Domain should be available before registration")
	}

	// Create and register a record
	record := &core.Record{
		Domain:   "test.alt",
		Mappings: map[string]interface{}{"A": "1.2.3.4"},
		TTL:      time.Hour,
		Metadata: map[string]interface{}{},
	}

	// Add the record
	err = store.Add(record)
	if err != nil {
		t.Fatalf("Failed to add record: %v", err)
	}

	// Check domain availability again
	available, err = store.IsDomainAvailable("test.alt")
	if err == nil {
		t.Error("Domain should not be available after registration")
	}

	// Get the record
	retrieved, found := store.Get("test.alt")
	if !found {
		t.Error("Failed to retrieve registered record")
	}
	if retrieved.Domain != record.Domain {
		t.Error("Retrieved record domain mismatch")
	}
}

func TestVoting(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	// Create and register a record
	record := &core.Record{
		Domain:   "vote.alt",
		Mappings: map[string]interface{}{"A": "1.2.3.4"},
		TTL:      time.Hour,
		Metadata: map[string]interface{}{},
	}

	// Add the record
	err := store.Add(record)
	if err != nil {
		t.Fatalf("Failed to add record: %v", err)
	}

	// Get vote result
	result, err := store.GetVoteResult("vote.alt")
	if err != nil {
		t.Fatalf("Failed to get vote result: %v", err)
	}

	// Check if we have at least one vote (our own)
	if result.TotalVotes < 1 {
		t.Error("Should have at least one vote")
	}
}

func TestRecordConfirmation(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	// Create and register a record
	record := &core.Record{
		Domain:   "confirm.alt",
		Mappings: map[string]interface{}{"A": "1.2.3.4"},
		TTL:      time.Hour,
		Metadata: map[string]interface{}{},
	}

	// Add the record
	err := store.Add(record)
	if err != nil {
		t.Fatalf("Failed to add record: %v", err)
	}

	// Confirm the record
	err = store.ConfirmRecord("confirm.alt")
	if err != nil {
		t.Fatalf("Failed to confirm record: %v", err)
	}

	// Get the record and check its status
	retrieved, found := store.Get("confirm.alt")
	if !found {
		t.Error("Failed to retrieve confirmed record")
	}
	if retrieved.Status != "confirmed" {
		t.Error("Record status should be confirmed")
	}
}

func TestRecordRejection(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	// Create and register a record
	record := &core.Record{
		Domain:   "reject.alt",
		Mappings: map[string]interface{}{"A": "1.2.3.4"},
		TTL:      time.Hour,
		Metadata: map[string]interface{}{},
	}

	// Add the record
	err := store.Add(record)
	if err != nil {
		t.Fatalf("Failed to add record: %v", err)
	}

	// Reject the record
	err = store.RejectRecord("reject.alt")
	if err != nil {
		t.Fatalf("Failed to reject record: %v", err)
	}

	// Check domain availability
	available, err := store.IsDomainAvailable("reject.alt")
	if err != nil {
		t.Fatalf("Failed to check domain availability: %v", err)
	}
	if !available {
		t.Error("Domain should be available after rejection")
	}
}
