package core

import (
	"errors"
	"sync"
)

type RecordStore struct {
	mu      sync.RWMutex
	records map[string]*Record
}

func NewRecordStore() *RecordStore {
	return &RecordStore{
		records: make(map[string]*Record),
	}
}

func (s *RecordStore) Add(record *Record) error {
	if !record.Verify() {
		return errors.New("record signature verification failed")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[record.Domain] = record
	return nil
}

func (s *RecordStore) Get(domain string) (*Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.records[domain]
	if !ok || rec.IsExpired() {
		return nil, false
	}
	return rec, true
}
