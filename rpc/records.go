package rpc

import (
	"encoding/json"
	"fmt"
	"time"

	"altica_node/core"
)

// Record management params
type RecordSetParams struct {
	Domain string        `json:"domain"`
	Value  string        `json:"value"`
	TTL    time.Duration `json:"ttl"`
}

type RecordGetParams struct {
	Domain string `json:"domain"`
}

type RecordStatusParams struct {
	Domain string `json:"domain"`
}

// Record management handlers
func (s *RPCServer) handleRecordGet(params json.RawMessage) (interface{}, error) {
	var p RecordGetParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	record, found := s.node.Store.Get(p.Domain)
	if !found {
		return nil, fmt.Errorf("record not found")
	}
	return record, nil
}

// Record management handlers
func (s *RPCServer) handleRecordSet(params json.RawMessage) (interface{}, error) {
	var p RecordSetParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	// Check domain availability first
	available, err := s.node.Store.IsDomainAvailable(p.Domain)
	if err != nil {
		return nil, err
	}
	if !available {
		return nil, fmt.Errorf("domain is not available")
	}

	// Use default TTL of 5 minutes if not specified
	ttl := p.TTL
	if ttl == 0 {
		ttl = time.Minute * 5
	}

	record := core.NewRecord(p.Domain, p.Value, ttl)
	record.Version = s.node.Store.GetCurrentVersion() + 1

	// Start registration process
	if err := s.node.Store.Add(record); err != nil {
		return nil, fmt.Errorf("failed to initiate registration: %w", err)
	}

	// Publish registration intent to network
	if err := s.node.PublishRecord(record); err != nil {
		_ = s.node.Store.RejectRecord(p.Domain, record.LockID)
		return nil, fmt.Errorf("failed to publish registration: %w", err)
	}

	return record, nil
}

// Record status handler
func (s *RPCServer) handleRecordStatus(params json.RawMessage) (interface{}, error) {
	var p RecordStatusParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	pending, err := s.node.Store.GetPendingRecordFromDHT(p.Domain)
	if err != nil || pending == nil {
		return nil, fmt.Errorf("no pending record for domain")
	}
	return pending, nil
}
