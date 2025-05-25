package rpc

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"altica_node/core"
)

type DomainRegisterParams struct {
	Domain    string        `json:"domain"`
	TTL       time.Duration `json:"ttl"`
	Signature string        `json:"signature"`
	PublicKey string        `json:"publicKey"`
}

type DomainGetParams struct {
	Domain string `json:"domain"`
}

type DomainStatusParams struct {
	Domain string `json:"domain"`
}

type RecordAddParams struct {
	Domain  string                 `json:"domain"`
	Chain   string                 `json:"chain"`
	Address string                 `json:"address"`
	Proof   map[string]interface{} `json:"proof"` // e.g., {"challenge":..., "signature":...}
}

func (p *DomainRegisterParams) Validate() error {
	if p.Domain == "" {
		return fmt.Errorf("missing required field: domain")
	}
	if p.Signature == "" {
		return fmt.Errorf("missing required field: signature")
	}
	if p.PublicKey == "" {
		return fmt.Errorf("missing required field: publicKey")
	}
	// if p.TTL <= 0 {
	// 	return fmt.Errorf("ttl must be greater than zero")
	// }
	return nil
}

func hex2Bytes(s string) []byte {
	result, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		log.Fatal(err)
	}
	return result
}

// Record management handlers
func (s *RPCServer) handleDomainGet(params json.RawMessage) (interface{}, error) {
	var p DomainGetParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	return s.domainGet(p.Domain)
}

func (s *RPCServer) domainGet(domain string) (interface{}, error) {
	record, found := s.node.Store.Get(domain)
	if !found {
		return nil, fmt.Errorf("record not found")
	}
	return record, nil
}

// Record status handler
func (s *RPCServer) handleDomainStatus(params json.RawMessage) (interface{}, error) {
	var p DomainStatusParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	pending, err := s.node.Store.GetPendingRecordFromDHT(p.Domain)
	if err != nil || pending == nil {
		return s.domainGet(p.Domain)
	}
	return pending, nil
}

// Domain registration handler
func (s *RPCServer) handleDomainRegister(params json.RawMessage) (interface{}, error) {
	var p DomainRegisterParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("validation error: %w", err)
	}

	available, err := s.node.Store.IsDomainAvailable(p.Domain)
	if err != nil {
		return nil, err
	}
	if !available {
		return nil, fmt.Errorf("domain is not available")
	}

	ttl := p.TTL
	if ttl == 0 {
		p.TTL = time.Hour * 1
	}

	sigBytes := hex2Bytes(p.Signature)
	pubKeyBytes := hex2Bytes(p.PublicKey)

	record, err := core.NewRecord(p.Domain, p.TTL, sigBytes, pubKeyBytes)
	if err != nil {
		return nil, err
	}
	record.Version = s.node.Store.GetCurrentVersion() + 1

	if err := s.node.Store.Add(record); err != nil {
		return nil, fmt.Errorf("failed to register domain: %w", err)
	}
	if err := s.node.PublishRecord(record); err != nil {
		_ = s.node.Store.RejectRecord(p.Domain, record.LockID)
		return nil, fmt.Errorf("failed to publish registration: %w", err)
	}
	return record, nil
}

// Mapping addition handler (wallet/address)
func (s *RPCServer) handleRecordAdd(params json.RawMessage) (interface{}, error) {
	var p RecordAddParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	record, found := s.node.Store.Get(p.Domain)
	if !found {
		return nil, fmt.Errorf("domain not found")
	}

	// Validate proof for the chain
	if !validateProof(p.Chain, p.Address, p.Proof) {
		return nil, fmt.Errorf("invalid proof for address on chain %s", p.Chain)
	}

	// Update mappings and metadata
	record.Mappings[p.Chain] = p.Address
	if record.Metadata == nil {
		record.Metadata = make(map[string]interface{})
	}
	if record.Metadata["proofs"] == nil {
		record.Metadata["proofs"] = map[string]interface{}{}
	}
	proofs := record.Metadata["proofs"].(map[string]interface{})
	proofs[p.Chain] = p.Proof
	record.Metadata["proofs"] = proofs

	// Save updated record
	if err := s.node.Store.Add(record); err != nil {
		return nil, fmt.Errorf("failed to update record: %w", err)
	}
	if err := s.node.PublishRecord(record); err != nil {
		return nil, fmt.Errorf("failed to publish update: %w", err)
	}
	return record, nil
}

func validateProof(chain, address string, proof map[string]interface{}) bool {
	// TODO: Implement chain-specific proof validation
	return true
}
