package rpc

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"altica_node/contracts/evm"
	"altica_node/core"

	"github.com/libp2p/go-libp2p/core/routing"
)

type DomainRegisterParams struct {
	Domain    string        `json:"domain"`
	TTL       time.Duration `json:"ttl"`
	Signature string        `json:"signature"`
	PublicKey string        `json:"public_key"`
	SignedTx  string        `json:"signed_tx"`
}

type DomainGetParams struct {
	Domain string `json:"domain"`
}

type DomainStatusParams struct {
	Domain string `json:"domain"`
}

type RecordAddParams struct {
	Domain  string                 `json:"domain"`
	Chain   int                    `json:"chain"`
	Address string                 `json:"address"`
	Proof   map[string]interface{} `json:"proof"` // e.g., {"challenge":..., "signature":...}
}

type DomainVotesParams struct {
	Domain string `json:"domain"`
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
	if p.SignedTx == "" {
		return fmt.Errorf("missing SignedTx")
	}
	return nil
}

func hex2Bytes(s string) ([]byte, error) {
	result, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}
	return result, nil
}

// Record management handlers
func (s *RPCServer) handleDomainGet(params json.RawMessage) (interface{}, error) {
	var p DomainGetParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	// Get the latest version of the record
	record, found := s.node.Store.Get(p.Domain)
	if !found {
		return nil, fmt.Errorf("not found")
	}
	return record, nil
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

	// TODO: refactor; make it fat model, thin view
	available, _ := s.node.Store.IsDomainAvailable(p.Domain)
	if !available {
		return nil, fmt.Errorf("domain is not available or locked for registration")
	}

	ttl := p.TTL
	if ttl == 0 {
		p.TTL = time.Hour * 1
	}

	sigBytes, err := hex2Bytes(p.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}
	pubKeyBytes, err := hex2Bytes(p.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid publicKey: %w", err)
	}
	signedTxBytes, err := hex2Bytes(p.SignedTx)
	if err != nil {
		return nil, fmt.Errorf("invalid signedTx: %w", err)
	}

	if len(sigBytes) == 0 || len(pubKeyBytes) == 0 || len(signedTxBytes) == 0 {
		return nil, fmt.Errorf("signature, publicKey and signedTx must be provided in hex format")
	}
	if len(sigBytes) != 65 {
		return nil, fmt.Errorf("signature must be 65 bytes long")
	}

	record, err := core.NewRecord(p.Domain, p.TTL, sigBytes, pubKeyBytes, signedTxBytes)
	if err != nil {
		return nil, err
	}

	valid, err := evm.ValidateSignedTx(record)
	if err != nil || !valid {
		return nil, fmt.Errorf("signedTx validation failed: %w", err)
	}

	if err := s.node.Store.Add(record); err != nil {
		return nil, fmt.Errorf("failed to register domain: %w", err)
	}
	if err := s.node.PublishRecord(record); err != nil {
		_ = s.node.Store.RejectRecord(p.Domain)
		return nil, fmt.Errorf("failed to publish registration: %w", err)
	}
	return record, nil
}

// Mapping addition handler (wallet/address)
// wallet add should be initiated from the blockchain for EVM, rewrite this later
func (s *RPCServer) handleRecordAdd(params json.RawMessage) (interface{}, error) {
	// var p RecordAddParams
	// if err := json.Unmarshal(params, &p); err != nil {
	// 	return nil, fmt.Errorf("invalid params: %w", err)
	// }

	// // Get the latest version of the record
	// record, err := s.node.Store.GetLatestRecord(p.Domain)
	// if err != nil {
	// 	return nil, fmt.Errorf("domain not found: %w", err)
	// }

	// // Validate proof for the chain
	// if !validateProof(p.Chain, p.Address, p.Proof) {
	// 	return nil, fmt.Errorf("invalid proof for address on chain %d", p.Chain)
	// }

	// // Update bindings and metadata
	// record.Bindings.Addresses[p.Chain] = p.Address
	// if record.Metadata == nil {
	// 	record.Metadata = make(map[string]interface{})
	// }
	// if record.Metadata["proofs"] == nil {
	// 	record.Metadata["proofs"] = map[string]interface{}{}
	// }
	// proofs := record.Metadata["proofs"].(map[int]interface{})
	// proofs[p.Chain] = p.Proof
	// record.Metadata["proofs"] = proofs
	// record.Metadata["updated_at"] = time.Now().UTC().Format(time.RFC3339)

	// // Save updated record
	// if err := s.node.Store.Add(record); err != nil {
	// 	return nil, fmt.Errorf("failed to update record: %w", err)
	// }
	// if err := s.node.PublishRecord(record); err != nil {
	// 	return nil, fmt.Errorf("failed to publish update: %w", err)
	// }
	// return record, nil
	return nil, fmt.Errorf("record add not implemented yet")
}

func validateProof(chain int, address string, proof map[string]interface{}) bool {
	// TODO: Implement chain-specific proof validation
	return true
}

func (s *RPCServer) handleDomainVotes(params json.RawMessage) (interface{}, error) {
	var p DomainVotesParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if p.Domain == "" {
		return nil, fmt.Errorf("missing required field: domain")
	}

	// Get vote result from voting manager
	result, err := s.node.Store.GetVoteResult(p.Domain)
	if err != nil {
		if errors.Is(err, routing.ErrNotFound) {
			return nil, fmt.Errorf("no votes found for domain")
		}
		return nil, fmt.Errorf("failed to get votes: %w", err)
	}

	return result, nil
}
