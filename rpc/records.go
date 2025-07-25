package rpc

import (
	"altica_node/utils"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"altica_node/contracts/evm"
	"altica_node/core"

	"github.com/libp2p/go-libp2p/core/routing"
)

type DomainParamBase struct {
	Domain string `json:"domain"`
}

type DomainGetParams struct {
	DomainParamBase
}

type DomainRegisterParams struct {
	DomainParamBase
	TTL       time.Duration `json:"ttl"`
	Signature string        `json:"signature"`
	PublicKey string        `json:"public_key"`
	SignedTx  string        `json:"signed_tx"`
}

type DomainVotesParams struct {
	DomainParamBase
}

type DomainStatusParams struct {
	DomainParamBase
}

type RecordAddParams struct {
	DomainParamBase
	Type  string `json:"type"`
	Value string `json:"value"`
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

func hex2Bytes(s ...string) ([][]byte, error) {
	defer utils.TraceAuto()()
	if len(s) == 0 {
		return nil, fmt.Errorf("empty hex string")
	}
	result := make([][]byte, len(s))
	for i, hexStr := range s {
		bytes, err := hex.DecodeString(strings.TrimPrefix(hexStr, "0x"))
		if err != nil {
			return nil, fmt.Errorf("invalid hex string %q: %w", hexStr, err)
		}
		result[i] = bytes
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
	defer utils.TraceAuto()()
	var p DomainRegisterParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("validation error: %w", err)
	}

	// Only call Get once
	_, found := s.node.Store.Get(p.Domain)
	if found {
		return nil, fmt.Errorf("domain is not available or locked for registration")
	}

	ttl := p.TTL
	if ttl == 0 {
		p.TTL = time.Hour * 1
	}

	decoded, err := hex2Bytes(p.Signature, p.PublicKey, p.SignedTx)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	sigBytes := decoded[0]
	pubKeyBytes := decoded[1]
	signedTxBytes := decoded[2]

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

	// Pass knownNotFound = true to avoid redundant Get in Add
	if err := s.node.Store.Add(record, true); err != nil {
		return nil, fmt.Errorf("failed to register domain: %w", err)
	}
	go s.node.PublishRecord(record)
	return record, nil
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

func (s *RPCServer) handleAddBinding(params json.RawMessage) (interface{}, error) {
	var p RecordAddParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if p.Domain == "" {
		return nil, fmt.Errorf("missing required field: domain")
	}
	if p.Type == "" || p.Value == "" {
		return nil, fmt.Errorf("missing required field: type or value")
	}

	record, found := s.node.Store.Get(p.Domain)
	if !found {
		return nil, fmt.Errorf("domain not found")
	}
	if record.Status != "confirmed" {
		return nil, fmt.Errorf("domain is not confirmed/active")
	}

	updated := false

	switch strings.ToLower(p.Type) {
	case "a":
		if record.Bindings.A != p.Value {
			record.Bindings.A = p.Value
			updated = true
		}
	case "txt":
		if record.Bindings.TXT != p.Value {
			record.Bindings.TXT = p.Value
			updated = true
		}
	case "contenthash":
		if record.Bindings.ContentHash != p.Value {
			record.Bindings.ContentHash = p.Value
			updated = true
		}
	// TODO: EVM Addresses should be updated from the smart contract, listen to 'NameBound' event and update our record
	case "address":
		// For address, expect value to be chain_id:address (e.g., "1:0xabc...")
		parts := strings.SplitN(p.Value, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("address binding value must be 'chain_id:address'")
		}
		chainID, err := strconv.ParseUint(parts[0], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid chain_id: %w", err)
		}
		if record.Bindings.Addresses == nil {
			record.Bindings.Addresses = make(map[uint]string)
		}
		if record.Bindings.Addresses[uint(chainID)] != parts[1] {
			record.Bindings.Addresses[uint(chainID)] = parts[1]
			updated = true
		}
	default:
		return nil, fmt.Errorf("unsupported binding type: %s", p.Type)
	}

	if updated {
		record.Metadata["updated_at"] = time.Now().UTC().Format(time.RFC3339)
		if err := s.node.Store.SaveRecord(*record); err != nil {
			return nil, fmt.Errorf("failed to save updated record: %w", err)
		}
	}
	return record, nil
}
