package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/sign/bls"
	"github.com/ipfs/go-datastore"
	"github.com/libp2p/go-libp2p/core/routing"
)

const (
	voteNamespace = "/altica/votes"
)

// Vote represents a single vote with threshold signature
type Vote struct {
	Domain    string `json:"domain"`
	PeerID    string `json:"peer_id"`
	Signature []byte `json:"signature"`
	PublicKey []byte `json:"public_key"`
	Decision  bool   `json:"decision"` // true for accept, false for reject
	Timestamp int64  `json:"timestamp"`
}

// VoteResult tracks the consensus state for a domain
type VoteResult struct {
	Domain      string           `json:"domain"`
	Votes       map[string]*Vote `json:"votes"` // peerID -> vote
	Threshold   int              `json:"threshold"`
	TotalVotes  int              `json:"total_votes"`
	Consensus   bool             `json:"consensus"`    // true if consensus reached
	Decision    bool             `json:"decision"`     // final decision if consensus reached
	Signature   []byte           `json:"signature"`    // aggregated threshold signature
	OnlineNodes int              `json:"online_nodes"` // Number of nodes online at registration intent
}

// VotingManager handles threshold signature voting
type VotingManager struct {
	store   *RecordStore
	suite   *bn256.Suite
	privKey kyber.Scalar
	pubKey  kyber.Point
	mu      sync.RWMutex
}

// NewVotingManager creates a new voting manager
func NewVotingManager(store *RecordStore, privKey kyber.Scalar) (*VotingManager, error) {
	if store == nil {
		return nil, fmt.Errorf("store is nil")
	}
	if privKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}

	suite := bn256.NewSuite()
	// privKey := suite.G1().Scalar().Pick(random.New())
	pubKey := suite.G1().Point().Base().Mul(privKey, nil)

	return &VotingManager{
		store:   store,
		privKey: privKey,
		pubKey:  pubKey,
		suite:   suite,
	}, nil
}

// makeVoteKey creates a DHT key for votes
func makeVoteKey(domain string) string {
	return fmt.Sprintf("%s/%s", voteNamespace, domain)
}

// SubmitVote submits a vote with threshold signature
func (vm *VotingManager) SubmitVote(domain string, decision bool, onlineNodes int) error {
	vote := &Vote{
		Domain:    domain,
		PeerID:    vm.store.hostID,
		Decision:  decision,
		Timestamp: time.Now().UnixNano(),
	}

	message := []byte(fmt.Sprintf("%s:%t:%d", domain, decision, vote.Timestamp))
	scheme := bls.NewSchemeOnG1(vm.suite)
	signature, err := scheme.Sign(vm.privKey, message)
	if err != nil {
		return fmt.Errorf("failed to sign vote: %w", err)
	}
	vote.Signature = signature

	pubKeyBytes, err := vm.pubKey.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	vote.PublicKey = pubKeyBytes

	result, err := vm.getVoteResult(domain)
	if err != nil {
		if !errors.Is(err, routing.ErrNotFound) {
			return err
		}
		result = &VoteResult{
			Domain:      domain,
			Votes:       make(map[string]*Vote),
			OnlineNodes: onlineNodes,
			Threshold:   (onlineNodes * 2) / 3,
		}
	}

	result.Votes[vm.store.hostID] = vote
	result.TotalVotes = len(result.Votes)

	err = vm.decide(result)
	if err != nil {
		return err
	}

	return vm.saveVoteResult(domain, result)
}

func (vm *VotingManager) decide(result *VoteResult) error {
	if result.TotalVotes >= result.Threshold {
		accepts := 0
		for _, v := range result.Votes {
			if v.Decision {
				accepts++
			}
		}
		result.Consensus = true
		result.Decision = accepts > result.TotalVotes/2

		if result.Consensus {
			signatures := make([][]byte, 0, len(result.Votes))
			for _, v := range result.Votes {
				signatures = append(signatures, v.Signature)
			}
			aggSig := vm.suite.G1().Point().Null()
			for _, sig := range signatures {
				sigPoint := vm.suite.G1().Point()
				if err := sigPoint.UnmarshalBinary(sig); err != nil {
					return fmt.Errorf("failed to unmarshal signature: %w", err)
				}
				aggSig.Add(aggSig, sigPoint)
			}
			aggSigBytes, err := aggSig.MarshalBinary()
			if err != nil {
				return fmt.Errorf("failed to marshal aggregated signature: %w", err)
			}
			result.Signature = aggSigBytes

			if err := vm.saveConsensusResult(result); err != nil {
				return fmt.Errorf("failed to save consensus result: %w", err)
			}

			vm.store.ConfirmRecord(d)
		}
	}
	return nil
}

// getVoteResult retrieves vote result from DHT
func (vm *VotingManager) getVoteResult(domain string) (*VoteResult, error) {
	key := makeVoteKey(domain)
	data, err := vm.store.dht.GetValue(vm.store.ctx, key)
	if err != nil {
		return nil, err
	}

	var result VoteResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// saveVoteResult saves vote result to DHT
func (vm *VotingManager) saveVoteResult(domain string, result *VoteResult) error {
	key := makeVoteKey(domain)
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return vm.store.dht.PutValue(vm.store.ctx, key, data)
}

// saveConsensusResult saves consensus result to LevelDB
func (vm *VotingManager) saveConsensusResult(result *VoteResult) error {
	key := datastore.NewKey(fmt.Sprintf("/consensus/%s", result.Domain))
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return vm.store.db.Put(context.Background(), key, data)
}

// VerifyVote verifies a single vote's signature
func (vm *VotingManager) VerifyVote(vote *Vote) bool {
	message := []byte(fmt.Sprintf("%s:%t:%d", vote.Domain, vote.Decision, vote.Timestamp))
	pubKey := vm.suite.Point()
	if err := pubKey.UnmarshalBinary(vote.PublicKey); err != nil {
		return false
	}
	scheme := bls.NewSchemeOnG1(vm.suite)
	return scheme.Verify(pubKey, message, vote.Signature) == nil
}

// VerifyConsensus verifies the aggregated signature of a consensus result
func (vm *VotingManager) VerifyConsensus(result *VoteResult) bool {
	if !result.Consensus || len(result.Signature) == 0 {
		return false
	}

	// Verify each individual vote
	for _, vote := range result.Votes {
		if !vm.VerifyVote(vote) {
			return false
		}
	}

	// Verify aggregated signature
	message := []byte(fmt.Sprintf("%s:%t", result.Domain, result.Decision))
	pubKeys := make([]kyber.Point, 0, len(result.Votes))
	for _, vote := range result.Votes {
		pubKey := vm.suite.Point()
		if err := pubKey.UnmarshalBinary(vote.PublicKey); err != nil {
			return false
		}
		pubKeys = append(pubKeys, pubKey)
	}

	scheme := bls.NewSchemeOnG1(vm.suite)
	aggPubKey := vm.suite.Point().Null()
	for _, pk := range pubKeys {
		aggPubKey.Add(aggPubKey, pk)
	}
	return scheme.Verify(aggPubKey, message, result.Signature) == nil
}
