package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"crypto/sha256"
	"encoding/binary"

	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/sign/bls"
	"github.com/libp2p/go-libp2p/core/routing"
)

const (
	voteNamespace   = "/altica/votes"
	decisionTimeout = 30 * time.Second // Timeout for decision maker
	maxAttempts     = 3                // Maximum number of decision maker attempts
	maxRetries      = 3                // Maximum number of retries for optimistic updates
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
	Domain        string           `json:"domain"`
	Votes         map[string]*Vote `json:"votes"` // peerID -> vote
	Threshold     int              `json:"threshold"`
	TotalVotes    int              `json:"total_votes"`
	Consensus     bool             `json:"consensus"`      // true if consensus reached
	Decision      bool             `json:"decision"`       // final decision if consensus reached
	Signature     []byte           `json:"signature"`      // aggregated threshold signature
	OnlineNodes   int              `json:"online_nodes"`   // Number of nodes online at registration intent
	DecisionMaker string           `json:"decision_maker"` // ID of the peer responsible for making the final decision
	LastUpdated   int64            `json:"last_updated"`   // Timestamp of last update
	Attempts      int              `json:"attempts"`       // Number of decision maker attempts
}

// VotingManager handles threshold signature voting
type VotingManager struct {
	store            *RecordStore
	suite            *bn256.Suite
	privKey          kyber.Scalar
	pubKey           kyber.Point
	mu               sync.RWMutex
	decisionInterval time.Duration // Interval for periodic decision making
	stopChan         chan struct{} // Channel to stop periodic decision making
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
	pubKey := suite.G1().Point().Base().Mul(privKey, nil)

	vm := &VotingManager{
		store:            store,
		privKey:          privKey,
		pubKey:           pubKey,
		suite:            suite,
		decisionInterval: 15 * time.Second, // Default interval
		stopChan:         make(chan struct{}),
	}

	// Start periodic decision making
	go vm.periodicDecisionMaking()

	return vm, nil
}

// SetDecisionInterval sets the interval for periodic decision making
func (vm *VotingManager) SetDecisionInterval(interval time.Duration) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.decisionInterval = interval
}

// Stop stops the periodic decision making
func (vm *VotingManager) Stop() {
	close(vm.stopChan)
}

// periodicDecisionMaking periodically checks and makes decisions for pending records
func (vm *VotingManager) periodicDecisionMaking() {
	ticker := time.NewTicker(vm.decisionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			vm.processPendingRecords()
		case <-vm.stopChan:
			return
		}
	}
}

// processPendingRecords processes all pending records
func (vm *VotingManager) processPendingRecords() {
	// Get only pending records from DHT
	domains, ok := vm.store.GetPendingDomains()
	if !ok {
		vm.store.log.WithField("domains", domains).Info("No pending record found")
		return
	}

	for _, domain := range domains {
		// Get vote result for this domain
		result, err := vm.getVoteResult(domain)
		if err != nil {
			if errors.Is(err, routing.ErrNotFound) {
				continue // No votes yet
			}
			vm.store.log.WithError(err).WithField("domain", domain).Error("Failed to get vote result")
			continue
		}

		// Check if we are the decision maker
		if vm.store.hostID == result.DecisionMaker {
			// Make decision if we have enough votes
			if result.TotalVotes >= result.Threshold {
				if err := vm.decide(result); err != nil {
					vm.store.log.WithError(err).WithField("domain", domain).Error("Failed to make decision")
				}
			}
			continue
		}

		// Check if decision maker is still available
		peers := vm.store.OnlineNodes()
		decisionMakerAvailable := false
		for _, peer := range peers {
			if peer.String() == result.DecisionMaker {
				decisionMakerAvailable = true
				break
			}
		}

		// If decision maker is unavailable or timeout reached, select new decision maker
		if !decisionMakerAvailable ||
			(time.Now().UnixNano()-result.LastUpdated) > decisionTimeout.Nanoseconds() {
			if result.Attempts >= maxAttempts {
				// If max attempts reached, select new decision maker from remaining peers
				result.DecisionMaker = vm.selectDecisionMaker(domain, len(peers))
				result.Attempts = 0
			} else {
				result.Attempts++
				fmt.Println("Attempt: ", result.Attempts)
			}
			result.LastUpdated = time.Now().UnixNano()
		}
	}
}

// makeVoteKey creates a DHT key for votes
func makeVoteKey(domain string) string {
	return fmt.Sprintf("%s/%s", voteNamespace, domain)
}

// SubmitVote submits a vote with threshold signature
func (vm *VotingManager) SubmitVote(domain string, decision bool) error {
	result, err := vm.getVoteResult(domain)
	if err != nil {
		if !errors.Is(err, routing.ErrNotFound) {
			return err
		}
		onlineNodes := vm.store.OnlineNodesCount()
		decisionMaker := vm.selectDecisionMaker(domain, onlineNodes)
		result = &VoteResult{
			Domain:        domain,
			Votes:         make(map[string]*Vote),
			OnlineNodes:   onlineNodes,
			Threshold:     (onlineNodes * 2) / 3,
			DecisionMaker: decisionMaker,
			LastUpdated:   time.Now().UnixNano(),
			Attempts:      0,
		}
	}
	if result.Consensus || result.Decision {
		return fmt.Errorf("Domain already reached consensus/decision")
	}

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

	result.Votes[vm.store.hostID] = vote
	result.TotalVotes = len(result.Votes)

	return vm.saveVoteResult(result)
}

// selectDecisionMaker selects a deterministic decision maker based on domain and online nodes
func (vm *VotingManager) selectDecisionMaker(domain string, onlineNodesCount int) string {
	if onlineNodesCount == 0 {
		return vm.store.hostID
	}
	// Use domain hash to select a peer
	hash := sha256.Sum256([]byte(domain))
	index := int(binary.BigEndian.Uint64(hash[:8])) % onlineNodesCount

	// Get sorted list of online peers
	peers := vm.store.OnlineNodes()
	fmt.Println("peers: ", peers)

	return peers[index].String()
}

func (vm *VotingManager) decide(result *VoteResult) error {
	// TODO: Persist voting result to local cache
	if result.TotalVotes >= result.Threshold {
		accepts := 0
		for _, v := range result.Votes {
			if v.Decision {
				accepts++
			}
		}
		// TODO: add better consensus condition
		result.Consensus = true
		result.Decision = accepts > result.TotalVotes/2

		if !result.Consensus {
			return nil
		}
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

		// submit signed tx to the blockchain
		if result.Decision {
			txHash, err := vm.store.GetAndSubmitSignedTx(result.Domain)
			if err != nil {
				return fmt.Errorf("failed to submit signed transaction: %w", err)
			}
			vm.store.log.WithField("domain", result.Domain).Infof("Submitted signed transaction: %s", txHash)
		} else {
			vm.store.log.WithField("domain", result.Domain).Info("Decision was to reject the record")
		}

		if err := vm.saveVoteResult(result); err != nil {
			return fmt.Errorf("failed to save consensus result: %w", err)
		}

		if err := vm.store.ConfirmRecord(result.Domain); err != nil {
			return fmt.Errorf("Unable to confirm record after consensus: %w", err)
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
func (vm *VotingManager) saveVoteResult(result *VoteResult) error {
	key := makeVoteKey(result.Domain)
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return vm.store.dht.PutValue(vm.store.ctx, key, data)
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
