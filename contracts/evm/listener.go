package evm

import (
	interfaces "altica_node/utils"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/sirupsen/logrus"
	"github.com/syndtr/goleveldb/leveldb"
)

// Store interface for dependency injection, avoiding circular dependency
// Only the required method is declared here
// The actual implementation should be passed in from the main application

// EventListener listens for events from the AlticaRegistry contract
type EventListener struct {
	client       *ethclient.Client
	contract     *bind.BoundContract
	log          *logrus.Logger
	contractAddr common.Address
	fromBlock    uint64
	gossip       interfaces.GossipManager // Optional, can be nil if not used
	store        interfaces.RecordStore
	logTopics    map[string]common.Hash
}

// loadABI loads the ABI from the contracts output folder
func LoadABI() abi.ABI {
	// Get the directory of the current file
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		fmt.Printf("failed to get current file path")
		panic(1)
	}
	currentDir := filepath.Dir(currentFile)

	// Construct the path to the ABI file relative to the current file
	abiPath := filepath.Join(currentDir, "contracts", "out", "AlticaRegistry.sol", "AlticaRegistry.json")

	// Read the ABI file
	data, err := os.ReadFile(abiPath)
	if err != nil {
		fmt.Printf("failed to read ABI file: %v", err)
		panic(1)
	}

	// Parse the JSON to get the ABI
	var contractData struct {
		ABI json.RawMessage `json:"abi"`
	}
	if err := json.Unmarshal(data, &contractData); err != nil {
		fmt.Printf("failed to parse ABI JSON: %v", err)
		panic(1)
	}

	parsed, err := abi.JSON(strings.NewReader(string(contractData.ABI)))
	if err != nil {
		fmt.Printf("failed to parse ABI: %v", err)
		panic(1)
	}
	return parsed

}

// NewEventListener creates a new event listener
// Accepts a RecordStore as a parameter
func NewEventListener(store interfaces.RecordStore, gossip interfaces.GossipManager) (*EventListener, error) {
	// Get RPC URL from environment
	rpcURL := os.Getenv("EVM_RPC_URL")
	if rpcURL == "" {
		return nil, fmt.Errorf("EVM_RPC_URL environment variable is required")
	}

	// Get contract address from environment
	contractAddr := os.Getenv("EVM_ALTICA_REGISTRY_ADDRESS")
	if contractAddr == "" {
		return nil, fmt.Errorf("EVM_ALTICA_REGISTRY_ADDRESS environment variable is required")
	}

	// Get deployment block from environment
	deploymentBlockStr := os.Getenv("EVM_DEPLOYMENT_BLOCK")
	if deploymentBlockStr == "" {
		return nil, fmt.Errorf("EVM_DEPLOYMENT_BLOCK environment variable is required")
	}
	deploymentBlock, err := strconv.ParseUint(deploymentBlockStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid EVM_DEPLOYMENT_BLOCK: %w", err)
	}

	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Ethereum client: %w", err)
	}

	// Load the ABI from file
	contract_abi := LoadABI()

	contract := bind.NewBoundContract(common.HexToAddress(contractAddr), contract_abi, client, client, client)

	logTopics := map[string]common.Hash{
		"submittedBinding": crypto.Keccak256Hash([]byte("SubmittedBinding(bytes32,address,uint64)")),
		"nameBound":        crypto.Keccak256Hash([]byte("NameBound(bytes32,address,uint64)")),
	}
	return &EventListener{
		client:       client,
		contract:     contract,
		log:          logrus.New(),
		contractAddr: common.HexToAddress(contractAddr),
		fromBlock:    deploymentBlock,
		gossip:       gossip,
		store:        store,
		logTopics:    logTopics,
	}, nil
}

// Start begins listening for events
func (l *EventListener) Start(ctx context.Context) error {
	// Get the latest block number
	latestBlock, err := l.client.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to get latest block: %w", err)
	}

	// Get last synced block from DB
	lastSyncedBlock, err := l.getLastSyncedBlock()
	if err != nil {
		return fmt.Errorf("failed to get last synced block: %w", err)
	}

	query := ethereum.FilterQuery{
		Addresses: []common.Address{l.contractAddr},
		FromBlock: big.NewInt(int64(lastSyncedBlock)),
		ToBlock:   big.NewInt(int64(latestBlock)),
		Topics: [][]common.Hash{
			{l.logTopics["submittedBinding"], l.logTopics["nameBound"]},
		},
	}

	if lastSyncedBlock < latestBlock {
		historyLogs, err := l.client.FilterLogs(ctx, query)
		if err != nil {
			l.log.WithError(err).Error("Failed to filter historical logs")
		}
		for _, log := range historyLogs {
			l.handleLogEvent(log, "historical")
		}
	}

	// Now subscribe to new logs from the latest block onward
	query.FromBlock = big.NewInt(int64(latestBlock))
	query.ToBlock = nil

	logs := make(chan types.Log, 100)
	sub, err := l.client.SubscribeFilterLogs(ctx, query, logs)
	if err != nil {
		return fmt.Errorf("failed to subscribe to logs: %w", err)
	}

	go func() {
		for {
			select {
			case err := <-sub.Err():
				l.log.WithError(err).Error("Subscription error")
				time.Sleep(5 * time.Second)
				sub, err = l.client.SubscribeFilterLogs(ctx, query, logs)
				if err != nil {
					l.log.WithError(err).Error("Failed to resubscribe")
					continue
				}
			case log := <-logs:
				l.handleLogEvent(log, "fresh")
			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
}

func (l *EventListener) Stop() {
	l.log.Info("Stopping EventListener")
	if l.client != nil {
		l.client.Close()
	}
}

func (l *EventListener) handleLogEvent(log types.Log, desc string) error {
	switch log.Topics[0] {
	case l.logTopics["submittedBinding"]:
		if err := l.handleSubmittedBinding(log); err != nil {
			l.log.WithError(err).Errorf("Failed to handle SubmittedBinding event (%s)", desc)
		}
	case l.logTopics["nameBound"]:
		if err := l.handleNameBound(log); err != nil {
			l.log.WithError(err).Errorf("Failed to handle NameBound event (%s)", desc)
		}
	}
	l.setLastSyncedBlock(uint64(log.BlockNumber))
	return nil
}

// handleSubmittedBinding processes a SubmittedBinding event
func (l *EventListener) handleSubmittedBinding(log types.Log) error {
	// Parse the event
	var event struct {
		Namehash  [32]byte
		Signer    common.Address
		ExpiresAt uint64
	}

	err := l.contract.UnpackLog(&event, "SubmittedBinding", log)
	if err != nil {
		return fmt.Errorf("failed to unpack event: %w", err)
	}

	var record interfaces.Record
	var found bool
	const maxRetries = 4
	for attempt := 1; !found && attempt <= maxRetries; attempt++ {
		record, found = l.store.GetByNamehash(event.Namehash[:])
		time.Sleep(time.Duration(2<<attempt) * time.Second) // exponential backoff: 4, 8, 16, 32 seconds
	}

	if !found {
		l.log.WithField("namehash", hex.EncodeToString(event.Namehash[:])).Info("No matching record found in DHT after retries")
		return nil
	}

	// Get the signer address from the record
	recordSigner := record.GetSigner()
	var accepted bool
	// Verify the signer matches
	if !strings.EqualFold(recordSigner.Hex(), event.Signer.Hex()) {
		l.log.WithFields(logrus.Fields{
			"domain":       record.GetDomain(),
			"dht_signer":   recordSigner.Hex(),
			"event_signer": event.Signer.Hex(),
		}).Info("Signer mismatch")
		accepted = false
	} else {
		accepted = true
	}

	// Call oracleDecideSigner
	auth, err := l.getTransactOpts()
	if err != nil {
		return fmt.Errorf("failed to get transaction options: %w", err)
	}

	var output []interface{}
	// Call the contract's bindingSigner mapping to get the current signer
	err = l.contract.Call(nil, &output, "bindingSigner", event.Namehash)
	if err != nil {
		return fmt.Errorf("failed to read bindingSigner from contract: %w", err)
	}
	// bindingSigner returns address, decode it
	onChainSigner := output[0].(common.Address)

	if strings.EqualFold(onChainSigner.Hex(), recordSigner.Hex()) {
		l.log.WithFields(logrus.Fields{
			"domain":         record.GetDomain(),
			"record_signer":  recordSigner.Hex(),
			"onchain_signer": onChainSigner.Hex(),
		}).Info("Signer already correct on-chain, skipping oracleDecideSigner")
	} else {
		tx, err := l.contract.Transact(auth, "oracleDecideSigner", event.Namehash, recordSigner, accepted)
		if err != nil {
			return fmt.Errorf("failed to call oracleDecideSigner: %w", err)
		}

		l.log.WithFields(logrus.Fields{
			"domain":   record.GetDomain(),
			"tx_hash":  tx.Hash().Hex(),
			"accepted": accepted,
		}).Info("Called oracleDecideSigner")
	}
	return nil
}

// Add this handler for NameBound
func (l *EventListener) handleNameBound(log types.Log) error {
	var event struct {
		Namehash  [32]byte
		Resolver  common.Address
		ExpiresAt uint64
		ChainID   uint64
		EventID   string // e.g. chainID:namehash:blockNumber
	}
	err := l.contract.UnpackLog(&event, "NameBound", log)
	if err != nil {
		return fmt.Errorf("failed to unpack NameBound event: %w", err)
	}
	// set the chain ID to the chain we're connected to
	chainID, err := l.client.ChainID(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get chain ID: %w", err)
	}
	event.ChainID = chainID.Uint64()
	event.EventID = fmt.Sprintf("%d:%s:%d", event.ChainID, hex.EncodeToString(event.Namehash[:]), log.BlockNumber)
	l.log.WithFields(logrus.Fields{
		"eventID":   event.EventID,
		"resolver":  event.Resolver.Hex(),
		"expiresAt": event.ExpiresAt,
	}).Info("NameBound event received")
	return l.gossip.PublishNameBound(interfaces.NameBoundEvent{
		Namehash:  event.Namehash,
		Resolver:  event.Resolver,
		ExpiresAt: event.ExpiresAt,
		ChainID:   event.ChainID,
		EventID:   event.EventID,
	})
}

// getTransactOpts returns transaction options for contract calls
func (l *EventListener) getTransactOpts() (*bind.TransactOpts, error) {
	keyHex := os.Getenv("EVM_PRIVATE_KEY")
	keyHex = strings.TrimSpace(keyHex)
	keyHex = strings.TrimPrefix(keyHex, "0x")
	privateKey, err := crypto.HexToECDSA(keyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	chainID, err := l.client.ChainID(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get chain ID: %w", err)
	}

	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
	if err != nil {
		return nil, fmt.Errorf("failed to create transactor: %w", err)
	}

	// Set gas price and limit
	gasPrice, err := l.client.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get gas price: %w", err)
	}
	auth.GasPrice = gasPrice
	auth.GasLimit = 300000 // Adjust based on your needs

	return auth, nil
}

func (l *EventListener) getLastSyncedBlock() (uint64, error) {
	db, err := leveldb.OpenFile(getEVMListenerDBPath(), nil)
	if err != nil {
		return 0, err
	}
	defer db.Close()
	val, err := db.Get([]byte("last_synced_block"), nil)
	if err != nil {
		return l.fromBlock, nil // fallback to fromBlock if not found
	}
	block, err := strconv.ParseUint(string(val), 10, 64)
	if err != nil {
		return l.fromBlock, nil
	}
	return block, nil
}

func (l *EventListener) setLastSyncedBlock(block uint64) error {
	db, err := leveldb.OpenFile(getEVMListenerDBPath(), nil)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Put([]byte("last_synced_block"), []byte(strconv.FormatUint(block, 10)), nil)
}

func getEVMListenerDBPath() string {
	return filepath.Join(interfaces.GetDataDir(), "evm_listener")
}
