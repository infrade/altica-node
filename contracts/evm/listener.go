package evm

import (
	"altica_node/core"
	"context"
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
)

// EventListener listens for events from the AlticaRegistry contract
type EventListener struct {
	client       *ethclient.Client
	contract     *bind.BoundContract
	store        *core.RecordStore
	log          *logrus.Logger
	contractAddr common.Address
	fromBlock    uint64
}

// loadABI loads the ABI from the contracts output folder
func loadABI() (string, error) {
	// Get the directory of the current file
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("failed to get current file path")
	}
	currentDir := filepath.Dir(currentFile)

	// Construct the path to the ABI file relative to the current file
	abiPath := filepath.Join(currentDir, "contracts", "out", "AlticaRegistry.sol", "AlticaRegistry.json")

	// Read the ABI file
	data, err := os.ReadFile(abiPath)
	if err != nil {
		return "", fmt.Errorf("failed to read ABI file: %w", err)
	}

	// Parse the JSON to get the ABI
	var contractData struct {
		ABI json.RawMessage `json:"abi"`
	}
	if err := json.Unmarshal(data, &contractData); err != nil {
		return "", fmt.Errorf("failed to parse ABI JSON: %w", err)
	}

	return string(contractData.ABI), nil
}

// NewEventListener creates a new event listener
func NewEventListener(store *core.RecordStore) (*EventListener, error) {
	// Get RPC URL from environment
	rpcURL := os.Getenv("EVM_RPC_URL")
	if rpcURL == "" {
		return nil, fmt.Errorf("EVM_RPC_URL environment variable is required")
	}

	// Get contract address from environment
	contractAddr := os.Getenv("EVM_CONTRACT_ADDRESS")
	if contractAddr == "" {
		return nil, fmt.Errorf("EVM_CONTRACT_ADDRESS environment variable is required")
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
	abiStr, err := loadABI()
	if err != nil {
		return nil, fmt.Errorf("failed to load ABI: %w", err)
	}

	parsed, err := abi.JSON(strings.NewReader(abiStr))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ABI: %w", err)
	}

	contract := bind.NewBoundContract(common.HexToAddress(contractAddr), parsed, client, client, client)

	return &EventListener{
		client:       client,
		contract:     contract,
		store:        store,
		log:          logrus.New(),
		contractAddr: common.HexToAddress(contractAddr),
		fromBlock:    deploymentBlock,
	}, nil
}

// Start begins listening for events
func (l *EventListener) Start(ctx context.Context) error {
	// Create event filter
	query := ethereum.FilterQuery{
		Addresses: []common.Address{l.contractAddr},
		FromBlock: big.NewInt(int64(l.fromBlock)),
		Topics: [][]common.Hash{
			{crypto.Keccak256Hash([]byte("SubmittedBinding(bytes32,address,uint64)"))},
		},
	}

	logs := make(chan types.Log)
	sub, err := l.client.SubscribeFilterLogs(ctx, query, logs)
	if err != nil {
		return fmt.Errorf("failed to subscribe to logs: %w", err)
	}

	go func() {
		for {
			select {
			case err := <-sub.Err():
				l.log.WithError(err).Error("Subscription error")
				// Attempt to resubscribe
				time.Sleep(5 * time.Second)
				sub, err = l.client.SubscribeFilterLogs(ctx, query, logs)
				if err != nil {
					l.log.WithError(err).Error("Failed to resubscribe")
					continue
				}
			case log := <-logs:
				if err := l.handleSubmittedBinding(log); err != nil {
					l.log.WithError(err).Error("Failed to handle SubmittedBinding event")
				}
			case <-ctx.Done():
				return
			}
		}
	}()

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

	record, found := l.store.GetByNamehash(event.Namehash[:])
	if !found {
		l.log.WithField("namehash", event.Namehash).Info("No matching record found in DHT")
		return nil
	}

	// Get the signer address from the record
	recordSigner, err := record.GetSignerAddress()
	if err != nil {
		return fmt.Errorf("failed to get record signer address: %w", err)
	}
	var accepted bool
	// Verify the signer matches
	if strings.ToLower(recordSigner.Hex()) != strings.ToLower(event.Signer.Hex()) {
		l.log.WithFields(logrus.Fields{
			"domain":       record.Domain,
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

	tx, err := l.contract.Transact(auth, "oracleDecideSigner", event.Namehash, event.Signer, accepted)
	if err != nil {
		return fmt.Errorf("failed to call oracleDecideSigner: %w", err)
	}

	l.log.WithFields(logrus.Fields{
		"domain":  record.Domain,
		"tx_hash": tx.Hash().Hex(),
		"acceptd": accepted,
	}).Info("Called oracleDecideSigner")

	return nil
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
