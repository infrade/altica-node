package evm

import (
	"altica_node/core"
	"context"
	"fmt"
	"math/big"
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

// AlticaRegistryABI is the ABI for the AlticaRegistry contract
const AlticaRegistryABI = `[{"anonymous":false,"inputs":[{"indexed":true,"name":"namehash","type":"bytes32"},{"indexed":true,"name":"signer","type":"address"},{"indexed":false,"name":"expiresAt","type":"uint64"}],"name":"SubmittedBinding","type":"event"}]`

// EventListener listens for events from the AlticaRegistry contract
type EventListener struct {
	client       *ethclient.Client
	contract     *bind.BoundContract
	store        *core.RecordStore
	log          *logrus.Logger
	contractAddr common.Address
	fromBlock    uint64
}

// NewEventListener creates a new event listener
func NewEventListener(rpcURL string, contractAddr string, store *core.RecordStore) (*EventListener, error) {
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Ethereum client: %w", err)
	}

	parsed, err := abi.JSON(strings.NewReader(AlticaRegistryABI))
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
		fromBlock:    0, // Will be set to latest block on start
	}, nil
}

// Start begins listening for events
func (l *EventListener) Start(ctx context.Context) error {
	// Get the latest block number
	latestBlock, err := l.client.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to get latest block: %w", err)
	}
	l.fromBlock = latestBlock

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

	// Convert namehash to domain name (you'll need to implement this)
	domain, err := l.namehashToDomain(event.Namehash)
	if err != nil {
		return fmt.Errorf("failed to convert namehash to domain: %w", err)
	}

	// Get the record from DHT
	record, found := l.store.Get(domain)
	if !found {
		l.log.WithField("domain", domain).Info("No matching record found in DHT")
		return nil
	}

	// Verify the signer matches
	if strings.ToLower(record.Signer) != strings.ToLower(event.Signer.Hex()) {
		l.log.WithFields(logrus.Fields{
			"domain":       domain,
			"dht_signer":   record.Signer,
			"event_signer": event.Signer.Hex(),
		}).Info("Signer mismatch")
		return nil
	}

	// Call oracleDecideSigner
	auth, err := l.getTransactOpts()
	if err != nil {
		return fmt.Errorf("failed to get transaction options: %w", err)
	}

	tx, err := l.contract.Transact(auth, "oracleDecideSigner", event.Namehash, event.Signer, true)
	if err != nil {
		return fmt.Errorf("failed to call oracleDecideSigner: %w", err)
	}

	l.log.WithFields(logrus.Fields{
		"domain":  domain,
		"tx_hash": tx.Hash().Hex(),
	}).Info("Called oracleDecideSigner")

	return nil
}

// namehashToDomain converts a namehash to a domain name
func (l *EventListener) namehashToDomain(namehash [32]byte) (string, error) {
	// For now, we'll use a simple hex encoding of the namehash
	// In production, you should implement proper namehash decoding
	domain := fmt.Sprintf("%x.alt", namehash)
	return domain, nil
}

// getTransactOpts returns transaction options for contract calls
func (l *EventListener) getTransactOpts() (*bind.TransactOpts, error) {
	// TODO: Load private key from environment or config
	privateKey, err := crypto.HexToECDSA("your-private-key-here")
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
