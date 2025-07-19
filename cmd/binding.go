package main

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"os"
	"time"

	"altica_node/contracts/evm"
	"altica_node/core"

	"github.com/ethereum/go-ethereum/common"
)

func BindDomain(domain string, resolver string, chainID int, expiresIn int, pk ecdsa.PrivateKey, nonce uint64) {
	// Create record for namehash calculation
	record := &core.Record{
		Domain:    domain,
		Namehash:  core.Namehash(domain),
		TTL:       time.Duration(expiresIn) * 24 * time.Hour,
		Signature: nil,
		PublicKey: nil,
	}

	// Parse resolver address
	resolverAddr := common.HexToAddress(resolver)

	// Calculate timestamps
	now := uint64(time.Now().Unix())
	expiresAt := now + uint64(expiresIn*24*60*60)

	// Get contract address from environment
	_contractAddr := os.Getenv("EVM_ALTICA_REGISTRY_ADDRESS")
	if _contractAddr == "" {
		fmt.Printf("EVM_ALTICA_REGISTRY_ADDRESS environment variable is required")
		os.Exit(1)
	}

	contractAddr := common.HexToAddress(_contractAddr)

	// Sign the record
	if err := record.Sign(&pk); err != nil {
		fmt.Printf("Failed to sign record: %v\n", err)
		os.Exit(1)
	}

	// Output results
	fmt.Printf("Domain: %s\n", domain)
	fmt.Printf("Namehash: %x\n", record.Namehash)
	fmt.Printf("Resolver: %s\n", resolverAddr.Hex())
	fmt.Printf("Expires At: %d\n", expiresAt)
	fmt.Printf("Timestamp: %d\n", now)
	fmt.Printf("Signature: 0x%x\n", record.Signature)
	fmt.Printf("PublicKey: 0x%x\n", record.PublicKey)

	gasLimit := uint64(250_000)                      // Enough for EIP-712 bind()
	var maxPriorityFeePerGas int64 = 2_000_000_000   // 2 Gwei tip
	var baseFee int64 = 15_000_000_000               // 15 Gwei base fee (can query or estimate)
	maxFeePerGas := baseFee*2 + maxPriorityFeePerGas // 32 Gwei total
	var value int64 = 1000000000000000               // 0.001 ETH

	// Generate signature
	signature, err := evm.GenerateBindingSignature(
		&pk,
		contractAddr,
		chainID,
		record.Namehash,
		resolverAddr,
		expiresAt,
		now,
	)
	if err != nil {
		fmt.Printf("Error generating signature: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("EVM Signature : 0x%x\n", signature)
	fmt.Printf("EVM Signature length: %d\n", len(signature))
	fmt.Printf("EVM Signature v: %d\n", signature[64])

	signedTx, err := evm.PreSignSubmitBindingTxEIP1559(
		&pk,
		contractAddr,
		chainID,
		record.Namehash,
		resolverAddr,
		expiresAt,
		now,
		signature,
		nonce,
		gasLimit,
		big.NewInt(maxFeePerGas),
		big.NewInt(maxPriorityFeePerGas),
		big.NewInt(value),
	)
	if err != nil {
		fmt.Printf("Error pre-signing tx: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("signedTx: 0x%x\n", signedTx)
}
