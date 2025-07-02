package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"altica_node/core"
)

func SignDomain(domain string, expiresIn int, pk ecdsa.PrivateKey) {
	// Create record
	record := &core.Record{
		Domain: domain,
		TTL:    time.Duration(expiresIn) * 24 * time.Hour,
	}

	// Sign the record
	if err := record.Sign(&pk); err != nil {
		fmt.Printf("Failed to sign record: %v\n", err)
		os.Exit(1)
	}

	// Get the signer address
	signerAddr, err := record.GetSignerAddress()
	if err != nil {
		fmt.Printf("Failed to get signer address: %v\n", err)
		os.Exit(1)
	}

	// Print the results
	fmt.Printf("Domain: %s\n", record.Domain)
	fmt.Printf("Signer Address: %s\n", signerAddr.Hex())
	fmt.Printf("Signature: 0x%s\n", hex.EncodeToString(record.Signature))
	fmt.Printf("Public Key: 0x%s\n", hex.EncodeToString(record.PublicKey))

	// Verify the signature
	if record.Verify() {
		fmt.Println("\nSignature verification: SUCCESS")
	} else {
		fmt.Println("\nSignature verification: FAILED")
	}

	// Print the full record as JSON
	recordJSON, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		fmt.Printf("Failed to marshal record: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\nFull Record:\n%s\n", string(recordJSON))
}
