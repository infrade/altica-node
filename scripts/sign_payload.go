package main

import (
	"altica_node/core"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

type Payload struct {
	Domain   string                 `json:"domain"`
	TTL      time.Duration          `json:"ttl"`
	Mappings map[string]interface{} `json:"mappings"`
}

func main() {
	// Load private key from environment or file
	privateKeyHex := os.Getenv("PRIVATE_KEY")
	if privateKeyHex == "" {
		fmt.Println("Please set PRIVATE_KEY environment variable")
		os.Exit(1)
	}

	// Remove "0x" prefix if present
	if len(privateKeyHex) > 2 && privateKeyHex[:2] == "0x" {
		privateKeyHex = privateKeyHex[2:]
	}

	// Decode private key
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		fmt.Printf("Failed to decode private key: %v\n", err)
		os.Exit(1)
	}

	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		fmt.Printf("Failed to create private key: %v\n", err)
		os.Exit(1)
	}

	// Create a sample payload
	payload := Payload{
		Domain: "example.alt",
		TTL:    time.Hour * 24,
		Mappings: map[string]interface{}{
			"A":   "1.2.3.4",
			"TXT": "v=spf1 include:_spf.google.com ~all",
		},
	}

	// Create record
	record := &core.Record{
		Domain:   payload.Domain,
		TTL:      payload.TTL,
		Mappings: payload.Mappings,
		Metadata: map[string]interface{}{
			"created_at": time.Now().UTC().Format(time.RFC3339),
		},
	}

	// Sign the record
	if err := record.Sign(privateKey); err != nil {
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
