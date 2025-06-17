package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"altica_node/core"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	// Parse command line flags
	domain := flag.String("domain", "", "Domain name (e.g., foo.alt)")
	resolver := flag.String("resolver", "", "Resolver address (hex)")
	expiresIn := flag.Int("expires-in", 365, "Expiration time in days")
	privateKeyPath := flag.String("key", "", "Path to private key file (hex)")
	flag.Parse()

	// Validate required flags
	if *domain == "" || *resolver == "" || *privateKeyPath == "" {
		fmt.Println("Error: domain, resolver, and key are required")
		flag.Usage()
		os.Exit(1)
	}

	// Read private key
	keyBytes, err := os.ReadFile(*privateKeyPath)
	if err != nil {
		fmt.Printf("Error reading private key: %v\n", err)
		os.Exit(1)
	}
	// Trim whitespace and newlines
	privateKeyHex := strings.TrimSpace(string(keyBytes))

	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		fmt.Printf("Error decoding private key: %v\n", err)
		os.Exit(1)
	}
	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		fmt.Printf("Error converting private key: %v\n", err)
		os.Exit(1)
	}
	// Get signer address
	signerAddress := crypto.PubkeyToAddress(privateKey.PublicKey)
	fmt.Printf("Signer Address: %s\n", signerAddress.Hex())

	// Create record for namehash calculation
	record := &core.Record{
		Domain:    *domain,
		Namehash:  core.Namehash(*domain),
		TTL:       time.Duration(*expiresIn) * 24 * time.Hour,
		Signature: nil,
		PublicKey: nil,
	}
	if err != nil {
		fmt.Printf("Error creating record: %v\n", err)
		os.Exit(1)
	}

	// Parse resolver address
	resolverAddr := common.HexToAddress(*resolver)

	// Calculate timestamps
	now := uint64(time.Now().Unix())
	expiresAt := now + uint64(*expiresIn*24*60*60)

	// Generate signature
	signature, err := record.GenerateBindingSignature(privateKey, resolverAddr, expiresAt, now)
	if err != nil {
		fmt.Printf("Error generating signature: %v\n", err)
		os.Exit(1)
	}

	// Output results
	fmt.Printf("Domain: %s\n", *domain)
	fmt.Printf("Namehash: %x\n", record.Namehash)
	fmt.Printf("Resolver: %s\n", resolverAddr.Hex())
	fmt.Printf("Expires At: %d\n", expiresAt)
	fmt.Printf("Timestamp: %d\n", now)
	fmt.Printf("Signature: 0x%x\n", signature)
	fmt.Printf("Signature length: %d\n", len(signature))
	fmt.Printf("Signature v: %d\n", signature[64])
}
