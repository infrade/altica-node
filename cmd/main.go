package main

import (
	"flag"
	"fmt"
	"os"

	"altica_node/core"

	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	// Parse command line flags
	domain := flag.String("domain", "", "Domain name (e.g., foo.alt)")
	expiresIn := flag.Int("expires-in", 365, "Expiration time in days")
	privateKeyPath := flag.String("key", "", "Path to private key file (hex)")
	chainID := flag.Int("chain", 1, "Chain ID of the EVM chain")
	resolver := flag.String("resolver", "", "Resolver address for the domain at given chain")
	action := flag.String("action", "sign", "CMD action: sign or bind")
	nonce := flag.Uint64("nonce", 0, "Signer nonce")

	flag.Parse()

	// Validate required flags
	if *domain == "" || *privateKeyPath == "" {
		fmt.Println("Error: domain, and key are required")
		flag.Usage()
		os.Exit(1)
	}
	if *action == "bind" && *resolver == "" {
		fmt.Println("Error: resolver require when action is 'bind'")
		flag.Usage()
		os.Exit(1)
	}
	privateKey := core.LoadPrivateKey(*privateKeyPath)

	// Get signer address
	signerAddress := crypto.PubkeyToAddress(privateKey.PublicKey)
	fmt.Printf("Signer Address: %s\n", signerAddress.Hex())
	switch *action {
	case "bind":
		BindDomain(*domain, *resolver, *chainID, *expiresIn, *privateKey, *nonce)
	case "sign":
		SignDomain(*domain, *expiresIn, *privateKey)
	}
}
