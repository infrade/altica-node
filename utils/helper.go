package utils

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"runtime"

	"github.com/ethereum/go-ethereum/crypto"
)

func TraceAuto() func() {
	pc, _, _, _ := runtime.Caller(1)
	fn := runtime.FuncForPC(pc).Name()
	start := time.Now()
	log.Printf("→ Enter %s", fn)
	return func() {
		log.Printf("← Exit  %s (took %s)", fn, time.Since(start))
	}
}

func GetDataDir() string {
	// Setup data directory
	dataDir := filepath.Join(".", ".altica")
	// Create data directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		fmt.Println("Error creating data directory:", err)
		os.Exit(1)
	}
	return dataDir
}

func LoadPrivateKey(privateKeyPath string) *ecdsa.PrivateKey {
	// Read private key
	keyBytes, err := os.ReadFile(privateKeyPath)
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
	return privateKey
}
