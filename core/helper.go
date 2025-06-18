package core

import (
	"fmt"
	"os"
	"path/filepath"
)

func GetDataDir() string {
	// Setup data directory
	dataDir := filepath.Join("..", ".altica")
	// Create data directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		fmt.Println("Error creating data directory:", err)
		os.Exit(1)
	}
	return dataDir
}
