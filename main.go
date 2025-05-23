package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"altica_node/core"
	"altica_node/rpc"

	"github.com/libp2p/go-libp2p/core/crypto"
)

func main() {
	// Parse command line flags
	port := flag.Int("port", 6361, "RPC server port")
	flag.Parse()

	ctx := context.Background()

	// Setup data directory
	dataDir := filepath.Join(".", ".altica")

	// Create data directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		fmt.Println("Error creating data directory:", err)
		os.Exit(1)
	}

	// Load or generate private key
	privKeyFile := filepath.Join(dataDir, "node.key")
	var priv crypto.PrivKey

	if keyData, err := os.ReadFile(privKeyFile); err == nil {
		priv, err = crypto.UnmarshalPrivateKey(keyData)
		if err != nil {
			fmt.Println("Error reading private key:", err)
			os.Exit(1)
		}
	} else {
		// Generate new key if none exists
		priv, _, err = crypto.GenerateEd25519Key(rand.Reader)
		if err != nil {
			fmt.Println("Error generating private key:", err)
			os.Exit(1)
		}

		// Save the private key
		keyBytes, err := crypto.MarshalPrivateKey(priv)
		if err != nil {
			fmt.Println("Error marshaling private key:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(privKeyFile, keyBytes, 0600); err != nil {
			fmt.Println("Error saving private key:", err)
			os.Exit(1)
		}
	}

	// Create node with persistent storage and private key
	node, err := core.NewNode(ctx, core.NodeOptions{
		PrivateKey: priv,
		DataDir:    dataDir,
	})
	if err != nil {
		fmt.Println("Error creating node:", err)
		os.Exit(1)
	}

	err = node.Bootstrap()
	if err != nil {
		fmt.Println("Error bootstrapping:", err)
		os.Exit(1)
	}

	err = node.SubscribeToRecords()
	if err != nil {
		fmt.Println("Error subscribing to records:", err)
		os.Exit(1)
	}

	// Start RPC server
	rpcServer := rpc.NewRPCServer(node)
	go func() {
		addr := fmt.Sprintf(":%d", *port)
		if err := rpcServer.Start(addr); err != nil {
			fmt.Printf("Failed to start RPC server: %s\n", err)
			os.Exit(1)
		}
	}()

	fmt.Println("Altica P2P node is running with ID:", node.Host.ID())
	fmt.Printf("RPC server listening on :%d\n", *port)

	// After node setup and bootstrap
	go func() {
		for {
			time.Sleep(time.Second * 30)
			fmt.Println("\n=== Current Peers ===")
			node.PrettyPrintPeers()
		}
	}()

	// Wait for interrupt
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
}
