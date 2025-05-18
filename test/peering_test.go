package test

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"altica_node/core"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPeerDiscoveryAndConnection(t *testing.T) {
	// Create two test nodes
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create first node
	priv1, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)

	node1, err := core.NewNode(ctx, core.NodeOptions{
		PrivateKey: priv1,
		DataDir:    t.TempDir(), // Use testing temporary directory
	})
	require.NoError(t, err)
	defer node1.Host.Close()

	// Create second node
	priv2, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)

	node2, err := core.NewNode(ctx, core.NodeOptions{
		PrivateKey: priv2,
		DataDir:    t.TempDir(),
	})
	require.NoError(t, err)
	defer node2.Host.Close()

	// Bootstrap both nodes
	err = node1.Bootstrap()
	require.NoError(t, err)

	err = node2.Bootstrap()
	require.NoError(t, err)

	// Wait for peer discovery
	t.Log("Waiting for peer discovery...")
	success := assertEventually(t, func() bool {
		peers1 := node1.ListPeers()
		peers2 := node2.ListPeers()
		return len(peers1) > 1 && len(peers2) > 1
	}, 20*time.Second)

	assert.True(t, success, "Peers should discover each other")

	// Verify bidirectional connectivity
	assert.Contains(t, node1.Host.Network().Peers(), node2.Host.ID(),
		"Node 1 should be connected to Node 2")
	assert.Contains(t, node2.Host.Network().Peers(), node1.Host.ID(),
		"Node 2 should be connected to Node 1")
}

// Helper function to assert condition eventually becomes true
func assertEventually(t *testing.T, condition func() bool, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(time.Second)
	}
	return false
}

func TestPeerDiscoveryWithMultipleNodes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	numNodes := 3
	nodes := make([]*core.Node, numNodes)

	// Create multiple nodes
	for i := 0; i < numNodes; i++ {
		priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
		require.NoError(t, err)

		node, err := core.NewNode(ctx, core.NodeOptions{
			PrivateKey: priv,
			DataDir:    t.TempDir(),
		})
		require.NoError(t, err)
		defer node.Host.Close()

		err = node.Bootstrap()
		require.NoError(t, err)

		nodes[i] = node
	}

	// Wait for peer discovery
	t.Log("Waiting for peer discovery...")
	success := assertEventually(t, func() bool {
		for _, node := range nodes {
			if len(node.ListPeers()) < numNodes-1 {
				return false
			}
		}
		return true
	}, 20*time.Second)

	assert.True(t, success, "All nodes should discover each other")

	// Verify full mesh connectivity
	for i, node := range nodes {
		for j, otherNode := range nodes {
			if i != j {
				assert.Contains(t, node.Host.Network().Peers(), otherNode.Host.ID(),
					"Node %d should be connected to Node %d", i, j)
			}
		}
	}
}
