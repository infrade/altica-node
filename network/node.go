package network

import (
	"context"
	"log"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	discovery "github.com/libp2p/go-libp2p/p2p/discovery/mdns"
)

type Node struct {
	Host   host.Host
	Ctx    context.Context
	PubSub *PubSubService
}

func NewNode(ctx context.Context) (*Node, error) {
	h, err := libp2p.New()
	if err != nil {
		return nil, err
	}

	node := &Node{
		Host: h,
		Ctx:  ctx,
	}

	// Setup mDNS for peer discovery
	if err := setupDiscovery(ctx, h); err != nil {
		log.Println("mDNS discovery error:", err)
	}

	// Attach pubsub
	ps, err := NewPubSubService(ctx, h)
	if err != nil {
		return nil, err
	}
	node.PubSub = ps

	log.Println("Node started with Peer ID:", h.ID().String())
	return node, nil
}

func setupDiscovery(ctx context.Context, h host.Host) error {
	s := discovery.NewMdnsService(h, "altica-mdns", &discoveryNotifee{h})
	return s.Start()
}

type discoveryNotifee struct {
	h host.Host
}

func (n *discoveryNotifee) HandlePeerFound(pi peer.AddrInfo) {
	log.Println("Discovered peer:", pi.ID.String())
	if err := n.h.Connect(context.Background(), pi); err != nil {
		log.Println("Failed to connect to peer:", err)
	}
}
