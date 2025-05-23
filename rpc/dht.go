package rpc

import (
	"encoding/json"
	"fmt"

	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p/core/peer"
)

type DHTFindPeerParams struct {
	PeerID string `json:"peer_id"`
}

type DHTProvideParams struct {
	Key string `json:"key"`
}

func (s *RPCServer) handleDHTFindPeer(params json.RawMessage) (interface{}, error) {
	var p DHTFindPeerParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	peerID, err := peer.Decode(p.PeerID)
	if err != nil {
		return nil, fmt.Errorf("invalid peer ID: %w", err)
	}

	peerInfo, err := s.node.DHT.FindPeer(s.node.Context, peerID)
	if err != nil {
		return nil, fmt.Errorf("peer not found: %w", err)
	}

	return peerInfo, nil
}

func (s *RPCServer) handleDHTProvide(params json.RawMessage) (interface{}, error) {
	var p DHTProvideParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	key := p.Key
	c, err := cid.Parse(key)
	if err != nil {
		return nil, fmt.Errorf("invalid key (not a CID): %w", err)
	}
	if err := s.node.DHT.Provide(s.node.Context, c, true); err != nil {
		return nil, fmt.Errorf("failed to provide: %w", err)
	}

	return "provided", nil
}

func (s *RPCServer) handleDHTFindProviders(params json.RawMessage) (interface{}, error) {
	var p DHTProvideParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	c, err := cid.Parse(p.Key)
	if err != nil {
		return nil, fmt.Errorf("invalid key (not a CID): %w", err)
	}

	providers := make([]peer.AddrInfo, 0)
	providerChan, err := s.node.DHT.FindProviders(s.node.Context, c)

	for _, info := range providerChan {
		providers = append(providers, info)
	}

	return providers, nil
}
