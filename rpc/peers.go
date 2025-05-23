package rpc

import (
	"encoding/json"
)

func (s *RPCServer) handlePeersList(params json.RawMessage) (interface{}, error) {
	peers := s.node.ListPeers()
	return peers, nil
}

func (s *RPCServer) handlePeersCount(params json.RawMessage) (interface{}, error) {
	peers := s.node.ListPeers()
	return len(peers), nil
}
