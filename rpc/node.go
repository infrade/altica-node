package rpc

import (
	"encoding/json"
)

func (s *RPCServer) handleNodeInfo(params json.RawMessage) (interface{}, error) {
	return map[string]interface{}{
		"id":        s.node.Host.ID().String(),
		"addresses": s.node.Host.Addrs(),
	}, nil
}

func (s *RPCServer) handleNodeStatus(params json.RawMessage) (interface{}, error) {
	return map[string]interface{}{
		"peers":     len(s.node.ListPeers()),
		"connected": s.node.Host.Network().Connectedness(s.node.Host.ID()),
	}, nil
}
