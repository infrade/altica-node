package rpc

import (
	"encoding/json"
	"net/http"

	"altica_node/core"
)

type RPCServer struct {
	node *core.Node
}

type RPCRequest struct {
	JsonRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      interface{}     `json:"id"`
}

type RPCResponse struct {
	JsonRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func NewRPCServer(node *core.Node) *RPCServer {
	return &RPCServer{
		node: node,
	}
}

func (s *RPCServer) Start(address string) error {
	http.HandleFunc("/", s.handleRPC)
	return http.ListenAndServe(address, nil)
}

func (s *RPCServer) handleRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeRPCError(w, &req, -32700, "Parse error")
		return
	}

	if req.JsonRPC != "2.0" {
		writeRPCError(w, &req, -32600, "Invalid Request")
		return
	}

	handler, exists := s.methods()[req.Method]
	if !exists {
		writeRPCError(w, &req, -32601, "Method not found")
		return
	}

	result, err := handler(req.Params)
	if err != nil {
		writeRPCError(w, &req, -32603, err.Error())
		return
	}

	writeRPCResponse(w, &req, result)
}

func (s *RPCServer) methods() map[string]func(json.RawMessage) (interface{}, error) {
	return map[string]func(json.RawMessage) (interface{}, error){
		// Peers management
		"peers.list":  s.handlePeersList,
		"peers.count": s.handlePeersCount,

		// Node management
		"node.info":   s.handleNodeInfo,
		"node.status": s.handleNodeStatus,

		// Record management
		"records.get":    s.handleRecordGet,
		"records.set":    s.handleRecordSet,
		"records.status": s.handleRecordStatus,

		// DHT operations
		"dht.findPeer":      s.handleDHTFindPeer,
		"dht.provide":       s.handleDHTProvide,
		"dht.findProviders": s.handleDHTFindProviders,
	}
}

// Helper functions
func writeRPCError(w http.ResponseWriter, req *RPCRequest, code int, message string) {
	resp := RPCResponse{
		JsonRPC: "2.0",
		Error: &RPCError{
			Code:    code,
			Message: message,
		},
		ID: req.ID,
	}
	writeJSON(w, &resp)
}

func writeRPCResponse(w http.ResponseWriter, req *RPCRequest, result interface{}) {
	resp := RPCResponse{
		JsonRPC: "2.0",
		Result:  result,
		ID:      req.ID,
	}
	writeJSON(w, &resp)
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
