package core

import (
	"strings"

	"golang.org/x/crypto/sha3"
)

func keccak256(data []byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(data)
	return hash.Sum(nil)
}

// Namehash calculates the namehash of a domain name
func Namehash(name string) []byte {
	var node []byte = make([]byte, 32) // 32-byte zero hash

	if name == "" {
		return node
	}

	labels := strings.Split(name, ".")
	for i := len(labels) - 1; i >= 0; i-- {
		labelHash := keccak256([]byte(labels[i]))
		node = keccak256(append(node, labelHash...))
	}

	return node
}

type Resolver struct {
	Store *RecordStore
}

func NewResolver(store *RecordStore) *Resolver {
	return &Resolver{Store: store}
}

func (r *Resolver) Resolve(domain string) (string, bool) {
	record, ok := r.Store.Get(domain)
	if !ok {
		return "", false
	}
	return record.Bindings.A, true
}
