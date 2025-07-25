package core

import (
	"fmt"
)

// ChainIDToBlockchainName maps EVM chain IDs to their blockchain names
var ChainIDToBlockchainName = map[uint]string{
	1:          "ethereum",
	56:         "bsc",
	137:        "polygon",
	42161:      "arbitrum",
	10:         "optimism",
	43114:      "avalanche",
	8453:       "base",
	324:        "zksync",
	59144:      "linea",
	534352:     "scroll",
	25:         "cronos",
	250:        "fantom",
	100:        "gnosis",
	5000:       "mantle",
	1313161554: "aurora",
}

type Binding struct {
	Addresses   map[uint]string `json:"addresses"`
	ContentHash string          `json:"contentHash"`
	TXT         string          `json:"TXT"`
	A           string          `json:"A"`
}

// ValidateAddressesChainIDs checks that all keys in Addresses are valid chain IDs
func (b *Binding) ValidateAddressesChainIDs() error {
	for chainID := range b.Addresses {
		if _, ok := ChainIDToBlockchainName[chainID]; !ok {
			return fmt.Errorf("invalid chain_id in Addresses: %d", chainID)
		}
	}
	return nil
}
