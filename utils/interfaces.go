package utils

import "github.com/ethereum/go-ethereum/common"

type Record interface {
	GetDomain() string
	GetSigner() common.Address
	GetNamehash() []byte
	GetSignedTx() []byte
}

type RecordStore interface {
	GetByNamehash(namehash []byte) (Record, bool)
}
