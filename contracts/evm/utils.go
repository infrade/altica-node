package evm

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

type EVMTx2 struct {
	ChainID    *big.Int
	Nonce      uint64
	GasTipCap  *big.Int // maxPriorityFeePerGas
	GasFeeCap  *big.Int // maxFeePerGas
	Gas        uint64
	To         *common.Address
	Value      *big.Int
	Data       []byte
	AccessList []struct{}
	V, R, S    *big.Int
}

// Helper to create ABI types
func mustABIType(t string) abi.Type {
	typ, err := abi.NewType(t, "", nil)
	if err != nil {
		panic(err)
	}
	return typ
}

// GenerateBindingSignature generates a signature for submitting a binding to the AlticaRegistry contract
func GenerateBindingSignature(privateKey *ecdsa.PrivateKey, contractAddr common.Address, chainID int, namehash []byte, resolver common.Address, expiresAt uint64, timestamp uint64) ([]byte, error) {
	typeHashSlice := crypto.Keccak256([]byte("SubmitBinding(bytes32 namehash,address resolver,uint64 expiresAt,uint64 timestamp)"))
	var typeHash [32]byte
	copy(typeHash[:], typeHashSlice)

	var Namehash [32]byte
	copy(Namehash[:], namehash)

	structArgs := abi.Arguments{
		{Type: mustABIType("bytes32")},
		{Type: mustABIType("bytes32")},
		{Type: mustABIType("address")},
		{Type: mustABIType("uint256")},
		{Type: mustABIType("uint256")},
	}
	structPacked, err := structArgs.Pack(
		typeHash,
		Namehash,
		resolver,
		big.NewInt(int64(expiresAt)),
		big.NewInt(int64(timestamp)),
	)
	if err != nil {
		return nil, fmt.Errorf("abi.Pack struct: %w", err)
	}
	structHash := crypto.Keccak256(structPacked)

	// Domain separator
	domainTypeHashSlice := crypto.Keccak256([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"))
	var domainTypeHash [32]byte
	copy(domainTypeHash[:], domainTypeHashSlice)

	nameHashSlice := crypto.Keccak256([]byte("AlticaRegistry"))
	var nameHash [32]byte
	copy(nameHash[:], nameHashSlice)

	versionHashSlice := crypto.Keccak256([]byte("0"))
	var versionHash [32]byte
	copy(versionHash[:], versionHashSlice)

	domainArgs := abi.Arguments{
		{Type: mustABIType("bytes32")},
		{Type: mustABIType("bytes32")},
		{Type: mustABIType("bytes32")},
		{Type: mustABIType("uint256")},
		{Type: mustABIType("address")},
	}

	domainPacked, err := domainArgs.Pack(
		domainTypeHash,
		nameHash,
		versionHash,
		big.NewInt(int64(chainID)),
		contractAddr,
	)
	if err != nil {
		return nil, fmt.Errorf("abi.Pack domain: %w", err)
	}
	domainSeparator := crypto.Keccak256(domainPacked)

	// Digest
	digestBytes := []byte{0x19, 0x01}
	digestBytes = append(digestBytes, domainSeparator...)
	digestBytes = append(digestBytes, structHash...)
	digest := crypto.Keccak256(digestBytes)
	fmt.Printf("DomainSeparator: 0x%x\n", domainSeparator)
	fmt.Printf("Digest: 0x%x\n", digest)
	fmt.Printf("StructHash: 0x%x\n", structHash)

	// Sign
	signature, err := crypto.Sign(digest, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign binding: %w", err)
	}
	// Fix v value for EVM
	if signature[64] < 27 {
		signature[64] += 27
	}
	return signature, nil
}

// PreSignSubmitBindingTxEIP1559 pre-signs an EIP-1559 (type 2) EVM transaction for SubmitBinding
func PreSignSubmitBindingTxEIP1559(
	privateKey *ecdsa.PrivateKey,
	contractAddr common.Address,
	chainID int,
	namehash []byte,
	resolver common.Address,
	expiresAt uint64,
	timestamp uint64,
	sig []byte,
	nonce uint64,
	gasLimit uint64,
	maxFeePerGas *big.Int,
	maxPriorityFeePerGas *big.Int,
	value *big.Int,
) ([]byte, error) {
	contractABI := LoadABI()

	// Prepare arguments
	var Namehash [32]byte
	copy(Namehash[:], namehash)
	inputData, err := contractABI.Pack("SubmitBinding", Namehash, resolver, expiresAt, timestamp, sig)
	if err != nil {
		return nil, err
	}

	// Build EIP-1559 tx (type 2)
	txData := &types.EVMTx2{
		ChainID:   big.NewInt(int64(chainID)),
		Nonce:     nonce,
		GasTipCap: maxPriorityFeePerGas,
		GasFeeCap: maxFeePerGas,
		Gas:       gasLimit,
		To:        &contractAddr,
		Value:     value,
		Data:      inputData,
	}
	tx := types.NewTx(txData)

	// Sign
	signer := types.LatestSignerForChainID(big.NewInt(int64(chainID)))
	signedTx, err := types.SignTx(tx, signer, privateKey)
	if err != nil {
		return nil, err
	}

	// Encode
	signedTxBytes, err := signedTx.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return signedTxBytes, nil
}

func DecodeType2Tx(signedTx string) (EVMTx2, error) {
	raw := strings.TrimPrefix(signedTx, "0x")
	rawBytes, err := hex.DecodeString(raw)
	if err != nil {
		return EVMTx2{}, fmt.Errorf("Invalid hex: %v", err)
	}

	if len(rawBytes) == 0 || rawBytes[0] != 0x02 {
		return EVMTx2{}, fmt.Errorf("Not a Type 2 transaction (missing 0x02 prefix)")
	}

	txPayload := rawBytes[1:] // strip 0x02
	var tx EVMTx2

	err = rlp.DecodeBytes(txPayload, &tx)
	if err != nil {
		return EVMTx2{}, fmt.Errorf("Failed to decode tx: %v", err)
	}

	fmt.Println("=== Decoded Type 2 Transaction ===")
	fmt.Println("Nonce:              ", tx.Nonce)
	fmt.Println("To:                 ", tx.To.Hex())
	fmt.Println("Value (ETH):        ", weiToEth(tx.Value))
	fmt.Println("Gas Limit:          ", tx.Gas)
	fmt.Println("Max Fee Per Gas:    ", tx.GasFeeCap, "wei")
	fmt.Println("Max Priority Fee:   ", tx.GasTipCap, "wei")
	fmt.Println("Chain ID:           ", tx.ChainID)
	fmt.Println("Data (hex):         ", hex.EncodeToString(tx.Data))
	fmt.Println("Signature:")
	fmt.Println("  v: ", tx.V)
	fmt.Println("  r: ", tx.R)
	fmt.Println("  s: ", tx.S)
	return tx, nil
}

func weiToEth(wei *big.Int) string {
	eth := new(big.Float).Quo(new(big.Float).SetInt(wei), big.NewFloat(1e18))
	return eth.Text('f', 18)
}

// Validates the tx for submission
func (tx *EVMTx2) Validate() bool {
	// check:
	// 		nonce
	return true
}
