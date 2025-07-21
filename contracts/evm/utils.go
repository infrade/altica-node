package evm

import (
	"altica_node/utils"
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
)

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
	digest, err := GetDigest(namehash, resolver, expiresAt, timestamp, chainID, contractAddr)
	if err != nil {
		return nil, err
	}

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

func GetDigest(namehash []byte, resolver common.Address, expiresAt uint64, timestamp uint64, chainID int, contractAddr common.Address) ([]byte, error) {
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
	return digest, nil
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
	txData := &types.DynamicFeeTx{
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

func decodeSignedTx(signedTx []byte) (types.Transaction, error) {
	var tx *types.Transaction

	if signedTx[0] == 0x02 {
		// Typed transaction (EIP-1559)
		var inner types.DynamicFeeTx
		if err := rlp.DecodeBytes(signedTx[1:], &inner); err != nil {
			return types.Transaction{}, fmt.Errorf("RLP decode error: %v", err)
		}
		tx = types.NewTx(&inner)
	} else {
		// Legacy transaction (EIP-155)
		tx = new(types.Transaction)
		if err := tx.UnmarshalBinary(signedTx); err != nil {
			return types.Transaction{}, fmt.Errorf("Unmarshal error: %v", err)
		}
	}
	return *tx, nil

	// if len(rawBytes) == 0 || rawBytes[0] != 0x02 {
	// 	return EVMTx2{}, fmt.Errorf("Not a Type 2 transaction (missing 0x02 prefix)")
	// }

	// txPayload := rawBytes[1:] // strip 0x02
	// var tx EVMTx2

	// err = rlp.DecodeBytes(txPayload, &tx)
	// if err != nil {
	// 	return EVMTx2{}, fmt.Errorf("Failed to decode tx: %v", err)
	// }

	// fmt.Println("=== Decoded Type 2 Transaction ===")
	// fmt.Println("Nonce:              ", tx.Nonce)
	// fmt.Println("To:                 ", tx.To.Hex())
	// fmt.Println("Value (ETH):        ", weiToEth(tx.Value))
	// fmt.Println("Gas Limit:          ", tx.Gas)
	// fmt.Println("Max Fee Per Gas:    ", tx.GasFeeCap, "wei")
	// fmt.Println("Max Priority Fee:   ", tx.GasTipCap, "wei")
	// fmt.Println("Chain ID:           ", tx.ChainID)
	// fmt.Println("Data (hex):         ", hex.EncodeToString(tx.Data))
	// fmt.Println("Signature:")
	// fmt.Println("  v: ", tx.V)
	// fmt.Println("  r: ", tx.R)
	// fmt.Println("  s: ", tx.S)
	// return tx, nil
}

func weiToEth(wei *big.Int) string {
	eth := new(big.Float).Quo(new(big.Float).SetInt(wei), big.NewFloat(1e18))
	return eth.Text('f', 18)
}

func getFromAddress(tx types.Transaction) (common.Address, error) {
	// Need signer (depends on tx type)
	signer := types.LatestSignerForChainID(tx.ChainId())
	sender, err := types.Sender(signer, &tx)
	if err != nil {
		return common.Address{}, fmt.Errorf("cannot recover sender: %w", err)
	}
	return sender, nil
}

func ValidateSignedTx(record utils.Record) (bool, error) {
	tx, err := decodeSignedTx(record.GetSignedTx())
	if err != nil {
		return false, fmt.Errorf("Invalid signedTx, %v", err)
	}
	valid, err := _validateSignedTx(tx, record.GetSigner(), record.GetNamehash())
	if err != nil || !valid {
		return false, fmt.Errorf("signedTx validation failed, %v", err)
	}
	return valid, nil
}

// _validateSignedTx checks that the decoded transaction matches the expected parameters and is valid for submission
func _validateSignedTx(
	tx types.Transaction,
	expectedFrom common.Address,
	expectedNamehash []byte,
	// expectedGas uint64,
) (bool, error) {
	// Only support CHAIN_ID from env
	chainID, err := strconv.ParseInt(os.Getenv("EVM_CHAIN_ID"), 10, 64)
	if err != nil {
		return false, fmt.Errorf("Invalid ChainID %v", err)
	}
	expectedTo := common.HexToAddress(os.Getenv("EVM_ALTICA_REGISTRY_ADDRESS"))
	rpcURL := os.Getenv("EVM_RPC_URL")

	if tx.ChainId() == nil || tx.ChainId().Cmp(big.NewInt(chainID)) != 0 {
		return false, fmt.Errorf("unsupported chainID: got %v, want %d", tx.ChainId(), chainID)
	}

	// Value must be exactly 0.01 ETH
	expectedValue := big.NewInt(0).Mul(big.NewInt(1e15), big.NewInt(1)) // 0.001 ETH in wei
	if tx.Value() == nil || tx.Value().Cmp(expectedValue) == -1 {
		return false, fmt.Errorf("value mismatch: got %v, want 0.01 ETH", weiToEth(tx.Value()))
	}

	if tx.To() == nil || *tx.To() != expectedTo {
		return false, fmt.Errorf("to address mismatch: got %v, want %v", tx.To(), expectedTo)
	}
	// if tx.Gas() != expectedGas {
	// 	return false, fmt.Errorf("gas mismatch: got %d, want %d", tx.Gas(), expectedGas)
	// }

	fromAddress, err := getFromAddress(tx)
	if err != nil {
		return false, fmt.Errorf("Cannot get fromAddress %v", err)
	}
	if fromAddress != expectedFrom {
		return false, fmt.Errorf("fromAddress is not expected address")
	}

	// Fetch nonce from the blockchain
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return false, fmt.Errorf("failed to connect to Ethereum node: %w", err)
	}
	defer client.Close()
	ctx := context.Background()

	// ensure that there's code at the contract address
	if code, err := client.CodeAt(ctx, expectedTo, nil); err != nil {
		return false, fmt.Errorf("failed to get code at contract address: %w", err)
	} else if len(code) == 0 {
		return false, fmt.Errorf("no code found at contract address %s", expectedTo.Hex())
	}

	nonce, err := client.PendingNonceAt(ctx, expectedFrom)
	if err != nil {
		return false, fmt.Errorf("failed to fetch nonce: %w", err)
	}
	if tx.Nonce() != nonce {
		return false, fmt.Errorf("nonce mismatch: got %d, want %d (pending nonce from chain)", tx.Nonce(), nonce)
	}
	return validateTxData(client, tx, expectedNamehash, expectedFrom)
}

func getBytesArg(arg interface{}) ([]byte, bool) {
	switch v := arg.(type) {
	case [32]byte:
		var value [32]byte
		copy(value[:], v[:])
		return value[:], true
	case []byte:
		value := make([]byte, len(v))
		copy(value, v)
		return value, true
	default:
		return nil, false
	}
}

func validateTxData(client *ethclient.Client, tx types.Transaction, expectedNamehash []byte, signerAddress common.Address) (bool, error) {
	parsedABI := LoadABI()
	txData := tx.Data()
	chainID := int(tx.ChainId().Int64())
	contractAddr := tx.To()

	method, err := parsedABI.MethodById(txData[:4])
	if err != nil {
		return false, fmt.Errorf("failed to get called method from ABI: %v", err)
	}
	fmt.Println("Method:", method.Name)
	if method.Name != "SubmitBinding" {
		return false, fmt.Errorf("Called method in SignedTx is not 'SubmitBinding', it is '%s'", method.Name)
	}
	args, err := method.Inputs.Unpack(txData[4:])
	if err != nil {
		return false, fmt.Errorf("failed to decode args: %v", err)
	}

	namehash, ok0 := getBytesArg(args[0])
	sig, ok4 := getBytesArg(args[4])
	if !ok0 || !ok4 {
		return false, fmt.Errorf("Failed to cast args[0] or args[4] to []byte (signature)")
	}
	resolver, ok1 := args[1].(common.Address)
	if !ok1 {
		return false, fmt.Errorf("Failed to cast args[1] to common.Address")
	}
	expiresAt := args[2].(uint64)
	timestamp := args[3].(uint64)

	// Compare namehash slices using bytes.Equal
	if !bytes.Equal(namehash, expectedNamehash) {
		return false, fmt.Errorf("Invalid namehash in signedTx")
	} else if expiresAt <= timestamp {
		return false, fmt.Errorf("args[2] is less than or equal to args[3] in signedTx")
	}
	// check that timestamp is not in the future and not too far in the past (MAX_TIME_DRIFT is 15mins)
	time_now := uint64(time.Now().Unix())
	if timestamp > time_now {
		return false, fmt.Errorf("timestamp is in the future")
	} else if timestamp < time_now-uint64(12*60) { // 12 minutes in seconds
		return false, fmt.Errorf("timestamp is too far in the past")
	}

	digest, err := GetDigest(namehash, resolver, expiresAt, timestamp, chainID, *contractAddr)
	if err != nil {
		return false, fmt.Errorf("Cannot compute digest %v", err)
	}

	// Ecrecover signer
	// adjust v value if necessary to be either 0 or 1
	if len(sig) == 65 && sig[64] >= 27 {
		sig[64] -= 27
	}
	pubKeyBytes, err := crypto.Ecrecover(digest, sig)

	// negate
	if err != nil {
		return false, fmt.Errorf("Failed to ecrecover pubkey from signature: %v", err)
	}
	pubKey, err := crypto.UnmarshalPubkey(pubKeyBytes)
	if err != nil {
		return false, fmt.Errorf("Failed to unmarshal pubkey: %v", err)
	}
	recoveredAddr := crypto.PubkeyToAddress(*pubKey)
	if !bytes.Equal(recoveredAddr.Bytes(), signerAddress.Bytes()) {
		return false, fmt.Errorf("Signature does not match expected signer: got %s, want %s", recoveredAddr.Hex(), signerAddress.Hex())
	}

	// Try call the contract with the provided data
	return simulateTx(client, contractAddr, txData, nil)
}

func simulateTx(client *ethclient.Client, to *common.Address, data []byte, blockNumber *big.Int) (bool, error) {
	// try to get the revert reason
	revertReason, err := client.CallContract(context.Background(), ethereum.CallMsg{
		To:   to,
		Data: data,
	}, blockNumber)

	if err != nil {
		return false, fmt.Errorf("transaction reverted with reason: %w", err)
	} else if len(revertReason) > 0 {
		return false, fmt.Errorf("transaction reverted with reason: %s", string(revertReason))
	}
	return true, nil

}

// SubmitSignedTx submits a signed transaction to the blockchain and returns the tx hash
// If the transaction is reverted, returns the revert reason as part of the error
func SubmitSignedTx(signedTx []byte) (string, error) {
	rpcURL := os.Getenv("EVM_RPC_URL")
	if rpcURL == "" {
		return "", fmt.Errorf("EVM_RPC_URL environment variable is not set")
	}
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return "", fmt.Errorf("failed to connect to Ethereum node: %w", err)
	}
	defer client.Close()

	// Use the underlying RPC client to send the raw transaction
	rpcClient := client.Client()
	var txHash common.Hash
	err = rpcClient.CallContext(context.Background(), &txHash, "eth_sendRawTransaction", hexutil.Encode(signedTx))
	if err != nil {
		return "", fmt.Errorf("failed to send raw transaction: %w", err)
	}

	isPending := true
	var tx *types.Transaction
	// Wait for the transaction to be mined
	const maxRetries = 4
	for attempt := 1; isPending && attempt <= maxRetries; attempt++ {
		time.Sleep(time.Duration(2<<attempt) * time.Second) // exponential backoff: 4, 8, 16, 32 seconds
		// check the result of the transaction using the transaction hash, avoid using := to avoid shadowing
		tx, isPending, err = client.TransactionByHash(context.Background(), txHash)
		if err != nil {
			return "", fmt.Errorf("failed to get transaction by hash: %w", err)
		}
		if isPending && attempt == maxRetries {
			return "", fmt.Errorf("transaction is still pending: %s", txHash.Hex())
		}
		if tx == nil {
			return "", fmt.Errorf("transaction not found: %s", txHash.Hex())
		}
	}

	// Check if the transaction was reverted
	receipt, err := client.TransactionReceipt(context.Background(), txHash)
	if receipt.Status == 0 {
		// Transaction was reverted, try to get the revert reason
		reverted, err := simulateTx(client, tx.To(), tx.Data(), receipt.BlockNumber)
		if err != nil {
			return "", fmt.Errorf("transaction reverted with error: %w", err)
		}
		if reverted {
			return "", fmt.Errorf("transaction reverted without a reason")
		}
		return "", fmt.Errorf("transaction reverted with an unknown reason")
	}
	if err != nil {
		return "", fmt.Errorf("failed to get transaction receipt: %w", err)
	}
	return txHash.Hex(), nil
}
