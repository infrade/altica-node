// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import { OwnableUpgradeable } from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import { EIP712Upgradeable } from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

// TODO: add access control
contract AlticaRegistry is Initializable, OwnableUpgradeable, EIP712Upgradeable {
    using ECDSA for bytes32;
    enum Status {
        pending,
        active
    }
    struct Binding {
        address resolver;
        uint64 expiresAt;
        address signer;
        Status status;
    }

    mapping(bytes32 => Binding) public bindings;
    mapping(bytes32 => address) public bindingSigner;

    bytes32 private BIND_TYPEHASH;
    uint64 public MAX_TIME_DRIFT;


    event SubmittedBinding(bytes32 indexed namehash, address indexed signer, uint64 expiresAt);
    event DeletedBinding(bytes32 indexed namehash, address indexed signer);
    event NameBound(bytes32 indexed namehash, address indexed resolver, uint64 expiresAt);
    event SignerBound(bytes32 indexed namehash, address indexed signer);

    function initialize() public initializer {
        BIND_TYPEHASH  = keccak256(
        "SubmitBinding(bytes32 namehash,address resolver,uint64 expiresAt,uint64 timestamp)"
    );
        MAX_TIME_DRIFT = 15 minutes;
        __Ownable_init(msg.sender);
        __EIP712_init("AlticaRegistry", "0");
    }

    /// @notice Submits Binding of a namehash to a resolver via off-chain signature
    /// @param namehash The name's bytes32 hash (e.g., namehash of "foo.alt")
    /// @param resolver Address to resolve this name    
    /// @param expiresAt Unix timestamp when this binding should expire
    /// @param timestamp Time when the message was signed
    /// @param sig Signature by resolver authorizing the binding
    function SubmitBinding(
        bytes32 namehash,
        address resolver,
        uint64 expiresAt,
        uint64 timestamp,
        bytes calldata sig
    ) external {
        require(block.timestamp <= timestamp + MAX_TIME_DRIFT, "Stale signature");

        Binding memory current = bindings[namehash];
        require(current.expiresAt < block.timestamp, "Name already bound");
        
        (, bytes32 digest) = computeStructHashAndDigest(
            namehash, resolver, expiresAt, timestamp
        );
        address signer = ECDSA.recover(digest, sig);
        bindings[namehash] = Binding(resolver, expiresAt, signer, Status.pending);

        emit SubmittedBinding(namehash, signer, expiresAt);
    }

    function computeStructHashAndDigest(bytes32 namehash, address resolver, uint64 expiresAt, uint64 timestamp) public view returns (bytes32, bytes32) {
        bytes32 structHash = keccak256(abi.encode(
            BIND_TYPEHASH,
            namehash,
            resolver,
            expiresAt,
            timestamp
        ));
        bytes32 digest = _hashTypedDataV4(structHash);
        return (structHash, digest);
    }
    
    function debugDomainSeparator() public view returns (bytes32) {
       return _domainSeparatorV4();
    }

    function finalizeBinding(bytes32 namehash) external onlyOwner {
        Binding storage b = bindings[namehash];
        address signer = bindingSigner[namehash];

        require(signer != address(0), "Signer not broadcasted");
        require(signer == bindingSigner[namehash], "Invalid signature");
        b.status = Status.active;

        emit NameBound(namehash, b.resolver, b.expiresAt);
    }

    /// @notice Resolve the current resolver for a namehash
    function resolve(bytes32 namehash) external view returns (address) {
        if (bindingSigner[namehash] == address(0)) {
            return address(0);
        }
        Binding memory b = bindings[namehash];
        if (b.expiresAt < block.timestamp) {
            return address(0);
        }
        return b.resolver;
    }

    function oracleUnbind(bytes32 namehash) external onlyOwner {
        Binding memory b = bindings[namehash];
        if (b.expiresAt < block.timestamp) {
            delete bindings[namehash];
            delete bindingSigner[namehash];
        }
    }
    
    function oracleDecideSigner(bytes32 namehash, address signer, bool accepted) external onlyOwner {
        if (!accepted) {
            delete bindings[namehash];
            emit DeletedBinding(namehash, signer);
        }
        require(bindingSigner[namehash] == address(0), "Signer exists for binding");
        bindingSigner[namehash] = signer;
        emit SignerBound(namehash, signer);
    }
}
