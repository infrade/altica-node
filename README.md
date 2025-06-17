# Altica Node

A decentralized domain name system for the Altica network.

## Building

```bash
make build
```

## Running

```bash
make run
```

## Testing

```bash
make test
```

## Binding CLI Tool

The binding CLI tool helps generate signatures for submitting domain bindings to the AlticaRegistry contract.

### Installation

```bash
make install-binding
```

This will install the tool as `altica-binding` in `/usr/local/bin/`.

### Usage

```bash
altica-binding \
  --domain <domain> \
  --resolver <address> \
  --expires-in <days> \
  --key <path>
```

#### Arguments

- `--domain`: Domain name (e.g., foo.alt)
- `--resolver`: Resolver contract address (hex)
- `--expires-in`: Expiration time in days (default: 365)
- `--key`: Path to private key file (hex)

#### Example

```bash
altica-binding \
  --domain example.alt \
  --resolver 0x1234567890123456789012345678901234567890 \
  --expires-in 365 \
  --key example.alt.pk.txt
```

#### Output

The tool outputs all values needed for the contract call:

```
Domain: example.alt
Namehash: 1234...
Resolver: 0x1234567890123456789012345678901234567890
Expires At: 1234567890
Timestamp: 1234567890
Signature: 0x1234...
```

### Private Key Format

The private key file should contain a hex-encoded private key without the "0x" prefix. For example:

```
1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
```

### Contract Integration

The output values can be used to call the `SubmitBinding` function on the AlticaRegistry contract:

```solidity
function SubmitBinding(
    bytes32 namehash,
    address resolver,
    uint64 expiresAt,
    uint64 timestamp,
    bytes calldata sig
)
``` 
