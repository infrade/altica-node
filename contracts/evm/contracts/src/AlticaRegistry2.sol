// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract AlticaDomainBinder {
    struct Binding {
        string domain;
        address wallet;
        uint256 expiresAt;
    }

    mapping(string => Binding) public bindings;
    address public oracle;

    uint256 public pricePerChar = 0.01 ether;
    uint256 public bindingDuration = 365 days;

    event Bound(string indexed domain, address indexed wallet, uint256 expiresAt);

    modifier onlyOracle() {
        require(msg.sender == oracle, "Not oracle");
        _;
    }

    constructor(address _oracle) {
        oracle = _oracle;
    }

    /// Called by user or frontend with off-chain signature + domain + wallet
    function bind(
        string memory domain,
        address wallet,
        uint256 expiresAt,
        uint256 timestamp,
        bytes memory signature
    ) external payable {
        require(block.timestamp < timestamp + 10 minutes, "Expired request");
        require(msg.value >= price(domain), "Insufficient fee");

        // Off-chain registered domain must be signed by the user who owns it
        bytes32 messageHash = keccak256(abi.encodePacked(domain, wallet, timestamp));
        address signer = recoverSigner(messageHash, signature);

        require(signer == wallet, "Invalid signature");

        bindings[domain] = Binding(domain, wallet, block.timestamp + bindingDuration);
        emit Bound(domain, wallet, block.timestamp + bindingDuration);
    }

    function price(string memory domain) public view returns (uint256) {
        return bytes(domain).length * pricePerChar;
    }

    function getBinding(string memory domain) external view returns (address wallet, uint256 expiresAt) {
        Binding memory b = bindings[domain];
        if (block.timestamp > b.expiresAt) {
            return (address(0), 0);
        }
        return (b.wallet, b.expiresAt);
    }

    /// Can be used by the oracle to update expiration or address (optional)
    function forceUpdate(string memory domain, address wallet, uint256 newExpiry) external onlyOracle {
        bindings[domain] = Binding(domain, wallet, newExpiry);
        emit Bound(domain, wallet, newExpiry);
    }

    /// ECDSA signature recovery
    function recoverSigner(bytes32 message, bytes memory sig) internal pure returns (address) {
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));
        (bytes32 r, bytes32 s, uint8 v) = splitSig(sig);
        return ecrecover(ethHash, v, r, s);
    }

    function splitSig(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Invalid signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }

    function withdraw() external {
        require(msg.sender == oracle, "Only oracle");
        payable(oracle).transfer(address(this).balance);
    }
}
