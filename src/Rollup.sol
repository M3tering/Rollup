// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;
import {IRollup, IM3ter} from "./interfaces/IRollup.sol";
import {ISP1Verifier} from "./interfaces/ISP1Verifier.sol";

/// @notice Four uint40 Wh accounts / uint24 nonces per word; full owner-controlled keys.
contract Rollup is IRollup {
    uint256[] public words;
    mapping(uint64 => bytes32) public publicKey;
    // TODO: replace with the target chain's audited SP1 verifier before deployment.
    ISP1Verifier public constant VERIFIER = ISP1Verifier(address(0x1111));
    // TODO: derive from the final prover program ELF; this placeholder is not a valid deployment key.
    bytes32 public constant SP1_PROGRAM_VKEY = bytes32(uint256(1));
    // TODO: replace with the M3ter NFT deployment on the target chain.
    address public constant M3ter = address(0x2222);
    uint256 public constant MAX_SLOT = type(uint32).max;

    /// @dev Records: uint32 slot (BE), uint256 new value (BE), strictly ascending.
    /// Transcript: chainId(32), this(20), then slot(4), old(32), new(32), usedKeysHash(32).
    /// Verification is STATICCALL; failure atomically rolls back provisional writes.
    function commitState(bytes calldata updates, bytes calldata proof) external {
        if (updates.length == 0 || updates.length % 36 != 0) revert InvalidEncoding();
        uint256 count = updates.length / 36;
        bytes memory transcript = new bytes(52 + 100 * count);
        uint256 baseSlot;
        assembly ("memory-safe") {
            mstore(add(transcript, 32), chainid())
            mstore(add(transcript, 64), shl(96, address()))
            mstore(0, words.slot)
            baseSlot := keccak256(0, 32)
        }
        uint256 previous;
        for (uint256 i; i < count; ++i) {
            uint256 slot;
            uint256 value;
            uint256 old;
            assembly ("memory-safe") {
                let record := add(updates.offset, mul(i, 36))
                slot := shr(224, calldataload(record))
                value := calldataload(add(record, 4))
                old := sload(add(baseSlot, slot))
            }
            if ((i != 0 && slot <= previous) || value <= old) revert InvalidUpdate();
            previous = slot;
            bytes32 keysHash = _keysHash(slot, old ^ value);
            assembly ("memory-safe") {
                let dest := add(add(transcript, 84), mul(i, 100))
                mstore(dest, shl(224, slot))
                mstore(add(dest, 4), old)
                mstore(add(dest, 36), value)
                mstore(add(dest, 68), keysHash)
                sstore(add(baseSlot, slot), value)
            }
        }
        if (previous >= words.length) {
            assembly ("memory-safe") { sstore(words.slot, add(previous, 1)) }
        }
        // ISP1Verifier declares verifyProof view: compiler emits STATICCALL, with a code-existence check.
        VERIFIER.verifyProof(SP1_PROGRAM_VKEY, abi.encodePacked(keccak256(transcript)), proof);
        emit StateCommitted(updates);
    }

    function setPublicKey(uint64 id, bytes32 key) external {
        if (id / 4 > MAX_SLOT) revert InvalidUpdate();
        if (IM3ter(M3ter).ownerOf(id) != msg.sender) revert Unauthorized();
        publicKey[id] = key;
        emit KeyChanged(id, key);
    }

    function wordCount() external view returns (uint256) {
        return words.length;
    }

    function account(uint64 id) external view returns (uint40) {
        return uint40(_pair(id));
    }

    function nonce(uint64 id) external view returns (uint24) {
        return uint24(_pair(id) >> 40);
    }

    function state(uint64 id, uint256 io) external view returns (uint40) {
        uint256 pair = _pair(id);
        return io == 0 ? uint40(pair) : uint40(uint24(pair >> 40));
    }

    function _pair(uint64 id) private view returns (uint256) {
        uint256 slot = id / 4;
        return slot < words.length ? words[slot] >> (64 * (id % 4)) : 0;
    }

    function _keysHash(uint256 slot, uint256 changed) private view returns (bytes32 hash) {
        // Reuse temporary memory instead of allocating 128 bytes on every iteration.
        // slot is decoded as uint32, so all four meter IDs fit safely in uint64.
        assembly ("memory-safe") {
            let first := mul(slot, 4)
            let buffer := mload(0x40)
            mstore(buffer, 0)
            mstore(add(buffer, 32), 0)
            mstore(add(buffer, 64), 0)
            mstore(add(buffer, 96), 0)
            mstore(32, publicKey.slot)
            if and(changed, 0xffffffffffffffff) {
                mstore(0, first)
                mstore(buffer, sload(keccak256(0, 64)))
            }
            if and(shr(64, changed), 0xffffffffffffffff) {
                mstore(0, add(first, 1))
                mstore(add(buffer, 32), sload(keccak256(0, 64)))
            }
            if and(shr(128, changed), 0xffffffffffffffff) {
                mstore(0, add(first, 2))
                mstore(add(buffer, 64), sload(keccak256(0, 64)))
            }
            if shr(192, changed) {
                mstore(0, add(first, 3))
                mstore(add(buffer, 96), sload(keccak256(0, 64)))
            }
            hash := keccak256(buffer, 128)
        }
    }
}
