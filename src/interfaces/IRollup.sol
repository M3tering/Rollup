// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

interface IM3ter {
    function ownerOf(uint256 id) external view returns (address);
}

interface IRollup {
    error InvalidEncoding();
    error InvalidUpdate();
    error Unauthorized();
    event KeyChanged(uint64 indexed id, bytes32 key);
    event StateCommitted(bytes updates);

    function commitState(bytes calldata updates, bytes calldata proof) external;
    function setPublicKey(uint64 id, bytes32 key) external;

    function words(uint256 slot) external view returns (uint256);
    function wordCount() external view returns (uint256);
    function publicKey(uint64 id) external view returns (bytes32);
    function account(uint64 id) external view returns (uint40);
    function nonce(uint64 id) external view returns (uint24);
    function state(uint64 id, uint256 io) external view returns (uint40);
}
