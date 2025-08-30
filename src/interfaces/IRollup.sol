// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts ^5.0.0
pragma solidity ^0.8.28;

interface IRollup {
    event NewState(
        address indexed from,
        bytes32 indexed anchorBlock,
        uint256 indexed chainLength,
        bytes accountBlob,
        bytes nonceBlob,
        bytes proof
    );

    function commitState(
        bytes calldata accountBlob,
        bytes calldata nonceBlob,
        bytes calldata proof
    ) external;

    function anchorBlock() external view returns (bytes32);

    function chainLength() external view returns (uint256);

    function account(uint256 tokenId) external view returns (bytes6);

    function nonce(uint256 tokenId) external view returns (bytes6);

    function latestStateAddress(uint256 io) external view returns (address);

    function state(uint256 at, bytes4 selector, uint256 tokenId) external view returns (bytes6);

    function stateAddress(uint256 at, bytes4 selector) external view returns (address);
}
