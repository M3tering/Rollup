// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts ^5.0.0
pragma solidity ^0.8.37;

interface IRollup {
    error InvalidBlobs();
    error OversizeBlobs();
    
    uint256 public constant QUOTA = 6; 
    address public constant SP1_GROTH16_GATEWAY = 0x397A5f7f3dBd538f23DE225B51f532c34448dA9B;
    bytes32 public constant SP1_PROGRAM_VKEY = 0x005120317542200324c9509e78315ad70799268f02d21504709c8973d2493203; // ToDo: set to actual SP1 program vKey


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

    function state(uint256 at, uint256 io, uint256 tokenId) external view returns (bytes6);

    function stateAddress(uint256 at, uint256 io) external view returns (address);
}
