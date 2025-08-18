// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SSTORE2} from "solady@0.1.7/src/utils/SSTORE2.sol";

import {ISP1Verifier} from "./interfaces/ISP1Verifier.sol";
import {IRollup} from "./interfaces/IRollup.sol";

/// @custom:security-contact info@whynotswitch.com
contract Rollup is IRollup {
    uint256 public chainLength;

    constructor() {
        SSTORE2.writeDeterministic(hex"00", _pointer(this.account.selector, 0));
        SSTORE2.writeDeterministic(hex"00", _pointer(this.nonce.selector, 0));
        emit NewState(msg.sender, 0, 0, hex"", hex"", hex"");
    }

    function commitState(
        uint256 anchorBlock,
        bytes calldata accountBlob,
        bytes calldata nonceBlob,
        bytes calldata proof
    ) external {
        // verifies proofs via SP1 Groth16 verifier gateway; reverts here if proof is invalid
        ISP1Verifier(0x397A5f7f3dBd538f23DE225B51f532c34448dA9B).verifyProof(
            0x005120317542200324c9509e78315ad70799268f02d21504709c8973d2493203, // ToDo: set to actual SP1 program vKey
            bytes.concat(
                blockhash(anchorBlock), // ethereum state commitment
                stateAddress(chainLength, this.account.selector).codehash, // parent state commitment
                stateAddress(chainLength, this.nonce.selector).codehash, // parent state commitment
                hex"00", accountBlob, // proposed account state
                hex"00", nonceBlob // proposed nonce state
            ),
            proof
        );

        chainLength++;
        emit NewState(msg.sender, chainLength, anchorBlock, accountBlob, nonceBlob, proof);
        SSTORE2.writeDeterministic(accountBlob, _pointer(this.account.selector, chainLength));
        SSTORE2.writeDeterministic(nonceBlob, _pointer(this.nonce.selector, chainLength));
    }

    function account(uint256 tokenId) external view returns (bytes6) {
        return state(chainLength, this.account.selector, tokenId);
    }

    function nonce(uint256 tokenId) external view returns (bytes6) {
        return state(chainLength, this.nonce.selector, tokenId);
    }

    function latestStateAddress(uint256 io) external view returns (address) {
        return stateAddress(chainLength, io == 0 ? this.account.selector : this.nonce.selector);
    }

    function stateAddress(uint256 at, bytes4 selector) public view returns (address) {
        return SSTORE2.predictDeterministicAddress(_pointer(selector, at));
    }

    function state(uint256 at, bytes4 selector, uint256 tokenId) public view returns (bytes6) {
        address pointer = stateAddress(at, selector);
        if (tokenId == 0) return bytes6(bytes.concat(hex"00", SSTORE2.read(pointer, 0, 5)));
        uint256 index = (tokenId * 6) - 1;
        return bytes6(SSTORE2.read(pointer, index, index + 6));
    }

    function _pointer(bytes4 selector, uint256 at) private pure returns (bytes32) {
        return bytes32(abi.encodePacked(selector, uint224(at)));
    }
}
