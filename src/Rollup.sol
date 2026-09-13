// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {LibRLP} from "solady@0.1.7/src/utils/LibRLP.sol";
import {SSTORE2} from "solady@0.1.7/src/utils/SSTORE2.sol";

import {ISP1Verifier} from "./interfaces/ISP1Verifier.sol";
import {IRollup} from "./interfaces/IRollup.sol";

/// @custom:security-contact info@whynotswitch.com
contract Rollup is IRollup {
    bytes32 public anchorBlock;
    uint256 public chainLength;
    bytes constant incipit = hex"00";
    address constant SP1_GROTH16_GATEWAY = 0x397A5f7f3dBd538f23DE225B51f532c34448dA9B;
    bytes32 constant SP1_PROGRAM_VKEY = 0x005120317542200324c9509e78315ad70799268f02d21504709c8973d2493203; // ToDo: set to actual SP1 program vKey

    constructor() {
        anchorBlock = blockhash(block.number - 1);
        SSTORE2.write(incipit);  //this contract nonce = 2x chainLength +1
        SSTORE2.write(incipit);  //this contract nonce = 2x chainLength +2
        emit NewState(msg.sender, hex"", 0, incipit, incipit, incipit);
    }

    function commitState(bytes calldata accountBlob, bytes calldata nonceBlob, bytes calldata proof) external {
        // verifies proofs via SP1 Groth16 verifier gateway; reverts here if proof is invalid
        ISP1Verifier(SP1_GROTH16_GATEWAY)
            .verifyProof(
                SP1_PROGRAM_VKEY, // ToDo: set to actual SP1 program vKey
                bytes.concat(
                    anchorBlock, // ethereum state commitment
                    stateAddress(chainLength, 0).codehash, // parent state commitment
                    stateAddress(chainLength, 1).codehash, // parent state commitment
                    incipit,
                    accountBlob, // proposed account state
                    incipit,
                    nonceBlob // proposed nonce state
                ),
                proof
            );

        chainLength++;
        anchorBlock = blockhash(block.number - 1);
        emit NewState(msg.sender, anchorBlock, chainLength, accountBlob, nonceBlob, proof);
        // Keep this order: exactly two CREATEs per committed state, account first.
        SSTORE2.write(accountBlob);  // this contract nonce = 2x chainLength +1 
        SSTORE2.write(nonceBlob);  // this contract nonce = 2x chainLength +2
    }

    function account(uint256 tokenId) external view returns (bytes6) {
        return state(chainLength, 0, tokenId);
    }

    function nonce(uint256 tokenId) external view returns (bytes6) {
        return state(chainLength, 1, tokenId);
    }

    function latestStateAddress(uint256 io) external view returns (address) {
        return stateAddress(chainLength, io);
    }

    function state(uint256 at, uint256 io, uint256 tokenId) public view returns (bytes6) {
        address pointer = stateAddress(at, io);
        if (tokenId == 0) return bytes6(bytes.concat(incipit, SSTORE2.read(pointer, 0, 5)));
        uint256 index = (tokenId * 6) - 1;
        return bytes6(SSTORE2.read(pointer, index, index + 6));
    }

    function stateAddress(uint256 at, uint256 io) public view returns (address) {        
        return LibRLP.computeAddress(address(this), at * 2 + 1 + (io == 0 ? 0: 1));
    }
}
