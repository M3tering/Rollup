// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import {LibRLP} from "solady@0.2.6/src/utils/LibRLP.sol";
import {SSTORE2} from "solady@0.2.6/src/utils/SSTORE2.sol";

import {ISP1Verifier} from "./interfaces/ISP1Verifier.sol";
import {IRollup} from "./interfaces/IRollup.sol";

/// @custom:security-contact info@whynotswitch.com
contract Rollup is IRollup {
    bytes32 public anchorBlock;
    uint256 public chainLength;
    bytes constant INCIPIT = hex"00";

    constructor() {
        SSTORE2.write(INCIPIT);  //this contract nonce = 2x chainLength +1
        SSTORE2.write(INCIPIT);  //this contract nonce = 2x chainLength +2
        emit NewState(msg.sender, hex"", 0, INCIPIT, INCIPIT, INCIPIT);
        anchorBlock = blockhash(block.number - 1);
    }

    function commitState(bytes calldata accountBlob, bytes calldata nonceBlob, bytes calldata proof) external {
        require(accountBlob.length == nonceBlob.length, InvalidBlobs());
        require(accountBlob.length <= 24575, OversizeBlobs());
        // verifies proofs via SP1 Groth16 verifier gateway; reverts here if proof is invalid
        ISP1Verifier(SP1_GROTH16_GATEWAY)
            .verifyProof(
                SP1_PROGRAM_VKEY, // ToDo: set to actual SP1 program vKey
                bytes.concat(
                    anchorBlock, // ethereum state commitment
                    stateAddress(chainLength, 0).codehash, // parent account-state commitment
                    stateAddress(chainLength, 1).codehash, // parent nonce-state commitment
                    INCIPIT,
                    accountBlob, // proposed account-state
                    INCIPIT,
                    nonceBlob // proposed nonce-state
                ),
                proof
            );

        // Keep this order: exactly two CREATEs per committed state, account first.
        SSTORE2.write(accountBlob);  // this contract nonce = 2x chainLength +1 
        SSTORE2.write(nonceBlob);  // this contract nonce = 2x chainLength +2

        chainLength++;
        emit NewState(msg.sender, anchorBlock, chainLength, accountBlob, nonceBlob, proof);
        anchorBlock = blockhash(block.number - 1);

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
        if (tokenId == 0) return bytes6(bytes.concat(INCIPIT, SSTORE2.read(pointer, 0, QUOTA-1)));
        uint256 index = (tokenId * QUOTA) - 1;
        return bytes6(SSTORE2.read(pointer, index, index + QUOTA));
    }

    function stateAddress(uint256 at, uint256 io) public view returns (address) {        
        return LibRLP.computeAddress(address(this), at * 2 + 1 + (io == 0 ? 0: 1));
    }
}
