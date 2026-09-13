// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import {LibRLP} from "solady@0.1.26/src/utils/LibRLP.sol";
import {SSTORE2} from "solady@0.1.26/src/utils/SSTORE2.sol";

import {ISP1Verifier} from "./interfaces/ISP1Verifier.sol";
import {IRollup} from "./interfaces/IRollup.sol";

/// @custom:security-contact info@whynotswitch.com
contract Rollup is IRollup {
    uint256 public constant QUOTA = 6;
    address public constant SP1_GROTH16_GATEWAY = 0x397A5f7f3dBd538f23DE225B51f532c34448dA9B;
    // TODO: replace with the verified production SP1 program key before deployment.
    bytes32 public constant SP1_PROGRAM_VKEY = 0x005120317542200324c9509e78315ad70799268f02d21504709c8973d2493203;

    bytes32 public anchorBlock;
    uint256 public chainLength;
    bytes constant INCIPIT = hex"00";

    constructor() {
        SSTORE2.write(INCIPIT); // Genesis account: CREATE nonce 1.
        SSTORE2.write(INCIPIT); // Genesis nonce: CREATE nonce 2.
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

        chainLength++;

        // Keep this order: exactly two CREATEs per committed state, account first.
        SSTORE2.write(accountBlob); // CREATE nonce = 2 * chainLength + 1.
        SSTORE2.write(nonceBlob); // CREATE nonce = 2 * chainLength + 2.
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

    function state(uint256 stateIndex, uint256 io, uint256 tokenId) public view returns (bytes6) {
        address pointer = stateAddress(stateIndex, io);
        if (tokenId == 0) return bytes6(bytes.concat(INCIPIT, SSTORE2.read(pointer, 0, QUOTA - 1)));
        uint256 index = (tokenId * QUOTA) - 1;
        return bytes6(SSTORE2.read(pointer, index, index + QUOTA));
    }

    function stateAddress(uint256 stateIndex, uint256 io) public view returns (address) {
        return LibRLP.computeAddress(address(this), stateIndex * 2 + 1 + (io == 0 ? 0 : 1));
    }
}
