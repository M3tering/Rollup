// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {Rollup} from "../src/Rollup.sol";
import {IRollup} from "../src/interfaces/IRollup.sol";
import {RollupFixture, StatementVerifier} from "./Rollup.t.sol";

contract RollupHandler is Test {
    Rollup public immutable rollup;
    StatementVerifier internal immutable verifier;
    bytes32 internal immutable key;
    bytes[] internal accounts;
    bytes[] internal nonces;
    bytes32 public anchor;
    uint256 public rejected;
    bytes internal constant PROOF = hex"123456";

    constructor(Rollup r, StatementVerifier v, bytes32 k, bytes32 genesisAnchor) {
        rollup = r;
        verifier = v;
        key = k;
        anchor = genesisAnchor;
        accounts.push(hex"00");
        nonces.push(hex"00");
    }

    function count() public view returns (uint256) {
        return accounts.length - 1;
    }

    function blobs(uint256 i) external view returns (bytes memory, bytes memory) {
        return (accounts[i], nonces[i]);
    }

    function advance(bytes32 seed, uint8 size, uint8 jump, address sender) external {
        uint256 length = uint256(size) % 97;
        bytes memory a = new bytes(length);
        bytes memory n = new bytes(length);
        for (uint256 i; i < length; ++i) {
            a[i] = seed[i % 32];
            n[i] = bytes1(~uint8(a[i]));
        }
        if (jump % 4 != 0) {
            vm.roll(block.number + uint256(jump));
            vm.setBlockhash(block.number - 1, keccak256(abi.encode(seed, block.number)));
        }
        uint256 last = count();
        bytes memory input = bytes.concat(
            anchor,
            keccak256(bytes.concat(hex"00", accounts[last])),
            keccak256(bytes.concat(hex"00", nonces[last])),
            hex"00",
            a,
            hex"00",
            n
        );
        verifier.authorize(key, input, PROOF);
        // Use real actor addresses, never impersonate Rollup or a predicted
        // snapshot. Foundry may touch a prank sender's nonce, creating artificial
        // CREATE collisions if arbitrary addresses include future snapshots.
        sender = uint160(sender) % 2 == 0 ? address(0xa11ce) : address(0xb0b);
        vm.prank(sender);
        rollup.commitState(a, n, PROOF);
        accounts.push(a);
        nonces.push(n);
        anchor = blockhash(block.number - 1);
    }

    function reject(uint8 mode) external {
        uint256 beforeCount = count();
        uint64 beforeNonce = vm.getNonce(address(rollup));
        if (mode % 3 == 0) {
            vm.expectRevert(IRollup.InvalidBlobs.selector);
            rollup.commitState(hex"01", hex"", PROOF);
        } else if (mode % 3 == 1) {
            bytes memory large = new bytes(24576);
            vm.expectRevert(IRollup.OversizeBlobs.selector);
            rollup.commitState(large, large, PROOF);
        } else {
            // No successful handler authorizes this proof.
            vm.expectRevert(StatementVerifier.WrongStatement.selector);
            rollup.commitState(hex"01", hex"02", hex"dead");
        }
        ++rejected;
        assertEq(rollup.chainLength(), beforeCount);
        assertEq(rollup.anchorBlock(), anchor);
        assertEq(vm.getNonce(address(rollup)), beforeNonce);
        assertEq(rollup.stateAddress(beforeCount + 1, 0).code.length, 0);
        assertEq(rollup.stateAddress(beforeCount + 1, 1).code.length, 0);
    }
}

contract RollupInvariantTest is StdInvariant, RollupFixture {
    RollupHandler internal handler;

    function setUp() public override {
        super.setUp();
        handler = new RollupHandler(rollup, verifier, VKEY, modelAnchor);
        // Seed a real transition so history properties cannot pass only on genesis.
        handler.advance(keccak256("initial transition"), 31, 1, address(123));
        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = RollupHandler.advance.selector;
        selectors[1] = RollupHandler.reject.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        targetContract(address(handler));
        // Top-level invariant transactions must originate from EOAs. Allowing
        // the fuzzer to choose Rollup as tx sender artificially consumes its nonce.
        targetSender(address(0xa11ce));
        targetSender(address(0xb0b));
    }

    function testHandlerNormalizesImpossibleSelfSender() public {
        handler.advance(bytes32(uint256(512)), 101, 5, address(rollup));
        invariantHistoryAndSequencing();
    }

    function invariantHistoryAndSequencing() public view {
        uint256 count = handler.count();
        assertEq(rollup.chainLength(), count);
        assertEq(vm.getNonce(address(rollup)), count * 2 + 3, "Rollup CREATE nonce");
        assertEq(rollup.anchorBlock(), handler.anchor());
        for (uint256 i; i <= count; ++i) {
            (bytes memory a, bytes memory n) = handler.blobs(i);
            checkState(i, a, n);
            assertEq(a.length, n.length);
            // Every stored record plus one beyond the end, for all historical states.
            for (uint256 token; token <= (a.length + 6) / 6; ++token) {
                assertEq(rollup.state(i, 0, token), record(a, token));
                assertEq(rollup.state(i, type(uint256).max, token), record(n, token));
            }
        }
        (bytes memory latestA, bytes memory latestN) = handler.blobs(count);
        assertEq(rollup.account(0), record(latestA, 0));
        assertEq(rollup.nonce(0), record(latestN, 0));
        assertEq(rollup.latestStateAddress(0), rollup.stateAddress(count, 0));
        assertEq(rollup.latestStateAddress(2), rollup.stateAddress(count, 1));
    }
}
