// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {Rollup} from "../src/Rollup.sol";
import {IRollup} from "../src/interfaces/IRollup.sol";
import {ISP1Verifier} from "../src/interfaces/ISP1Verifier.sol";
import {SSTORE2} from "solady@0.1.26/src/utils/SSTORE2.sol";

// Strict protocol-boundary double, NOT a cryptographic SP1 verifier.
// Every test authorizes an independently constructed statement and proof.
contract StatementVerifier is ISP1Verifier {
    bytes32 public expected;
    error WrongStatement();

    function authorize(bytes32 key, bytes memory inputs, bytes memory proof) external {
        expected = keccak256(abi.encode(key, inputs, proof));
    }

    function verifyProof(bytes32 key, bytes calldata inputs, bytes calldata proof) external view {
        if (keccak256(abi.encode(key, inputs, proof)) != expected) revert WrongStatement();
    }
}

abstract contract RollupFixture is Test {
    address internal constant GATEWAY = 0x397A5f7f3dBd538f23DE225B51f532c34448dA9B;
    bytes32 internal constant VKEY = 0x005120317542200324c9509e78315ad70799268f02d21504709c8973d2493203;
    bytes internal constant PROOF = hex"123456";
    Rollup internal rollup;
    StatementVerifier internal verifier;
    bytes internal oldA = hex"00";
    bytes internal oldN = hex"00";
    bytes32 internal modelAnchor;

    function setUp() public virtual {
        vm.roll(100);
        modelAnchor = keccak256("block 99");
        vm.setBlockhash(99, modelAnchor);
        StatementVerifier template = new StatementVerifier();
        vm.etch(GATEWAY, address(template).code);
        verifier = StatementVerifier(GATEWAY);
        rollup = new Rollup();
    }

    function statement(bytes32 anchor, bytes memory pa, bytes memory pn, bytes memory a, bytes memory n)
        internal
        pure
        returns (bytes memory)
    {
        return bytes.concat(
            anchor, keccak256(bytes.concat(hex"00", pa)), keccak256(bytes.concat(hex"00", pn)), hex"00", a, hex"00", n
        );
    }

    function authorize(bytes memory a, bytes memory n) internal {
        verifier.authorize(VKEY, statement(modelAnchor, oldA, oldN, a, n), PROOF);
    }

    function commit(bytes memory a, bytes memory n) internal {
        authorize(a, n);
        rollup.commitState(a, n, PROOF);
        oldA = a;
        oldN = n;
        modelAnchor = blockhash(block.number - 1);
    }

    // Independent oracle: six consecutive bytes from runtime 00 || payload,
    // right-padded with zero, without SSTORE2 offset arithmetic.
    function record(bytes memory payload, uint256 token) internal pure returns (bytes6 value) {
        bytes memory runtime = bytes.concat(hex"00", payload);
        uint48 result;
        for (uint256 j; j < 6; ++j) {
            uint256 pos = token * 6 + j;
            result = (result << 8) | (pos < runtime.length ? uint48(uint8(runtime[pos])) : uint48(0));
        }
        return bytes6(result);
    }

    function checkState(uint256 stateIndex, bytes memory a, bytes memory n) internal view {
        address ap = vm.computeCreateAddress(address(rollup), stateIndex * 2 + 1);
        address np = vm.computeCreateAddress(address(rollup), stateIndex * 2 + 2);
        assertEq(rollup.stateAddress(stateIndex, 0), ap);
        assertEq(rollup.stateAddress(stateIndex, 1), np);
        assertEq(ap.code, bytes.concat(hex"00", a));
        assertEq(np.code, bytes.concat(hex"00", n));
    }
}

contract RollupTest is RollupFixture {
    function testGenesisAndSentinelEvent() public {
        vm.recordLogs();
        Rollup fresh = new Rollup();
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(logs[0].topics[0], keccak256("NewState(address,bytes32,uint256,bytes,bytes,bytes)"));
        assertEq(logs[0].topics[1], bytes32(uint256(uint160(address(this)))));
        assertEq(logs[0].topics[2], bytes32(0));
        assertEq(logs[0].topics[3], bytes32(0));
        assertEq(logs[0].data, abi.encode(hex"00", hex"00", hex"00"));
        assertEq(fresh.anchorBlock(), modelAnchor);
        assertEq(rollup.chainLength(), 0);
        assertEq(vm.getNonce(address(rollup)), 3);
        checkState(0, hex"00", hex"00");
        assertEq(rollup.account(0), bytes6(0));
        assertEq(rollup.nonce(100), bytes6(0));
    }

    function testConstantsAndLatestGetters() public {
        assertEq(rollup.QUOTA(), 6);
        assertEq(rollup.SP1_GROTH16_GATEWAY(), GATEWAY);
        assertEq(rollup.SP1_PROGRAM_VKEY(), VKEY);
        commit(hex"0102030405111213141516", hex"2122232425313233343536");
        assertEq(rollup.account(0), bytes6(hex"000102030405"));
        assertEq(rollup.account(1), bytes6(hex"111213141516"));
        assertEq(rollup.nonce(1), bytes6(hex"313233343536"));
        assertEq(rollup.latestStateAddress(0), rollup.stateAddress(1, 0));
        assertEq(rollup.latestStateAddress(99), rollup.stateAddress(1, 1));
    }

    function testAnchorEventUsesVerifiedAnchorAndStorageAdvances() public {
        bytes32 previous = modelAnchor;
        vm.roll(105);
        bytes32 next = keccak256("block 104");
        vm.setBlockhash(104, next);
        authorize(hex"1234", hex"abcd");
        vm.recordLogs();
        vm.prank(address(0xbeef));
        rollup.commitState(hex"1234", hex"abcd", PROOF);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(logs[0].topics[1], bytes32(uint256(0xbeef)));
        assertEq(logs[0].topics[2], previous);
        assertEq(logs[0].topics[3], bytes32(uint256(1)));
        assertEq(logs[0].data, abi.encode(hex"1234", hex"abcd", PROOF));
        assertEq(rollup.anchorBlock(), next);
    }
}

contract RollupProofTest is RollupFixture {
    function testRejectTamperedProofAndPayloadAtomically() public {
        authorize(hex"1234", hex"abcd");
        vm.expectRevert(StatementVerifier.WrongStatement.selector);
        rollup.commitState(hex"1234", hex"abcd", hex"12");
        vm.expectRevert(StatementVerifier.WrongStatement.selector);
        rollup.commitState(hex"1235", hex"abcd", PROOF);
        vm.expectRevert(StatementVerifier.WrongStatement.selector);
        rollup.commitState(hex"1234", hex"abce", PROOF);
        assertEq(rollup.chainLength(), 0);
        assertEq(rollup.anchorBlock(), modelAnchor);
        assertEq(vm.getNonce(address(rollup)), 3);
        assertEq(rollup.stateAddress(1, 0).code.length, 0);
    }

    function testRejectWrongParentAnchorAndKey() public {
        bytes memory a = hex"01";
        bytes memory n = hex"02";
        verifier.authorize(VKEY, statement(bytes32(uint256(1)), oldA, oldN, a, n), PROOF);
        vm.expectRevert(StatementVerifier.WrongStatement.selector);
        rollup.commitState(a, n, PROOF);
        verifier.authorize(VKEY, statement(modelAnchor, hex"ff", oldN, a, n), PROOF);
        vm.expectRevert(StatementVerifier.WrongStatement.selector);
        rollup.commitState(a, n, PROOF);
        verifier.authorize(VKEY, statement(modelAnchor, oldA, hex"ff", a, n), PROOF);
        vm.expectRevert(StatementVerifier.WrongStatement.selector);
        rollup.commitState(a, n, PROOF);
        verifier.authorize(bytes32(0), statement(modelAnchor, oldA, oldN, a, n), PROOF);
        vm.expectRevert(StatementVerifier.WrongStatement.selector);
        rollup.commitState(a, n, PROOF);
    }

    function testChangedParentRejectsReplayInSameBlock() public {
        commit(hex"11", hex"22");
        // Keep previous authorization: parent hashes have now changed.
        vm.expectRevert(StatementVerifier.WrongStatement.selector);
        rollup.commitState(hex"11", hex"22", PROOF);
        commit(hex"33", hex"44");
        assertEq(rollup.chainLength(), 2);
    }

    function testChangedAnchorRejectsOldStatementEvenWhenStateUnchanged() public {
        vm.roll(101);
        vm.setBlockhash(100, keccak256("block 100"));
        commit(hex"00", hex"00");
        vm.expectRevert(StatementVerifier.WrongStatement.selector);
        rollup.commitState(hex"00", hex"00", PROOF);
    }

    function testNoopReplayIsCurrentlyAllowedWhenStatementIsUnchanged() public {
        // Characterization, not a recommendation: no sequence number is in the statement.
        authorize(hex"00", hex"00");
        rollup.commitState(hex"00", hex"00", PROOF);
        rollup.commitState(hex"00", hex"00", PROOF);
        assertEq(rollup.chainLength(), 2);
        checkState(2, hex"00", hex"00");
    }

    function testOldStoredAnchorDoesNotExpireAfter256Blocks() public {
        vm.roll(1000);
        vm.setBlockhash(999, keccak256("block 999"));
        commit(hex"11", hex"22");
        assertEq(rollup.chainLength(), 1);
        assertEq(rollup.anchorBlock(), keccak256("block 999"));
    }

    function testMissingVerifierCannotAcceptCommit() public {
        vm.etch(GATEWAY, hex"");
        vm.expectRevert();
        rollup.commitState(hex"11", hex"22", PROOF);
        assertEq(rollup.chainLength(), 0);
        assertEq(vm.getNonce(address(rollup)), 3);
    }

    function testShapeChecksBeforeVerifier() public {
        vm.expectRevert(IRollup.InvalidBlobs.selector);
        rollup.commitState(hex"01", hex"", PROOF);
        bytes memory large = new bytes(24576);
        vm.expectRevert(IRollup.OversizeBlobs.selector);
        rollup.commitState(large, large, PROOF);
        assertEq(vm.getNonce(address(rollup)), 3);
    }
}

contract RollupStorageTest is RollupFixture {
    function testMaximumAndEmptyPayloads() public {
        bytes memory a = new bytes(24575);
        a[0] = 0x42;
        a[24574] = 0xff;
        commit(a, a);
        checkState(1, a, a);
        assertEq(rollup.account(4095), record(a, 4095));
        assertEq(rollup.account(4096), bytes6(0));
        commit(hex"", hex"");
        checkState(2, hex"", hex"");
        assertEq(rollup.account(0), bytes6(0));
        checkState(1, a, a);
    }

    function testHistoricalReadsAcrossRlpNonceBoundaries() public {
        for (uint256 i = 1; i <= 129; ++i) {
            commit(abi.encode(i), abi.encode(i + 1000));
        }
        for (uint256 i = 1; i <= 129; ++i) {
            checkState(i, abi.encode(i), abi.encode(i + 1000));
            assertEq(rollup.state(i, 0, 5), record(abi.encode(i), 5));
        }
        assertEq(vm.getNonce(address(rollup)), 261);
    }

    function testSecondCreateFailureRollsBackFirst() public {
        address first = rollup.stateAddress(1, 0);
        address second = rollup.stateAddress(1, 1);
        // Artificial collision to exercise rollback, not an attacker deployment claim.
        vm.etch(second, hex"00");
        authorize(hex"11", hex"22");
        vm.expectRevert(SSTORE2.DeploymentFailed.selector);
        rollup.commitState{gas: 1000000}(hex"11", hex"22", PROOF);
        assertEq(first.code.length, 0);
        assertEq(rollup.chainLength(), 0);
        assertEq(rollup.anchorBlock(), modelAnchor);
        assertEq(vm.getNonce(address(rollup)), 3);
        vm.etch(second, hex"");
        commit(hex"11", hex"22");
        checkState(1, hex"11", hex"22");
    }

    function testPrefundingDoesNotBlockCreationAndAnySenderCanCommit() public {
        vm.deal(rollup.stateAddress(1, 0), 1 ether);
        authorize(hex"11", hex"22");
        vm.prank(address(123));
        rollup.commitState(hex"11", hex"22", PROOF);
        checkState(1, hex"11", hex"22");
    }

    function testFutureStateReadRevertsButAddressCanBePredicted() public {
        assertTrue(rollup.stateAddress(1, 0) != address(0));
        vm.expectRevert();
        rollup.state(1, 0, 0);
    }

    function testFuzzRecordsAndIo(bytes32 seed, uint16 size, uint16 token, uint256 io) public {
        uint256 length = bound(size, 0, 512);
        bytes memory a = new bytes(length);
        bytes memory n = new bytes(length);
        for (uint256 i; i < length; ++i) {
            a[i] = seed[i % 32];
            n[i] = bytes1(~uint8(a[i]));
        }
        commit(a, n);
        uint256 id = bound(token, 0, 100);
        assertEq(rollup.state(1, io, id), record(io == 0 ? a : n, id));
        assertEq(rollup.account(id), record(a, id));
        assertEq(rollup.nonce(id), record(n, id));
        checkState(1, a, n);
    }

    function testFuzzAddressNormalization(uint32 stateIndex, uint256 io) public view {
        assertEq(
            rollup.stateAddress(stateIndex, io),
            vm.computeCreateAddress(address(rollup), uint256(stateIndex) * 2 + 1 + (io == 0 ? 0 : 1))
        );
    }
}
