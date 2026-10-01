// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;
import {Vm} from "forge-std/Vm.sol";
import {Test} from "forge-std/Test.sol";
import {Rollup} from "../src/Rollup.sol";
import {IRollup} from "../src/interfaces/IRollup.sol";
import {ISP1Verifier} from "../src/interfaces/ISP1Verifier.sol";

contract TestVerifier is ISP1Verifier {
    function verifyProof(bytes32, bytes calldata values, bytes calldata proof) external pure {
        require(values.length == 32 && keccak256(values) == keccak256(proof), "statement mismatch");
    }
}

contract TestM3ter {
    address public owner;

    function setOwner(address next) external {
        owner = next;
    }

    function ownerOf(uint256) external view returns (address) {
        return owner;
    }
}

contract MutatingVerifier {
    function verifyProof(bytes32, bytes calldata, bytes calldata) external {
        assembly { sstore(0, 1) }
    }
}

contract RollupTest is Test {
    Rollup r;

    function setUp() public {
        r = new Rollup();
        vm.etch(address(r.VERIFIER()), address(new TestVerifier()).code);
        vm.etch(r.M3ter(), address(new TestM3ter()).code);
        TestM3ter(r.M3ter()).setOwner(address(this));
    }

    function oldWord(uint256 slot) internal view returns (uint256) {
        return slot < r.wordCount() ? r.words(slot) : 0;
    }

    function proofFor(bytes memory updates) internal view returns (bytes memory) {
        bytes memory transcript = abi.encodePacked(block.chainid, address(r));
        for (uint256 offset; offset < updates.length; offset += 36) {
            uint32 slot;
            uint256 value;
            assembly {
                slot := shr(224, mload(add(add(updates, 32), offset)))
                value := mload(add(add(updates, 36), offset))
            }
            uint256 old = oldWord(slot);
            bytes32[4] memory keys;
            for (uint64 lane; lane < 4; ++lane) {
                if (uint64(old >> (lane * 64)) != uint64(value >> (lane * 64))) {
                    keys[lane] = r.publicKey(uint64(slot) * 4 + lane);
                }
            }
            transcript = bytes.concat(transcript, abi.encodePacked(slot, old, value, keccak256(abi.encode(keys))));
        }
        return abi.encodePacked(keccak256(transcript));
    }

    function commit(uint32 slot, uint256 value) internal {
        bytes memory updates = abi.encodePacked(slot, value);
        r.commitState(updates, proofFor(updates));
    }

    function testOwnerAuthorityAndFullKeyPersistence() public {
        r.setPublicKey(0, bytes32(uint256(123)));
        commit(0, uint256(1) << 40);
        assertEq(r.publicKey(0), bytes32(uint256(123)));
        TestM3ter(r.M3ter()).setOwner(address(99));
        vm.expectRevert(IRollup.Unauthorized.selector);
        r.setPublicKey(0, bytes32(0));
        vm.prank(address(99));
        r.setPublicKey(0, bytes32(0));
        assertEq(r.publicKey(0), bytes32(0));
    }

    function testUsedKeyRotationRevertsAllWritesAndLength() public {
        bytes memory updates = abi.encodePacked(uint32(0), uint256(1) << 40, uint32(100), uint256(1) << 40);
        bytes memory proof = proofFor(updates);
        r.setPublicKey(0, bytes32(uint256(1)));
        vm.expectRevert("statement mismatch");
        r.commitState(updates, proof);
        assertEq(r.wordCount(), 0);
        assertEq(vm.load(address(r), keccak256(abi.encode(uint256(0)))), bytes32(0));
        assertEq(vm.load(address(r), bytes32(uint256(keccak256(abi.encode(uint256(0)))) + 100)), bytes32(0));
    }

    function testUnusedKeyRotationAndDisjointCommitDoNotInvalidateProof() public {
        bytes memory updates = abi.encodePacked(uint32(0), uint256(1) << 40);
        bytes memory proof = proofFor(updates);
        r.setPublicKey(1, bytes32(uint256(10)));
        commit(1, uint256(1) << 40);
        vm.roll(100000); // No anchor expiry.
        r.commitState(updates, proof);
        assertEq(r.nonce(0), 1);
        assertEq(r.nonce(4), 1);
    }

    function testReplayAndStaleOldWordRejected() public {
        bytes memory updates = abi.encodePacked(uint32(0), uint256(2) << 40);
        bytes memory proof = proofFor(updates);
        commit(0, uint256(1) << 40);
        vm.expectRevert("statement mismatch");
        r.commitState(updates, proof);
        r.commitState(updates, proofFor(updates));
        vm.expectRevert(IRollup.InvalidUpdate.selector);
        r.commitState(updates, proof);
    }

    function testChainAndDeploymentBound() public {
        bytes memory updates = abi.encodePacked(uint32(0), uint256(1) << 40);
        bytes memory proof = proofFor(updates);
        vm.chainId(block.chainid + 1);
        vm.expectRevert("statement mismatch");
        r.commitState(updates, proof);
        Rollup other = new Rollup();
        proof = proofFor(updates);
        vm.expectRevert("statement mismatch");
        other.commitState(updates, proof);
    }

    function testVerifierCannotMutateAndFailureRollsBack() public {
        vm.etch(address(r.VERIFIER()), address(new MutatingVerifier()).code);
        vm.expectRevert();
        r.commitState{gas: 500000}(abi.encodePacked(uint32(10), uint256(1) << 40), "");
        assertEq(r.wordCount(), 0);
        assertEq(r.account(40), 0);
    }

    function testMissingVerifierFailsClosed() public {
        vm.etch(address(r.VERIFIER()), hex"");
        vm.expectRevert();
        r.commitState{gas: 500000}(abi.encodePacked(uint32(10), uint256(1) << 40), "");
        assertEq(r.wordCount(), 0);
    }

    function testFramingDuplicatesDescendingAndNoop() public {
        vm.expectRevert(IRollup.InvalidEncoding.selector);
        r.commitState("", "");
        vm.expectRevert(IRollup.InvalidEncoding.selector);
        r.commitState(hex"01", "");
        vm.expectRevert(IRollup.InvalidUpdate.selector);
        r.commitState(abi.encodePacked(uint32(1), uint256(1), uint32(1), uint256(2)), "");
        vm.expectRevert(IRollup.InvalidUpdate.selector);
        r.commitState(abi.encodePacked(uint32(1), uint256(1), uint32(0), uint256(2)), "");
        vm.expectRevert(IRollup.InvalidUpdate.selector);
        r.commitState(abi.encodePacked(uint32(0), uint256(0)), "");
        assertEq(r.wordCount(), 0);
    }

    function testMaxSlotAndGetterBounds() public {
        commit(type(uint32).max, uint256(7) << 192);
        assertEq(r.wordCount(), uint256(1) << 32);
        assertEq(r.account((uint64(1) << 34) - 1), 7);
        assertEq(r.words(0), 0);
        vm.expectRevert();
        r.words(uint256(1) << 32);
        vm.expectRevert(IRollup.InvalidUpdate.selector);
        r.setPublicKey(uint64(1) << 34, bytes32(uint256(1)));
    }

    function testEventContainsExactCalldataUpdates() public {
        bytes memory updates = abi.encodePacked(uint32(0), uint256(1) << 40, uint32(8), uint256(2) << 40);
        bytes memory proof = proofFor(updates);
        vm.recordLogs();
        r.commitState(updates, proof);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(logs[0].topics[0], keccak256("StateCommitted(bytes)"));
        assertEq(abi.decode(logs[0].data, (bytes)), updates);
    }

    function testFuzzPacking(uint40 accountValue, uint24 nonceValue, uint8 rawLane, uint256 io) public {
        uint64 lane = rawLane % 4;
        uint256 pair = uint256(accountValue) | (uint256(nonceValue) << 40);
        vm.assume(pair != 0);
        commit(0, pair << (64 * lane));
        assertEq(r.account(lane), accountValue);
        assertEq(r.nonce(lane), nonceValue);
        assertEq(r.state(lane, io), io == 0 ? accountValue : nonceValue);
        assertEq(r.account((lane + 1) % 4), 0);
    }

    function testFourByteSlotAboveOldBoundary() public {
        uint32 slot = 0x01020304;
        commit(slot, uint256(1) << 40);
        assertEq(r.words(slot), uint256(1) << 40);
        assertEq(r.nonce(uint64(slot) * 4), 1);
        assertEq(r.wordCount(), uint256(slot) + 1);
        vm.expectRevert(IRollup.InvalidEncoding.selector);
        r.commitState(abi.encodePacked(uint24(1), uint256(1)), "");
    }

    function testRustFixture() public {
        string memory f = vm.readFile("test/fixtures/statement.json");
        address target = address(0x1111111111111111111111111111111111111111);
        vm.etch(target, address(r).code);
        vm.chainId(1);
        vm.store(target, bytes32(0), bytes32(uint256(2)));
        vm.store(target, keccak256(abi.encode(uint256(0))), vm.parseJsonBytes32(f, ".oldWord"));
        bytes32 key = 0x197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61;
        uint64[4] memory meters = [uint64(0), uint64(3), uint64(4), uint64(4000)];
        for (uint256 i; i < 4; ++i) {
            vm.store(target, keccak256(abi.encode(uint256(meters[i]), uint256(1))), key);
        }
        Rollup(target)
            .commitState(vm.parseJsonBytes(f, ".payload"), abi.encodePacked(vm.parseJsonBytes32(f, ".commitment")));
        assertEq(Rollup(target).account(0), 41);
        assertEq(Rollup(target).nonce(4), 1);
    }
}
