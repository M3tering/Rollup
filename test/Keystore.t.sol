// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;
import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {Rollup} from "../src/Rollup.sol";
import {IRollup} from "../src/interfaces/IRollup.sol";
import {TestM3ter} from "./Rollup.t.sol";

contract KeystoreTest is Test {
    Rollup r;

    function setUp() public {
        r = new Rollup();
        vm.etch(r.M3ter(), address(new TestM3ter()).code);
        TestM3ter(r.M3ter()).setOwner(address(this));
    }

    function testZeroIdAndUnknownKeys() public {
        bytes32 key = bytes32(uint256(7));
        vm.expectRevert(IRollup.KeyNotFound.selector);
        r.m3terId(key);
        r.setPublicKey(0, key);
        assertEq(r.m3terId(key), 0);
        r.setPublicKey(0, key); // Idempotent registration keeps both directions.
        assertEq(r.publicKey(0), key);
        assertEq(r.m3terId(key), 0);
        vm.expectRevert(IRollup.KeyNotFound.selector);
        r.m3terId(bytes32(0));
    }

    function testDuplicateRejectedWithoutLosingPreviousKey() public {
        bytes32 first = bytes32(uint256(1));
        bytes32 second = bytes32(uint256(2));
        r.setPublicKey(0, first);
        r.setPublicKey(7, second);
        vm.expectRevert(IRollup.KeyAlreadyRegistered.selector);
        r.setPublicKey(7, first);
        assertEq(r.publicKey(0), first);
        assertEq(r.publicKey(7), second);
        assertEq(r.m3terId(first), 0);
        assertEq(r.m3terId(second), 7);
    }

    function testRotationRevocationAndReuse() public {
        bytes32 first = bytes32(uint256(1));
        bytes32 second = bytes32(uint256(2));
        r.setPublicKey(7, first);
        r.setPublicKey(7, second);
        vm.expectRevert(IRollup.KeyNotFound.selector);
        r.m3terId(first);
        assertEq(r.m3terId(second), 7);
        r.setPublicKey(0, first);
        assertEq(r.m3terId(first), 0);
        r.setPublicKey(7, bytes32(0));
        r.setPublicKey(7, bytes32(0));
        assertEq(r.publicKey(7), bytes32(0));
        vm.expectRevert(IRollup.KeyNotFound.selector);
        r.m3terId(second);
        vm.expectRevert(IRollup.KeyNotFound.selector);
        r.m3terId(bytes32(0));
        r.setPublicKey(8, second);
        assertEq(r.m3terId(second), 8);
    }

    function testTransferRetainsKeyAndOnlyNewOwnerCanRotate() public {
        bytes32 key = bytes32(uint256(1));
        r.setPublicKey(7, key);
        TestM3ter(r.M3ter()).setOwner(address(99));
        assertEq(r.m3terId(key), 7);
        vm.expectRevert(IRollup.Unauthorized.selector);
        r.setPublicKey(7, bytes32(0));
        assertEq(r.m3terId(key), 7);
        vm.prank(address(99));
        r.setPublicKey(7, bytes32(0));
        vm.expectRevert(IRollup.KeyNotFound.selector);
        r.m3terId(key);
    }

    function testMaximumMeterId() public {
        uint64 id = (uint64(1) << 34) - 1;
        r.setPublicKey(id, bytes32(type(uint256).max));
        assertEq(r.m3terId(bytes32(type(uint256).max)), id);
        vm.expectRevert(IRollup.InvalidUpdate.selector);
        r.setPublicKey(id + 1, bytes32(uint256(2)));
        vm.expectRevert(IRollup.KeyNotFound.selector);
        r.m3terId(bytes32(uint256(2)));
    }

    function testFuzzBidirectionalLookupAndRevoke(uint64 rawId, bytes32 key) public {
        vm.assume(key != bytes32(0));
        uint64 id = rawId % (uint64(1) << 34);
        r.setPublicKey(id, key);
        assertEq(r.publicKey(id), key);
        assertEq(r.m3terId(key), id);
        r.setPublicKey(id, bytes32(0));
        assertEq(r.publicKey(id), bytes32(0));
        vm.expectRevert(IRollup.KeyNotFound.selector);
        r.m3terId(key);
    }
}

contract KeystoreHandler is Test {
    Rollup public r;
    bytes32[8] public keys;
    uint64[9] public ownersPlusOne;

    constructor(Rollup target) {
        r = target;
    }

    function register(uint8 rawId, uint8 rawKey) external {
        uint64 id = rawId % 8;
        uint256 keyNumber = rawKey % 9;
        bytes32 key = bytes32(keyNumber);
        if (keyNumber != 0 && ownersPlusOne[keyNumber] != 0 && ownersPlusOne[keyNumber] != id + 1) {
            vm.expectRevert(IRollup.KeyAlreadyRegistered.selector);
            r.setPublicKey(id, key);
            return;
        }
        r.setPublicKey(id, key);
        if (keys[id] != bytes32(0)) ownersPlusOne[uint256(keys[id])] = 0;
        keys[id] = key;
        if (keyNumber != 0) ownersPlusOne[keyNumber] = id + 1;
    }
}

contract KeystoreInvariantTest is StdInvariant, Test {
    Rollup r;
    KeystoreHandler h;

    function setUp() public {
        r = new Rollup();
        vm.etch(r.M3ter(), address(new TestM3ter()).code);
        h = new KeystoreHandler(r);
        TestM3ter(r.M3ter()).setOwner(address(h));
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = h.register.selector;
        targetSelector(FuzzSelector(address(h), selectors));
        targetContract(address(h));
    }

    function invariantBothDirectionsMatchModel() public {
        for (uint64 id; id < 8; ++id) {
            bytes32 key = h.keys(id);
            assertEq(r.publicKey(id), key);
            if (key != bytes32(0)) assertEq(r.m3terId(key), id);
        }
        for (uint256 keyNumber; keyNumber < 9; ++keyNumber) {
            uint64 ownerPlusOne = h.ownersPlusOne(keyNumber);
            if (ownerPlusOne == 0) {
                vm.expectRevert(IRollup.KeyNotFound.selector);
                r.m3terId(bytes32(keyNumber));
            } else {
                assertEq(r.m3terId(bytes32(keyNumber)), ownerPlusOne - 1);
            }
        }
        assertEq(r.wordCount(), 0);
    }
}
