// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;
import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {Rollup} from "../src/Rollup.sol";
import {TestM3ter, TestVerifier} from "./Rollup.t.sol";

contract RollupHandler is Test {
    Rollup public r;
    uint40[32] public accounts;
    uint24[32] public nonces;
    uint256 public commits;

    constructor(Rollup target) {
        r = target;
    }

    function update(uint8 rawMeter, uint16 mwh) external {
        uint64 id = rawMeter % 32;
        uint64 slot = id / 4;
        uint256 old = (slot < r.wordCount() ? r.words(slot) : 0);
        uint256 shift = 64 * (id % 4);
        uint40 wh = accounts[id] + uint40(mwh / 1000);
        uint24 nonce = nonces[id] + 1;
        uint256 value =
            (old & ~(uint256(type(uint64).max) << shift)) | ((uint256(wh) | (uint256(nonce) << 40)) << shift);
        bytes32 keyHash = keccak256(abi.encode(bytes32(0), bytes32(0), bytes32(0), bytes32(0)));
        bytes32 commitment = keccak256(abi.encodePacked(block.chainid, address(r), uint32(slot), old, value, keyHash));
        r.commitState(abi.encodePacked(uint32(slot), value), abi.encodePacked(commitment));
        accounts[id] = wh;
        nonces[id] = nonce;
        ++commits;
    }
}

contract RollupInvariantTest is StdInvariant, Test {
    Rollup r;
    RollupHandler h;

    function setUp() public {
        r = new Rollup();
        vm.etch(address(r.VERIFIER()), address(new TestVerifier()).code);
        h = new RollupHandler(r);
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = h.update.selector;
        targetSelector(FuzzSelector(address(h), selectors));
        targetContract(address(h));
    }

    function invariantMatchesIndependentMeterModel() public view {
        for (uint64 m; m < 32; ++m) {
            assertEq(r.account(m), h.accounts(m));
            assertEq(r.nonce(m), h.nonces(m));
        }
        assertLe(r.wordCount(), 8);
        assertEq(r.account(32), 0);
    }
}
