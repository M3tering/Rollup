// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;
import {Test} from "forge-std/Test.sol";
import {Rollup} from "../src/Rollup.sol";
import {TestVerifier} from "./Rollup.t.sol";

contract RollupGasTest is Test {
    function testGas4096WorstCase() public {
        benchmark(4096, false, 4);
    }

    function testGas128Reused() public {
        benchmark(128, false, 4);
    }

    function testGas512Reused() public {
        benchmark(512, false, 4);
    }

    function testGas768Reused() public {
        benchmark(768, false, 4);
    }

    function testGas1024Reused() public {
        benchmark(1024, false, 4);
    }

    function testGas128Fresh() public {
        benchmark(128, true, 4);
    }

    function testGas512Fresh() public {
        benchmark(512, true, 4);
    }

    function testGas512OneMeter() public {
        benchmark(512, false, 1);
    }

    function benchmark(uint256 count, bool fresh, uint256 changedMeters) internal {
        Rollup target = new Rollup();
        vm.etch(address(target.VERIFIER()), address(new TestVerifier()).code);
        bytes memory transcript = new bytes(52 + 100 * count);
        bytes memory payload = new bytes(36 * count);
        assembly {
            mstore(add(transcript, 32), chainid())
            mstore(add(transcript, 64), shl(96, target))
        }
        {
            uint256 old;
            uint256 value;
            for (uint256 p; p < 4; ++p) {
                if (!fresh) old |= (uint256(10000) | (uint256(100) << 40)) << (64 * p);
                value |= (p < changedMeters
                            ? (uint256(10001) | (uint256(101) << 40))
                            : (uint256(10000) | (uint256(100) << 40))) << (64 * p);
            }
            if (count == 4096) value = type(uint256).max;
            bytes32[4] memory keys;
            for (uint256 p; p < changedMeters; ++p) {
                keys[p] = bytes32(uint256(7));
            }
            bytes32 hash = keccak256(abi.encode(keys));
            uint256 base = uint256(keccak256(abi.encode(uint256(0))));
            for (uint256 i; i < count; ++i) {
                if (!fresh) vm.store(address(target), bytes32(base + i), bytes32(old));
                for (uint256 p; p < 4; ++p) {
                    vm.store(address(target), keccak256(abi.encode(i * 4 + p, uint256(1))), bytes32(uint256(7)));
                }
                assembly {
                    let dest := add(add(transcript, 84), mul(i, 100))
                    mstore(dest, shl(224, i))
                    mstore(add(dest, 4), old)
                    mstore(add(dest, 36), value)
                    mstore(add(dest, 68), hash)
                    let wire := add(add(payload, 32), mul(i, 36))
                    mstore(wire, shl(224, i))
                    mstore(add(wire, 4), value)
                }
            }
            if (!fresh) vm.store(address(target), bytes32(0), bytes32(count));
        }
        measure(target, payload, abi.encodePacked(keccak256(transcript)), count);
    }

    function measure(Rollup target, bytes memory payload, bytes memory proof, uint256 count) internal {
        bytes memory callData = abi.encodeCall(target.commitState, (payload, proof));
        uint256 intrinsic = 21000;
        for (uint256 i; i < callData.length; ++i) {
            intrinsic += callData[i] == 0 ? 4 : 16;
        }
        vm.cool(address(target));
        vm.cool(address(target.VERIFIER()));
        uint256 beforeGas = gasleft();
        target.commitState(payload, proof);
        uint256 used = beforeGas - gasleft();
        emit log_named_uint("words", count);
        emit log_named_uint("execution (mock verifier, includes CALL overhead)", used);
        emit log_named_uint("intrinsic calldata gas (32-byte mock proof)", intrinsic);
        emit log_named_uint("execution plus intrinsic", used + intrinsic);
        emit log_named_uint("payload bytes", payload.length);
    }
}
