# M3tering Rollup 🐻‍❄️

Rollup stores proven meter accounts, nonces and public keys on Ethereum. Contracts can read the current state directly. The companion [prover](https://github.com/M3tering/Prover) validates signed meter actions with SP1 and submits sparse replacements for changed storage words.

## State and units

`words` is a public dynamic array of uint256 values. Four meters share each word. Meter `id` uses slot `id / 4` and lane `id % 4`; the lane starts at bit `64 * (id % 4)`.

| Lane field | Bits | Meaning |
|---|---:|---|
| Account, low bits | 40 | Cumulative watt-hours |
| Nonce, high bits | 24 | Last accepted action nonce |

The account limit is 1,099,511,627,775 Wh and the nonce limit is 16,777,215. Slot IDs are uint32: 4,294,967,296 slots support IDs 0–17,179,869,183. Sparse array growth does not write zero-filled gaps.

Signed messages are eight bytes: uint32 big-endian nonce followed by uint32 big-endian **milliwatt-hours**. The prover verifies the exact signed bytes, processes consecutive nonces and aggregates accepted mWh per meter. Each commit adds `floor(total_mWh / 1000)` Wh. Fractional Wh are discarded at each commit. A nonce advances even when the Wh increment is zero. Bounds fail instead of wrapping.

Every full 32-byte public key stays in `publicKey(id)`. Only the current `M3ter.ownerOf(id)` may set or revoke it; zero revokes. An NFT transfer does not automatically rotate its key. There is no administrator bypass or nonce reset.

`m3terId(key)` returns the meter currently registered with a nonzero key. Keys are unique across meters: attempting to register a key already assigned to another meter reverts with `KeyAlreadyRegistered`. Setting the same key again for its existing meter is allowed. Rotation and revocation remove the previous reverse entry, making that key available for registration again. Unknown, revoked and zero keys revert with `KeyNotFound`, so a valid result of zero always means meter 0. Registration authenticates the NFT owner; it does not prove possession of the signing key.

## Updates and proof statement

`commitState(bytes updates, bytes proof)` takes concatenated **36-byte records**, sorted by strictly increasing slot:

```
uint32 slot, big endian       4 bytes
uint256 new word, big endian 32 bytes
```

There are no modes, deltas, block anchors or global sequence counters. Empty/malformed data, duplicate/descending slots and non-increasing words revert. The guest enforces signatures, per-lane bounds, consecutive nonces and preservation of untouched lanes.

Public values are exactly `keccak256(transcript)` as 32 bytes. The transcript has a 52-byte prefix and 100 bytes per changed word:

| Field | Bytes | Purpose |
|---|---:|---|
| Chain ID | 32 | Bind the destination chain |
| Rollup address | 20 | Bind the destination contract |
| Slot, repeated | 4 | Bind the meter positions |
| Old word, repeated | 32 | Authenticate starting state and reject stale proofs |
| New word, repeated | 32 | Authenticate the replacement |
| Used-key hash, repeated | 32 | Authenticate the signing keys |

The used-key hash is keccak256 of four 32-byte entries: the stored key when that lane changes, zero otherwise. Old words and keys come from contract storage, not calldata. The fixed guest key identifies the accepted protocol. Record count is implicit in the fixed-length encoding. No MPT proofs, headers or historical state authentication are required.

A proof remains valid while its old words and used keys match. Disjoint-slot batches can coexist; batches sharing a slot conflict. A successful transition cannot replay against its new state. Rotating a used key invalidates a pending proof; rotating an unrelated lane's key does not. There is no time expiry or key-epoch history. Rotating back can restore a still-current proof's validity.

Batch destination binding does not change the eight-byte meter signature format. Reusing keys/nonces across deployments can permit the same signatures to be used to construct a different batch proof.

## Commit execution and events

One loop decodes each record, reads old state and used keys, constructs its transcript record and writes the replacement word. Temporary memory is reused for key hashing. Array length grows once after the loop, if needed. The verifier is called through a `view` interface, so verification uses STATICCALL. Failure reverts every provisional write and the length change. A missing verifier fails closed.

The verifier can read provisional new state but cannot mutate state through its static call. It must verify the supplied guest key, public values and proof rather than depend on getters exposing old values.

After success, `StateCommitted(bytes updates)` emits the exact update payload. Indexers split it into 36-byte records and overwrite their corresponding words. Transaction/log order provides ordering; reorgs require rolling back indexed events. Logs do not provide historical EVM-accessible state.

## Contract interface

| Function | Behavior |
|---|---|
| `commitState(updates, proof)` | Verify and apply sparse replacements |
| `setPublicKey(id, key)` | Owner-authorized key registration, rotation or revocation |
| `words(slot)` | Generated array getter; reverts outside the current length |
| `wordCount()` | Current array length |
| `publicKey(id)` | Full stored key; zero if absent/revoked |
| `m3terId(key)` | Meter ID for a registered key; reverts if absent/revoked/zero |
| `account(id)` | uint40 Wh account; zero for absent state |
| `nonce(id)` | uint24 nonce; zero for absent state |

Storage slot 0 holds the word-array length; slot 1 is the key mapping base. Word `slot` lives at `keccak256(bytes32(0)) + slot`. Changing this layout or wire format requires a coordinated prover release.

The program key remains in slot 2; the reverse mapping is appended at slot 3 and stores meter ID plus one internally. Reverse lookup adds storage work to key registration/rotation/revocation, not to `commitState`. The guest ELF and statement encoding are unchanged.

`src/Rollup.sol` contains the implementation. `src/interfaces/IRollup.sol` declares the API, errors/events and M3ter owner interface. Functions are ordered external, public, internal, private; state-changing functions precede view functions, which precede pure functions within each visibility group. Generated public getters are declared with their storage variables.

## Build and deployment

Install Foundry 1.8.1, then:

```sh
forge soldeer install
forge fmt --check
forge build --sizes
FOUNDRY_PROFILE=ci forge test -vvv
```

The compiler is Solidity 0.8.37 with Cancun-compatible bytecode. Forge-std 1.16.2 is locked by Soldeer. The contract no longer needs Solady.

The Sepolia deployment is `0xAb683B638f634F0a56e83acAcB81D17900606A79`; its transaction, program key, ELF checksum and meter 7 key registration are recorded in `deployments/sepolia.json`. It starts with zero accounts/nonces. Register keys through each meter's NFT owner and begin signed actions at nonce 1.

`VERIFIER` is `0x397A5f7f3dBd538f23DE225B51f532c34448dA9B`, and `M3ter` is `0x2c0008b6ea87802fc729A8f34B534F9D90d7Ac53`. `SP1_PROGRAM_VKEY` is storage-backed for testing. Only `VKEY_ADMIN` (the deploying wallet) can call `setProgramVKey(bytes32)`, only on chain ID 11155111, and zero keys are rejected. Every change emits `ProgramVKeyChanged`. This testing authority can change the transition rules, so it is a trust assumption, not a production upgrade mechanism. For a mainnet release, use a fixed, validated guest key and remove the test-only administration code. The setter is already disabled on other chains.

Derive the program key from the exact companion guest ELF. The key/admin fields follow `words` and `publicKey`, preserving their storage slots 0 and 1. No historical state or old queue is imported into the fresh deployment.

## Gas and batch size

A K-slot payload uses `36*K` bytes before the ABI envelope and proof. At 512 slots this is 18,432 bytes, 512 bytes more than three-byte slot IDs. For slots below 2^24 the additional index byte is zero, adding 4 intrinsic calldata gas per slot and approximately 8 log-data gas per slot, plus modest transcript/memory overhead. Higher slot IDs can add 16 rather than 4 calldata gas for that byte.

Actual local Anvil Osaka receipts, cold storage, four changed meters per word, mock verifier and 32-byte mock proof:

| Slots | Reused words | Fresh words |
|---:|---:|---:|
| 128 | 1,943,587 | 4,152,398 |
| 512 | 7,690,146 | 16,465,357 |

The 512-slot increase over three-byte IDs was 6,682 gas (about 13.05 per slot). Binary searches at a 16,777,216 gas cap found these boundaries; the next slot was sent and failed with out-of-gas:

| Fixture | Three-byte IDs | Four-byte IDs |
|---|---:|---:|
| Reused, ordinary values | 1,118 | 1,117 |
| Fresh, ordinary values | 521 | 521 |
| Reused, all-nonzero new words | 1,101 | 1,100 |
| Fresh, all-nonzero new words | 518 | 517 |

These are mock-verifier ceilings, not production limits. Real proof verification, proof calldata, sparse IDs and chain rules affect capacity. The prover's conservative defaults remain **647 reused / 322 fresh** words under current pricing, or **454 reused / 90 fresh** under the specified Glamsterdam model, with both budgets at 15m, 1.5m fixed allowance, 12,000 per-word overhead and 20% headroom. The extra byte remains inside that overhead allowance. Mixed batches are priced using their actual old words.

The forecast uses [EIP-8037](https://eips.ethereum.org/EIPS/eip-8037) and [EIP-8038](https://eips.ethereum.org/EIPS/eip-8038); it is not a measurement on a finalized fork client. Recalibrate against the deployed verifier and target chain before changing allowances. The [transaction cap](https://eips.ethereum.org/EIPS/eip-7825) and any separate state-gas budget must both be respected.

Reproduce local receipts after `forge build`:

```sh
anvil --hardfork osaka --gas-limit 100000000 --port 18548 --silent
# In another terminal, from this repository:
python3 scripts/benchmark.py
WORST_WORD=1 python3 scripts/benchmark.py
```

The script resets only its hard-coded localhost node. JSON results are under `benchmarks/`. Tests cover authority, full-key persistence, rollback, static verification, replay/stale proofs, destination binding, framing, four-byte/max-slot boundaries, exact event bytes, Rust statement equality and stateful accounting. Mocks test the contract/prover interface; a real production proof remains part of deployment validation.
