# M3tering Rollup

This repository contains the Ethereum settlement and runtime-readable state contract for the M3tering metering protocol. `Rollup` accepts SP1-proven state transitions, stores account and nonce snapshots in immutable contract code, and exposes current and historical six-byte records to other contracts.

The Solidity contract authenticates the transition through an SP1 verifier gateway. Meter-action rules, signature verification, and proofs of public keys held in an Ethereum keystore belong to the corresponding SP1 program; they are not independently implemented by this contract.

**Deployment status:** `SP1_PROGRAM_VKEY` is marked TODO in source. Confirm the exact production program key, gateway deployment, public-value encoding, and a real end-to-end proof before deploying. The test verifier in this repository checks the contract/verifier boundary; it does not verify cryptographic proofs.

## Repository layout

| Path | Purpose |
| --- | --- |
| `src/Rollup.sol` | State transition verification, snapshot creation, record getters |
| `src/interfaces/IRollup.sol` | Public contract ABI, errors, and event |
| `src/interfaces/ISP1Verifier.sol` | SP1 verifier gateway interface |
| `test/Rollup.t.sol` | Behavioral, negative-path, boundary, and fuzz tests |
| `test/Rollup.invariant.t.sol` | Randomized transition sequences checked against an independent history model |
| `foundry.toml`, `soldeer.lock` | Compiler, EVM target, dependency pins, and test configuration |
| `.github/workflows/test.yml` | Reproducible dependency install, formatting, build, and tests |

## State lifecycle

Deployment creates two genesis snapshots, account first and nonce second. Each payload is `0x00`; each snapshot's deployed runtime code is consequently `0x0000`, because SSTORE2 adds a leading STOP byte. `chainLength` starts at zero, identifying genesis. It counts successful subsequent commits, so there are always `chainLength + 1` historical snapshot pairs.

For `commitState(accountBlob, nonceBlob, proof)`:

1. Both payloads must have equal length. Each must contain at most 24,575 bytes.
2. The contract builds public values from the stored anchor, current snapshot code hashes, and proposed snapshot runtime bytes, then calls the configured verifier.
3. If verification succeeds, it deploys the account snapshot and then the nonce snapshot using `SSTORE2.write`.
4. It increments `chainLength` and emits `NewState` containing the anchor used to verify this transition.
5. It sets `anchorBlock` to `blockhash(block.number - 1)` for the next proof.

Anyone may submit a valid proof. A verifier rejection or deployment failure reverts the entire call, including both CREATE nonce effects, stored fields, and logs. There are no owner-only transition controls or upgrade functions in this contract.

## Anchoring the EVM state

`anchorBlock` is an Ethereum **block hash**, not a state root. The SP1 program must authenticate the block header against this hash, derive its state root, and validate keystore account/storage proofs against that root before accepting meter signatures.

The constructor sets the first anchor to its parent block. Each successful commit verifies against the previously stored anchor and selects its own parent block as the next anchor. This fixes the external-state snapshot before the next proof is generated.

For example, deployment in block 100 selects block 99. A commit in block 110 proves against block 99, then selects block 109 for the following proof. A key rotation in block 105 is not visible to that first commit. This contract provides a previously selected snapshot, not validation against the latest state at transaction execution time.

Several commits in one block can select the same next anchor. A long idle period does not expire a stored anchor hash after 256 blocks: the hash is already in storage. The prover still needs historical header/state witnesses, which may require an archive-capable data provider. If signature revocation must take effect sooner, a different freshness policy is needed in both the contract and proving protocol.

## Proof public values

The exact encoding is raw byte concatenation, **not** `abi.encode`:

```text
anchorBlock                     32 bytes
keccak256(previous account code) 32 bytes
keccak256(previous nonce code)   32 bytes
0x00 || accountBlob             1 + L bytes
0x00 || nonceBlob               1 + L bytes
```

The total length is `98 + 2*L`. Previous code hashes include the SSTORE2 STOP byte. The caller supplies payloads without that byte; the contract adds it to the statement and SSTORE2 adds it when deploying code.

The equal-length rule makes the final two fields unambiguous: after the first 96 bytes, split the remainder exactly in half and require both leading bytes to be zero. The prover and submission client must use this same framing. The zkVM must enforce it: unequal prover outputs can otherwise encode the same bytes as a different equal-length Solidity pair. If they trim trailing zero records independently, pad both outputs to a shared length **before producing the proof**. Padding after proving changes the public values and invalidates that proof.

The contract does not separately enforce record alignment, monotonic meter nonces, balance arithmetic, or signature authorization. The pinned SP1 program must enforce the intended semantic rules. Empty payloads and partial trailing records pass the Solidity shape checks if a proof is accepted.

The current statement does not include the Rollup address, chain ID, or `chainLength`. Changed parent hashes or an updated anchor invalidate an old statement. However, a no-op proof can be reused when the anchor and both parent hashes remain unchanged. Identical deployments may also share statements. Applications needing unique transitions or deployment-specific proofs should add explicit domain/sequence binding in a coordinated protocol change.

## Snapshot addresses

Snapshots use direct CREATE; no CREATE3 helper proxy or stored pointer mapping is needed. A newly created contract begins with CREATE nonce 1. Genesis consumes nonces 1 and 2; each later transition consumes exactly two more.

For historical state index `s`:

```text
account CREATE nonce = 2*s + 1
nonce   CREATE nonce = 2*s + 2
address = last20bytes(keccak256(RLP([address(rollup), CREATE nonce])))
```

`stateAddress(s, io)` implements this calculation using Solady `LibRLP`. `io == 0` selects account state; **every nonzero value** selects nonce state. After genesis and every successful commit, the Rollup account's actual nonce is `2*chainLength + 3`.

This calculation depends on exactly two ordered CREATEs per successful transition and the two constructor CREATEs. Adding any other CREATE/CREATE2 in the Rollup execution context, switching to a proxy without equivalent initialization, or skipping a snapshot requires redesigning the address scheme. Failed transactions do not consume the sequence. Sending ETH to a future snapshot address alone does not prevent its creation.

## Reading six-byte records

Records are indexed over the **deployed runtime** `0x00 || payload`. Record `tokenId` consists of runtime bytes `[6*tokenId, 6*tokenId + 6)`, padded on the right with zeros when a deployed snapshot is shorter.

| Record | Payload bytes used | Result |
| --- | --- | --- |
| Token 0 | First five bytes | Leading `0x00` followed by five payload bytes |
| Token 1 | Bytes 5 through 10 | Six payload bytes |
| Token 2 | Bytes 11 through 16 | Six payload bytes |

SSTORE2's read functions omit its STOP byte. The getter therefore adds that byte back for token zero and uses payload offset `6*tokenId - 1` for subsequent tokens. Token zero has 40 usable bits; the others have 48. `bytes6` preserves byte order; use `uint48(value)` for the corresponding unsigned big-endian integer.

At the 24,575-byte payload limit, runtime code is 24,576 bytes and contains 4,096 records, indexed 0 through 4,095. Each account/nonce snapshot has this capacity independently. Reads beyond a deployed snapshot return zero for ordinary token IDs. Extreme indexes can revert on checked arithmetic overflow. Reading an undeployed future snapshot fails in SSTORE2; address prediction itself does not assert that a snapshot exists. An all-zero record is not an explicit existence flag.

```solidity
IRollup rollup = IRollup(rollupAddress);
uint48 currentAccount = uint48(rollup.account(tokenId));
uint48 currentNonce = uint48(rollup.nonce(tokenId));
bytes6 historicalAccount = rollup.state(stateIndex, 0, tokenId);
address currentNonceSnapshot = rollup.latestStateAddress(1);
```

## Events

```solidity
event NewState(
    address indexed from,
    bytes32 indexed anchorBlock,
    uint256 indexed chainLength,
    bytes accountBlob,
    bytes nonceBlob,
    bytes proof
);
```

For ordinary commits, `from` is the submitter, `chainLength` is the newly created index, and the event anchor is the one verified by that commit. The stored anchor after the transaction is for the next proof.

Genesis intentionally uses a sentinel event: anchor `bytes32(0)`, index zero, both payloads `0x00`, and proof `0x00`. No genesis proof is verified. The stored anchor is nevertheless the constructor's parent-block hash. Indexers must handle index zero explicitly rather than interpreting its proof/anchor as a verified transition.

## Build and test

The project uses Foundry v1.8.1, Solidity 0.8.37, Solady 0.1.26, and forge-std 1.16.2. Soldeer installs dependencies into `dependencies/`; the legacy `lib/forge-std` submodule is not used by this configuration.

```sh
foundryup --install v1.8.1
forge soldeer install
forge fmt --check
forge build --sizes
forge test -vv
FOUNDRY_PROFILE=ci forge test -vvv --gas-report
```

Commit `foundry.toml` and `soldeer.lock` together. Use `forge soldeer update` deliberately when changing versions; ordinary setup and CI use `install`. CI rejects lockfile/config changes caused by installation.

The EVM code-generation/test target is pinned to Cancun, and the contract-size limit is explicitly 24,576 bytes. This gives a reproducible baseline; it does not simulate proposed Glamsterdam gas schedules. Test gas reports include the test verifier and test machinery and must not be presented as production proof-verification or transaction costs.

The default profile runs each fuzz test 256 times and each invariant for 64 sequences of depth 32. CI uses 1,024 fuzz cases and 256 sequences of depth 64, with unexpected handler reverts treated as failures. Foundry prints failing inputs and retains counterexamples for diagnosis.

## What the tests establish

The tests check genesis/event conventions, accepted transitions from arbitrary submitters, exact proof-statement binding, invalid input/proof rollback, maximum and empty payloads, record decoding, all-nonzero `io` normalization, historical immutability, address calculation across RLP nonce boundaries, and recovery after a failed second creation. They also characterize no-op replay and old-anchor acceptance.

Stateful tests maintain separate account/nonce histories and the expected anchor. After randomized valid and invalid submissions, they compare all historical snapshot code and record values against that model, together with `chainLength`, latest getters, and the actual CREATE nonce. Stateful submissions alternate between two EOA actors; unit tests also submit from a contract. The verifier double only accepts the statement prepared by the model.

These checks do not establish the correctness of the SP1 program or gateway. Add a fixture using a real production program/proof, authenticated keystore state at a known anchor, and the exact deployment environment before treating this repository as an end-to-end protocol test. See [TESTING.md](TESTING.md) for the integration cases and maintenance policy.
