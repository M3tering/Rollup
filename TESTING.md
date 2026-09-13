# Behavioral test specification

These tests protect protocol behavior, not just a particular implementation of SSTORE2 addressing. When a protocol rule changes deliberately, update the specification, prover, contract, and relevant expected behavior together.

## Executable checks

| Requirement | Coverage |
| --- | --- |
| Genesis is index zero, two zero-payload snapshots, no verified genesis transition | Genesis storage, CREATE nonce, and sentinel event test |
| Only an accepted statement advances state | Strict verifier double; proof, account data, nonce data, parent account hash, parent nonce hash, anchor, and program-key mismatch cases |
| Submissions are permissionless | Arbitrary submitter test and randomized senders |
| The committed event describes the proven transition | Old anchor, sender, new index, payloads, and proof checked |
| Next proof is pinned to the previous successful commit's selected EVM snapshot | Block advancement test, stale-statement rejection, long-idle characterization |
| Blob framing is unambiguous and obeys the code-size limit | Equal lengths; mismatch/oversize rejection; exact maximum; empty payload acceptance |
| Records match runtime bytes, including genesis and partial records | Independent byte-loop oracle; payload fuzzing; token-zero and end-of-blob checks |
| Zero selects accounts and every nonzero selector selects nonces | Full uint256 `io` fuzzing and invariant reads with maximum selector |
| History cannot be overwritten by later transitions | Independent complete history model and 129-commit RLP boundary test |
| All successful commits consume exactly two CREATE nonces | Actual VM nonce and independently computed address checks |
| Failure cannot leave a partial snapshot or skip addresses | Proof/shape rejection checks; artificial second-CREATE collision and successful retry |
| Existing limitations remain visible | Undeployed future read, same-statement no-op replay, old stored anchor acceptance |

`RollupHandler.advance` creates model-derived statements, random payloads, selection between two EOA actors, and block gaps. `reject` exercises three rejected submission classes. The invariant checks the complete modeled history after each action. Setup seeds a successful transition to avoid genesis-only vacuity. The invariant target is restricted to those two handler selectors; the fuzzer cannot directly reconfigure the verifier.

The artificial collision uses a cheatcode to place code at the second predicted address. This is fault injection to test transaction atomicity; it does not demonstrate that an external attacker can deploy code at that address.

## CI and gas policy

Run formatting, locked dependency installation, build/size checks, behavioral fuzz tests, and stateful invariants on each pull request. The committed workflow implements these checks with a pinned Foundry version.

Gas reports are informational. The previous workflow's plain `forge snapshot` generated numbers without comparing a committed baseline, so it was not a regression gate. If desired, add a dedicated gas suite with fixed payloads and clearly separate proof verification, snapshot writing, and reads; commit its baseline and run `forge snapshot --check` against that suite. Benchmark actual transaction gas separately, including calldata and the real verifier, on the intended chain/fork.

Keep the mainnet code-size limit enabled in tests. Split oversized test harnesses rather than raising that limit and accidentally allowing oversized data contracts. Increase fuzz/invariant budgets periodically, and retain minimized failures as explicit regression tests.

Invariant transaction origins and submitters are drawn from two fixed EOA actors. This prevents cheatcode impersonation from touching the Rollup or future snapshot addresses. Unit tests also submit from a deployed contract. A handler regression checks normalization of an input that names the Rollup itself.
