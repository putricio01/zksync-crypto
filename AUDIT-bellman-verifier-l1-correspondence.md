# Bellman Verifier L1 Correspondence Audit

## Scope

Confirm that the Fiat-Shamir-audited Bellman verifier corresponds to the
verifier used by the deployed L1 smart contract for zkSync Era.

## L1 Verifier Path

```
Boojum Proof (Goldilocks field, FRI-based)
  -> snark-wrapper (crates/snark-wrapper/)
     Verifies Boojum proof inside a Bellman PLONK circuit.
     WrapperCircuit (PLONK variant) or WrapperCircuitWidth3NoLookupNoCustomGate (FFLONK variant)
  -> Bellman PLONK/FFLONK Proof (BN254, KZG)
  -> Scheduler Verification Key (JSON)
     plonk_scheduler_key.json / fflonk_scheduler_key.json
  -> era-contracts/tools/src/main.rs (VK injection into templates)
  -> L1VerifierPlonk.sol / L1VerifierFflonk.sol
  -> DualVerifier.sol (routes by proof type)
  -> Deployed on Ethereum L1
```

## Production Verifier Modules

### PLONK
- Rust: `crates/bellman/src/plonk/better_better_cs/verifier/mod.rs`
  - verify() line 21, aggregate() line 51
  - Circuit: ZkSyncSnarkWrapperCircuit
  - Gate: SelectorOptimizedWidth4MainGateWithDNext + Rescue5CustomGate + lookups
  - VK hash: 0x93e83aa1ec05a2ac4de1f0b241394efb9f94a4e7c1784a5a9bf6b85eb930c62a

### FFLONK
- Rust: `crates/fflonk/src/verifier.rs`
  - verify() line 98
  - Circuit: ZkSyncSnarkWrapperCircuitNoLookupCustomGate
  - Gate: NaiveMainGate only, no lookups
  - VK hash: 0xe4503cf38485e3d728a7362155d53d3d63293e2fa48dca4f5588aa4625de251f

### Unused/Deprecated
- `bellman/src/plonk/better_cs/verifier.rs` - DEPRECATED (old verify_nonhomomorphic)
- `bellman/src/plonk/verifier/mod.rs` - DEPRECATED (legacy verifier)
- `bellman/src/plonk/better_better_cs/redshift/` - UNUSED (FRI transparency variant)
- `crates/codegen/template/` - SUPERSEDED by era-contracts/tools/data/ templates

## Transcript: RollingKeccakTranscript

File: `crates/bellman/src/plonk/commitments/transcript/keccak_transcript.rs`

- Keccak-256 based, two-state rolling sponge
- DST tags: 0 (state_0 update), 1 (state_1 update), 2 (challenge extraction)
- State update: keccak256(DST[4 BE bytes] || state_0[32] || state_1[32] || data[32]) = 100 bytes
- Challenge: keccak256(DST=2[4 BE bytes] || state_0[32] || state_1[32] || counter[4 BE bytes]) = 72 bytes
- Field mask applied to keep challenges in scalar field

Byte-level match confirmed with Solidity implementations in era-contracts.

## Challenge Ordering

### PLONK: PI -> [a,b,c,d] -> eta -> [s] -> beta,gamma -> [z_perm] -> beta',gamma' -> [z_lookup] -> alpha -> [t_0..t_3] -> z -> evaluations -> v -> [W],[W'] -> u

### FFLONK: PI -> c0 -> commitment_0 -> beta,gamma -> commitment_1 -> r -> evaluations -> alpha -> W -> y; z = r^24

Both orderings confirmed identical between Rust and Solidity.

## Verdict: UNCERTAIN

The structural correspondence is strong: transcript scheme, challenge ordering, opening
proof binding, and VK injection pipeline all match. However, the Solidity verifier is a
hand-written re-implementation (~1600 lines of Yul assembly), not auto-generated from
the Rust code. A formal equivalence proof does not exist in these repositories.

No currently exploitable Fiat-Shamir vulnerability was identified.
