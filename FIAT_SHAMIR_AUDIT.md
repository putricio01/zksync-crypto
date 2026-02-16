# Fiat-Shamir Security Audit Report: zkSync Era Proof System

**Date:** February 2026
**Scope:** Fiat-Shamir transcript integrity across boojum (FRI-based), bellman (PLONK/KZG), fflonk, and snark-wrapper
**Methodology:** Based on known vulnerability patterns (Frozen Heart, Last Challenge Attack, SP1, Plonky3 FRI)

---

## 1. Executive Summary

This audit systematically checks the zkSync Era proof system against all known Fiat-Shamir vulnerability classes. The audit covers:

- **Boojum** (core FRI-based proof system): native verifier, prover, and in-circuit recursive verifier
- **Snark-wrapper** (recursive verifier wrapping boojum proofs into PLONK/KZG)
- **Bellman** (outer PLONK/KZG verifier for L1 Ethereum verification)
- **FFlonk** (alternative fold-friendly PLONK variant)

**Overall Assessment: No critical Fiat-Shamir vulnerabilities detected.** All transcript operations follow correct ordering, and all known attack vectors are properly mitigated.

---

## 2. Architecture Overview

The zkSync Era proof system uses a multi-layer recursive structure:

```
Base Layer (20 circuit types, Goldilocks + FRI + Poseidon2)
  └─> Leaf Layer (recursive verification)
       └─> Node Layer (recursive aggregation, 32-arity tree)
            └─> Recursion Tip
                 └─> Scheduler
                      └─> Compression (5 modes)
                           └─> SNARK Wrapper (BN256 + KZG + Keccak transcript)
                                └─> L1 Ethereum Verifier Contract
```

Each layer involves a Fiat-Shamir transcript. The audit checks every layer.

---

## 3. Boojum Native Verifier: Transcript Sequence

**File:** `crates/boojum/src/cs/implementations/verifier.rs`

### Complete Transcript Operation Sequence

| Step | Line | Operation | Data | Type |
|------|------|-----------|------|------|
| 1 | 924 | `witness_merkle_tree_cap` | VK setup Merkle tree cap | ABSORB |
| 2 | 944 | `witness_field_elements` | Public input values (each) | ABSORB |
| 3 | 952 | `witness_merkle_tree_cap` | Witness oracle cap (variables + witness + multiplicities) | ABSORB |
| 4 | 955 | `get_multiple_challenges_fixed::<2>` | **beta** (copy permutation) | SQUEEZE |
| 5 | 957 | `get_multiple_challenges_fixed::<2>` | **gamma** (copy permutation) | SQUEEZE |
| 6 | 962 | `get_multiple_challenges_fixed::<2>` | **lookup_beta** (conditional) | SQUEEZE |
| 7 | 964 | `get_multiple_challenges_fixed::<2>` | **lookup_gamma** (conditional) | SQUEEZE |
| 8 | 978 | `witness_merkle_tree_cap` | Stage 2 oracle cap (z-poly, lookup encoding) | ABSORB |
| 9 | 981 | `get_multiple_challenges_fixed::<2>` | **alpha** (quotient combination) | SQUEEZE |
| 10 | 1059 | `witness_merkle_tree_cap` | Quotient oracle cap | ABSORB |
| 11 | 1063 | `get_multiple_challenges_fixed::<2>` | **z** (evaluation point) | SQUEEZE |
| 12 | 1068 | `witness_field_elements` | All values_at_z evaluations | ABSORB |
| 13 | 1072 | `witness_field_elements` | All values_at_z_omega evaluations | ABSORB |
| 14 | 1076 | `witness_field_elements` | All values_at_0 evaluations | ABSORB |
| 15 | 1819-1820 | `get_challenge` x2 | **c0, c1** (FRI quotient batching) | SQUEEZE |
| 16 | 1864 | `witness_merkle_tree_cap` | FRI base oracle cap | ABSORB |
| 17 | 1867-1868 | `get_challenge` x2 | **c0, c1** (first FRI fold) | SQUEEZE |
| 18 | 1903 | `witness_merkle_tree_cap` | Intermediate FRI oracle cap (per round) | ABSORB |
| 19 | 1907-1908 | `get_challenge` x2 | **c0, c1** (FRI fold challenges, per round) | SQUEEZE |
| 20 | 1954-1955 | `witness_field_elements` | Final FRI monomials [c0, c1] | ABSORB |
| 21 | 1964 | `get_multiple_challenges` | PoW seed (conditional) | SQUEEZE |
| 22 | 1981 | `witness_field_elements` | PoW challenge value (conditional) | ABSORB |

---

## 4. Audit Checklist Results

### Check 1: Public Parameters Absorbed at Initialization

**Result: PASS**

- **Line 924:** `transcript.witness_merkle_tree_cap(&vk.setup_merkle_tree_cap)` — The verification key's setup Merkle tree cap (covering constant columns, permutation polynomials, and selector polynomials) is the **first** value absorbed.
- The `VerificationKeyCircuitGeometry` structural parameters (`domain_size`, `lookup_parameters`, etc.) are not directly absorbed as field elements but are validated against the verifier's own expected parameters (lines 900-918) and are implicitly bound through the Merkle cap commitment.

### Check 2: Public Inputs Absorbed Before First Challenge (Frozen Heart)

**Result: PASS**

- **Lines 936-944:** Each public input value is absorbed individually via `transcript.witness_field_elements(&[value])`.
- This happens **before** the first challenge derivation at line 955 (beta).
- **Frozen Heart is blocked:** The evaluation challenge depends on public inputs, so a malicious prover cannot compute random polynomials and retrofit public inputs.

### Check 3: All Prover Commitments Absorbed Before Dependent Challenges

**Result: PASS**

| Commitment | Absorbed At | Challenge Dependent On It | Squeezed At | Correct? |
|------------|------------|--------------------------|------------|----------|
| witness_oracle_cap | 952 | beta, gamma | 955, 957 | YES |
| stage_2_oracle_cap | 978 | alpha | 981 | YES |
| quotient_oracle_cap | 1059 | z | 1063 | YES |
| fri_base_oracle_cap | 1864 | FRI fold c0,c1 | 1867-1868 | YES |
| intermediate FRI caps | 1903 | FRI fold c0,c1 | 1907-1908 | YES |
| final_fri_monomials | 1954-1955 | PoW seed | 1964 | YES |

### Check 4: Polynomial Evaluations Absorbed Before FRI Batching Challenge

**Result: PASS**

- **Lines 1068-1076:** All `values_at_z`, `values_at_z_omega`, and `values_at_0` are absorbed.
- **Lines 1819-1820:** FRI quotient batching challenges c0, c1 are squeezed **after** all evaluations.
- This prevents the Last Challenge Attack pattern where a prover could choose evaluation values after knowing the batching challenge.

### Check 5: Opening Proofs Bound Before Final Batching (Last Challenge Attack)

**Result: PASS (for boojum FRI-based system)**

In the boojum system, there is no separate "opening proof" commitment like in KZG-based PLONK. Instead, FRI oracle commitments and query responses serve this role. The FRI base oracle cap (line 1864) and all intermediate oracle caps (line 1903) are absorbed before their respective fold challenges. The final monomial coefficients (line 1954-1955) are absorbed before the PoW challenge.

**Result: PASS (for bellman KZG-based wrapper)**

See Section 7 below.

### Check 6: Cross-Component Values (SP1 Pattern)

**Result: PASS**

- **Lookup multiplicities:** Included in the witness oracle (committed at step 3, line 952).
- **Lookup encoding polynomials (A(x), B(x)):** Included in stage 2 oracle (committed at step 8, line 978).
- **Lookup evaluations at 0 (sumcheck values):** Included in values_at_0 (committed at step 14, line 1076).
- **Copy-permutation intermediate products:** Included in stage 2 oracle.
- **SP1 pattern (unbound cumulative sums):** NOT APPLICABLE — zkSync uses Lasso-style direct encoding, not cumulative sum products.

### Check 7: FRI Folding Randomization (Plonky3 Pattern)

**Result: PASS**

**File:** `crates/boojum/src/cs/implementations/fri/mod.rs`

- FRI challenges are generated in the extension field Fp2 (two base field elements c0, c1).
- At each folding step, the challenge is properly **squared** for higher-degree interpolation: `current.square()` (lines 220-224, 284-288).
- The folding operation properly applies `challenge * (f(x) - f(-x)) / 2x`, with correct domain element and coset inverse updates.
- **No missing beta^2 randomization:** Challenge powers are correctly computed as `[alpha, alpha^2, alpha^4, ...]` for multi-level folding.

### Check 8: Final Polynomial Degree Bound Check

**Result: PASS**

**Lines 1929-1951:** The verifier:
1. Computes `expected_degree` by tracking degree reduction through the FRI schedule.
2. Validates `final_expected_degree == expected_degree` (line 1929).
3. Validates monomial coefficient lengths match `expected_degree` (lines 1944-1951).
4. Rejects zero-length monomials (lines 1939-1942).

### Check 9: Verifier Recomputes All Challenges (No Prover-Supplied Challenges)

**Result: PASS**

The verifier constructs its own transcript and derives all challenges independently. No challenge values from the proof struct are trusted — the verifier absorbs proof elements and squeezes its own challenges.

### Check 10: Prover/Verifier Transcript Consistency

**Result: PASS**

The prover (`crates/boojum/src/cs/implementations/prover.rs`) and verifier perform identical transcript operations in the same order:

| Prover | Verifier | Match? |
|--------|----------|--------|
| Line 211: `witness_merkle_tree_cap(vk.setup_merkle_tree_cap)` | Line 924 | YES |
| Line 264-265: `witness_field_elements(public_inputs)` | Line 944 | YES |
| Line 353: `witness_merkle_tree_cap(witness_tree_cap)` | Line 952 | YES |
| Line 360-363: `get_multiple_challenges_fixed::<2>` x2 | Lines 955, 957 | YES |
| Line 402-405: lookup challenges (conditional) | Lines 962, 964 | YES |
| Line 554: `witness_merkle_tree_cap(stage_2_cap)` | Line 978 | YES |
| Line 560: `get_multiple_challenges_fixed::<2>` | Line 981 | YES |
| Line 1507: `witness_merkle_tree_cap(quotient_cap)` | Line 1059 | YES |
| Line 1513: `get_multiple_challenges_fixed::<2>` | Line 1063 | YES |
| Lines 1716, 1754, 1813: evaluations | Lines 1068, 1072, 1076 | YES |
| Lines 1840-1841: FRI challenges | Lines 1819-1820 | YES |
| FRI `do_fri()`: same pattern | Same pattern | YES |

### Check 11: Recursive/In-Circuit Verifier Consistency

**Result: PASS**

Three recursive verifiers were checked:

1. **Boojum in-circuit verifier** (`crates/boojum/src/gadgets/recursion/recursive_verifier.rs`): Follows identical transcript sequence using `CircuitTranscript` trait methods that mirror the native `Transcript` trait.

2. **Snark-wrapper** (`crates/snark-wrapper/src/verifier/`): Uses `CircuitGLTranscript` with the same absorb/squeeze ordering.

3. **Recursion layer circuits** (`zksync-protocol/crates/zkevm_circuits/src/recursion/`): Leaf, node, and scheduler circuits all use the same recursive verifier interface.

No SP1/OpenVM-pattern divergence detected between native and recursive verifiers.

### Check 12: Polynomial Batching Distinctness

**Result: PASS**

**Lines 1830-1834:** FRI quotient batching uses `materialize_ext_challenge_powers` which generates distinct powers `[c^0, c^1, c^2, ..., c^(n-1)]` in the extension field. Each polynomial receives a unique randomization coefficient.

---

## 5. Bellman PLONK Verifier (L1 Wrapper)

**File:** `crates/bellman/src/plonk/better_better_cs/verifier/mod.rs`

This is the outermost verifier — the one whose transcript correctness is most critical because it's verified on Ethereum L1.

### Transcript Sequence

| Step | Lines | Operation | Data |
|------|-------|-----------|------|
| 1 | 66-68 | `commit_field_element` | Public inputs |
| 2 | 70-78 | `commit_point_as_xy` | Wire commitments |
| 3 | 80-86 | `commit_point_as_xy` + `get_challenge` | Lookup s-poly + eta (conditional) |
| 4 | 88-89 | `get_challenge` x2 | **beta, gamma** (copy permutation) |
| 5 | 91-92 | `commit_point_as_xy` | Grand product Z(x) commitment |
| 6 | 97-105 | `get_challenge` x2 + `commit_point_as_xy` | Lookup challenges + grand product |
| 7 | 108 | `get_challenge` | **alpha** |
| 8 | 158-160 | `commit_point_as_xy` | Quotient polynomial parts |
| 9 | 162 | `get_challenge` | **z** (evaluation point) |
| 10 | 214-408 | `commit_field_element` | All polynomial evaluations at z, z*omega |
| 11 | 804 | `get_challenge` | **v** (aggregation challenge) |
| 12 | 808-809 | `commit_point_as_xy` x2 | **[W_z] and [W_z_omega]** (opening proofs) |
| 13 | 811 | `get_challenge` | **u** (final batching challenge) |

### Frozen Heart Check: PASS
- Public inputs committed at lines 66-68, before any challenge.
- Grand product committed at line 91-92, after beta/gamma but this is correct (Z(x) depends on beta/gamma).

### Last Challenge Attack Check: PASS
- **[W_z]** committed at line 808 (after v, before u).
- **[W_z_omega]** committed at line 809 (after v, before u).
- **u** derived at line 811, AFTER both opening proof points are in the transcript.
- This directly blocks the Last Challenge Attack.

### Keccak Transcript Security
- Uses `RollingKeccakTranscript` with dual-state design and challenge counter.
- Domain separation via DST tags prevents cross-protocol attacks.
- 256-bit security from Keccak256.

---

## 6. FFlonk Verifier

**File:** `crates/fflonk/src/verifier.rs`

### Transcript Sequence

| Step | Lines | Operation | Data |
|------|-------|-----------|------|
| 1 | 136-138 | `commit_field_element` | Public inputs |
| 2 | 140 | `commit_point_as_xy` | VK c0 setup commitment |
| 3 | 143 | `commit_point_as_xy` | Witness commitment |
| 4 | 146-157 | `get_challenge` | Copy permutation + lookup challenges |
| 5 | 158 | `commit_point_as_xy` | Second commitment |
| 6 | 160 | `get_challenge` | **r** |
| 7 | 162-164 | `commit_field_element` | All evaluations |
| 8 | 170 | `get_challenge` | **alpha** |
| 9 | 171 | `commit_point_as_xy` | Opening proof W |
| 10 | 174 | `get_challenge` | **y** (final challenge) |

**Result: PASS** — Opening proof committed before final challenge.

---

## 7. Observations and Recommendations

### 7.1 Positive Findings

1. **Consistent transcript design:** All layers (boojum, snark-wrapper, bellman, fflonk) follow the same discipline of absorb-before-squeeze.
2. **Extension field challenges:** Boojum uses Fp2 challenges throughout, providing quadratic soundness amplification over the 64-bit Goldilocks base field.
3. **No shortcuts in recursive verifier:** The in-circuit verifier performs the same transcript operations as the native verifier — no SP1-style omissions.
4. **Proper degree checking:** FRI final polynomial degree is strictly validated before use.

### 7.2 Areas for Continued Monitoring

1. **VK Geometry Parameters:** The `VerificationKeyCircuitGeometry` fields (`domain_size`, `quotient_degree`, etc.) influence verifier behavior but are not individually absorbed as field elements. They are instead validated against the verifier's expected parameters (lines 900-918) and implicitly bound via the Merkle cap. Future changes should ensure these validations remain comprehensive.

2. **Lookup Parameters Conditional Branching:** The lookup challenge derivation (steps 6-7) is conditional on `lookup_parameters != NoLookup`. Both prover and verifier must agree on this condition. The current implementation correctly derives this from the VK parameters, but any refactoring should preserve this synchronization.

3. **PoW Conditional Path:** The proof-of-work section (steps 21-22) is conditional on `new_pow_bits != 0`. When PoW is disabled (pow_bits = 0), these transcript operations are skipped. This is correct but creates two distinct valid transcript paths.

4. **FRI Schedule Determinism:** The FRI folding schedule is computed by `compute_fri_schedule` from the proof config and VK parameters. The verifier recomputes this independently rather than trusting the proof's claimed schedule. This is correct.

### 7.3 Testing Recommendations

For each vulnerability class, the following test vectors would strengthen confidence:

1. **Frozen Heart Test:** Construct a proof with random wire polynomials, verify that the verifier rejects it (cannot retrofit public inputs because they're bound to challenges).

2. **Last Challenge Attack Test (bellman):** Modify [W_z] and [W_z_omega] in a valid proof, verify the verifier rejects (because u changes, invalidating the pairing check).

3. **Transcript Divergence Test:** Modify the prover to skip one absorb operation, verify the verifier rejects (challenges will differ).

4. **FRI Degree Bound Test:** Submit a proof with final monomials of incorrect length, verify rejection at line 1944-1951.

---

## 8. Vulnerability Matrix Summary

| # | Check | Vulnerability Prevented | Status |
|---|-------|------------------------|--------|
| 1 | VK/setup absorbed at initialization | Frozen Heart (variant) | PASS |
| 2 | Public inputs absorbed before first challenge | Frozen Heart | PASS |
| 3 | Every commitment absorbed before dependent challenge | All variants | PASS |
| 4 | Evaluations absorbed before FRI batching challenge | Last Challenge Attack | PASS |
| 5 | Opening proofs absorbed before final challenge (bellman) | Last Challenge Attack | PASS |
| 6 | Cross-component values (lookups, permutations) absorbed | SP1 Cumulative Sum | PASS |
| 7 | FRI batching uses distinct challenge powers | FRI Folding | PASS |
| 8 | FRI folding applies proper squared challenges | Plonky3 FRI | PASS |
| 9 | Verifier recomputes all challenges from transcript | All variants | PASS |
| 10 | Prover/verifier transcript sequences are identical | Transcript mismatch | PASS |
| 11 | Recursive verifier performs same FS operations as native | SP1, OpenVM bugs | PASS |
| 12 | Final polynomial degree bounds checked | Plonky3 degree check | PASS |

---

## 9. Key File References

### Boojum (FRI-based core)
- Transcript trait: `crates/boojum/src/cs/implementations/transcript.rs`
- Algebraic sponge: `crates/boojum/src/algebraic_props/sponge.rs`
- Verifier: `crates/boojum/src/cs/implementations/verifier.rs`
- Prover: `crates/boojum/src/cs/implementations/prover.rs`
- FRI: `crates/boojum/src/cs/implementations/fri/mod.rs`
- Recursive verifier: `crates/boojum/src/gadgets/recursion/recursive_verifier.rs`

### Snark-wrapper (recursive bridge)
- Wrapper verifier: `crates/snark-wrapper/src/verifier/mod.rs`
- First step: `crates/snark-wrapper/src/verifier/first_step.rs`
- FRI verification: `crates/snark-wrapper/src/verifier/fri.rs`
- Challenge holder: `crates/snark-wrapper/src/verifier_structs/challenges.rs`

### Bellman (L1 PLONK/KZG)
- Main verifier: `crates/bellman/src/plonk/better_better_cs/verifier/mod.rs`
- Alternative verifier: `crates/bellman/src/plonk/better_cs/verifier.rs`
- Keccak transcript: `crates/bellman/src/plonk/commitments/transcript/keccak_transcript.rs`

### FFlonk
- Verifier: `crates/fflonk/src/verifier.rs`
