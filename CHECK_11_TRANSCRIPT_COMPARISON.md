# Check 11: Line-by-Line Transcript Comparison
# Native Verifier vs Recursive Verifier (Fiat-Shamir Transcript Operations)

**Native:** `zksync-crypto/crates/boojum/src/cs/implementations/verifier.rs` — `fn verify()` starting at line 888
**Recursive:** `zksync-crypto/crates/boojum/src/gadgets/recursion/recursive_verifier.rs` — `fn verify()` starting at line 381

---

## Comparison Table

| Step | Operation | Native Verifier | Recursive Verifier | Match? | Notes |
|------|-----------|----------------|-------------------|--------|-------|
| **1** | **ABSORB** setup Merkle tree cap | `transcript.witness_merkle_tree_cap(&vk.setup_merkle_tree_cap)` **L924** | `<TR::CircuitReflection as CircuitTranscript<F>>::witness_merkle_tree_cap(&mut transcript, cs, setup_tree_cap)` **L427-431** | MATCH | Both absorb VK setup cap first. Recursive uses fully-qualified trait call syntax but identical semantics. |
| **2** | **ABSORB** public inputs (each) | `transcript.witness_field_elements(&[value])` **L944** (in loop L936-945) | `transcript.witness_field_elements(cs, &[value])` **L448** (in loop L442-452) | MATCH | Both iterate `public_inputs_locations.zip(proof.public_inputs)` and absorb each value individually. |
| **3** | **ABSORB** witness oracle cap | `transcript.witness_merkle_tree_cap(&proof.witness_oracle_cap)` **L952** | `transcript.witness_merkle_tree_cap(cs, &proof.witness_oracle_cap)` **L456** | MATCH | Identical data, identical position in sequence. |
| **4** | **SQUEEZE** beta (2 challenges) | `transcript.get_multiple_challenges_fixed::<2>()` **L955** | `transcript.get_multiple_challenges_fixed::<_, 2>(cs)` **L460** | MATCH | Both squeeze 2 field elements for copy-permutation beta. The `<_, 2>` turbofish difference is Rust syntax for circuit generics — semantically identical. |
| **5** | **SQUEEZE** gamma (2 challenges) | `transcript.get_multiple_challenges_fixed::<2>()` **L957** | `transcript.get_multiple_challenges_fixed::<_, 2>(cs)` **L463** | MATCH | Same pattern as beta. |
| **6** | **SQUEEZE** lookup_beta (conditional, 2 challenges) | `transcript.get_multiple_challenges_fixed::<2>()` **L962** (inside `if self.lookup_parameters != NoLookup`) | `transcript.get_multiple_challenges_fixed::<_, 2>(cs)` **L468** (inside `if self.lookup_parameters != NoLookup`) | MATCH | Both gate on `self.lookup_parameters != LookupParameters::NoLookup`. Branch condition is compile-time identical since both use same `self.lookup_parameters` field. |
| **7** | **SQUEEZE** lookup_gamma (conditional, 2 challenges) | `transcript.get_multiple_challenges_fixed::<2>()` **L964** | `transcript.get_multiple_challenges_fixed::<_, 2>(cs)` **L471** | MATCH | Same conditional branch as step 6. |
| **8** | **ABSORB** stage 2 oracle cap | `transcript.witness_merkle_tree_cap(&proof.stage_2_oracle_cap)` **L978** | `transcript.witness_merkle_tree_cap(cs, &proof.stage_2_oracle_cap)` **L481** | MATCH | Both absorb stage 2 cap (z-poly, intermediate products, lookup encoding) immediately after lookup challenge derivation. |
| **9** | **SQUEEZE** alpha (2 challenges) | `transcript.get_multiple_challenges_fixed::<2>()` **L981** | `transcript.get_multiple_challenges_fixed::<_, 2>(cs)` **L484** | MATCH | Quotient combination challenge. |
| **10** | **ABSORB** quotient oracle cap | `transcript.witness_merkle_tree_cap(&proof.quotient_oracle_cap)` **L1059** | `transcript.witness_merkle_tree_cap(cs, &proof.quotient_oracle_cap)` **L560** | MATCH | Both absorb after alpha power materialization (lines 1044 / 548 respectively). |
| **11** | **SQUEEZE** z (2 challenges) | `transcript.get_multiple_challenges_fixed::<2>()` **L1063** | `transcript.get_multiple_challenges_fixed::<_, 2>(cs)` **L563** | MATCH | Evaluation point challenge. |
| **12** | **ABSORB** values_at_z | `transcript.witness_field_elements(set.as_coeffs_in_base())` **L1068** (loop over `proof.values_at_z`) | `transcript.witness_field_elements(cs, set)` **L584** (loop over `proof.values_at_z`) | MATCH | Native: `set` is `ExtensionField<F,2,EXT>`, `.as_coeffs_in_base()` returns `&[F; 2]`. Recursive: `set` is `&[Num<F>; 2]`, auto-coerced to `&[Num<F>]`. Both absorb 2 base field elements per evaluation. Serialization is identical. |
| **13** | **ABSORB** values_at_z_omega | `transcript.witness_field_elements(set.as_coeffs_in_base())` **L1072** (loop over `proof.values_at_z_omega`) | `transcript.witness_field_elements(cs, set)` **L588** (loop over `proof.values_at_z_omega`) | MATCH | Same serialization pattern as step 12. |
| **14** | **ABSORB** values_at_0 | `transcript.witness_field_elements(set.as_coeffs_in_base())` **L1076** (loop over `proof.values_at_0`) | `transcript.witness_field_elements(cs, set)` **L592** (loop over `proof.values_at_0`) | MATCH | Same serialization pattern as step 12. |
| **15** | **SQUEEZE** c0, c1 (FRI quotient batching) | `transcript.get_challenge()` x2 **L1819-1820** | `transcript.get_challenge(cs)` x2 **L1365-1366** | MATCH | Both squeeze two individual challenges (not `get_multiple_challenges_fixed::<2>`). This is important — they call `get_challenge` twice, not once for a pair. Semantically identical. |
| **16** | **ABSORB** FRI base oracle cap | `transcript.witness_merkle_tree_cap(&proof.fri_base_oracle_cap)` **L1864** | `transcript.witness_merkle_tree_cap(cs, &proof.fri_base_oracle_cap)` **L1422** | MATCH | First FRI oracle commitment. |
| **17** | **SQUEEZE** first FRI fold c0, c1 | `transcript.get_challenge()` x2 **L1867-1868** | `transcript.get_challenge(cs)` x2 **L1426-1427** | MATCH | First FRI folding challenges. Both then compute `challenge_powers` by squaring. |
| **18** | **ABSORB** intermediate FRI oracle cap (per round) | `transcript.witness_merkle_tree_cap(cap)` **L1903** (loop L1894-1927) | `transcript.witness_merkle_tree_cap(cs, cap)` **L1456** (loop L1450-1477) | MATCH | Loop iterates `interpolation_log2s_schedule[1..].zip(proof.fri_intermediate_oracles_caps)`. Identical structure. |
| **19** | **SQUEEZE** intermediate FRI fold c0, c1 (per round) | `transcript.get_challenge()` x2 **L1907-1908** (inside loop) | `transcript.get_challenge(cs)` x2 **L1460-1461** (inside loop) | MATCH | Both squeeze two challenges per intermediate FRI round, then compute powers by squaring. |
| **20** | **ABSORB** final FRI monomials | `transcript.witness_field_elements(&proof.final_fri_monomials[0])` **L1954** + `transcript.witness_field_elements(&proof.final_fri_monomials[1])` **L1955** | `transcript.witness_field_elements(cs, &proof.final_fri_monomials[0])` **L1489** + `transcript.witness_field_elements(cs, &proof.final_fri_monomials[1])` **L1490** | MATCH | Both absorb c0 monomial coefficients then c1 monomial coefficients, in that order. |
| **21** | **SQUEEZE** PoW seed challenges (conditional) | `transcript.get_multiple_challenges(num_challenges)` **L1964** (inside `if new_pow_bits != 0`, L1957) | `transcript.get_multiple_challenges(cs, num_challenges)` **L1499** (inside `if new_pow_bits != 0`, L1492) | MATCH | Both compute `num_challenges = 256.next_multiple_of(F::CHAR_BITS) / F::CHAR_BITS`. Identical formula. See FLAG below. |
| **22** | **ABSORB** PoW challenge value (conditional) | `transcript.witness_field_elements(&[low, high])` **L1981** where `low = F::from_u64_unchecked(pow_challenge as u32)`, `high = F::from_u64_unchecked((pow_challenge >> 32) as u32)` | **MISSING — `todo!()` at L1501** | **FLAG** | See detailed analysis below. |
| **23** | **SQUEEZE** query indices (per query) | `bools_buffer.get_bits(&mut transcript, max_needed_bits)` **L2050** (loop L2048) | `bools_buffer.get_bits(cs, &mut transcript, max_needed_bits)` **L1578** (loop L1576) | MATCH | Both use `BoolsBuffer::get_bits` which internally calls `transcript.get_challenge()` to produce random bits for query index selection. |

---

## Flagged Items

### FLAG 1: PoW ABSORB — `todo!()` in Recursive Verifier (Step 22)

**Severity: LOW (currently non-exploitable, requires monitoring)**

**Native verifier** (L1957-1981):
```rust
if new_pow_bits != 0 {
    let num_challenges = SEED_BITS.next_multiple_of(F::CHAR_BITS) / F::CHAR_BITS;
    let challenges = transcript.get_multiple_challenges(num_challenges);  // SQUEEZE
    let pow_is_valid = POW::verify_from_field_elements(challenges, ...);
    // ... verify PoW ...
    let (low, high) = (pow_challenge as u32, (pow_challenge >> 32) as u32);
    let low = F::from_u64_unchecked(low as u64);
    let high = F::from_u64_unchecked(high as u64);
    transcript.witness_field_elements(&[low, high]);  // ABSORB pow result
}
```

**Recursive verifier** (L1492-1502):
```rust
if new_pow_bits != 0 {
    let num_challenges = SEED_BITS.next_multiple_of(F::CHAR_BITS) / F::CHAR_BITS;
    let _challenges: Vec<_> = transcript.get_multiple_challenges(cs, num_challenges);  // SQUEEZE
    todo!()  // <--- STOPS HERE, PoW verification + absorb NOT implemented
}
```

**Analysis:**
- The recursive verifier squeezes the PoW seed (step 21) identically, but then hits `todo!()`.
- The PoW result ABSORB (step 22) and the PoW validity check are NOT implemented.
- **Current impact: NONE** — The current production config uses `pow_bits: 0` (see `circuit_definitions/src/lib.rs` where `pow_bits: 0` in both `base_layer_proof_config()` and `recursion_layer_proof_config()`). With `pow_bits == 0`, the entire `if new_pow_bits != 0` block is skipped in both verifiers. The transcript sequences are therefore identical in production.
- **Future risk: HIGH** — If `pow_bits` is ever set to a non-zero value, the recursive verifier will panic at `todo!()`. If the `todo!()` were replaced with incomplete code that squeezes but doesn't absorb the PoW result, the transcripts would diverge, and query indices (step 23) would differ between native and recursive verifiers. This would make the recursive verifier either unsound or cause it to reject valid proofs.
- **Recommendation:** Implement the PoW verification and absorb in the recursive verifier, or add a compile-time assertion that `pow_bits == 0` to prevent accidental misconfiguration.

### No Other Flags

All other 21 transcript operations (steps 1-21, 23) are **structurally identical** between the native and recursive verifiers. The differences are limited to:
1. Rust trait syntax (`<2>` vs `<_, 2>`) — no semantic difference
2. Circuit-compatible types (`Num<F>` vs `F`) — same field elements at the witness level
3. `cs` parameter threading — required for constraint system but doesn't affect transcript state

---

## Serialization Consistency Details

| Data Type | Native Serialization | Recursive Serialization | Match? |
|-----------|---------------------|------------------------|--------|
| Merkle tree cap element | `witness_merkle_tree_cap` iterates cap, calls `witness_field_elements` on each `[F; CW]` element | Same via `CircuitTranscript::witness_merkle_tree_cap` iterating `CircuitOutput` elements | YES |
| Extension field evaluation | `set.as_coeffs_in_base()` → `&[F; 2]` → absorbed as 2 base field elements | `set` is `&[Num<F>; 2]` coerced to `&[Num<F>]` → absorbed as 2 circuit field elements | YES |
| Public input | `&[value]` where `value: F` | `&[value]` where `value: Num<F>` | YES |
| FRI monomial coefficients | `&proof.final_fri_monomials[i]` → `&[F]` slice | `&proof.final_fri_monomials[i]` → `&[Num<F>]` slice | YES |
| Challenge output | `get_challenge() → F` | `get_challenge(cs) → Num<F>` | YES |

---

## Summary

- **21 of 22 pre-query transcript operations: EXACT MATCH**
- **1 operation (Step 22, PoW absorb): UNIMPLEMENTED in recursive verifier (`todo!()`)**
- **Query phase (Step 23): MATCH**
- **Production impact of the `todo!()`: NONE** (pow_bits is configured to 0)
- **The `todo!()` is a latent risk** if PoW is ever enabled without completing the recursive implementation
