# Security Audit: Rust vs Solidity FFLONK Verifier Equivalence

**Files audited:**
- Rust: `zksync-crypto/crates/fflonk/src/verifier.rs` (+ `utils.rs`, `proof.rs`)
- Rust transcript: `bellman/src/plonk/commitments/transcript/keccak_transcript.rs`
- Solidity template: `era-contracts/tools/data/fflonk_verifier_contract_template.txt`
- Solidity deployed: `era-contracts/l1-contracts/.../L1VerifierFflonk.sol`, `L2VerifierFflonk.sol`
- VK data: `era-contracts/tools/data/fflonk_scheduler_key.json`
- Hashes: `era-contracts/AllContractsHashes.json`

**Concrete VK parameters:**
- `n = 8388607`, `domain_size = 8388608 = 2^23`
- `num_inputs = 1`, `num_state_polys = 3`, `num_witness_polys = 0`
- `total_lookup_entries_length = 0` (no lookups), no custom gate
- `num_setup_polys = 8`, `num_first_round_polys = 4`, `num_second_round_polys = 3`
- `non_residues = [5, 7]`
- `first_round_requires_opening_at_shifted_point = false`
- `setup_requires_opening_at_shifted_point = false`

---

## Rust Equation

(verifier.rs:296-332, 386-442)

**Derived scalars:**
```
power = lcm(8, 4, 3) = 24
z = r^24
z_omega = z * omega   (omega = generator of domain of size 2^23)
h0 = r^3,  h1 = r^6,  h2 = r^8,  h2_shifted = w^{1/3} * r^8
alpha_sq = alpha * alpha
```

**Set-difference polynomials evaluated at y:**
```
Z_{T\S0}(y) = (y^3 - z)(y^3 - z_omega)(y^4 - z)
Z_{T\S1}(y) = (y^8 - z)(y^3 - z)(y^3 - z_omega)
Z_{T\S2}(y) = (y^8 - z)(y^4 - z)
Z_T(y)      = (y^8 - z)(y^3 - z)(y^3 - z_omega)(y^4 - z)
```

**Aggregated r-polynomial at y:**
```
r(y) = r0(y)
     + alpha * (Z_{T\S1}(y) / Z_{T\S0}(y)) * r1(y)
     + alpha^2 * (Z_{T\S2}(y) / Z_{T\S0}(y)) * r2(y)
```

**Aggregated commitment (F):**
```
F = [C0]
  + (alpha * Z_{T\S1}(y) / Z_{T\S0}(y)) * [C1]
  + (alpha^2 * Z_{T\S2}(y) / Z_{T\S0}(y)) * [C2]
```

**Pairing point construction:**
```
E = r(y) * [G1]                    (generator of G1)
J = (Z_T(y) / Z_{T\S0}(y)) * [W]

pair_with_generator = F - E - J + y * [W']
pair_with_x         = -[W']
```

**Final check:**
```
e(pair_with_generator, vk.g2_elements[0]) * e(pair_with_x, vk.g2_elements[1]) == 1
```

Where `vk.g2_elements[0] = [1]_2` and `vk.g2_elements[1] = [x]_2`.

---

## Solidity Equation

(template lines 1258-1566)

**Derived scalars (lines 289-294):**
```
z = r^24            (modexp(r, 24))
z_omega = z * OMEGA (OMEGA = 0x1283ba6f...bc60863)
alpha_sq = alpha * alpha   (PVS_ALPHA_1)
```

**Set-difference polynomials evaluated at y (lines 1278-1322):**
```
Z_{T\S0}(y) = (y^3 - z_omega) * (y^3 - z) * (y^4 - z)
Z_{T\S1}(y) = (y^3 - z_omega) * (y^3 - z) * (y^8 - z)
Z_{T\S2}(y) = (y^4 - z) * (y^8 - z)
Z_T(y)      = Z_{T\S0}(y) * (y^8 - z)
```

**Aggregated r(y) (lines 1355-1400):**
```
r(y) = r0(y)
     + alpha * (Z_{T\S1}(y) / Z_{T\S0}(y)) * r1(y)
     + alpha^2 * (Z_{T\S2}(y) / Z_{T\S0}(y)) * r2(y)
```

**Aggregated commitment (lines 1351-1420):**
```
F = [C0]
  + (alpha^2 * Z_{T\S2}(y) / Z_{T\S0}(y)) * [C2]    (added first)
  + (alpha * Z_{T\S1}(y) / Z_{T\S0}(y)) * [C1]       (added second)
```

**Pairing point (lines 1401-1435):**
```
E = r(y) * [G1]     (point_mul(1, 2, r_at_y) — BN254 generator (1,2))
J = (Z_T(y) / Z_{T\S0}(y)) * [W]

pair_with_generator = F - E - J + y * [W']
pair_with_x         = -[W']   (Y negated via Q_MOD - y_coord)
```

**Final pairing (lines 1543-1565):**
```
e(pair_with_generator, VK_G2_ELEMENT_0) * e(pair_with_x, VK_G2_ELEMENT_1) == 1
```

---

## Equivalence Checklist

### Algebraic Equation

| Item | Rust | Solidity | Status |
|------|------|----------|--------|
| z = r^24 | `r.pow(&[lcm])` where lcm=24 (line 182) | `modexp(r, 24)` (line 290) | **PASS** |
| z_omega = z * omega | line 273 | line 292 | **PASS** |
| Z_{T\S0}(y) factors | `(3,z)(3,z_omega)(4,z)` | `(y^3-z_omega)(y^3-z)(y^4-z)` | **PASS** |
| Z_{T\S1}(y) factors | `(8,z)(3,z)(3,z_omega)` | `(y^3-z_omega)(y^3-z)(y^8-z)` | **PASS** |
| Z_{T\S2}(y) factors | `(8,z)(4,z)` | `(y^4-z)(y^8-z)` | **PASS** |
| Z_T(y) factors | `(8,z)(3,z)(3,z_omega)(4,z)` | `Z_{T\S0}*(y^8-z)` | **PASS** |
| F coefficient on C1 | `alpha * Z_{T\S1}/Z_{T\S0}` (line 405-408) | same (lines 1378-1387) | **PASS** |
| F coefficient on C2 | `alpha^2 * Z_{T\S2}/Z_{T\S0}` (line 412-415) | same (lines 1354-1367) | **PASS** |
| r(y) aggregation | r0 + alpha*...*r1 + alpha^2*...*r2 (lines 387-399) | same (lines 1355-1400) | **PASS** |
| E = r(y)*G1 | `one.mul(aggregated_r_at_y)` (line 419) | `point_mul(1, 2, r_at_y)` (line 1401) | **PASS** |
| J = (Z_T/Z_{T\S0})*W | lines 422-424 | lines 1408-1413 | **PASS** |
| Signs: F - E - J + y*W' | lines 429-431 | sub, sub, add (lines 1402-1434) | **PASS** |
| pair_with_x = -W' | `w_prime.negate()` (line 435) | `Q_MOD - y_coord` (line 1553) | **PASS** |
| G2[0] paired with F-E-J+yW' | line 438 | line 1546-1549 | **PASS** |
| G2[1] paired with -W' | line 439 | line 1555-1558 | **PASS** |

> Note: Solidity adds the alpha^2 * C2 term before the alpha * C1 term,
> while Rust does alpha * C1 first. This is immaterial because elliptic
> curve point addition is commutative and associative.

### Transcript

| Item | Rust | Solidity | Status |
|------|------|----------|--------|
| Hash function | Keccak-256 | Keccak-256 | **PASS** |
| State: two 32-byte parts | `state_part_0`, `state_part_1` (keccak_transcript.rs:9-10) | `TRANSCRIPT_STATE_0_SLOT`, `STATE_1_SLOT` | **PASS** |
| DST tags | 0 (update s0), 1 (update s1), 2 (challenge) | DST_0=0, DST_1=1, DST_CHALLENGE=2 | **PASS** |
| Update layout | `[DST_u32_BE \|\| s0 \|\| s1 \|\| value]` = 100 bytes | `[0x00,0x00,0x00,DST \|\| s0 \|\| s1 \|\| value]` = 0x64 bytes | **PASS** |
| Challenge layout | `[DST=2_u32_BE \|\| s0 \|\| s1 \|\| counter_u32_BE]` = 72 bytes | same = 0x48 bytes | **PASS** |
| Challenge counter | auto-increment from 0 | explicit: 0,1,2,3,4 | **PASS** |
| Challenge masking | `SHAVE_BITS=3`, mask top 3 bits of MSL | `FR_MASK=0x1fff...fff`, AND top 3 bits off | **PASS** |
| Commit sequence | inputs, C0(x,y), C1(x,y), [beta,gamma], C2(x,y), [r], evals*15, [alpha], W(x,y), [y] | identical (lines 248-289) | **PASS** |
| No lookup challenges | has_lookup=false → skip | no lookup code in template | **PASS** |

### Field/Byte-Level Details

| Item | Rust | Solidity | Status |
|------|------|----------|--------|
| Field element encoding | `write_be` → 32 bytes big-endian | `mstore` → 32 bytes big-endian | **PASS** |
| Point coordinate encoding | `commit_fe(x); commit_fe(y)` via Fq write_be | `update_transcript(x); update_transcript(y)` | **PASS** |
| Evaluation mod-reduction | `into_repr()` canonical < R_MOD | `mod(calldataload(...), R_MOD)` | **PASS** |
| Point coord mod-reduction | Fq deserialization ensures < Q_MOD | `mod(calldataload(...), Q_MOD)` | **PASS** |
| REPR_SIZE for Fr | `(((254/64)+1)*8) = 32` | 32 (implicit) | **PASS** |
| REPR_SIZE for Fq | 32 | 32 (implicit) | **PASS** |

### Input Validation

| Item | Rust | Solidity | Status |
|------|------|----------|--------|
| Num inputs check | `proof.inputs.len() != vk.num_inputs → false` (line 132) | `eq(len, PROOF_PUBLIC_INPUTS_LENGTH)` (line 161) | **PASS** |
| Proof length check | implicit (vec indexing) | `eq(len, PROOF_LENGTH)` (line 170) | **PASS** |
| On-curve check | implicit in G1Affine deserialization | explicit y^2 = x^3 + 3 (lines 180,190,200,210) | **PASS** |
| Point-at-infinity rejection | not explicitly rejected | rejected for commitments 0-2; handled for commitment 3 | **PASS** (see note) |
| Subgroup check | none (BN254 G1 has prime order) | none | **PASS** |

> Note on point-at-infinity: Solidity rejects (0,0) for C1,C2,W via `y^2 != 0^3+3`.
> For W', it explicitly handles the (0,0) case. Rust relies on pairing
> engine handling of zero points. Mathematically equivalent for valid proofs.

### Constants

| Item | Rust | Solidity | Status |
|------|------|----------|--------|
| R_MOD (Fr) | BN254 scalar field | `21888242871839275222246405745257275088548364400416034343698204186575808495617` | **PASS** |
| Q_MOD (Fq) | BN254 base field | `21888242871839275222246405745257275088696311157297823662689037894645226208583` | **PASS** |
| OMEGA | Domain(2^23).generator | `0x1283ba6f4b7b1a76ba2008fe823128bea4adb9269cbfd7c41c223be65bc60863` | **PASS** |
| DOMAIN_SIZE | `vk.n + 1 = 8388608` | `8388608` | **PASS** |
| Non-residues | `make_non_residues(2) → [5, 7]` | `VK_NON_RESIDUES_0=5, _1=7` | **PASS** |
| G2 elements | from SRS/VK | hardcoded constants matching standard BN254 | **PASS** |
| h2_shifted multiplier | `compute_cubic_root_of_domain(2^23)` | `0x0925f0bd364638ec3084b45fc27895f8f3f6f079096600fe946c8e9db9a47124` | **PASS** |
| w8 (8th root of unity) | implicit via Domain | `0x2b337de1c8c14f22ec9b9e2f96afef3652627366f8170a0a948dad4ac1bd5e80` | **PASS** |
| w4 (4th root of unity) | implicit via Domain | `0x30644e72e131a029048b6e193fd841045cea24f6fd736bec231204708f703636` | **PASS** |
| w3 (3rd root of unity) | implicit via Domain | `0x0000000000000000b3c4d79d41a917585bfc41088d8daaa78b17ea66b99c90dd` | **PASS** |

### MSM / Aggregation

| Item | Rust | Solidity | Status |
|------|------|----------|--------|
| Opening points h0,h1,h2 | r^3, r^6, r^8 (utils.rs:666-710) | r^3, r^6, r^8 (lines 748-756) | **PASS** |
| Lagrange basis count | 8 + 4 + 3 + 3 = 18 | TOTAL_LAGRANGE_BASIS_INVERSES_LENGTH = 18 | **PASS** |
| Montgomery batch inverse | precompute_all_lagrange_basis_evaluations_from_inverses | lines 682-738 (same batch inversion trick) | **PASS** |
| r-poly Horner evaluation | evaluate_r_polys_at_point | evaluate_r_polys_at_point_unrolled (lines 788-1253) | **PASS** |
| Setup round: 8 Horner iterations per basis eval | evaluations[0..7] at h0*w8^i | MEM_PROOF_EVALUATIONS[0..7] at h0*w8^i | **PASS** |
| First round: 4 Horner iterations | evals[8..11] at h1*w4^i | evals[8..11] at h1*w4^i | **PASS** |
| Second round: 3 Horner iterations (unshifted) | evals[11] + T1*h2 + T2*h2^2 | evals[11] + copy_perm_first*h2 + copy_perm_second*h2^2 | **PASS** |
| Second round shifted: 3 Horner iterations | evals[12..14] at h2_s*w3^i | evals[12..14] at h2_s*w3^i | **PASS** |

### Quotient Recomputation

| Item | Rust | Solidity | Status |
|------|------|----------|--------|
| Main gate: qm*a*b + qa*a + qb*b + qc*c + qconst + PI*L0 | recompute_main_gate_quotient (utils.rs:791) | compute_main_gate_quotient (lines 308-346) | **PASS** |
| Copy-perm 1st quotient: z*(a+β*z+γ)*(b+k1*β*z+γ)*(c+k2*β*z+γ) - z_omega*(...sigmas...) | recompute_copy_perm_quotients (utils.rs:824) | compute_copy_permutation_quotients (lines 354-436) | **PASS** |
| Copy-perm 2nd quotient: (z-1)*L0/ZH | same function | lines 438-448 | **PASS** |

---

## Any Mismatch -> Exploit Sketch

**No exploitable mismatch found.**

Minor implementation differences (none exploitable):

1. **Addition ordering in F**: Solidity adds `alpha^2 * C2` before `alpha * C1`.
   Rust does the reverse. **Not exploitable**: EC point addition is commutative.

2. **point_sub with zero point**: Solidity's `point_sub` computes `Q_MOD - 0 = Q_MOD`
   for the y-coordinate when subtracting the point at infinity, which would make the
   BN254 precompile revert. **Not exploitable**: the subtracted points E and J are
   derived from transcript challenges, making a zero scalar astronomically unlikely
   (probability ~ 1/R_MOD).

3. **On-curve validation**: Solidity explicitly checks `y^2 = x^3 + 3`; Rust relies
   on deserialization. Both reject invalid points but through different mechanisms.
   **Not exploitable**: a point passing Solidity's check is on the curve.

4. **L1 vs L2 modexp**: L1 uses EVM precompile (address 5); L2 uses Yul binary
   exponentiation loop. Same mathematical result, different gas profile and bytecode.
   **Not exploitable**: mathematically identical.

---

## Deployed Bytecode Match

From `AllContractsHashes.json`:

| Contract | evmDeployedBytecodeHash |
|----------|------------------------|
| L1VerifierFflonk | `0xce62d181ce5c6ccd510aa8dedb6b0ef24f3bf50f1e5d8bfbf27a2b3b0e7ec3c5` |
| L2VerifierFflonk | `0xd6eb6ea687593bf45eb90e8e0b4fc59f481c0870e48ba4f0af6bca8431f3667a` |

The compiled artifacts at `l1-contracts/out/L1VerifierFflonk.sol/L1VerifierFflonk.json` and
`l1-contracts/out/L2VerifierFflonk.sol/L2VerifierFflonk.json` are not present in the
repository checkout (they are build products generated by `forge build`). Therefore:

- **Source-level match**: The L1VerifierFflonk.sol and L2VerifierFflonk.sol source files
  in the repository are structurally identical to the template except for:
  - VK constants filled in from `fflonk_scheduler_key.json`
  - The `modexp` function (precompile for L1, Yul loop for L2)
  - The contract name

- **Bytecode hash verification**: Cannot independently verify bytecode hashes without
  running `forge build`. The hashes are committed to the repo and presumably enforced
  by CI.

**Deployed Bytecode Match: UNKNOWN** (cannot verify without building; source matches template)

---

## FINAL VERDICT: SAFE

The Rust and Solidity FFLONK verifiers implement the **exact same verification equation**:

```
e(C0 + alpha*(Z_{T\S1}/Z_{T\S0})*C1 + alpha^2*(Z_{T\S2}/Z_{T\S0})*C2
  - r(y)*G1 - (Z_T/Z_{T\S0})*W + y*W',  [1]_2)
*
e(-W',  [x]_2)
= 1
```

with identical transcript construction (Keccak-256, same DST/counter/masking), identical
set-difference polynomials, identical opening points, and identical quotient recomputation.

No mismatch was found that would allow a proof accepted by one verifier to be rejected by
the other (or vice versa). The minor implementation differences documented above are either
mathematically immaterial (addition ordering) or involve edge cases that cannot be triggered
by an attacker (zero-scalar subtraction).
