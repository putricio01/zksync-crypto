# Security Audit: FFLONK Verifier -- W' (commitment_3) Absence from Fiat-Shamir Transcript

**Scope**: `crates/fflonk/src/verifier.rs` (Rust) and `era-contracts/tools/data/fflonk_verifier_contract_template.txt` (Solidity).
Confined to W' opening proof and its absence from the transcript.

**Verdict**: **NOT EXPLOITABLE** under standard cryptographic assumptions (d-SDH / Algebraic Group Model).

---

## 1. Proof Structure

**File**: `crates/fflonk/src/definitions/proof.rs:6-13`

```rust
pub struct FflonkProof<E: Engine, C: Circuit<E>> {
    pub n: usize,
    pub inputs: Vec<E::Fr>,
    pub commitments: Vec<E::G1Affine>,   // 4 entries
    pub evaluations: Vec<E::Fr>,
    pub lagrange_basis_inverses: Vec<E::Fr>,
}
```

The four commitments (confirmed at `prover.rs:1040`):

| Index | Name | Role |
|-------|------|------|
| `commitments[0]` | C1 | First-round commitment (witnesses + gate identities) |
| `commitments[1]` | C2 | Second-round commitment (copy-permutation grand product + quotients) |
| `commitments[2]` | W  | Opening proof -- quotient of f(X) / Z_T(X) |
| `commitments[3]` | W' | Final opening proof -- quotient of L(X) / (Z_{T\S0}(y) * (X - y)) |

---

## 2. Fiat-Shamir Transcript Trace

### Rust verifier (`verifier.rs:136-174`)

| Step | Line(s) | Operation | Transcript effect |
|------|---------|-----------|-------------------|
| 1 | 136-138 | `transcript.commit_field_element(inp)` for each public input | Absorb public inputs |
| 2 | 140 | `commit_point_as_xy(transcript, &vk.c0)` | Absorb setup commitment C0 |
| 3 | 143 | `commit_point_as_xy(transcript, &proof.commitments[0])` | Absorb C1 |
| 4 | 146-147 | `transcript.get_challenge()` x2 | Squeeze beta, gamma |
| 5 | 158 | `commit_point_as_xy(transcript, &proof.commitments[1])` | Absorb C2 |
| 6 | 160 | `transcript.get_challenge()` | Squeeze r (evaluation challenge) |
| 7 | 162-164 | `transcript.commit_field_element(eval)` for each evaluation | Absorb all evaluations |
| 8 | 170 | `transcript.get_challenge()` | Squeeze alpha (aggregation challenge) |
| 9 | 171 | `commit_point_as_xy(transcript, &w)` | **Absorb W (commitment_2)** |
| 10 | 174 | `transcript.get_challenge()` | **Squeeze y (final challenge)** |

**W' (`commitments[3]`) is NEVER absorbed into the transcript.**

### Solidity verifier (`fflonk_verifier_contract_template.txt:241-289`)

```solidity
// commit w(X)
update_transcript(mload(MEM_PROOF_COMMITMENT_2_G1_X))   // line 286
update_transcript(mload(MEM_PROOF_COMMITMENT_2_G1_Y))   // line 287
// opening challenge
mstore(PVS_Y, get_challenge(4))                         // line 289
```

W' (`MEM_PROOF_COMMITMENT_3_*`) is never fed to `update_transcript()`. Both implementations match.

### Prover (`prover.rs:949-1034`)

```rust
commit_point_as_xy::<E, T>(&mut transcript, &w_commitment);  // line 950
let y = transcript.get_challenge();                           // line 953
// ... compute L(x) using y ...
let l_divided_by_y = divide_by_linear_term(l_poly.as_ref(), y);  // line 1024
let mut w_prime = Polynomial::from_coeffs_unpadded(l_divided_by_y)?;  // line 1025
w_prime.scale(&worker, inv_sparse_polys_for_setup_at_y);  // line 1027
let w_prime_commitment = commit_using_monomials(&w_prime, mon_crs, worker)?;  // line 1034
```

The prover computes W' **after** y is derived. This is required by the protocol: W' = [L(X) / (Z_{T\S0}(y) * (X - y))]_1 depends on y.

---

## 3. The Pairing Equation

**File**: `verifier.rs:309-332, 401-444`

The verifier constructs:

```
F = C0 + (alpha * Z_{T\S1}(y)/Z_{T\S0}(y)) * C1 + (alpha^2 * Z_{T\S2}(y)/Z_{T\S0}(y)) * C2
E = r(y) * G1          (aggregated evaluation, scalar times generator)
J = (Z_T(y)/Z_{T\S0}(y)) * W
```

And checks the pairing (line 437-442):

```
e(F - E - J + y*W',  [1]_2) * e(-W',  [x]_2) = 1
```

where `[1]_2 = vk.g2_elements[0]` and `[x]_2 = vk.g2_elements[1]` (x is the SRS secret).

Using bilinearity, this simplifies to:

```
e(F - E - J,  [1]_2) = e(W',  [(x - y)]_2)
```

Denoting P = F - E - J:

```
e(P, [1]_2) = e(W', [(x - y)]_2)        ... (*)
```

This is a standard KZG-style opening verification. It checks that W' is the commitment to the polynomial L(X) / (Z_{T\S0}(y) * (X - y)).

---

## 4. Analysis: Can a Malicious Prover Solve for W'?

### Attacker model

The prover controls: C1, C2, evaluations, lagrange_basis_inverses, W, and W'. The prover knows the polynomials behind C1, C2, and W (since they constructed them). The prover does NOT know x (the SRS trapdoor).

### Transcript ordering

After committing C1, C2, evaluations, and W, the challenge y is determined. The prover then picks W' freely (it is not transcript-bound). The question: does this freedom allow constructing a fraudulent proof?

### Why the answer is NO

Once y is fixed, P = F - E - J is fully determined. At the polynomial level, P = [p(x)]_1 where:

```
p(X) = c0(X) + a1*c1(X) + a2*c2(X) - r(y) - b*w(X)
```

(with a1, a2, b being the scalar aggregation factors involving alpha, y, and set-difference evaluations).

**Case 1: Honest evaluations.** If the claimed evaluations are genuine, then L(y) = 0 by construction, so p(X) is divisible by (X - y). The honest W' = [p(X) / (X - y)]_1 is a valid polynomial commitment computable from the SRS. The pairing check passes. No freedom to exploit.

**Case 2: Dishonest evaluations.** If any claimed evaluation is fake, then L(y) != 0, meaning p(X) is NOT divisible by (X - y). The prover needs W' in G1 such that equation (*) holds:

```
e([p(x)]_1, [1]_2) = e(W', [(x - y)]_2)
```

This requires W' = [p(x) / (x - y)]_1. But p(X) / (X - y) is a **rational function** (not a polynomial) when (X - y) does not divide p(X). Under the **Algebraic Group Model (AGM)**, any G1 element produced by the prover must be a linear combination of SRS elements [1, x, x^2, ..., x^d]_1. Such a combination always yields a polynomial commitment. A rational function with a pole at y cannot be represented this way.

Formally, under the **d-Strong Diffie-Hellman (d-SDH)** assumption, given `{[x^i]_1}_{i=0..d}` and `{[x^i]_2}_{i=0..1}`, it is computationally infeasible to output `(c, [1/(x-c)]_1)` for any field element c. This is exactly what the attacker would need: the ability to compute [1/(x-y)]_1 (and scale it by the known group element P).

**Therefore: the pairing equation uniquely determines W' given all transcript-bound data. A malicious prover cannot "solve for" a valid W' when the underlying polynomial identity does not hold.**

---

## 5. Why Transcript-Binding W' Is Unnecessary

W' occupies the same structural role as the proof element pi in a standard KZG opening:

```
KZG: commit(P) is transcript-bound; verifier sends z; prover returns (v, pi); check e([P] - v*[1], [1]_2) = e(pi, [x-z]_2)
```

In KZG, pi is never "committed to the transcript" -- it is the final prover message verified directly by the pairing check. This is universally accepted as sound. FFLONK follows the same paradigm:

- W is committed before y (line 171) to ensure y depends on W.
- W' is the response to challenge y, verified by the pairing check (lines 437-442).
- Committing W' to the transcript would serve no purpose: there are no further challenges derived after y, so binding W' cannot influence any subsequent randomness.

---

## 6. Potential Attack Vectors (All Blocked)

| Attack | Why it fails |
|--------|-------------|
| **Fake evaluations + solve W'** | p(y) != 0, so p(X)/(X-y) is not a polynomial. Cannot compute W' from SRS. (d-SDH hardness) |
| **W' = point-at-infinity** | Forces P = O, imposing F = E + J. This heavily constrains evaluations and commitments; does not grant useful freedom. |
| **Choose W' after y** | The pairing equation uniquely pins W' to [p(X)/(X-y)]_1. No degree of freedom remains. |
| **Malleability** | Given fixed (C0, C1, C2, evals, W, y), W' is uniquely determined. Changing W' breaks the pairing. |

---

## 7. Conclusion

**W' (commitment_3) not being committed to the Fiat-Shamir transcript is NOT a vulnerability.** The pairing equation at `verifier.rs:437-442` (and equivalently in the Solidity template at lines 1543-1566) uniquely constrains W' given all transcript-bound data. Under standard cryptographic assumptions (d-SDH / AGM), a malicious prover who submits incorrect polynomial evaluations cannot find a valid W' that makes the pairing check pass.

This design follows the well-established KZG opening proof pattern where the final proof element is verified directly by the pairing and does not need transcript binding.
