# Finding: Warm/Cold Storage Refund Is Unverifiable in the Proof System

**Severity: LOW / INFORMATIONAL**
**Category: Operator Trust Assumption — Gas Accounting**
**Primary Location: zksync-protocol repo (VM circuits)**

---

## Summary

The warm/cold storage access gas refund in the VM circuit (`zkevm_circuits/src/main_vm/opcodes/log.rs`) is a prover-supplied witness value not verified by any downstream circuit. The `LogQuery` struct has no refund or warm/cold status field, making the refund invisible to the storage sorter and storage applicator.

## Severity Rationale

**LOW / INFORMATIONAL** — all three impact-determining questions answered negatively:

1. **No circuit-enforced block gas budget** — `VmOutputData` has no gas commitment, VM runs fixed cycle count, `MAX_TX_ERGS_LIMIT` is software-only. The gap can't bypass something that doesn't exist.

2. **`ergs_remaining` only gates control flow** — determines whether operations succeed/fail via `should_apply`. Does not influence queue state, pubdata counters, or public outputs.

3. **No external gas consistency check** — no gas-used counter in public inputs, no receipt verification in the proof.

The operator already has unconstrained control over block contents as the centralized sequencer. Gas is software policy, not a circuit invariant. State transition soundness (storage values, pubdata, Merkle proofs) is maintained.

**Note:** This finding becomes more relevant if/when the sequencer is decentralized.

## Full Analysis

See `FINDING-warm-cold-refund-analysis.md` in the `putricio01/zksync-protocol` repository for the complete code-level trace, escalation analysis, and remediation recommendations.
