# Live-readiness assessment

Verdict as of `v0.3.1-readiness`: **live inference stays disabled.**
`LIVE_INFERENCE_ENABLED = False` in `src/predict.py` is a deliberate,
evidence-backed decision, not an unfinished feature.

## What is established

| Evidence | Value | Source |
|---|---|---|
| Held-out accuracy | 99.55 % | `README.md`, 404,127 records |
| Held-out precision / recall / F1 | 98.20 / 99.01 / 98.60 % | same |
| Confusion matrix | `[[337409, 1188], [650, 64880]]` | same |
| Weak slice: lowest `flow_packets` quartile | 88.07 % attack recall | `scripts/analyze_heldout_error_slices.py` |
| Weak slice: lowest `flow_bytes` quartile | 1.367 % benign false positives | same |
| Frozen model digest | `1992228D…831B3F2` | `docs/model-provisioning.md` |
| Offline suite | 86 passed, 0 skipped | `v0.3.0-artifacts` |

These are offline CICIDS2017 results. They describe the model on its training
distribution.

## What is not established

1. **No representative live traffic dataset.** Extended live sampling showed
   distribution differences from CICIDS2017 in duration, packet rate,
   inter-arrival times, active/idle time, and packet/byte distributions.
2. **No live-label truth set.** Without ground truth, live precision/recall
   cannot be computed — only agreement with an unvalidated model.
3. **Historical training provenance unresolved.** The reconstruction is
   reproducible (CSV hash matches), but which generator/config produced the
   historical training features is not proven.
4. **Feature parity for live capture** was validated packet-by-packet against
   the canonical extractor, but parity of *semantics* at scale under real
   traffic mixtures is unproven.

## Diagnostic tooling that exists

`scripts/validate_live_features.py`, `validate_live_feature_distribution.py`,
`validate_live_feature_distribution_extended.py`,
`inspect_live_flow_semantics.py` — all require a live capture session with
appropriate privileges. None can be executed in CI or in this environment.

## Conditions to revisit

Enable live inference only after all of the following:

1. Canonical packet-to-flow semantics confirmed for the deployment interface.
2. A representative live/operational capture collected and documented.
3. Distribution comparison against the CICIDS2017 training population,
   reported with the same rigor as the offline evaluation.
4. Evaluation of the frozen model on a labeled live-domain validation set.
5. Any retraining done as a separate, reproducible model-development process —
   never by modifying the frozen artifact.
6. Operational failure modes, false-positive cost, and monitoring defined.

## What would change the verdict fastest

A **labeled** live capture (even a few hundred flows, reviewed by hand) would
let items 2–4 be answered. Unlabeled capture only supports item 3 and cannot
justify enabling inference.

## Rule

Do not enable live inference because the offline numbers look strong. The
offline numbers are exactly why the domain question matters: 99.55 % on
CICIDS2017 says nothing about a network whose flow distribution differs.
