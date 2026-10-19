# AI-NIDS Release Readiness

**Review date:** 2026-10-19  
**Status:** Local validation milestone complete; live inference not approved.

## Verified

- The local test suite passed: **86 passed** in the latest recorded run before this documentation change.
- Flow grouping splits flows when elapsed time from the first packet exceeds the configured timeout.
- A timeout split preserves a nonempty one-packet flow; regression tests cover the exact timeout boundary, one microsecond beyond it, and the singleton-before-split case.
- Pinned packet fixtures compare canonical flow features against a pinned CICFlowMeter reference. They are comparators, not proof of the historical training generator.
- The reconstructed processed dataset contains 2,020,632 rows and matches the saved processed CSV byte for byte.

## Provenance evidence

- Reconstructed processed CSV SHA-256: `14B517C997478428C14512CC94312C23017BD6D8F96048BD168619C89B7B3737`
- Frozen model SHA-256: `1992228DFDC81529D8F87028252688AB39BC5AEB66A7AA2C5A38D164C831B3F2`

These hashes identify the current artifacts. The available evidence does not prove that the historical training run used the exact reconstructed inputs, preprocessing version, or a particular historical CICFlowMeter build/configuration.

## Evidence still required

1. Exact historical training-input bytes and provenance.
2. The preprocessing code/version and configuration used for the original training run.
3. The historical feature-generator version and configuration.
4. The original training environment, parameters, and artifact-generation record sufficient to reproduce or audit the frozen model.
5. A representative operational traffic dataset, domain-distribution analysis, and suitable live-domain validation.
6. Evaluation of detection performance, false positives, and operational failure modes before enabling live predictions.

## Deployment boundary

- **Offline evaluation:** supported, subject to the documented dataset and evaluation limitations.
- **Live packet capture:** available for diagnostics where authorized.
- **Live machine-learning inference:** disabled. Passing tests and offline CICIDS2017 metrics do not authorize live inference.
- The frozen model, canonical feature schema, and inference thresholds must not be changed as part of this provenance documentation task.

## Local commits awaiting push review

The branch was reported seven commits ahead of `origin/main`:

- `ae7c6d4` test: cover synthetic TCP flag counts
- `975183d` fix: align header length with CICFlowMeter
- `0a6651f` fix: match CICFlowMeter active period accounting
- `816bb61` test: assert frozen model class probability contract
- `3170ca1` fix: validate aggregate flow predictions and probabilities
- `ca68442` test: add pinned CICFlowMeter feature parity fixtures
- `d3d5f08` fix: preserve singleton flows on timeout splits

Recommendation: review the documentation diff and rerun validation before deciding whether to push. No remote push is implied by this note.
