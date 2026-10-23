# Real benign false-positive measurement — 2026-10-24

First measurement on **real, non-loopback** traffic: the active Wi-Fi
interface of this host, 45 seconds of ordinary outbound activity (DNS lookups
and HTTPS attempts to five hosts), 1,463 packets, 45 flows. Every flow is
benign by construction — no attack traffic was generated.

Reproduction: `python scripts/real_benign_fpr.py --seconds 45`.

## Result

| Model | Flows flagged | False-positive rate |
|---|---|---|
| Frozen CICIDS2017 | 0 / 45 | **0.00** |
| Live-scenario candidate | 11 / 45 | **0.2444** |

## Reading this

**The frozen model's 0 % is not a win.** It flagged nothing here and nothing in
the 75 live attack flows from the earlier experiment — it appears to call real
traffic benign almost unconditionally, which is a degenerate specificity, not
discrimination.

**The candidate's 24.4 % is the real finding.** Trained only on synthetic
loopback scenarios, it flags roughly one in four genuinely benign real-world
flows. That confirms the earlier 37 % figure was not a loopback artefact; the
over-flagging persists on real traffic. It is not deployable.

Together the two numbers define the actual problem: one model is insensitive,
the other is indiscriminate, and neither was trained on a representative benign
distribution.

## Limits

- One host, 45 seconds, one network, five hosts contacted. This is not a
  network population.
- HTTPS to some destinations was blocked by the proxy, so the captured mix
  over-represents DNS retries and failed connections.
- No attack traffic was present, so no recall can be estimated here. The
  earlier 0/75 recall result stands for the synthetic scenarios only.
- Flows are labelled by construction, not by adjudication.

## Consequence

The next useful measurement still requires a labelled capture with a realistic
benign mix — either a reachable CTU-13 mirror (see
`dataset-acquisition-2026-10-24.md`) or the lab workflow in
`scripts/lab_capture.py`. The candidate should not be promoted on these
numbers, and the frozen model's specificity should not be quoted as evidence
that it detects benign traffic correctly.
