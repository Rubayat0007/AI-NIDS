# Live scenario measurement — 2026-10-24

First measurement of the frozen model on **live-captured** packets with
labels assigned by construction, rather than on CICIDS2017 CSV rows.

## Setup

- Capture: Npcap loopback (`\Device\NPF_Loopback`), scapy.
- Scenarios, generated locally and captured while running:
  - `benign-http` — six HTTP requests to a local server (label benign);
  - `port-scan` — TCP connects to eight closed ports (label attack);
  - `syn-flood` — 120 rapid connection attempts to a closed port (label attack).
- Model: `nids_random_forest_cicids2017.pkl` (digest `1992228D…831B3F2`).
- Reproduction: `python scripts/live_scenario_eval.py`.

## Result

| Scenario | Packets | Flows | Predicted attack |
|---|---|---|---|
| benign-http | 66 | 6 | 0 |
| port-scan | 16 | 8 | 0 |
| syn-flood | 133 | 67 | 0 |

| Metric | Value |
|---|---|
| samples | 81 |
| TP / FN | 0 / 75 |
| TN / FP | 6 / 0 |
| recall | **0.00** |
| precision | 0.00 |
| F1 | 0.00 |
| false-positive rate | 0.00 |

**The model detected none of the 75 attack-labelled flows.**

## Interpretation

This is consistent with the domain-shift finding already documented in
`README.md` and `docs/live-readiness.md`: the frozen model was trained on
CICIDS2017 flow statistics and these loopback flows differ in duration,
packet rate, and inter-arrival timing. A classifier can be near-perfect on its
training distribution and near-useless on another.

Three things this does **not** mean:

- It does not prove the model is bad on real network traffic. Loopback traffic
  generated in seconds is not a production capture.
- It does not prove the opposite either. There is still no labelled,
  representative capture.
- It does not change the live-inference decision. It strengthens it.

## What it does establish

- The packet→flow→feature→prediction path runs on captured packets and
  produces a measurable outcome, not just plausible output.
- "Benign by construction" traffic is classified benign (6/6), so the pipeline
  is not indiscriminately flagging everything.
- A scenario-based evaluation harness now exists (`scripts/live_scenario_eval.py`),
  so the next capture — real, labelled, representative — produces a number
  immediately.

## Decision

Unchanged: live inference stays disabled. The gap is no longer "we have no
measurement"; it is "we have one measurement on non-representative traffic,
and it says the model does not transfer to it".
