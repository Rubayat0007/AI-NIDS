# Evidence ledger — AI-NIDS

Append-only. Every number quoted in a report or README must have a row.

| ID | commit | date | command | data | n | model | metrics | status |
|---|---|---|---|---|---|---|---|---|
| R-NIDS-offline-01 | a0147f9 | 2026-10-24 | `src/evaluate_model.py` (recorded earlier) | CICIDS2017 held-out | 404,127 | frozen `1992228D…831B3F2` | acc 99.55 %, prec 98.20 %, rec 99.01 %, F1 98.60 %; matrix [[337409,1188],[650,64880]] | RECORDED (offline) |
| R-NIDS-tests-01 | a0147f9 | 2026-10-24 | `python -m pytest -q` | — | 102 | — | 102 passed, 0 skipped | RECORDED |
| R-NIDS-live-01 | a0147f9 | 2026-10-24 | `scripts/live_flow_check.py` | captured loopback, benign | 90 packets / 8 flows | frozen | all flows benign p≈0.97, aggregate LOW | RECORDED |
| R-NIDS-scenario-01 | a0147f9 | 2026-10-24 | `scripts/live_scenario_eval.py` | loopback benign/scan/flood, labels by construction | 81 flows (75 attack) | frozen | recall 0.00, precision 0.00, F1 0.00, TP0 FN75 TN6 FP0 | RECORDED, DEVELOPMENT |
| R-NIDS-adapt-01 | a0147f9 | 2026-10-24 | `scripts/live_adaptation_experiment.py` | 18 runs, split by run | 754 flows (498 train / 257 test) | candidate `A45DA031…E86AA1` vs frozen | candidate acc .8016 prec .8901 rec .8500 F1 .8696 FPR .3684; frozen rec 0.00 | RECORDED, DEVELOPMENT |
| R-NIDS-benign-01 | a0147f9 | 2026-10-24 | `scripts/real_benign_fpr.py --seconds 45` | real Wi-Fi, benign by construction | 45 flows | frozen / candidate | frozen 0/45 (0.00); candidate 11/45 (0.2444) | RECORDED, DEVELOPMENT |
| R-NIDS-acquire-01 | a0147f9 | 2026-10-24 | probe of `mcfp.felk.cvut.cz` | CTU-13 | — | — | HTTP 502, TLS verify failed; dataset NOT obtained | BLOCKED |

Notes:
- H1–H4 (causes of R-NIDS-scenario-01) remain **HYPOTHESIS**, untested.
- Flows in R-NIDS-benign-01 come from one host in 45 s; not independent, so the
  true interval is wider than a Wilson interval suggests.
- No live-inference claim is authorised by any row here.
