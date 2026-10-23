# Live-domain adaptation experiment

Runs: 6 per scenario, 4 for training, 2 held out. Split by run, not by flow.

Train flows 498 (396 attack) | test flows 257 (200 attack)

| Metric | Candidate (live scenarios) | Frozen CICIDS model |
|---|---|---|
| accuracy | 0.8016 | 0.2218 |
| precision | 0.8901 | 0.0000 |
| recall | 0.8500 | 0.0000 |
| f1 | 0.8696 | 0.0000 |
| false_positive_rate | 0.3684 | 0.0000 |

Candidate digest: `A45DA031D658F10E64B00DAD60D310576754DF1567570935829A772798E86AA1`

## Reading this

- The candidate was trained on generated loopback scenarios and tested on
  held-out runs of the same generator. It shows the features are separable,
  not that the model detects real attacks.
- The frozen model's numbers on the same rows quantify the transfer gap.
- Both classes are synthetic. A real deployment needs real labelled traffic;
  nothing here changes the live-inference decision.
