# Model provisioning

The frozen Random Forest classifier is **not committed**. Several tests and
every real detection path need it, so this is the procedure for putting it
in place and proving it is the expected artifact.

## Expected artifact

| Property | Value |
|---|---|
| Path | `src/models/nids_random_forest_cicids2017.pkl` |
| SHA-256 | `1992228DFDC81529D8F87028252688AB39BC5AEB66A7AA2C5A38D164C831B3F2` |
| Training data | reconstructed CICIDS2017 CSV, SHA-256 `14B517C997478428C14512CC94312C23017BD6D8F96048BD168619C89B7B3737` |
| Loader | `joblib.load` via `src/inference.py` |

`src/models/*.pkl` is ignored by Git (`*.pkl`), so the artifact never enters
history.

## Procedure

1. Obtain the artifact from the release/backup source recorded for this
   project. Do not retrain to "fix" a missing model; a newly trained model
   is a **different artifact** with different provenance and must not
   silently replace the frozen one.
2. Place it at the path above.
3. Verify the digest before trusting any result:

   ```powershell
   python -c "import hashlib,pathlib; p=pathlib.Path('src/models/nids_random_forest_cicids2017.pkl'); print(hashlib.sha256(p.read_bytes()).hexdigest().upper())"
   ```

4. Confirm the suite state changes from skips to runs:

   ```powershell
   python -m pytest -q
   ```

   Without the artifact: `81 passed, 5 skipped`. With it: all tests run.

## What the artifact does and does not authorize

- Passing tests with the artifact present prove the **saved model matches
  the canonical feature schema** and that offline inference works. They do
  not prove fitness for live traffic.
- Live inference remains disabled (`LIVE_INFERENCE_ENABLED = False` in
  `src/predict.py`). Re-enabling it requires the distribution-shift work
  described in `README.md` under "Live inference compatibility boundary".
- The historical training provenance is unresolved; the digest identifies
  the artifact, not the process that produced it.

## Raw CICIDS2017 data

`tests/test_cicids_feature_provenance.py` additionally needs the raw CSVs
under `data/raw/MachineLearningCVE/`. They are not committed and are not
required for model loading; that test skips until they exist.
