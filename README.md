# AI-NIDS

AI-Based Network Intrusion Detection System using machine learning and live network traffic analysis.

## Overview

AI-NIDS is a desktop-based Network Intrusion Detection System that captures network traffic, extracts network-flow features, and uses a Random Forest classifier to identify potentially suspicious traffic.

The application provides a Tkinter dashboard for:

* Live network packet capture for authorized diagnostic use
* Network-flow feature extraction
* Capture duration and packet-count reporting
* Recent detection-history display

The Random Forest model and detection-result logic remain available for offline
evaluation and controlled validation. Live machine-learning inference is currently
disabled because compatibility between the frozen CICIDS2017 model and the live
traffic domain has not been established.

The project combines offline machine-learning evaluation with an experimental live
packet-capture and feature-validation workflow.

## Features

* Live network packet capture
* Network-flow feature extraction
* Frozen Random Forest model for offline evaluation
* Model feature-schema validation
* Packet-to-flow semantic validation
* Live feature-distribution diagnostics
* CSV-based detection history
* Tkinter desktop dashboard
* CICIDS2017-based model training and evaluation
* CICIDS2017-based model training and evaluation

## Technology Stack

* Python
* Tkinter
* Scapy
* NumPy
* Pandas
* Scikit-learn
* Joblib
* Random Forest
* CICIDS2017 dataset

## Main Project Structure

```text
AI-NIDS/
├── src/
│   ├── dashboard.py
│   ├── predict.py
│   ├── evaluate_model.py
│   ├── features/
│   │   └── schema.py
│   └── models/
│       └── nids_random_forest_cicids2017.pkl
├── data/
│   ├── raw/
│   └── processed/
├── tests/
│   ├── test_model_schema.py
│   ├── test_schema.py
│   └── test_severity.py
├── results/
│   ├── cicids2017_metrics.txt
│   ├── cicids2017_confusion_matrix.png
│   └── detection_log.csv
├── requirements.txt
├── .gitignore
└── README.md
```

Large dataset and model files are excluded from the repository where appropriate. The datasets and model must be stored locally or obtained separately.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Rubayat0007/AI-NIDS.git
cd AI-NIDS
```

### 2. Create a virtual environment

On Windows PowerShell:

```powershell
python -m venv .venv
```

### 3. Activate the virtual environment

```powershell
.\.venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

## Running the Application

From the project root, run:

```powershell
python .\src\dashboard.py
```

The application opens the AI-NIDS desktop dashboard.

The dashboard can capture live network traffic for diagnostic purposes. Live packet
capture currently does **not** perform machine-learning inference because compatibility
between the frozen CICIDS2017 model and the live traffic domain has not been established.

Live packet capture may require administrative privileges and appropriate permission to monitor the selected network.

## Live Prediction Status

Live machine-learning prediction is currently **disabled**.

The packet capture and flow-extraction components can be exercised independently for
validation and diagnostics, but the frozen CICIDS2017 model is not applied to live
traffic. This prevents the application from presenting unvalidated live predictions
when the deployment traffic distribution differs substantially from the model's
training domain.

Offline model evaluation remains supported through the documented CICIDS2017
evaluation pipeline.

## Detection Output

The dashboard can display results similar to the following:

```text
Prediction: NORMAL
Confidence: 78.00%
Risk Score: 22.00%
Severity: LOW
```

It may also display uncertain traffic:

```text
Prediction: UNCERTAIN
Confidence: 70.00%
Risk Score: 30.00%
Severity: SUSPICIOUS
```

The UNCERTAIN status is used when the model predicts normal traffic but the confidence or severity assessment indicates that the traffic may require further investigation.

## Model Features

The model uses 20 network-flow features in the following order:

1. `flow_duration`
2. `total_fwd_packets`
3. `total_bwd_packets`
4. `fwd_packet_length`
5. `bwd_packet_length`
6. `flow_bytes`
7. `flow_packets`
8. `flow_rate`
9. `packet_rate`
10. `avg_packet_size`
11. `syn_count`
12. `ack_count`
13. `rst_count`
14. `fin_count`
15. `active_time`
16. `idle_time`
17. `header_length`
18. `down_up_ratio`
19. `fwd_iat_mean`
20. `bwd_iat_mean`

The canonical feature order is defined in `src/features/schema.py` and must remain consistent with the trained model.

## Model Evaluation

Run the evaluation script from the project root:

```powershell
python src/evaluate_model.py
```

The evaluation script uses an **80/20 train-test split**:

* Total dataset rows: `2,020,632`
* Training rows: `1,616,505`
* Held-out testing rows: `404,127`

The evaluation uses a reproducible random state of `42` and calculates the reported metrics on the held-out test set containing `404,127` records. The held-out test records are not used for training during this evaluation run.

The script generates:

* `results/cicids2017_metrics.txt`
* `results/cicids2017_confusion_matrix.png`

The files `results/cicids2017_evaluation_metrics.txt` and `results/cicids2017_classification_report.txt` contain results from an earlier full-dataset evaluation and are retained as supplementary outputs. They are not the primary held-out test-set results documented above.

### Held-Out Evaluation Results

| Metric    |  Score |
| --------- | -----: |
| Accuracy  | 99.55% |
| Precision | 98.20% |
| Recall    | 99.01% |
| F1-score  | 98.60% |

The evaluation was performed with:

- Random state: `42`
- Test size: `20%`
- Test records: `404,127`

### Held-Out Confusion Matrix

```text
[[337409   1188]
 [   650  64880]]
```

The confusion matrix contains `404,127` predictions, corresponding to the held-out test set.

### Supplementary Full-Dataset Evaluation

A previous full-dataset evaluation is also retained in:

* `results/cicids2017_evaluation_metrics.txt`
* `results/cicids2017_classification_report.txt`

That evaluation processed all `2,020,632` dataset rows and reported:

| Metric    |  Score |
| --------- | -----: |
| Accuracy  | 99.77% |
| Precision | 98.80% |
| Recall    | 99.80% |
| F1-score  | 99.30% |

These full-dataset figures are provided for reference only. They should not be interpreted as held-out test performance because the evaluation was performed across the complete dataset rather than exclusively on unseen test data.

### Supplementary Held-Out Error-Slice Analysis

The repository includes `scripts/analyze_heldout_error_slices.py` for supplementary
analysis of error concentration within the same reproducible held-out test split.
This analysis uses the frozen model and does not retrain or modify the model or dataset.

The analysis shows that held-out errors are not uniformly distributed across the
feature space. In particular:

* The lowest `flow_packets` quartile has 88.07% attack recall, compared with
  99.94% in the highest quartile.
* The lowest `flow_bytes` quartile has a 1.367% benign false-positive rate,
  substantially higher than the other `flow_bytes` quartiles.
* The highest `packet_rate` quartile has 94.22% attack recall, compared with
  99.78% in the third quartile.
* Long-duration and high-activity regimes perform substantially better; for
  example, the highest `flow_duration` quartile has 99.97% attack recall.

These are descriptive held-out slices, not causal feature-effect estimates or
deployment thresholds. The supplementary analysis does not replace the primary
held-out benchmark above and does not authorize live inference.

## Validation

Run the test suite:

```powershell
python -m pytest -q
```

The current test suite validates:

* The model contains the expected feature names.
* The canonical feature schema contains exactly 20 unique features in the expected order.
* The severity classification logic returns the expected labels.

Run syntax validation:

```powershell
python -m compileall -q src tests
```

## Repository Maintenance

Generated evaluation outputs and local backup directories are ignored by Git. The model and dataset files should not be committed unless they are intentionally distributed with the project.

## License and Responsible Use

AI-NIDS is an experimental cybersecurity project intended for authorized testing, research, and educational use. Only capture or inspect network traffic when you have permission to do so.

## Live inference compatibility boundary

The frozen CICIDS2017 Random Forest model is validated against the reproduced CICIDS2017 training pipeline and held-out evaluation data. The repository also validates the packet-to-flow feature extractor independently against captured packet semantics.

Live packet capture is currently **not authorized for model inference**.

The reason is not an established packet-feature extraction error. Packet-level diagnostics have shown that the canonical live flow features reconcile with the packets observed during capture. However, extended live traffic sampling demonstrated substantial distribution differences between live model-eligible flows and the frozen CICIDS2017 training population, including differences in flow duration, packet rate, inter-arrival times, active/idle time, and packet/byte distributions.

The current live distribution diagnostic therefore provides evidence of **domain/distribution shift**, but it does not establish that the frozen model is valid for live traffic.

### Requirements before enabling live inference

Live inference must remain disabled until all of the following are established:

1. The live packet-to-flow feature semantics remain consistent with the canonical CICIDS2017 feature definitions.
2. A representative live/operational traffic dataset is collected and documented.
3. The live feature distribution is evaluated against the intended deployment population.
4. The frozen model is evaluated on an appropriate, representative live-domain validation set.
5. Any retraining or adaptation is performed as a separate, reproducible model-development process rather than by modifying the frozen production artifact.
6. Detection performance, false-positive behavior, and operational failure modes are evaluated before enabling live predictions.

The current diagnostics are validation and evidence-gathering tools only. They do not authorize live inference and do not modify the frozen model or dataset.
