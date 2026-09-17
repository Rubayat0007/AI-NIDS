# AI-NIDS

AI-Based Network Intrusion Detection System using machine learning and live network traffic analysis.

## Overview

AI-NIDS is a desktop-based Network Intrusion Detection System that captures network traffic, extracts network-flow features, and uses a Random Forest classifier to identify potentially suspicious traffic.

The application provides a Tkinter dashboard that displays:

* Traffic prediction
* Prediction confidence
* Attack-probability risk score
* Severity classification
* Number of captured packets
* Capture duration
* Recent detection history

The project combines offline machine-learning evaluation with an experimental live packet-capture demonstration.

## Features

* Live network packet capture
* Network-flow feature extraction
* Machine-learning-based traffic classification
* Random Forest classification
* Prediction confidence display
* Attack-probability risk scoring
* Severity classification
* Normal and suspicious traffic display
* CSV-based detection history
* Tkinter desktop dashboard
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
│   ├── evaluation_predictions.csv
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

Select **Run Network Detection** to capture live network traffic. The application captures traffic for approximately eight seconds, processes the captured packets, and displays the resulting prediction.

Live packet capture may require administrative privileges and appropriate permission to monitor the selected network.

## Running Live Prediction Directly

The prediction module can also be run directly:

```powershell
python -m src.predict
```

The prediction module:

1. Loads the Random Forest model.
2. Captures a short traffic window.
3. Extracts the canonical 20-feature schema.
4. Produces a prediction and confidence score.
5. Calculates the severity classification.
6. Appends the result to `results/detection_log.csv`.

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
* `results/evaluation_predictions.csv`

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
