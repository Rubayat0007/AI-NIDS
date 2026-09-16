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

## Project Structure

```text
AI-NIDS/
|-- src/
|   |-- dashboard.py
|   `-- predict.py
|-- data/
|   |-- raw/
|   `-- processed/
|-- results/
|-- requirements.txt
|-- .gitignore
`-- README.md
```

Large dataset files are excluded from the repository because some files exceed GitHub's file-size limits. The datasets must be stored locally or obtained separately.

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

The `UNCERTAIN` status is used when the model predicts normal traffic but the calculated severity indicates that the traffic may require further investigation.

## Model Features

The model uses 20 network-flow features:

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

## Model Evaluation

The Random Forest model was evaluated on a held-out CICIDS2017 test set.

| Metric | Score |
|---|---:|
| Accuracy | 99.5452% |
| Precision | 98.2019% |
| Recall | 99.0081% |
| F1-score | 98.6033% |

### Evaluation Dataset

- Total dataset rows: 2,020,632
- Training rows: 1,616,505
- Testing rows: 404,127
- Benign test samples: 338,597
- Attack test samples: 65,530

### Confusion Matrix

```text
[[337409   1188]
 [   650  64880]]
```
