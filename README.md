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

The primary model is a Random Forest classifier trained and evaluated using the CICIDS2017 network-intrusion dataset.

The project reports the following offline evaluation results:

| Metric    | Result |
| --------- | -----: |
| Accuracy  | 99.55% |
| Precision | 98.20% |
| Recall    | 99.01% |
| F1-score  | 98.60% |

These metrics represent offline evaluation on a held-out portion of the CICIDS2017 dataset.

The project also contains a separate synthetic demonstration dataset for development and testing. Results from the synthetic dataset are not used as the primary model-performance claim.

## Live Detection Demonstration

The dashboard provides an experimental packet-capture and prediction workflow using Scapy and the trained Random Forest model.

The live-capture workflow is intended for educational and research demonstrations. It should not be interpreted as a production-grade, continuously operating enterprise Network Intrusion Detection System.

The offline CICIDS2017 evaluation and the live packet-capture demonstration are separate parts of the project.

## Limitations

* The reported performance metrics come from offline evaluation on CICIDS2017.
* Offline dataset performance may not represent performance on unseen real-world network traffic.
* The synthetic dataset is used for development and demonstration only.
* The live packet-capture workflow is experimental.
* The risk score and severity labels are application-level indicators.
* The risk score has not been independently calibrated as a probability of compromise.
* Live packet capture may require administrative privileges.
* The system is intended for educational and experimental use.
* The application should not replace production security monitoring, network sensors, or incident-response tools.

## Future Improvements

* Add network-interface selection
* Add real-time traffic charts
* Add email or notification alerts
* Improve multi-class attack classification
* Add automated model retraining
* Add database storage for detection history
* Add additional validation on unseen network traffic
* Package the application as a Windows executable

## Important Notes

* Run the application only on networks where packet capture is permitted.
* Administrative privileges may be required for live packet capture.
* The trained model file may not be included if it is excluded by `.gitignore`.
* Raw and processed datasets may need to be obtained separately.
* Detection results are intended for educational and experimental use.

## Author

Rubayat Karim

## Repository

[GitHub Repository](https://github.com/Rubayat0007/AI-NIDS)
