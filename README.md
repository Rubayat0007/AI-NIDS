# AI-NIDS

AI-Based Network Intrusion Detection System using machine learning and live network traffic analysis.

## Overview

AI-NIDS is a desktop-based Network Intrusion Detection System that captures live network traffic, extracts network-flow features, and uses a Random Forest machine-learning model to classify traffic.

The application displays detection results in a Tkinter dashboard, including:

* Traffic prediction
* Prediction confidence
* Attack-probability risk score
* Severity classification
* Number of captured packets
* Capture duration
* Recent detection history

## Features

* Live network packet capture
* Machine-learning-based traffic classification
* Random Forest model
* Traffic feature extraction
* Attack-probability calculation
* Severity classification
* Normal and suspicious traffic display
* CSV-based detection history
* Desktop dashboard built with Tkinter

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
├── src/
│   ├── dashboard.py
│   └── predict.py
├── data/
│   ├── raw/
│   └── processed/
├── results/
├── requirements.txt
├── .gitignore
└── README.md
```

The large dataset files are excluded from GitHub because of GitHub file-size limits. They must be stored locally or obtained separately.

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

Click **Run Network Detection** to capture live network traffic. The application captures traffic for approximately eight seconds, processes the captured packets, and displays the detection result.

## Detection Output

The dashboard can display results such as:

```text
Prediction: NORMAL
Confidence: 78.00%
Risk Score: 22.00%
Severity: LOW
```

It can also display uncertain traffic:

```text
Prediction: UNCERTAIN
Confidence: 70.00%
Risk Score: 30.00%
Severity: SUSPICIOUS
```

The `UNCERTAIN` status is used when the model predicts normal traffic but the calculated severity indicates that the traffic requires further investigation.

## Model Features

The model uses 20 network-flow features:

1. flow_duration
2. total_fwd_packets
3. total_bwd_packets
4. fwd_packet_length
5. bwd_packet_length
6. flow_bytes
7. flow_packets
8. flow_rate
9. packet_rate
10. avg_packet_size
11. syn_count
12. ack_count
13. rst_count
14. fin_count
15. active_time
16. idle_time
17. header_length
18. down_up_ratio
19. fwd_iat_mean
20. bwd_iat_mean

## Important Notes

* Run the application on a system where packet capture is permitted.
* Administrative privileges may be required for live packet capture.
* The model file is not included in the repository if it is excluded by `.gitignore`.
* The raw and processed datasets are excluded because some files exceed GitHub's file-size limit.
* The detection results are intended for educational and experimental use.
* The system should not be treated as a replacement for a production security monitoring system.

## Future Improvements

* Add support for selecting a network interface
* Add real-time charts
* Add email or notification alerts
* Improve attack-class classification
* Add model evaluation metrics
* Add automated model retraining
* Add database storage for detection history
* Package the application as a Windows executable

## Author

Rubayat Shaikh

## Repository

https://github.com/Rubayat0007/AI-NIDS
