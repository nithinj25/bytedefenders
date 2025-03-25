# Network Threat Detection Model

A machine learning-based network threat detection system using Random Forest classification on network traffic data.

## Features

- Real-time threat detection and classification
- Port scan detection
- Anomaly detection with detailed metrics
- Traffic flow analysis
- Visualization of results (confusion matrix and feature importance)

## Dataset

The model uses the CIC-IDS 2017 dataset, specifically:
- Friday-WorkingHours-Morning.pcap_ISCX.csv
- Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv

## Requirements

- Python 3.x
- Required packages listed in `requirements.txt`

## Setup

1. Clone the repository:
```bash
git clone <your-repo-url>
cd threatdetection
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the model:
```bash
python model.py
```

## Output

The model provides detailed threat reports including:
1. Threat Detection Results
   - Boolean Flag (Threat/No Threat)
   - Threat Score

2. Threat Classification
   - Attack Type
   - Severity Level
   - Destination Port

3. Anomaly Detection Insights
   - List of Anomalies
   - Flow Metrics
   - Traffic Patterns

4. Suggested Actions
   - Port Blocking Recommendations
   - System Isolation Recommendations

## Performance

- High accuracy in detecting port scan attacks
- Detailed feature importance analysis
- Confusion matrix visualization
- Classification report with precision, recall, and F1-score 