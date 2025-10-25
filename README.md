# 🧠 NETGUARD-AI: Intelligent Network Threat Detector & Packet Analyzer

### 🚀 Overview
NETGUARD-AI is a hybrid cybersecurity tool that captures live network packets, extracts features, and detects malicious behavior using ML-based models. It’s designed for real-time anomaly detection and visualization.

---

### ⚙️ Features
- Live packet capture using Scapy or PyShark  
- ML-based intrusion detection (trained on Kaggle dataset)  
- Streamlit-powered visualization dashboard  
- Real-time alerts and logging  

```
NetGuardAI/
├── 📊 dashboard/
│   └── app_working.py          # Main dashboard (CURRENTLY RUNNING)
│
├── 📂 data/
│   ├── packets_log.csv         # Sample packet data
│   ├── threat_logs.json        # Sample threat data
│   ├── ml_predictions.json     # Live ML predictions
│   └── ml_stats.json           # Live statistics
│
├── 🤖 models/
│   └── threat_detector.joblib  # Trained ML model
│
├── 🔧 utils/
│   ├── __init__.py
│   └── data_preprocess.py      # Data preprocessing utilities
│
├── 📓 jupyter_notebooks/
│   ├── Evalution.ipynb
│   ├── feature_and_combined.ipynb
│   └── Thread_model.ipynb
│
├── 🐍 Core Python Files:
│   ├── live_simulator.py       # Live data generator (NO SUDO!)
│   ├── train_model.py          # ML model training
│   ├── realtime_analyzer.py    # Real packet analyzer (backup)
│   ├── feature_extractor.py    # Feature extraction
│   ├── packet_capture.py       # Packet capture utilities
│   ├── threat_model.py         # Threat detection logic
│   └── main.py                 # Original main entry point
│
├── 📚 Documentation:
│   ├── README.md               # Project overview
│   ├── FINAL_WORKING_GUIDE.md  # Complete usage guide
│   └── DASHBOARD_ENHANCEMENTS.md # Latest features
│
└── 🚀 Scripts:
    ├── START_HERE.sh           # Main entry point
    └── WHATS_NEW.sh            # Feature overview
```

![alt text](image.png)
![alt text](image-1.png)
