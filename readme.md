C:\ids-ml\
├── .venv\                    # Python Virtual Environment
├── datasets\                 # Folder for raw data
│   └── CICIDS2017\           # Industry standard training data
├── models\                   # Folder for trained ML models
│   └── ids_model.pkl         # The Random Forest model file
├── src\                      # All source code
│   ├── capture\              # Network packet handling
│   │   ├── live_capture.py   # Real-time packet sniffing
│   │   ├── replay_capture.py # Analyzing saved .pcap files
│   │   └── utils.py          # Network adapter helper tools
│   ├── dashboard\            # User Interface
│   │   └── app.py            # Main Streamlit Dashboard file
│   ├── ingestors\            # Log monitoring
│   │   ├── browser_logs.py   # Chrome/Edge history monitoring
│   │   └── system_logs.py    # Windows Event Viewer monitoring
│   ├── ml\                   # Machine Learning logic
│   │   └── feature_engineering.py # Converts packets to ML features
│   └── logging_setup.py      # Console logging configuration
├── train\                    # NEW: Training scripts folder
│   ├── train_model.py        # Main RandomForest training script
│   └── train_supervised.py   # Alternative training logic
└── requirements.txt          # Project dependencies (libraries)