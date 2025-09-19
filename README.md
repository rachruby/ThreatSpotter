# ThreatSpotter
Developed a Python-based detection tool for host authentication logs; automated identification of brute-force login attempts and suspicious post-failure logins; integrated MITRE ATT&CK mapping (T1110, T1078) to structure alerts; produced structured JSON output to simulate automated detection pipelines.


# Project Directories
'''
ThreatSpotter/
├── threatspotter.py # Main Python script
├── README.md # Project description and instructions
├── sample_logs/ # Example (anonymized) logs
│ └── auth.log
├── requirements.txt # Python dependencies
├── .gitignore # Files/folders to ignore in Git
└── output/ # Generated detections (created at runtime)
'''
