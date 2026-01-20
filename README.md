# 🔐 Intrusion Detection Pipeline
### Batch Log Analysis & Security Threat Detection System

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Portfolio_Project-success.svg)]()

---

## 📋 Project Overview

A **batch ETL pipeline** that analyzes SSH authentication logs to detect cybersecurity threats. This project demonstrates data engineering fundamentals, security analysis, and automated anomaly detection using pattern recognition and threshold-based heuristics.

### Business Value
- **Detects brute force attacks** through pattern analysis of failed login attempts
- **Identifies suspicious access patterns** from unusual geographic locations  
- **Flags vulnerable account targeting** (root, admin, test accounts)
- **Provides actionable security intelligence** for incident response teams

### Project Scope
This is a **portfolio demonstration project** showcasing:
- End-to-end ETL pipeline design
- Log parsing and data transformation
- Security-focused analytics
- Professional code architecture

**Note:** This is a batch processing system designed for demonstration purposes, not a real-time streaming solution.

---

## 🎯 Key Features

### 1. **Complete ETL Pipeline**
- **Extract**: Reads raw SSH authentication log files
- **Transform**: Parses unstructured logs using regex into structured data
- **Load**: Stores results in CSV and Parquet formats

### 2. **Security Threat Detection**
✅ **Brute Force Attacks** - Detects excessive failed login attempts with temporal clustering  
✅ **Geographic Anomalies** - Flags access from suspicious IP ranges (heuristic-based)  
✅ **Vulnerable Account Targeting** - Identifies attempts on common system accounts  
✅ **Post-Attack Success** - Alerts when attackers succeed after many failures  

### 3. **Data Visualization**
- Timeline analysis of authentication patterns
- Heatmaps showing attack distribution by hour
- Comparative analysis of internal vs external traffic
- Top attacker IP rankings

---

## 🏗️ Architecture

```
┌──────────────┐      ┌──────────────┐      ┌──────────────┐      ┌──────────────────┐
│  Raw Logs    │ ───> │   Extract    │ ───> │  Transform   │ ───> │  Anomaly         │
│ (SSH Auth)   │      │  (Python)    │      │  (Pandas)    │      │  Detection       │
└──────────────┘      └──────────────┘      └──────────────┘      └──────────────────┘
                                                                            │
                                                                            ▼
                                                              ┌──────────────────────┐
                                                              │  CSV Reports &       │
                                                              │  Visualizations      │
                                                              └──────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Installation

**1. Clone the repository**
```bash
git clone https://github.com/yourusername/intrusion-detection-pipeline.git
cd intrusion-detection-pipeline
```

**2. Install dependencies**
```bash
pip install -r requirements.txt
```

**3. Generate sample data**
```bash
python generate_logs.py
```

**4. Run the pipeline**
```bash
python main_pipeline.py
```

**5. View visualizations**
```bash
cd notebooks
jupyter notebook analysis.ipynb
```

---

## 📊 Sample Output

### Console Output
```
======================================================================
INTRUSION DETECTION ANALYSIS
======================================================================

✓ Transformed 4,982 log entries
  ⚠ Failed to parse: 18 (0.4%)
  ✓ Success rate: 99.6%

⚠ BRUTE FORCE DETECTED: 3 suspicious IPs
  - 45.142.212.61: 127 failed attempts in 42.3 min (180.1/hr) [CRITICAL]
  - 103.75.201.12: 89 failed attempts in 31.7 min (168.4/hr) [HIGH]

🚨 POSSIBLE BREACHES: 2 successful logins after many failures
  - 45.142.212.61 → admin: SUCCESS after 73 failures [CRITICAL]
```

### Performance Metrics
- **Total logs processed**: ~5,000
- **Parse success rate**: 99.6%
- **Processing time**: ~3-6 seconds (varies by system)
- **Throughput**: 800-1,200 records/second

---

## 🛠️ Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Language** | Python 3.8+ | Core pipeline logic |
| **Data Processing** | Pandas | ETL transformations |
| **Pattern Matching** | Regex | Log parsing |
| **Visualization** | Matplotlib, Seaborn | Analytics & insights |
| **Analysis** | Jupyter Notebook | Interactive exploration |
| **Storage** | CSV, Parquet | Structured data persistence |

---

## 📁 Project Structure

```
intrusion-detection-pipeline/
│
├── data/
│   └── raw/
│       └── ssh_auth.log          # Generated sample logs
│
├── src/
│   ├── __init__.py               # Package initialization
│   ├── extract.py                # Extraction module
│   ├── transform.py              # Transformation logic
│   ├── load.py                   # Data loading
│   └── detect_anomalies.py       # Threat detection algorithms
│
├── notebooks/
│   └── analysis.ipynb            # Visualization & analysis
│
├── output/
│   └── processed/
│       ├── processed_logs.csv
│       ├── summary_stats.csv
│       ├── anomaly_brute_force.csv
│       └── anomaly_breaches.csv
│
├── generate_logs.py              # Sample data generator
├── main_pipeline.py              # Pipeline orchestrator
├── requirements.txt              # Python dependencies
└── README.md                     # This file
```

---

## 🎓 Skills Demonstrated

### Data Engineering
- ✅ ETL pipeline design and implementation
- ✅ Data parsing and transformation with regex
- ✅ Schema design for structured log data
- ✅ Error handling and data validation
- ✅ Batch processing optimization

### Security & Analytics
- ✅ Log analysis and pattern recognition
- ✅ Anomaly detection using statistical thresholds
- ✅ Security heuristics (brute force, geographic anomalies)
- ✅ Risk classification and severity scoring

### Software Engineering
- ✅ Modular, maintainable code architecture
- ✅ Object-oriented design patterns
- ✅ Comprehensive error handling
- ✅ Professional documentation
- ✅ Package structure and imports

---

## 🔍 Detection Algorithms

### Brute Force Detection
- Counts failed login attempts per IP address
- Applies temporal clustering (configurable time window)
- Calculates attempts-per-hour rate
- Severity: MEDIUM (10-25), HIGH (25-50), CRITICAL (50+)

### Geographic Anomaly Detection
- Identifies external IP addresses
- Uses prefix-based heuristic for geographic classification
- **Note**: Simplified approach; production systems use GeoIP databases

### Vulnerable Account Detection
- Tracks attempts on common system accounts (root, admin, test, etc.)
- Flags IPs with 5+ attempts on these accounts
- Helps identify automated scanning tools

### Breach Detection
- Identifies successful logins preceded by multiple failures
- **Critical severity** for 20+ failures before success
- Indicates potential credential compromise

---

## 📈 Performance Benchmarks

Tests performed on sample dataset of 5,000 log entries:

| Metric | Value |
|--------|-------|
| Total processing time | 3-6 seconds |
| Extract phase | <1 second |
| Transform phase | 1-2 seconds |
| Load phase | <1 second |
| Detection phase | 1-2 seconds |
| Throughput | 800-1,200 rec/sec |
| Parse success rate | >99% |

*Benchmarks may vary based on system specifications*

---

## 🔮 Future Enhancements

**Planned improvements for learning/expansion:**

- [ ] **Streaming Processing** - Implement Apache Kafka for real-time log ingestion
- [ ] **Machine Learning** - Train models for predictive threat detection
- [ ] **Dashboard** - Build live monitoring dashboard with Grafana
- [ ] **Alert System** - Add email/Slack notifications for critical threats
- [ ] **GeoIP Integration** - Use MaxMind GeoIP2 for accurate location data
- [ ] **Database Backend** - Store results in PostgreSQL or ClickHouse
- [ ] **Docker Deployment** - Containerize for easy deployment
- [ ] **Unit Tests** - Add comprehensive test coverage

---

## ⚠️ Known Limitations

This project is designed for **portfolio demonstration** and has the following limitations:

1. **Batch Processing Only** - Not designed for real-time streaming
2. **Heuristic Geographic Detection** - Uses IP prefix matching, not true geolocation
3. **Sample Data** - Works with generated logs; real-world logs may vary
4. **Threshold-Based Detection** - Uses statistical thresholds, not ML models
5. **Limited Scale** - Optimized for datasets up to ~100K entries

These limitations are intentional to keep the project focused on core ETL and data engineering concepts.

---

## 🤝 Contributing

This is a portfolio project, but suggestions and feedback are welcome! Feel free to:
- Open issues for bugs or improvements
- Submit pull requests with enhancements
- Share your own implementations or variations

---

## 📧 Contact

**Your Name**  
📧 your.email@example.com  
💼 [LinkedIn](https://linkedin.com/in/yourprofile)  
🐱 [GitHub](https://github.com/yourusername)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Inspired by enterprise SIEM systems and security operations
- Built with modern data engineering best practices
- Designed for educational and portfolio purposes
- Sample data simulates realistic attack patterns based on industry research

---

## 📚 Learning Resources

If you're learning from this project, here are helpful resources:

- **ETL Concepts**: "Designing Data-Intensive Applications" by Martin Kleppmann
- **Log Analysis**: SANS Institute - Log Management guides
- **Python Data Engineering**: "Python for Data Analysis" by Wes McKinney
- **Cybersecurity Basics**: NIST Cybersecurity Framework

---

<div align="center">

**⭐ If you found this project helpful for learning, please consider giving it a star! ⭐**

Built with 🔐 by aspiring data engineers

</div>
