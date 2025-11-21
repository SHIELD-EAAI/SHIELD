# APT Detection and Investigation with LLM

**Advanced Persistent Threat detection and investigation system using Large Language Models for security analysis of system provenance graphs.**

## 📋 Overview

This project implements an automated APT detection system that:
- Performs anomaly detection using deviation analysis
- Constructs provenance graphs from system events
- Leverages Azure OpenAI GPT/open source models for attack pattern recognition
- Identifies and validates coherent attack sequences with high accuracy


## 📦 Dataset Download

Download the DARPA TC dataset from:
**https://drive.google.com/drive/folders/1fOCY3ERsEmXmvDekG-LUUSjfWs6TRdp-**

---

## 🚀 Quick Start

### 1. Prerequisites

```bash
# Python 3.8+
pip install -r requirements.txt
```

**Required packages:**
```txt
pandas
numpy
networkx
python-louvain
scikit-learn
pyvis
openai
pickle5
```

### 2. Setup Azure OpenAI

Create a configuration file or set environment variables:

```python
# config.py or in your notebook
AZURE_OPENAI_ENDPOINT = "your-endpoint-here"
AZURE_OPENAI_KEY = "your-api-key-here"
DEPLOYMENT_NAME = "your-deployment-name"
```

## 📊 Running the Evaluation

### Simple Method: Run the Jupyter Notebook

The easiest way to evaluate the system is to run the provided Jupyter notebook:

```bash
# Start Jupyter
jupyter notebook

# Open and run: apt_detection_evaluation.ipynb
```

## 📈 Understanding Results

### Console Output

```
============================================================
ATTACK DETECTED - Set 0
============================================================
Description: Multi-stage attack chain starting with email 
compromise (imapd)...
Set data: 73 events
============================================================
```

### Key Metrics

- **Probability Score**: 
  - ≥0.90: High confidence complete attack chain
  - 0.80-0.89: Partial attack sequence
  - 0.70-0.79: Suspicious coherence
  - <0.70: Filtered out

- **Attack Stages Detected**:
  - Initial Access
  - Reconnaissance
  - Execution
  - Persistence
  - Command & Control
  - Exfiltration

---

## ⚙️ Configuration Options

### Dataset Parameters

```python
interval = 30          # Window duration (minutes)
sliding_window = 15    # Slide step (minutes)
lower_bound = "2018-04-06 14:00"  # Start time
upper_bound = "2018-04-13 23:55"  # End time
```

### LLM Parameters

```python
# In llm_analyzer.py
temperature = 0.1      # Low for consistent analysis
max_tokens = 2000      # Response length
response_format = {"type": "json_object"}  # Force JSON
```

### Detection Thresholds

```python
# In process4.py
min_probability = 0.7  # Minimum confidence threshold
min_set_size = 2       # Minimum events for attack set
```

---

## 📝 Citation

If you use this code in your research, please cite:

---

## 📄 License

This project is licensed under the MIT License.

---

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with clear description

---

## 🙏 Acknowledgments

- DARPA Transparent Computing Program for the dataset
- OpenAI, Alibaba and the broader AI research community for advancing large language models and making our lives better and easier
- NetworkX and python-louvain communities

---

*Last updated: November 2024*