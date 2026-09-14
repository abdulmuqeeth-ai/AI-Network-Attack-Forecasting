# 🛡️ AI Network Attack Forecasting

**Smart India Hackathon 2026 — Problem Statement 26153**

An AI-based cybersecurity system that analyzes network traffic, identifies the current attack stage, forecasts the likely next stage of an attack, maps it to **MITRE ATT&CK**, and presents the results through an interactive SOC-style dashboard.

> **Network Traffic → Threat Detection → Attack Stage → Next-Stage Forecast → MITRE ATT&CK → Visualization**

---

## 📌 Problem Statement

Traditional security monitoring mainly focuses on detecting attacks that are already happening.

Our system aims to go one step further:

**Can we predict what an attacker is likely to do next?**

The prototype analyzes network-flow data and attempts to identify the current stage of an attack before forecasting its possible next stage.

This can help security teams move from **reactive detection** toward **proactive threat intelligence**.

---

## 🎯 Key Features

* 🔍 **Network Traffic Analysis** — Processes network-flow CSV data
* 🚨 **Threat Detection** — Identifies suspicious network behavior
* 🧠 **Attack Stage Detection** — Determines the current stage of an attack
* 🔮 **Next-Stage Forecasting** — Predicts the likely next attack stage
* 🎯 **MITRE ATT&CK Mapping** — Connects attack stages with relevant techniques
* 📊 **SOC Dashboard** — Interactive visualization using Streamlit and Plotly
* 📁 **CSV Upload** — Supports custom network-flow datasets
* 🧪 **Synthetic Sample Data** — Includes sample data for demonstration

---

## 🏗️ System Architecture

```text
┌─────────────────────────┐
│   Network Flow Data     │
│        CSV / Dataset    │
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│   Feature Extraction    │
│   src/preprocessing.py  │
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│    Threat Detection     │
│     src/detector.py     │
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│   Attack Stage          │
│   Identification        │
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│   Next-Stage Forecast   │
│   src/forecaster.py     │
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│   MITRE ATT&CK Mapping  │
│   src/mitre_mapper.py   │
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│     SOC Dashboard       │
│       Streamlit         │
└─────────────────────────┘
```

---

## 🧠 Current Forecasting Approach

The current prototype uses a **stage-transition / Markov-style forecasting approach**.

The system:

1. Extracts features from network-flow data
2. Detects suspicious behavior
3. Identifies the current attack stage
4. Uses stage transitions to estimate the next likely stage
5. Calculates a forecast confidence
6. Maps the predicted stage to MITRE ATT&CK
7. Displays the result on the dashboard

This provides a working **MVP** that can later be extended with sequence-learning and world-model approaches.

---

## 🧩 MITRE ATT&CK Mapping

The prototype connects detected or forecasted stages with relevant MITRE ATT&CK techniques.

| Attack Stage         | Example Technique                     | Technique ID |
| -------------------- | ------------------------------------- | ------------ |
| Reconnaissance       | Active Scanning                       | T1595        |
| Initial Access       | Exploit Public-Facing Application     | T1190        |
| Execution            | Command and Scripting Interpreter     | T1059        |
| Persistence          | Scheduled Task/Job                    | T1053        |
| Privilege Escalation | Exploitation for Privilege Escalation | T1068        |
| Lateral Movement     | Remote Services                       | T1021        |
| Exfiltration         | Exfiltration Over C2 Channel          | T1041        |

> MITRE ATT&CK mappings are used for threat-context visualization and analysis.

---

## 📂 Project Structure

```text
AI-Network-Attack-Forecasting/
│
├── app.py
├── requirements.txt
├── README.md
├── test_pipeline.py
│
├── data/
│   └── sample_network_data.csv
│
└── src/
    ├── preprocessing.py
    ├── detector.py
    ├── forecaster.py
    └── mitre_mapper.py
```

---

## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/abdulmuqeeth-ai/AI-Network-Attack-Forecasting.git
cd AI-Network-Attack-Forecasting
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the application

```bash
python -m streamlit run app.py
```

The dashboard will open locally at:

```text
http://localhost:8501
```

---

## 🛠️ Technology Stack

* **Python**
* **Pandas**
* **NumPy**
* **Streamlit**
* **Plotly**
* **MITRE ATT&CK**
* **CSV / Network Flow Data**

---

## 🔬 Future Work

The current repository represents the working MVP. Future development includes:

* [ ] Machine-learning based threat detection
* [ ] LSTM / Transformer sequence forecasting
* [ ] Improved confidence calibration
* [ ] SHAP-based explainability
* [ ] Real-time network telemetry
* [ ] PCAP-based processing
* [ ] Graph Neural Network modeling
* [ ] World-model based attack progression forecasting
* [ ] Real-time SOC alert integration

---

## 🎥 Demo

The project is designed as an interactive cybersecurity dashboard where users can upload network-flow data and observe:

**Current Threat → Attack Stage → Forecasted Next Stage → MITRE ATT&CK Technique**

---

## 🏆 Smart India Hackathon

**SIH 2026 — Problem Statement 26153**

**Theme:** Cybersecurity / Artificial Intelligence

**Project:** AI Network Attack Forecasting

---

## 👨‍💻 Team

Developed by a student team for **Smart India Hackathon 2026**.

**Lead Developer:** Abdul Muqeeth

GitHub: [@abdulmuqeeth-ai](https://github.com/abdulmuqeeth-ai)

---

## 📜 License

This project is released under the **MIT License**.
