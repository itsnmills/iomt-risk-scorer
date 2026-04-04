# 🛡️ IoMT Risk Assessment Tool

**Score and prioritize your hospital's IoMT risks in 5 minutes.**
Transparent, tunable, patient-safety focused.

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.30+-FF4B4B?logo=streamlit&logoColor=white)
![Plotly](https://img.shields.io/badge/Plotly-5.18+-3F4F75?logo=plotly&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-20808D)
![Security+](https://img.shields.io/badge/CompTIA-Security%2B-C8202F?logo=comptia&logoColor=white)

---

## Why This Exists

Healthcare organizations face a unique cybersecurity challenge: thousands of connected medical devices — infusion pumps, ventilators, patient monitors, PACS systems — running on legacy operating systems with limited patching options, often sharing network segments with general IT traffic.

**Vendors charge six figures** for IoMT risk assessment platforms. **Academic tools** are research prototypes that don't work with real hospital data. **This tool fills the gap** for the engineer who has a CSV export from their asset inventory and a deadline to present risk findings to leadership.

This is not a replacement for a full security program — it's a practical scoring tool that gives you:
- A defensible, framework-backed risk score for every device
- Prioritized remediation recommendations mapped to NIST and HIPAA
- A professional PDF report you can hand to your CISO

---

## Features

### 📋 Device Inventory Management
- **CSV Upload** — Import your existing device inventory in one click
- **Manual Entry** — Add devices through a guided form with validated dropdowns
- **Sample Data** — 25 realistic hospital devices across ICU, ER, Radiology, Lab, and Building Systems
- **12 risk-relevant fields** per device including network segment, FDA class, PHI handling, and authentication posture

### 📊 Risk Scoring Engine
A composite risk score (0–100) calculated from five weighted sub-scores:

| Sub-Score | Weight | What It Measures |
|-----------|--------|-----------------|
| **Exposure** | 20% | Network segment placement (Internet-Facing → Air-Gapped) |
| **Vulnerability** | 20% | Patchability + vendor support + OS risk + scan recency |
| **Data Sensitivity** | 20% | PHI handling level (Transmit → None) |
| **Patient Safety** | 25% | FDA classification × device type criticality |
| **Authentication** | 15% | Auth method × encryption posture |

Weights are **fully tunable** via the sidebar — adjust them to match your organization's risk appetite.

Risk levels: **Critical** (75–100) · **High** (50–74) · **Medium** (25–49) · **Low** (0–24)

### 📈 Interactive Dashboard
- Risk distribution bar chart
- Score histogram with threshold markers
- Risk heatmap: Device Type × Network Segment
- Top 10 riskiest devices
- Radar chart of average sub-scores
- All charts built with Plotly (dark theme, interactive tooltips)

### 🔍 Device Detail View
- Per-device risk breakdown with visual sub-score bars
- Radar chart of individual device risk profile
- Actionable recommended controls with:
  - NIST CSF 2.0 citations
  - HIPAA Security Rule references
  - Priority ratings (Critical → Low)
  - Category tags (Network Isolation, Patching, Authentication, etc.)

### 📄 PDF Risk Assessment Report
Professional, downloadable PDF including:
- Executive summary with key metrics
- Methodology documentation
- Full device inventory (sorted by risk)
- Per-device findings with sub-scores and recommendations
- Prioritized remediation plan with timelines
- Framework reference section with URLs

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│                  Streamlit UI (app.py)            │
│  ┌─────────┐ ┌──────────┐ ┌────────┐ ┌────────┐ │
│  │Inventory│ │Dashboard │ │ Detail │ │ Report │ │
│  └────┬────┘ └────┬─────┘ └───┬────┘ └───┬────┘ │
│       │           │           │           │      │
│  ┌────▼───────────▼───────────▼───────────▼────┐ │
│  │          scorer.py — Risk Engine            │ │
│  │  Exposure · Vulnerability · Data Sensitivity│ │
│  │  Patient Safety · Authentication            │ │
│  └────────────────┬───────────────────────────┘ │
│                   │                              │
│  ┌────────────────▼────┐  ┌───────────────────┐ │
│  │   controls.py       │  │ report_generator  │ │
│  │   NIST/HIPAA Map    │  │   ReportLab PDF   │ │
│  └─────────────────────┘  └───────────────────┘ │
└──────────────────────────────────────────────────┘
```

### Scoring Formula

```python
RISK_SCORE = (
    Exposure_Score      × 0.20 +   # Network segment → 5 (Air-Gapped) to 100 (Internet-Facing)
    Vulnerability_Score × 0.20 +   # Patchability + vendor support + OS risk + scan age
    Data_Sensitivity    × 0.20 +   # PHI handling → 10 (None) to 100 (Transmit)
    Patient_Safety      × 0.25 +   # FDA class × device type criticality factor
    Authentication      × 0.15     # Auth method modified by encryption posture
)
```

### Frameworks Informing the Methodology

| Framework | How It's Used |
|-----------|---------------|
| **NIST SP 800-30 Rev. 1** | Risk assessment methodology: threat/vulnerability identification, likelihood, and impact |
| **NIST CSF 2.0** | Control taxonomy for recommended remediations (ID, PR, DE, RS, RC, GV functions) |
| **FDA Premarket Cybersecurity Guidance (2023)** | Patient safety scoring and FDA class-based risk tiering |
| **HHS 405(d) HICP** | Healthcare-specific cybersecurity practices |
| **HIPAA Security Rule (45 CFR §164.308-312)** | Administrative, physical, and technical safeguard citations |

---

## Quick Start

### Prerequisites
- Python 3.11 or higher
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/itsnmills/iomt-risk-scorer.git
cd iomt-risk-scorer

# Install dependencies
pip install -r requirements.txt

# Run the app
streamlit run app.py
```

The app will open at `http://localhost:8501`.

### First Run

1. Click **"📦 Load Sample Data"** to load 25 realistic hospital devices
2. Navigate to **📊 Risk Dashboard** to see the risk overview
3. Click **🔍 Device Detail** to drill into individual devices
4. Go to **📄 Assessment Report** to generate a PDF

### Using Your Own Data

Prepare a CSV with these columns:

| Column | Example Values |
|--------|---------------|
| Device Name | ICU Ventilator #3 |
| Device Type | Ventilator, Infusion Pump, Patient Monitor, PACS Imaging, Lab Analyzer, Smart Bed, Nurse Call, Building Automation, Wearable Sensor, Custom |
| Manufacturer / Model | Hamilton Medical C6 |
| Network Segment | Clinical VLAN, Guest WiFi, DMZ, Internet-Facing, Air-Gapped, Flat Network |
| OS/Firmware | Embedded RTOS, Linux, Windows CE/IoT, Windows 10/11, Proprietary, Unknown |
| Patchable | Yes, No, Vendor-Only |
| Vendor Support Status | Active, End of Life, Limited, Unknown |
| PHI Handling | None, Read-Only, Read-Write, Transmit |
| FDA Class | I, II, III, N/A |
| Last Vulnerability Scan | 2025-11-15 (or blank) |
| Authentication | None, Default Creds, Local Auth, AD/LDAP, MFA |
| Encryption | None, In-Transit Only, At-Rest Only, Both, Unknown |

---

## Sample Output

The sample dataset includes devices ranging from:
- **Low risk** — Air-gapped surgical robot with MFA and full encryption (score ~12)
- **Critical risk** — Internet-facing building HVAC controller with default credentials and no encryption (score ~82)
- **Mixed** — Clinical VLAN infusion pumps with vendor-only patching and partial encryption (score ~45-55)

The tool correctly identifies the highest-risk devices and generates specific, actionable remediation steps for each.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| **UI Framework** | Streamlit |
| **Data Handling** | Pandas |
| **Visualization** | Plotly (dark theme) |
| **PDF Generation** | ReportLab |
| **Language** | Python 3.11+ |

---

## File Structure

```
iomt-risk-scorer/
├── app.py                  # Streamlit app — multi-page routing and UI
├── scorer.py               # Risk scoring engine — all math lives here
├── controls.py             # Recommended controls mapped to NIST/HIPAA
├── report_generator.py     # PDF report generation with ReportLab
├── sample_devices.csv      # 25 realistic hospital IoMT devices
├── requirements.txt        # Python dependencies
├── README.md               # This file
└── .streamlit/
    └── config.toml         # Dark theme configuration
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Author

**Nathan Mills** — Security+ Certified

Built as a healthcare cybersecurity portfolio project demonstrating practical risk assessment tooling for IoMT environments.
