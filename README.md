# 🛡️ ICDC Program (All-in-One Security Framework)

The **ICDC Program** is a unified, Python-based cybersecurity orchestration framework that simulates and integrates **25 different security domains** into a single dashboard.
![Dashboard](dashboard.png)

## 🚀 Features (The 25 Modules)
This tool consolidates:
- **Detect & Respond:** SIEM, SOC, IDS/IPS, EDR, Honeypot, MISP, SOAR, Forensics
- **Identity & Access:** IAM/SSO/MFA, PAM, Zero Trust
- **Vulnerability & Offensive:** Vuln Mgmt, PenTesting, Patch Automation
- **Network & Data:** Segmentation, WAF, Email Gateway, DLP, Backup/DR
- **Cloud & DevSecOps:** CSPM, CI/CD Security
- **Governance:** ISO 27001/SOC2, IR Playbooks, Phishing Awareness, Vendor Risk

## ⚙️ Architecture
The tool uses a phased execution model (Phase 1 to 4) to deploy these modules, feeding data into a centralized SQLite database (`icdc_program.db`) and generating unified KPI dashboards.

## 🛠️ Installation & Usage (Kali Linux)
1. Clone the repository:
   ```bash
   git clone https://github.com/sanankhan318112233-boop/ICDC-All-in-One-Security-Tool.git
   cd ICDC-All-in-One-Security-Tool
