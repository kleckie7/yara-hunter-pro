![YARA](https://img.shields.io/badge/YARA-4.5.4-blue)
![Python](https://img.shields.io/badge/Python-3.13-blue?logo=python&logoColor=white)
![macOS](https://img.shields.io/badge/macOS-native-black?style=flat&logo=apple)
![VirusTotal](https://img.shields.io/badge/VirusTotal-Enriched-green)
![License](https://img.shields.io/badge/License-MIT-green)

# YARA Hunter Pro – macOS-native Malware Scanner & Interactive Dashboard

Automated malware scanner using **YARA 4.5.4** with real-time **VirusTotal enrichment** and a fully interactive dark-mode **Plotly dashboard**.

### Live Demo
![Dashboard Screenshot](reports/yara_hunter_report.png)  
→ → [Open full interactive HTML report](https://raw.githubusercontent.com/kleckie7/yara-hunter-pro/main/reports/yara_hunter_report.html)
### Live Demo
![Dashboard Screenshot](reports/yara_hunter_report.png)  
→ [Open full interactive HTML report](https://raw.githubusercontent.com/kleckie7/yara-hunter-pro/main/reports/yara_hunter_report.html)

### Features
- Real YARA 4.5.4 rule matching (EICAR, LockBit, Emotet, Clop, PowerShell, etc.)
- Optional VirusTotal API enrichment (free tier works perfectly)
- Interactive HTML dashboard (heatmaps, bar charts, tables, pie charts)
- 100% macOS native (Apple Silicon + Intel)
- Docker-ready

### Run in 60 Seconds (macOS)

```bash
git clone https://github.com/kleckie7/yara-hunter-pro.git
cd yara-hunter-pro
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
./main.py


