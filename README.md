![YARA](https://img.shields.io/badge/YARA-4.5.4-blue)
![Python](https://img.shields.io/badge/Python-3.13-blue?logo=python&logoColor=white)
![macOS](https://img.shields.io/badge/macOS-native-black?style=flat&logo=apple)
![VirusTotal](https://img.shields.io/badge/VirusTotal-Enriched-green)
![License](https://img.shields.io/badge/License-MIT-green)

# YARA Hunter Pro – macOS-native Malware Scanner & Interactive Dashboard

Automated malware scanner using **YARA 4.5.4** with real-time **VirusTotal enrichment** and a fully interactive dark-mode **Plotly dashboard**.

### Live Demo
![Dashboard Screenshot](reports/yara_hunter_report.png)  
→ [Open full interactive HTML report](https://raw.githubusercontent.com/kleckie7/yara-hunter-pro/main/reports/yara_hunter_report.html)

# 1. Create project folder
mkdir -p ~/Documents/yara-hunter-pro && cd ~/Documents/yara-hunter-pro

# 2. Initialize git
git init

# 3. Create folders & files
mkdir -p rules samples reports
touch main.py scanner.py dashboard.py .env .gitignore Dockerfile requirements.txt

# 4. Set up Python environment
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install yara-python==4.5.4 pandas==2.2.3 plotly==5.24.0 requests==2.32.3 python-dotenv==1.0.1
pip freeze > requirements.txt

# 5. (Optional) Add your free VirusTotal API key
read -p "Paste your VT API key → " vtkey && echo "VIRUSTOTAL_API_KEY=$vtkey" > .env

# 6. Run it
chmod +x main.py
./main.py

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


