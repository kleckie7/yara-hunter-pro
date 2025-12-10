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

# 5. Add safe test samples
cat > samples/eicar_test.com <<'EOF'
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
EOF
for i in {2..4}; do echo "Malicious payload $i (encrypt ransom)" > samples/malware_sim_$i.bin; done

# 6. Add working YARA rules
cat > rules/rules.yar <<'EOF'
rule EICAR_Test { strings: $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"; condition: $eicar }
rule Ransomware_LockBit { strings: $a = "LockBit" ascii wide; $b = "encrypt" ascii; condition: all of them }
rule Trojan_Emotet { strings: $a = "Emotet" ascii; $b = /cmd\.exe.*\/c/; condition: all of them }
rule Clop_Ransomware_2025 { strings: $a = "Clop" ascii wide; condition: $a }
rule Suspicious_PowerShell { strings: $a = "powershell.exe" ascii; $b = "-ExecutionPolicy Bypass" ascii; condition: all of them }
EOF

# 7. (Optional) Add your free VirusTotal API key
read -p "Paste your VT API key → " vtkey && echo "VIRUSTOTAL_API_KEY=$vtkey" > .env

# 8. Run it
chmod +x main.py
./main.py
# → Interactive dashboard opens automatically
