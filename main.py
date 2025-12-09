#!/usr/bin/env python3
import os
from scanner import load_rules, scan_files, enrich_vt, get_file_hash
from dashboard import generate_dashboard
from datetime import datetime

def print_banner():
    os.system('clear')
    print("=" * 60)
    print("        YARA HUNTER PRO – Malware Rule Scanner")
    print(f"        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60 + "\n")

def main():
    print_banner()
    rules = load_rules()
    print("[+] Scanning samples...")
    raw_results = scan_files('samples', rules)
    
    print(f"[+] Found {len(raw_results)} matches")
    results = []
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    for result in raw_results:
        file_path = os.path.join('samples', result['file'])
        hash_val = get_file_hash(file_path)
        vt_data = enrich_vt(hash_val, api_key) if api_key else {'detections': 'N/A'}
        result['vt'] = vt_data
        results.append(result)
    
    generate_dashboard(results)
    if results:
        print("[!] Threats detected – check reports/yara_hunter_report.html")
    else:
        print("[+] Clean scan")

if __name__ == "__main__":
    main()
