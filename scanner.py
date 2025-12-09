import yara
import os
import requests
from dotenv import load_dotenv
import hashlib

load_dotenv()

def load_rules(rules_path='rules/rules.yar'):
    return yara.compile(rules_path)

def scan_files(sample_dir, rules):
    results = []
    for file in os.listdir(sample_dir):
        file_path = os.path.join(sample_dir, file)
        if os.path.isfile(file_path):
            matches = rules.match(file_path)
            if matches:
                for match in matches:
                    results.append({
                        'file': file,
                        'rule': match.rule,
                        'matches': match.strings,
                        'size': os.path.getsize(file_path)
                    })
    return results

def enrich_vt(file_hash, api_key):
    if not api_key:
        return {'detections': 'N/A'}
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    params = {'apikey': api_key, 'resource': file_hash}
    response = requests.get(url, params=params)
    if response.status_code == 200:
        data = response.json()
        return {
            'detections': data.get('positives', 0),
            'total': data.get('total', 0),
            'scan_date': data.get('scan_date', 'N/A')
        }
    return {'error': 'API failure'}

def get_file_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256.update(chunk)
    return sha256.hexdigest()
