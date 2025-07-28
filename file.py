import os
import hashlib
import json
import math
import re
import pefile
import requests
from datetime import datetime

def calculate_entropy(data):
    if not data:
        return 0.0
    byte_freq = [0] * 256
    for b in data:
        byte_freq[b] += 1
    data_len = len(data)
    entropy = 0.0
    for freq in byte_freq:
        if freq > 0:
            p = freq / data_len
            entropy -= p * math.log2(p)
    return round(entropy, 2)

VIRUSTOTAL_API_KEY = "5cdd731ffe102ac14c823178e67cddfddfdca2f92d65c489de9e8f276a19cc27"

MAX_FILE_SIZE = 50 * 1024 * 1024 
HASH_DB_DIR = "hashes"
SIGNATURE_FILE = "signatures.txt"
WHITELIST_FILE = "whitelist.json"

SUSPICIOUS_APIS = [
    "CreateRemoteThread", "VirtualAlloc", "WriteProcessMemory",
    "SetWindowsHookEx", "GetAsyncKeyState", "WinExec", "ShellExecuteA",
    "LoadLibrary", "InternetOpen", "InternetConnect", "HttpSendRequest"
]

URL_PATTERN = re.compile(rb"(http[s]?://[^\s]+|www\.[^\s]+)", re.IGNORECASE)
IP_PATTERN = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def load_hash_database(directory, prefix):
    hash_set = set()
    for filename in os.listdir(directory):
        if filename.startswith(prefix):
            with open(os.path.join(directory, filename), "r") as file:
                for line in file:
                    hash_candidate = line.strip()
                    if len(hash_candidate) in (32, 40, 64):
                        hash_set.add(hash_candidate.lower())
    return hash_set

def load_whitelist():
    try:
        with open(WHITELIST_FILE, "r") as file:
            return set(json.load(file))
    except:
        return set()

def detect_file_type(contents):
    if contents.startswith(b"MZ"):
        return "PE executable"
    elif contents.startswith(b"\x7fELF"):
        return "ELF executable"
    elif contents.startswith(b"PK\x03\x04"):
        return "ZIP archive"
    elif contents.startswith(b"Rar!"):
        return "RAR archive"
    elif contents.startswith(b"\x1f\x8b"):
        return "GZIP archive"
    else:
        return "Unknown"

def extract_pe_info(contents):
    try:
        pe = pefile.PE(data=contents)
        imports = [entry.dll.decode(errors='ignore') for entry in pe.DIRECTORY_ENTRY_IMPORT]
        return {
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "imports": imports
        }
    except:
        return {}

def extract_strings(contents, min_length=4):
    return [s.decode("utf-8", errors="ignore") for s in re.findall(rb"[ -~]{%d,}" % min_length, contents)]

def clean_output(item):
    if isinstance(item, dict) or isinstance(item, list):
        return json.dumps(item, indent=2)
    return str(item)

def check_virustotal(sha256_hash):
    if not VIRUSTOTAL_API_KEY:
        return ("SKIPPED", "VirusTotal API key not set.")
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            msg = f"VirusTotal: {malicious} malicious, {suspicious} suspicious, {harmless} harmless."
            if malicious >= 2:
                return ("Malicious", msg)
            elif suspicious >= 5:
                return ("Suspicious", msg)
            else:
                return ("Safe", msg)
        elif response.status_code == 404:
            return ("Unknown", "VirusTotal: Hash not found.")
        else:
            return ("Error", f"VirusTotal error {response.status_code}: {response.text}")
    except Exception as e:
        return ("Error", f"VirusTotal exception: {e}")

def scan_file(file_path):
    verdicts = []
    indicators = []

    if os.path.getsize(file_path) > MAX_FILE_SIZE:
        return {"error": "File too large to scan."}

    with open(file_path, "rb") as f:
        contents = f.read()

    entropy = calculate_entropy(contents)
    if entropy > 7.3:
        verdicts.append("High file entropy (possible packing/encryption)")
        indicators.append({"type": "entropy", "value": entropy})

    md5 = hashlib.md5(contents).hexdigest()
    sha1 = hashlib.sha1(contents).hexdigest()
    sha256 = hashlib.sha256(contents).hexdigest()

    whitelist = load_whitelist()
    if md5 in whitelist or file_path in whitelist:
        return {"verdict": "Whitelisted file", "file_info": {"path": file_path}}

    md5_hashes = load_hash_database(HASH_DB_DIR, "md5")
    sha1_hashes = load_hash_database(HASH_DB_DIR, "sha1")
    sha256_hashes = load_hash_database(HASH_DB_DIR, "sha256")

    if md5 in md5_hashes or sha1 in sha1_hashes or sha256 in sha256_hashes:
        verdicts.append("Known malicious hash")
        indicators.append({"type": "hash", "value": md5})

    if os.path.exists(SIGNATURE_FILE):
        with open(SIGNATURE_FILE, "rb") as sig_file:
            for signature in sig_file:
                signature = signature.strip()
                if signature and signature in contents:
                    verdicts.append("Matched known signature")
                    indicators.append({"type": "signature", "value": signature.decode(errors='ignore')})

    file_type = detect_file_type(contents)
    pe_info = extract_pe_info(contents) if file_type == "PE executable" else {}

    bad_keywords = ["crack", "keygen", "patch", "hack"]
    if any(kw in file_path.lower() for kw in bad_keywords):
        verdicts.append("Suspicious filename")
        indicators.append({"type": "filename", "value": file_path})

    if any(x in contents.lower() for x in [b"virtualbox", b"wireshark", b"sandbox"]):
        verdicts.append("Sandbox detection artifacts found")
        indicators.append({"type": "sandbox", "value": "Detected"})

    non_ascii_ratio = sum(1 for byte in contents if byte > 127) / len(contents)
    if non_ascii_ratio > 0.5:
        verdicts.append("High non-ASCII byte ratio")
        indicators.append({"type": "non_ascii_ratio", "value": round(non_ascii_ratio, 2)})

    strings_found = extract_strings(contents)

    vt_status, vt_msg = check_virustotal(sha256)
    indicators.append({"type": "VirusTotal", "value": vt_msg})
    if vt_status == "Malicious":
        verdicts.append("VirusTotal detection: Malicious")
    elif vt_status == "Suspicious":
        verdicts.append("VirusTotal detection: Suspicious")

    for api in SUSPICIOUS_APIS:
        if api.encode() in contents:
            verdicts.append("Suspicious API call: " + api)
            indicators.append({"type": "api", "value": api})

    if b"UPX0" in contents or b"UPX1" in contents:
        verdicts.append("File appears to be UPX-packed")
        indicators.append({"type": "packer", "value": "UPX"})

    urls = URL_PATTERN.findall(contents)
    ips = IP_PATTERN.findall(contents)
    if urls or ips:
        verdicts.append("Embedded network indicators found")
        indicators.append({"type": "url/ip", "value": [u.decode(errors='ignore') for u in urls[:3] + ips[:3]]})

    file_info = {
        "path": file_path,
        "size": os.path.getsize(file_path),
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
        "file_type": file_type,
        "strings_found": strings_found[:10],
        **pe_info
    }

    threat_score = 0
    weights = {
        "Known malicious hash": 50,
        "Matched known signature": 30,
        "Suspicious filename": 10,
        "Sandbox detection artifacts found": 10,
        "High non-ASCII byte ratio": 10,
        "VirusTotal detection: Malicious": 50,
        "VirusTotal detection: Suspicious": 15,
        "High file entropy (possible packing/encryption)": 10,
        "Suspicious API call": 5,
        "File appears to be UPX-packed": 5,
        "Embedded network indicators found": 10,
    }

    for verdict in verdicts:
        for key in weights:
            if verdict.startswith(key):
                threat_score += weights[key]
                break
        else:
            threat_score += 5

    threat_score = min(threat_score, 100)

    if threat_score >= 60:
        classification = "Malicious"
    elif threat_score >= 40:
        classification = "Suspicious"
    else:
        classification = "Safe"

    return {
        "file_info": file_info,
        "verdicts": verdicts,
        "indicators": indicators,
        "threat_score": threat_score,
        "classification": classification
    }

# def main():
#     print("Malware Scanner v2.2 - Enhanced Detection Engine\n")

#     file_path = input("Enter the path to the file you want to scan: ").strip()

#     if os.path.exists(file_path):
#         results = scan_file(file_path)
#         print("\n=== SCAN REPORT ===")
#         for key, value in results.items():
#             print(f"{key.upper()}:")
#             if isinstance(value, list):
#                 for item in value:
#                     print(f"  - {clean_output(item)}")
#             elif isinstance(value, dict):
#                 for subkey, subval in value.items():
#                     print(f"  {subkey}: {subval}")
#             else:
#                 print(f"  {clean_output(value)}")
#             print()

#         try:
#             log_dir = "scan_logs"
#             os.makedirs(log_dir, exist_ok=True)
#             log_file = os.path.join(log_dir, f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
#             with open(log_file, "w", encoding='utf-8') as f:
#                 json.dump(results, f, indent=2)
#             print(f"\n[LOG] Scan log saved to: {log_file}")
#         except Exception as e:
#             print(f"[!] Could not save scan log: {str(e)}")
#     else:
#         print("[ERROR] File not found")

# if __name__ == "__main__":
#     main()
