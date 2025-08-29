# Real-time PII detection and redaction code by Dishant Shah(dishadishantshah071). 
# Hi Team, I have focused on A. PII (Standalone) detection and redaction using regex patterns only. My own work take help from medium articles & YouTube videos.
import sys
import csv
import json
import re
from typing import Dict, Any, Tuple

Regex_Phone_number = re.compile(r'(?<!\d)(\d{10})(?!\d)')                     
Regex_Aadhaar  = re.compile(r'(?<!\d)(\d(?:[\s-]?\d){11})(?!\d)')         
Regex_Passport = re.compile(r'(?<![A-Z0-9])([A-PR-WY][1-9]\d{6})(?![A-Z0-9])', re.IGNORECASE)
Regex_UPI      = re.compile(r'\b([a-zA-Z0-9.\-_]{2,})@([a-zA-Z]{2,})\b')
Regex_NON_DIGITS = re.compile(r'\D')

def normalize_str(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        try:
            return json.dumps(v, ensure_ascii=False)
        except Exception:
            return str(v)
    return str(v)
def mask_phone(s: str) -> str:
    return s[:2] + "XXXXXX" + s[-2:]
def mask_aadhaar(_: str) -> str:
    return "XXXX XXXX XXXX"
def mask_passport(s: str) -> str:
    if len(s) >= 3:
        return s[:1] + "XXXXX"
    return "XXXXXXX"
def mask_upi(local: str, handle: str) -> str:
    keep = min(len(local), 2)
    return local[:keep] + "XXX@" + handle

def detect_standalone(rec: Dict[str, Any]) -> Dict[str, Any]:
    hits = {}
    for v in rec.values():
        val = normalize_str(v)
        for m in Regex_Phone_number.finditer(val):
            hits.setdefault("phone", []).append(m.group(1))
    for v in rec.values():
        val = normalize_str(v)
        for m in Regex_Aadhaar.finditer(val):
            digits = Regex_NON_DIGITS.sub("", m.group(1))
            if len(digits) == 12:
                hits.setdefault("aadhaar", []).append(digits)
    for v in rec.values():
        val = normalize_str(v)
        for m in Regex_Passport.finditer(val):
            hits.setdefault("passport", []).append(m.group(1))
    for v in rec.values():
        val = normalize_str(v)
        for m in Regex_UPI.finditer(val):
            hits.setdefault("upi", []).append((m.group(1), m.group(2)))
    return hits


def redact_record(rec: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    try:
        data = json.loads(json.dumps(rec))
    except Exception:
        data = dict(rec)
    Standalone_PII = detect_standalone(rec)
    is_pii = bool(Standalone_PII)
    if is_pii:
        for k in list(data.keys()):
            val = normalize_str(data[k])
            if "phone" in Standalone_PII:
                val = Regex_Phone_number.sub(lambda m: mask_phone(m.group(1)), val)
            if "aadhaar" in Standalone_PII:
                def _sub_aadhaar(m):
                    digits = Regex_NON_DIGITS.sub("", m.group(1))
                    return mask_aadhaar(digits) if len(digits) == 12 else m.group(0)
                val = Regex_Aadhaar.sub(_sub_aadhaar, val)
            if "passport" in Standalone_PII:
                val = Regex_Passport.sub(lambda m: mask_passport(m.group(1)), val)
            if "upi" in Standalone_PII:
                val = Regex_UPI.sub(lambda m: mask_upi(m.group(1), m.group(2)), val)
            data[k] = val
    return data, is_pii

def process_csv(in_path: str, out_path: str) -> None:
    with open(in_path, "r", encoding="utf-8") as f_in, open(out_path, "w", encoding="utf-8", newline="") as f_out:
        reader = csv.DictReader(f_in)
        writer = csv.writer(f_out)
        writer.writerow(["record_id", "redacted_data_json", "is_pii"])
        for row in reader:
            rec_id = row.get("record_id") or row.get("id") or ""
            data_raw = row.get("Data_json") or row.get("data_json") or "{}"
            try:
                data_obj = json.loads(data_raw)
                if not isinstance(data_obj, dict):
                    data_obj = {"_data": data_obj}
            except Exception:
                data_obj = {"_data": data_raw}
            redacted_obj, is_pii = redact_record(data_obj)
            redacted_json = json.dumps(redacted_obj, ensure_ascii=False)
            writer.writerow([rec_id, redacted_json, str(bool(is_pii))])

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python detector_Dishant_Shah.py iscp_pii_dataset_-_Sheet1.csv")
        sys.exit(1)
    input_csv = sys.argv[1]
    output_csv = "redacted_output_Dishant_Shah.csv"
    process_csv(input_csv, output_csv)
    print(f"Wrote: {output_csv}")
