# 🕵️ IOC Extractor from Log Files

A simple Python script for extracting IOCs (Indicators of Compromise) like IP addresses, domains, and file hashes from raw log files.  
It also attempts to classify each IOC as **suspicious** or **clean** based on keywords found in the same log line.

---

## 🚀 Features

- Extracts:
  - IPv4 addresses
  - Domains
  - MD5 and SHA256 file hashes
- Classifies IOCs as:
  - `suspicious` – if the log line contains keywords like `malicious`, `blocked`, `suspicious`, `deny`
  - `clean` – if no such keyword is detected
- Outputs results to a CSV-like file with the format: <ioc_value>,<ioc_type>,<status>


---

## 📂 Example Output

```csv
8.8.8.8,ip,clean
abc.com,domain,clean
45.76.90.12,ip,malicious
9a2f4c6b16b6b23f1638791a44c73d01,md5,clean
