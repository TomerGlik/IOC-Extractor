import re

# IOC patterns
patterns = {
    "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b"
}

# Keywords for classifying suspicion
suspicious_keywords = ["malicious", "suspicious", "block", "deny", "blacklist"]

def analyze_line(line):
    found = []
    for ioc_type, pattern in patterns.items():
        matches = re.findall(pattern, line)
        for match in matches:
            tag = "suspicious" if any(word in line.lower() for word in suspicious_keywords) else "clean"
            found.append((match, ioc_type, tag))
    return found

def process_log(input_file, output_file="ioc_extracted.csv"):
    results = []
    with open(input_file, "r") as f:
        for line in f:
            iocs = analyze_line(line)
            results.extend(iocs)

    with open(output_file, "w") as out:
        for ioc, ioc_type, status in results:
            out.write(f"{ioc},{ioc_type},{status}\n")

    print(f"✅ Extracted {len(results)} IOCs → saved to {output_file}")

if __name__ == "__main__":
    log_file = "sample_log.txt"
    process_log(log_file)
