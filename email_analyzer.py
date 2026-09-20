import re
from email import policy
from email.parser import BytesParser

# Step 2: Urgent keywords & suspicious patterns
URGENT_KEYWORDS = ["urgent", "immediate action", "verify now", "account suspended", "click here", "password expired"]
SUSPICIOUS_LINKS = [r"bit\.ly", r"tinyurl", r"@.*\.ru", r"free.*money"]

def parse_headers(raw_email_path):
    with open(raw_email_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    print("=== Step 1: Header Analysis ===")
    headers = {
        "Return-Path": msg['Return-Path'],
        "Received": msg['Received'],
        "SPF": msg['Authentication-Results'] or msg['Received-SPF'],
        "DKIM": "DKIM" in str(msg['Authentication-Results']),
        "From": msg['From']
    }
    for k, v in headers.items():
        print(f"{k}: {v}")
    return headers, msg.get_body(preferencelist=('plain')).get_content() if msg.get_body() else ""

def analyze_body(body):
    print("\n=== Step 2: Body Scan ===")
    risk_points = 0
    findings = []

    # Check urgent keywords
    for word in URGENT_KEYWORDS:
        if word.lower() in body.lower():
            findings.append(f"Urgent keyword found: '{word}'")
            risk_points += 15

    # Check suspicious links
    urls = re.findall(r'http[s]?://\S+', body)
    print(f"Found URLs: {urls}")
    for url in urls:
        for pattern in SUSPICIOUS_LINKS:
            if re.search(pattern, url, re.I):
                findings.append(f"Suspicious link pattern in {url}")
                risk_points += 25
        if url.count('@') > 0 or url.count('-') > 3:
            findings.append(f"Possible spoofed domain: {url}")
            risk_points += 20

    return risk_points, findings

def generate_report(headers, findings, score):
    # Step 3 & 4: Risk score & Report
    print("\n=== Step 3: Risk Score ===")
    if score < 30: level = "LOW (Safe)"
    elif score < 60: level = "MEDIUM (Suspicious)"
    else: level = "HIGH (Phishing Likely)"

    print(f"Total Risk Score: {score}/100 -> {level}")

    print("\n=== Step 4: Email Security Audit Report ===")
    report = f"""
EMAIL SECURITY AUDIT REPORT

From: {headers.get('From')}
SPF/DKIM Check: {headers.get('SPF')}

Findings:
"""
    for f in findings:
        report += f"- {f}\n"
    report += f"\nFinal Verdict: {level} with score {score}\n"
    report += "Recommendation: " + ("Block & Report" if score>=60 else "Allow with caution")

    print(report)

    # Save as txt (you can convert to PDF)
    with open("Phishing_Analysis_Report.txt", "w") as out:
        out.write(report)
    print("\nReport saved as Phishing_Analysis_Report.txt -> Convert to PDF for submission")

# Demo with a sample
if __name__ == "__main__":
    # Create a dummy raw email for testing
    sample_body = "Dear user, URGENT: Your account suspended! Click here http://bit.ly/free-money to verify now @ secure-bank.com"
    # For demo we skip file parsing
    dummy_headers = {"From": "support@secure-bank.com", "SPF": "Fail - Not aligned", "Return-Path": "attacker@evil.ru"}
    score, findings = analyze_body(sample_body)
    generate_report(dummy_headers, findings, score)
