import email
import dns.resolver
import dkim
import re
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix

# ==========================
# Helper Functions
# ==========================

def extract_headers(raw_email):
    """Extract headers from raw email string"""
    msg = email.message_from_string(raw_email)
    headers = {}
    for header in ["From", "Reply-To", "Return-Path", "Received", "DKIM-Signature"]:
        headers[header] = msg[header] if header in msg else None
    return headers

def check_header_mismatch(headers):
    """Check for mismatched From, Reply-To, and Return-Path"""
    issues = []
    from_addr = headers.get("From", "")
    reply_to = headers.get("Reply-To", "")
    return_path = headers.get("Return-Path", "")

    def extract_domain(addr):
        if not addr:
            return None
        match = re.search(r'@([A-Za-z0-9.-]+)', addr)
        return match.group(1).lower() if match else None

    from_domain = extract_domain(from_addr)
    reply_domain = extract_domain(reply_to)
    return_domain = extract_domain(return_path)

    if reply_to and reply_domain != from_domain:
        issues.append("Mismatch between From and Reply-To")
    if return_path and return_domain != from_domain:
        issues.append("Mismatch between From and Return-Path")

    return issues

def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            if "v=spf1" in str(rdata):
                return True
    except Exception:
        return False
    return False

def check_dkim(raw_email, headers):
    if not headers.get("DKIM-Signature"):
        return False
    try:
        return dkim.verify(raw_email.encode("utf-8"))
    except Exception:
        return False

def check_dmarc(domain):
    try:
        dmarc_domain = "_dmarc." + domain
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            if "v=DMARC1" in str(rdata):
                return True
    except Exception:
        return False
    return False

# ==========================
# Main Detection Function
# ==========================

def detect_spoofing(raw_email):
    headers = extract_headers(raw_email)
    report = {"headers": headers, "issues": []}

    header_issues = check_header_mismatch(headers)
    report["issues"].extend(header_issues)

    from_addr = headers.get("From", "")
    match = re.search(r'@([A-Za-z0-9.-]+)', from_addr) if from_addr else None
    if match:
        domain = match.group(1).lower()

        if not check_spf(domain):
            report["issues"].append("No valid SPF record found")

        if not check_dkim(raw_email, headers):
            report["issues"].append("DKIM validation failed or missing")

        if not check_dmarc(domain):
            report["issues"].append("No valid DMARC record found")

    report["result"] = "⚠️ Likely Spoofed" if report["issues"] else "✅ Legitimate Email"
    return report

# ==========================
# Example Usage + ML
# ==========================

if __name__ == "__main__":
    # Example raw emails
    raw_email = """From: "Fake Bank" <support@bank-secure.com>
Reply-To: scammer@gmail.com
Return-Path: hacker@evil.com
Received: from mail.evil.com by example.com
Subject: Urgent: Verify Your Account

This is a test email.
"""

    result = detect_spoofing(raw_email)
    print("\n===== Email Spoofing Analysis =====")
    print("From       :", result["headers"].get("From"))
    print("Reply-To   :", result["headers"].get("Reply-To"))
    print("Return-Path:", result["headers"].get("Return-Path"))
    print("\n⚠️ Issues Found:")
    for issue in result["issues"]:
        print(" -", issue)
    print("\n✅ Final Verdict:", result["result"])

    # --------------------------
    # Fixed dataset with 2 classes (0 = Legitimate, 1 = Spoofed)
    # --------------------------
    emails = [
        raw_email,  # Spoofed
        """From: "Bank" <support@bank.com>
           Reply-To: support@bank.com
           Return-Path: support@bank.com
           Received: from mail.bank.com by example.com
           Subject: Your statement""",  # Legitimate
        """From: "Fake Shop" <info@fakeshop.com>
           Reply-To: scammer@gmail.com
           Return-Path: hacker@evil.com
           Received: from mail.evil.com by example.com
           Subject: Order Confirmation"""  # Spoofed
    ]

    dataset = []
    for e in emails:
        report = detect_spoofing(e)
        spf_pass = 1 if "No valid SPF record found" not in report["issues"] else 0
        dkim_pass = 1 if "DKIM validation failed or missing" not in report["issues"] else 0
        header_mismatch = 1 if any("Mismatch" in issue for issue in report["issues"]) else 0
        received_count = len(report["headers"].get("Received", "").split("\n")) if report["headers"].get("Received") else 1
        is_spoofed = 1 if "⚠️ Likely Spoofed" in report["result"] else 0
        dataset.append([spf_pass, dkim_pass, header_mismatch, received_count, is_spoofed])

    df = pd.DataFrame(dataset, columns=["spf_pass", "dkim_pass", "header_mismatch", "received_count", "is_spoofed"])

    # --------------------------
    # Train/Test Logistic Regression
    # --------------------------
    X = df[["spf_pass", "dkim_pass", "header_mismatch", "received_count"]]
    y = df["is_spoofed"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)

    model = LogisticRegression(max_iter=300, solver='liblinear')
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("\n===== ML Model Results =====")
    print("Accuracy:", round(accuracy_score(y_test, y_pred), 2))
    print("F1 Score:", round(f1_score(y_test, y_pred), 2))
    print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

    # --------------------------
    # Hybrid Prediction Example
    # --------------------------
    report = detect_spoofing(raw_email)
    spf_pass = 1 if "No valid SPF record found" not in report["issues"] else 0
    dkim_pass = 1 if "DKIM validation failed or missing" not in report["issues"] else 0
    header_mismatch = 1 if any("Mismatch" in issue for issue in report["issues"]) else 0
    received_count = len(report["headers"].get("Received", "").split("\n")) if report["headers"].get("Received") else 1

    new_email_df = pd.DataFrame({
        "spf_pass": [spf_pass],
        "dkim_pass": [dkim_pass],
        "header_mismatch": [header_mismatch],
        "received_count": [received_count]
    })

    ml_prediction = model.predict(new_email_df)[0]
    print("\nML Model Prediction:", "⚠️ Likely Spoofed" if ml_prediction==1 else "✅ Legitimate Email")

