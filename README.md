📧 Email Spoofing Detection Tool — Assignment 2
This project is an Email Spoofing Detection Tool written in Python.
It detects fraudulent and spoofed emails using a hybrid approach: combining rule-based checks and a machine learning model.

Based on the research paper: "Email Spoofing Detection — IJARIIE".

🚀 Features
Extracts key email headers: From, Reply-To, Return-Path, Received, DKIM-Signature.
Detects header mismatches, a common spoofing indicator.
Validates:
✅ SPF (Sender Policy Framework)
✅ DKIM (DomainKeys Identified Mail)
✅ DMARC (Domain-based Message Authentication, Reporting & Conformance)
Hybrid detection:
Rule-based analysis
Logistic Regression ML model using dynamic features
Outputs verdict: ✅ Legitimate Email or ⚠️ Likely Spoofed.
Shows ML evaluation metrics: Accuracy, F1 score, and Confusion Matrix.
🎯 Research Gap & Improvement
Research Gap:
The original paper used only rule-based or single ML classification methods, which limits accuracy and generalization.

Improvements in Assignment 2:

Dynamic dataset creation from multiple emails using rule-based features.
Hybrid model combining rule-based and Logistic Regression ML classification.
Improved detection accuracy and reliability.
📦 Installation
1. Clone the repository
git clone https://github.com/RithikaHamsagouni/email-spoofing-detection--cybersecurity.git
cd email-spoofing-detection--cybersecurity
