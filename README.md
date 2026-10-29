# 🛡️ PhishGuard – Phishing Email Analyzer

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?logo=python" alt="Python">
  <img src="https://img.shields.io/badge/Flask-Web%20Framework-black?logo=flask" alt="Flask">
  <img src="https://img.shields.io/badge/Security-Email%20Analysis-red" alt="Email Analysis">
  <img src="https://img.shields.io/badge/Status-Active-success" alt="Active">
</p>

<p align="center">
  A lightweight web-based security tool that analyzes suspicious emails using rule-based risk scoring and identifies potentially malicious indicators.
</p>

---

## 📑 Table of Contents

- [About](#-about)
- [Screenshots](#-screenshots)
- [Key Features](#-key-features)
- [Detection Capabilities](#-detection-capabilities)
- [Technology Stack](#-technology-stack)
- [Analysis Workflow](#-analysis-workflow)
- [Demo](#-demo)
- [Project Structure](#-project-structure)
- [Security and Limitations](#-security-and-limitations)
- [Author](#-author)

---

## 🔍 About

**PhishGuard** is a web-based phishing email analysis tool developed using Python and Flask. It helps users inspect suspicious emails by extracting potentially dangerous indicators and calculating a risk score based on predefined security rules.

The application analyzes email content, identifies suspicious URLs and email addresses, checks for possible brand impersonation, and presents findings through a simple web interface.

PhishGuard is designed as a cybersecurity learning project to demonstrate email security analysis, phishing indicators, and basic threat detection techniques.

---

## 📸 Screenshots

<div align="center">

### 🖥️ PhishGuard Dashboard

<a href="docs/screenshots/dashboard.png">
  <img src="docs/screenshots/dashboard.png" alt="PhishGuard Dashboard" width="90%">
</a>

*The PhishGuard web interface for submitting and analyzing suspicious emails.*

<br>

### 🚨 Phishing Analysis Results

<a href="docs/screenshots/analysis-result.png">
  <img src="docs/screenshots/analysis-result.png" alt="PhishGuard Phishing Analysis Results" width="90%">
</a>

*Example analysis showing the risk score, verdict, and detected indicators.*

</div>

---

## ✨ Key Features

- **Email Analysis:** Analyze suspicious email content by pasting text or uploading an `.eml` file.
- **URL Extraction:** Identify URLs found in the submitted email.
- **Email Address Extraction:** Extract email addresses for further investigation.
- **Risk Scoring:** Calculate a risk score using predefined detection rules.
- **Brand Impersonation Detection:** Identify potential attempts to impersonate supported well-known brands.
- **HTML Link Analysis:** Detect cases where the displayed link text differs from its destination.
- **Authentication Result Parsing:** Parse SPF, DKIM, and DMARC results when those results are supplied in the email content.
- **SHA-256 Hashing:** Generate a SHA-256 hash of the submitted email text.
- **JSON Report Export:** Export analysis findings as a JSON report.
- **Web Interface:** Display analysis results and security indicators through a Flask-powered interface.

---

## 🚨 Detection Capabilities

PhishGuard uses rule-based analysis to identify potentially suspicious email characteristics.

| Detection | Description |
|---|---|
| Suspicious URLs | Extracts URLs for inspection. |
| Suspicious Email Addresses | Identifies email addresses present in the submitted content. |
| Brand Impersonation | Checks for possible impersonation of supported brands. |
| Lookalike Domains | Identifies certain suspicious domain-name patterns. |
| HTML Link Mismatch | Detects differences between displayed link text and link destinations. |
| Email Authentication Results | Parses SPF, DKIM, and DMARC results supplied in the email content. |
| Risk Scoring | Assigns a risk score based on configured detection rules. |
| Email Hashing | Calculates a SHA-256 hash of the submitted email text. |

**Note:** These detections are heuristic indicators. A finding does not independently prove that an email is malicious.

---

## 🛠️ Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application logic and analysis |
| Flask | Web application framework |
| HTML | Web interface structure |
| CSS | User interface styling |
| Regular Expressions | Extraction and pattern matching |
| hashlib | SHA-256 hashing |
| email | Email message parsing |
| JSON | Structured analysis report export |

---

## 🔄 Analysis Workflow

```text
        Suspicious Email
                |
                v
       Email Input / .eml
                |
                v
       Email Content Parsing
                |
                v
       Indicator Extraction
                |
       +--------+---------+
       |        |         |
       v        v         v
      URLs   Email IDs  Link Analysis
       |        |         |
       +--------+---------+
                |
                v
       Rule-Based Detection
                |
                v
          Risk Scoring
                |
                v
       Results and Findings
                |
                v
          JSON Report
```

---

## 🧪 Demo

The following fictional email illustrates how PhishGuard can be used to inspect suspicious content.

**Example email:**

```text
From: account-alert@secure-login.example
Subject: Urgent: Account Verification Required

Dear User,

Your account requires immediate verification.
Please review your account information using the link below:

http://secure-login.example/verify

Failure to verify your account may result in restricted access.

Thank you,
Account Security Team
```

**Possible indicators to investigate:**

- Urgent language that pressures the recipient to act.
- A link requesting account verification.
- A sender address and domain that should be independently investigated.

The `.example` domain is reserved for illustrative examples and is not intended to represent a real phishing website.

Actual findings and risk scores depend on the content submitted and the application's configured detection rules.

---

## 📂 Project Structure

```text
PhishGuard/
│
├── app.py
├── analyzer.py
├── requirements.txt
├── README.md
│
├── templates/
│   └── index.html
│
├── static/
│   └── style.css
│
└── docs/
    └── screenshots/
        ├── dashboard.png
        └── analysis-result.png
```

---

## 🔐 Security and Limitations

- PhishGuard uses predefined rules and heuristics; it is not a definitive phishing detection system.
- A low risk score does not guarantee that an email is safe.
- SPF, DKIM, and DMARC results are parsed from supplied email content and are not independently verified by the application.
- Extracted URLs are not automatically opened by the analyzer.
- The SHA-256 hash represents the submitted email text, not necessarily the original raw email file.
- Brand impersonation detection is limited to the brands and patterns implemented in the application.
- Unicode homoglyph detection is not implemented.
- Analysis results should be treated as indicators for further investigation, not as a substitute for a complete security assessment.

**Safety recommendation:** Avoid opening suspicious links or attachments while investigating potentially malicious emails.

---

## 👩‍💻 Author

**Rutika Shinde**

- GitHub: [@rutikashinde273](https://github.com/rutikashinde273)
- Project: [PhishGuard – Phishing Email Analyzer](https://github.com/rutikashinde273/PhishGuard-Email-Analyzer)

---

<p align="center">
  Built as a hands-on cybersecurity project to explore phishing email analysis and threat detection.
</p>
