# Phishing Awareness Training

**CodeAlpha Cyber Security Internship — Task 2**

## Overview

This project is an interactive cybersecurity awareness training module developed as part of the CodeAlpha Cyber Security Internship.

Its primary objective is to educate users about phishing attacks, social engineering techniques, malicious emails, and fraudulent websites while providing practical knowledge to recognize and prevent common phishing threats.

## Objectives

- Understand phishing attacks and their common techniques.
- Recognize suspicious emails and malicious links.
- Identify fake websites and domain spoofing.
- Understand social engineering tactics.
- Learn effective phishing prevention methods.
- Evaluate cybersecurity awareness through interactive quizzes.

## Features

### 1. Educational Presentation
A structured presentation covering phishing fundamentals, attack types, social engineering, email security, fake websites, and prevention techniques.

### 2. Interactive Training Module
A responsive web-based learning environment with educational sections and practical phishing scenarios.

### 3. Email Analysis
Examples of suspicious and legitimate-looking emails, with explanations of common phishing indicators.

### 4. Fake Website Recognition
Educational examples demonstrating suspicious domains, typosquatting, and fraudulent login pages.

### 5. Interactive Quiz
A knowledge assessment featuring:
- Multiple-choice questions.
- Immediate answer feedback.
- Explanations for answers.
- Final score calculation.
- Retake functionality.

## Technologies Used

| Technology | Purpose |
|---|---|
| HTML5 | Web structure |
| CSS3 | Styling and responsive design |
| JavaScript | Interactive functionality |
| JSON | Quiz data storage |
| PDF | Educational presentation |

## Project Structure

```text
Task-2_Phishing-Awareness/
│
├── README.md
│
├── presentation/
│   └── phishing_awareness.pdf
│
├── interactive_module/
│   ├── index.html
│   ├── style.css
│   └── script.js
│
├── quiz/
│   └── questions.json
│
├── screenshots/
│
└── references/
    └── sources.md
```

## Installation and Usage

### Prerequisites
- A modern web browser.
- Python 3 (for running a local HTTP server).

### Run the Training Module

Clone the repository:

```bash
git clone YOUR_REPOSITORY_URL
```

Navigate to the project directory:

```bash
cd CodeAlpha_CyberSecurity_Internship/Task-2_Phishing-Awareness
```

Start a local HTTP server:

```bash
python3 -m http.server 8000
```

Open the following address in your browser:

```text
http://localhost:8000/interactive_module/
```

## Learning Outcomes

Through this project, users can develop practical awareness of:

- Phishing identification and prevention.
- Email and URL security analysis.
- Social engineering recognition.
- Safe browsing practices.
- Cybersecurity awareness and incident response.

## References

- [CISA — Recognize and Report Phishing](https://www.cisa.gov/secure-our-world/recognize-and-report-phishing)
- [NIST — Phishing Guidance](https://www.nist.gov/itl/smallbusinesscyber/guidance-topic/phishing)
- [Canadian Centre for Cyber Security](https://www.cyber.gc.ca/en/guidance/dont-take-bait-recognize-and-avoid-phishing-attacks)
- [Microsoft Security](https://www.microsoft.com/en-us/security/business/cybersecurity-awareness)

## Disclaimer

This project is developed strictly for educational and cybersecurity awareness purposes.

All phishing examples and website mockups are intended for defensive training and do not collect or transmit personal credentials.

---

**Author:** Ramiz Səmədov

**Program:** CodeAlpha Cyber Security Internship

**Task:** 02 — Phishing Awareness Training
