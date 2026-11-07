# Phishing Awareness Training – CodeAlpha Task 2

An interactive, dependency-free training module that teaches users to recognize phishing emails and fake websites, understand social engineering, and respond to incidents. Includes a PDF presentation and a 10-question quiz.

## Objectives
Recognize phishing emails and fake websites · understand social-engineering tactics · learn prevention best practices · practise with fictional scenarios · test knowledge with a quiz.

## Features
- Dashboard with progress indicator and navigation
- Modules: fundamentals, attack types, social engineering, prevention and incident response
- Email analysis: 3 fictional phishing emails and 1 legitimate comparison, with revealable indicators
- Fake-website mockups (static, inputs disabled, nothing collected) with explained markers
- 10-question quiz loaded from `quiz/questions.json`: instant feedback, explanations, score, percentage, retake
- 12-slide PDF presentation (`presentation/phishing_awareness.pdf`), regenerable with `presentation/build_pdf.py`

## Technologies
HTML5, CSS3, vanilla JavaScript; Python + ReportLab (PDF only).

## Structure
```text
Task-2_Phishing-Awareness/
├── README.md
├── presentation/ (phishing_awareness.pdf, build_pdf.py)
├── interactive_module/ (index.html, style.css, script.js)
├── quiz/questions.json
├── screenshots/
└── references/sources.md
```

## Run locally
The quiz uses `fetch`, which browsers block on `file://`, so serve the project root:
```bash
cd Task-2_Phishing-Awareness
python3 -m http.server 8000
```
Open http://localhost:8000/interactive_module/index.html

Regenerate the PDF (optional): `pip install reportlab && cd presentation && python3 build_pdf.py`

## Screenshots
The `screenshots/` folder is empty. Run the module and add your own captures (dashboard, email analysis, website mockups, quiz results).

## Disclaimer
Educational use only. All brands, domains and scenarios are fictional (`.example` domains) and describe no real incident. The mockups collect, transmit and store nothing. Do not use this material to deceive anyone.

## References
See `references/sources.md`: CISA, NIST, Canadian Centre for Cyber Security, Microsoft Security.
