# CyberGuard — Cyber Fraud Detection System

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Django](https://img.shields.io/badge/Django-4.x-green?logo=django&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-Optional-brightgreen?logo=mongodb&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow)

A full-stack fraud detection system that analyzes SMS and WhatsApp messages using TF-IDF scoring, Shannon entropy URL analysis, and cosine/Jaccard similarity matching. Includes a Django web dashboard for live detection, case history, and analytics.

---

## Screenshots

| Home Page | Detection Result | Analytics Dashboard |
|-----------|-------------------|----------------------|
| Enter a message for analysis | Risk score with signal breakdown | Bar, pie, line, and scatter charts |

---

## Features

- **6 fraud categories** — banking, crypto, job, loan, OTP, and safe message classification
- **TF-IDF scoring engine** — weighted keyword matching with per-category risk bands
- **URL analyzer** — Shannon entropy detection and homograph/lookalike domain checks
- **Similarity engine** — Jaccard and cosine similarity against a known scam corpus
- **SMS/WhatsApp parser** — OOP-based message parser for real-world message formats
- **Data analytics** — NumPy statistics, Pandas DataFrames, and Matplotlib charts
- **Django web app** — full MVT architecture with live detection, history, and dashboard
- **MongoDB support** — optional persistent storage, falls back to a log file if unavailable
- **Case history** — view and filter previously analyzed messages

---

## Project Structure

```
cyber-fraud-detector/
│
├── module1/                    Pure Python detection engine (no Django)
│   ├── main.py                 CLI entry point — run this first
│   ├── fraud_engine.py         TF-IDF scoring, 6 fraud types, risk bands
│   ├── url_analyzer.py         Shannon entropy, homograph detection
│   ├── similarity_engine.py    Jaccard + cosine similarity matching
│   ├── message_parser.py       SMS/WhatsApp OOP message parser
│   ├── fraud_models.py         OOP class hierarchy + MongoDB CRUD
│   ├── fraud_analytics.py      NumPy + Pandas + Matplotlib charts
│   └── fraud_cases.log         Auto-generated case log (no MongoDB needed)
│
└── module2/                    Django web application
    ├── manage.py
    ├── cyberguard/              Django project settings and URLs
    │   ├── settings.py
    │   └── urls.py
    └── fraud_app/               Main Django app
        ├── views.py             View logic, imports the module1 engine
        ├── urls.py
        ├── templates/fraud_app/
        └── static/fraud_app/    Chart images
```

---

## Installation & Setup

### Prerequisites
- Python 3.8+
- pip
- MongoDB (optional — the app works without it)

### 1. Clone the repository

```bash
git clone https://github.com/ishaq-9e1/cyber-fraud-detector.git
cd cyber-fraud-detector
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run module 1 — CLI demo

```bash
cd module1
python3 main.py
```

This scans a set of test messages, prints a per-signal risk breakdown for each, saves results to `fraud_cases.log` (and to MongoDB if running), and generates summary statistics and charts.

### 4. Run module 2 — Django web app

```bash
cd ../module2
python3 manage.py migrate
python3 manage.py runserver
```

Then open http://127.0.0.1:8000 in a browser.

---

## MongoDB Setup (Optional)

The app works fully without MongoDB — it falls back to `fraud_cases.log`. To enable it:

```bash
# macOS
brew services start mongodb-community

# Ubuntu/Debian
sudo systemctl start mongod

# Windows
net start MongoDB
```

MongoDB URI: `mongodb://localhost:27017/` — Database: `cyberfraud`

---

## How It Works

```
Input Message
     |
     v
Message Parser        SMS/WhatsApp OOP parser
     |
     v
Fraud Engine           TF-IDF keyword scoring x category weight (6 categories)
     |
     v
URL Analyzer           Shannon entropy + homograph detection
     |
     v
Similarity Engine      Jaccard + cosine similarity vs known scam database
     |
     v
Risk Score (0-100)     Safe / Suspicious / Critical
```

### Risk Bands

| Score | Label | Severity |
|-------|-------|----------|
| 0–15 | Safe | Low |
| 16–35 | Low Suspicion | Low |
| 36–60 | Suspicious | Medium |
| 61–80 | High Risk | High |
| 81–100 | Critical Scam | Critical |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.8+ |
| Web Framework | Django 4.x |
| Database | SQLite (default) / MongoDB (optional) |
| Data Analysis | NumPy, Pandas |
| Visualization | Matplotlib |
| Frontend | HTML5, CSS3, Bootstrap |
| NLP Engine | Custom TF-IDF (no external NLP library) |

---

## Requirements

See [`requirements.txt`](requirements.txt) for the full list. Core dependencies:

```
django
pymongo
pandas
numpy
matplotlib
```

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## Author

**Mohammed Ishaq**
GitHub: [@ishaq-9e1](https://github.com/ishaq-9e1)
