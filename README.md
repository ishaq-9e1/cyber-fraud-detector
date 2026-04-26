# 🛡️ CyberGuard — Cyber Fraud Detection System

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Django](https://img.shields.io/badge/Django-4.x-green?logo=django&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-Optional-brightgreen?logo=mongodb&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Status](https://img.shields.io/badge/Status-Active-success)

> A full-stack intelligent fraud detection system that analyzes SMS and WhatsApp messages in real-time using TF-IDF scoring, Shannon entropy URL analysis, cosine/Jaccard similarity matching, and a Django-powered analytics dashboard.

---

## 📸 Screenshots

| Home Page | Detection Result | Analytics Dashboard |
|-----------|-----------------|---------------------|
| Enter any suspicious message for analysis | Risk score with signal breakdown | Charts: bar, pie, line, scatter |

---

## 🚀 Features

- 🔍 **6 Fraud Categories** — Banking, Crypto, Job, Loan, OTP, and Safe message classification
- 📊 **TF-IDF Scoring Engine** — Weighted keyword matching with per-category risk bands
- 🔗 **URL Analyzer** — Shannon entropy detection, homograph/lookalike domain alerts, and Kadane's algorithm for suspicious windows
- 🧠 **Similarity Engine** — Jaccard + cosine similarity against a known scam corpus
- 📱 **SMS/WhatsApp Parser** — OOP-based message parser for real-world message formats
- 📈 **Data Analytics** — NumPy statistics, Pandas DataFrames, and Matplotlib chart generation
- 🌐 **Django Web App** — Full MVT architecture with live detection, history, and dashboard
- 🗄️ **MongoDB Support** — Optional persistent storage; falls back to `.log` file gracefully
- 📋 **Case History** — View and filter all previously analyzed messages

---

## 🗂️ Project Structure

```
cyberfraud_detection/
│
├── module1/                    ← Pure Python detection engine (no Django)
│   ├── main.py                 ← CLI entry point — run this first
│   ├── fraud_engine.py         ← TF-IDF scoring, 6 fraud types, risk bands
│   ├── url_analyzer.py         ← Shannon entropy, homograph detection
│   ├── similarity_engine.py    ← Jaccard + cosine similarity matching
│   ├── message_parser.py       ← SMS/WhatsApp OOP message parser
│   ├── fraud_models.py         ← OOP class hierarchy + MongoDB CRUD
│   ├── fraud_analytics.py      ← NumPy + Pandas + Matplotlib charts
│   └── fraud_cases.log         ← Auto-generated case log (no MongoDB needed)
│
└── module2/                    ← Django web application
    ├── manage.py
    ├── db.sqlite3
    ├── cyberguard/             ← Django project settings & URLs
    │   ├── settings.py
    │   └── urls.py
    └── fraud_app/              ← Main Django app
        ├── views.py            ← All view logic, imports Module 1 engine
        ├── urls.py
        ├── templates/
        │   └── fraud_app/
        │       ├── base.html
        │       ├── home.html
        │       ├── result.html
        │       ├── dashboard.html
        │       ├── history.html
        │       └── case_detail.html
        └── static/
            └── fraud_app/      ← Pre-generated chart images
```

---

## ⚙️ Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip
- MongoDB (optional — app works without it)

### 1. Clone the Repository

```bash
git clone https://github.com/ishaq-9e1/cyber-fraud-detector.git
cd cyberfraud-detection
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run Module 1 — CLI Demo (Terminal)

```bash
cd module1
python3 main.py
```

This will:
- ✅ Scan 5 test messages (banking, crypto, job, loan, safe)
- ✅ Show per-signal risk breakdown for each message
- ✅ Save results to `fraud_cases.log`
- ✅ Save to MongoDB (if running)
- ✅ Print NumPy/Pandas statistics
- ✅ Generate Matplotlib charts

### 4. Run Module 2 — Django Web App

```bash
cd ../module2
python3 manage.py migrate
python3 manage.py runserver
```

Open your browser at: **http://127.0.0.1:8000**

---

## 🔌 MongoDB Setup (Optional)

The app works fully **without MongoDB** — it falls back to `fraud_cases.log`. To enable MongoDB:

```bash
# macOS
brew services start mongodb-community

# Ubuntu/Debian
sudo systemctl start mongod

# Windows
net start MongoDB
```

MongoDB URI used: `mongodb://localhost:27017/` — Database: `cyberfraud`

---

## 🧪 How It Works

### Detection Pipeline

```
Input Message
     │
     ▼
┌─────────────────┐
│  Message Parser │  ← OOP-based SMS/WhatsApp parser
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Fraud Engine   │  ← TF-IDF keyword scoring × category weight
│  (6 categories) │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  URL Analyzer   │  ← Shannon entropy + homograph detection
└────────┬────────┘
         │
         ▼
┌──────────────────┐
│ Similarity Engine│  ← Jaccard + cosine vs known scam database
└────────┬─────────┘
         │
         ▼
   Risk Score (0–100)
   Safe / Suspicious / Critical
```

### Risk Bands

| Score | Label | Severity |
|-------|-------|----------|
| 0–15 | ✅ Safe | LOW |
| 16–35 | 🟡 Low Suspicion | LOW |
| 36–60 | 🟠 Suspicious | MEDIUM |
| 61–80 | 🔴 High Risk | HIGH |
| 81–100 | 🚨 Critical Scam | CRITICAL |

---

## 📚 Syllabus / Curriculum Coverage

This project was built as a comprehensive Python & Django academic project, covering:

| Unit | Topics Covered | Files |
|------|---------------|-------|
| Unit I | Constructs, lambdas, functions, loops | `fraud_engine.py` |
| Unit II | Lists, tuples, dicts, sets, illustrative programs | `fraud_engine.py`, `similarity_engine.py`, `url_analyzer.py` |
| Unit III | File I/O, modules, regex, exception handling | `url_analyzer.py`, `message_parser.py`, `fraud_models.py` |
| Unit IV | OOP — 6 subclasses, inheritance, MongoDB CRUD | `fraud_models.py` |
| Unit V | NumPy, Pandas, Matplotlib, Django MVT | `fraud_analytics.py`, `module2/views.py` |

---

## 🛠️ Tech Stack

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

## 📦 Requirements

See [`requirements.txt`](requirements.txt) for the full list.

Core dependencies:
```
django
pymongo
pandas
numpy
matplotlib
```

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add some feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**ishaq-9e1**
- GitHub: [@ishaq-9e1](https://github.com/ishaq-9e1)

---

> ⭐ If this project helped you, please consider giving it a star!
