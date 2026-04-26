╔══════════════════════════════════════════════════════════════╗
║       CYBER FRAUD DETECTION SYSTEM — Project Structure       ║
╚══════════════════════════════════════════════════════════════╝

cyberfraud/
├── module1/               ← Pure Python + MongoDB (no Django)
│   ├── fraud_engine.py    ← TF-IDF scoring, 6 fraud types
│   ├── url_analyzer.py    ← Shannon entropy, homograph detection
│   ├── similarity_engine.py ← Jaccard + cosine matching
│   ├── message_parser.py  ← SMS/WhatsApp OOP parser
│   ├── fraud_models.py    ← OOP hierarchy + MongoDB CRUD
│   ├── fraud_analytics.py ← NumPy + Pandas + Matplotlib
│   └── main.py            ← CLI entry point ← RUN THIS FIRST
│
└── module2/               ← Django web app (imports module1)
    ├── manage.py
    ├── cyberguard/        ← Django project settings
    └── fraud_app/         ← Django app (views, templates, URLs)


══════════════════════════════════════════════
  STEP 1 — Install dependencies (once only)
══════════════════════════════════════════════

pip3 install django pymongo pandas numpy matplotlib


══════════════════════════════════════════════
  STEP 2 — Run Module 1 (terminal demo)
══════════════════════════════════════════════

cd module1
python3 main.py

This will:
✓ Scan 5 test messages (banking, crypto, job, loan, safe)
✓ Show per-signal breakdown for each
✓ Save results to fraud_cases.log
✓ Save to MongoDB (if running)
✓ Print NumPy/Pandas stats
✓ Run all illustrative programs


══════════════════════════════════════════════
  STEP 3 — Run Module 2 (Django web app)
══════════════════════════════════════════════

cd ../module2
python3 manage.py migrate
python3 manage.py runserver

Open: http://127.0.0.1:8000


══════════════════════════════════════════════
  MongoDB (optional — app works without it)
══════════════════════════════════════════════

brew services start mongodb-community
# App falls back to fraud_cases.log if MongoDB is not running


══════════════════════════════════════════════
  Syllabus Coverage Map
══════════════════════════════════════════════

Unit I  — fraud_engine.py (constructs, lambdas, functions, loops)
Unit II — fraud_engine.py + similarity_engine.py + url_analyzer.py
          (lists, tuples, dicts, sets, illustrative programs)
Unit III— url_analyzer.py + message_parser.py + fraud_models.py
          (files, modules, regex, exceptions)
Unit IV — fraud_models.py (OOP: 6 subclasses, MongoDB CRUD)
Unit V  — fraud_analytics.py + module2/views.py
          (NumPy, Pandas, Matplotlib, Django MVT)
