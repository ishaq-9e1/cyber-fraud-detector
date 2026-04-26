"""
fraud_engine.py — ULTRA PRO MAX (BALANCED + SMART)
High Detection + Low False Positives
"""

import re
from datetime import datetime
from url_analyzer import analyze_all_urls

VERSION = "5.2-BALANCED"

# ─────────────────────────────────────────────────────────────
# RISK LEVELS
# ─────────────────────────────────────────────────────────────

RISK_BANDS = (
    (0,  15,  "Safe",          "#2ecc71", "LOW"),
    (16, 35,  "Low Suspicion", "#27ae60", "LOW"),
    (36, 60,  "Suspicious",    "#e67e22", "MEDIUM"),
    (61, 80,  "High Risk",     "#e74c3c", "HIGH"),
    (81, 100, "Critical Scam", "#c0392b", "CRITICAL"),
)

# ─────────────────────────────────────────────────────────────
# FRAUD KEYWORDS (FULL POWER)
# ─────────────────────────────────────────────────────────────

FRAUD_PATTERNS = {
    "banking": {
        "weight": 1.6,
        "keywords": {
            "otp": 12, "pin": 12, "cvv": 12, "password": 10,
            "account blocked": 10, "account suspended": 10,
            "kyc expired": 10, "verify kyc": 10, "update kyc": 10,
            "bank alert": 8, "unusual activity": 9,
            "debit card blocked": 10, "credit card blocked": 10,
            "upi pin": 10, "transaction failed": 8,
            "refund initiated": 8, "amount debited": 8,
            "link aadhaar": 9, "pan verification": 9,
            "net banking suspended": 10,
            "secure your account": 9,
            "login immediately": 9,
        }
    },

    "crypto": {
        "weight": 1.5,
        "keywords": {
            "bitcoin": 10, "ethereum": 10, "crypto": 10,
            "send eth": 12, "double your crypto": 12,
            "guaranteed profit": 11, "investment guaranteed": 11,
            "wallet": 10, "seed phrase": 12, "private key": 12,
            "metamask": 10, "binance": 9, "coinbase": 9,
            "airdrop": 10, "giveaway": 10,
            "instant return": 11,
        }
    },

    "job": {
        "weight": 1.4,
        "keywords": {
            "work from home": 10, "earn money": 9,
            "no experience": 9, "daily payment": 10,
            "registration fee": 11, "joining fee": 11,
            "earn 50000": 11, "data entry job": 10,
            "part time job": 9, "google hiring": 8,
            "amazon job": 8, "urgent hiring": 9,
            "salary advance": 10,
        }
    },

    "loan": {
        "weight": 1.5,
        "keywords": {
            "instant loan": 11, "loan approved": 11,
            "no cibil": 12, "low interest loan": 10,
            "processing fee": 11, "gst fee": 11,
            "loan without documents": 12,
            "quick loan": 10, "urgent loan": 10,
            "loan disbursed": 10,
        }
    },

    "lottery": {
        "weight": 1.4,
        "keywords": {
            "you won": 11, "winner": 10, "jackpot": 11,
            "lottery": 12, "prize money": 11,
            "claim reward": 11, "lucky draw": 10,
            "free gift": 9, "selected randomly": 10,
        }
    },

    "shopping": {
        "weight": 1.3,
        "keywords": {
            "free voucher": 10, "gift card": 10,
            "delivery failed": 9, "parcel held": 10,
            "customs fee": 11, "undelivered package": 9,
            "click to track": 9, "order cancelled": 9,
        }
    }
}

# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def normalize(text):
    return text.lower()

def extract_urls(text):
    return re.findall(r'https?://[^\s]+|www\.[^\s]+', text)

def extract_phones(text):
    return re.findall(r'(?<!\d)[6-9]\d{9}(?!\d)', text)

def extract_amounts(text):
    return re.findall(r'(₹|rs\.?|inr)\s*\d+', text.lower())

# ─────────────────────────────────────────────────────────────
# KEYWORD ENGINE (FIXED)
# ─────────────────────────────────────────────────────────────

def compute_keyword_score(text):
    text_l = normalize(text)
    scores = {}
    hits = []

    for cat, data in FRAUD_PATTERNS.items():
        s = 0
        for phrase, w in data["keywords"].items():
            if phrase in text_l:
                val = w * data["weight"]
                s += val
                hits.append(phrase)
        scores[cat] = s

    total = min(sum(scores.values()), 95)
    return total, scores, hits[:20]

# ─────────────────────────────────────────────────────────────
# CONTEXT ENGINE
# ─────────────────────────────────────────────────────────────

SCAM_CONTEXT = [
    (r"(share|send|provide).*(otp|pin|password|cvv)", 35),
    (r"(click|open).*(link|url)", 20),
    (r"(pay|transfer).*(fee|amount)", 25),
    (r"(urgent|immediately|now|within 24 hours)", 20),
    (r"(account).*(blocked|suspended)", 25),
]

def context_score(text):
    score = 0
    for pattern, weight in SCAM_CONTEXT:
        if re.search(pattern, text.lower()):
            score += weight
    return min(score, 50)

# ─────────────────────────────────────────────────────────────
# FEATURES
# ─────────────────────────────────────────────────────────────

def extract_features(text):
    return {
        "caps": sum(1 for c in text if c.isupper()),
        "exclam": text.count("!"),
        "has_url": bool(extract_urls(text)),
        "has_phone": bool(extract_phones(text)),
        "has_amount": bool(extract_amounts(text)),
    }

# ─────────────────────────────────────────────────────────────
# 🧠 FALSE POSITIVE CONTROL (KEY ADDITION)
# ─────────────────────────────────────────────────────────────

def reduce_false_positives(text, score):
    t = text.lower()

    casual = ["bro", "hey", "lol", "ok", "thanks", "tomorrow", "later"]
    strong_signals = ["otp", "link", "http", "verify", "click"]

    if not any(s in t for s in strong_signals):
        score -= 15

    if any(c in t for c in casual):
        score -= 10

    if not extract_urls(text) and not extract_amounts(text):
        score -= 10

    return max(score, 0)

# ─────────────────────────────────────────────────────────────
# EXTRA INTELLIGENCE
# ─────────────────────────────────────────────────────────────

def detect_urgency(text):
    return [w for w in ["urgent", "immediately", "now"] if w in text.lower()]

def detect_authority(text):
    return [e for e in ["sbi", "rbi", "hdfc", "icici", "amazon", "google"] if e in text.lower()]

# ─────────────────────────────────────────────────────────────

def _generate_recommendation(severity: str) -> str:
    """Returns specific, actionable advice based on severity level."""
    return {
        "CRITICAL": "STOP — Do NOT click any link, share OTP, or call back. Block the sender immediately and report at cybercrime.gov.in or call 1930.",
        "HIGH":     "Do NOT click any link or share any personal/financial details. Verify directly via your bank's official app or helpline.",
        "MEDIUM":   "Proceed with caution. Do not act on this message before verifying through official channels.",
        "LOW":      "This message appears mostly safe. Stay alert — never share OTP or passwords with anyone.",
    }.get(severity, "Stay cautious about unsolicited messages asking for personal information.")


def classify_fraud_type(scores):
    if not any(scores.values()):
        return "General Phishing"
    return max(scores, key=scores.get).title() + " Fraud"

def get_risk_band(score):
    for lo, hi, label, color, sev in RISK_BANDS:
        if lo <= score <= hi:
            return label, color, sev
    return "Unknown", "#888", "LOW"

# ─────────────────────────────────────────────────────────────
# MAIN ENGINE
# ─────────────────────────────────────────────────────────────

def scan_message(text: str, url_score: int = None):

    if url_score is None:
        url_data = analyze_all_urls(text)
        url_score = url_data["max_score"]

    kw_score, cat_scores, hits = compute_keyword_score(text)
    ctx_score = context_score(text)
    features = extract_features(text)

    feat_score = 0
    if features["caps"] > 5: feat_score += 12
    if features["exclam"] >= 2: feat_score += 10
    if features["has_url"]: feat_score += 20
    if features["has_phone"]: feat_score += 12
    if features["has_amount"]: feat_score += 12

    raw = (
        kw_score * 0.30 +
        ctx_score * 0.25 +
        url_score * 0.20 +
        feat_score * 0.15 +
        15
    )

    score = min(int(raw), 100)

    t = text.lower()

    # BOOSTS
    if "otp" in t and ("link" in t or "http" in t):
        score += 25
    if "send" in t and "receive" in t:
        score += 20
    if kw_score > 30 and url_score > 20:
        score += 20

    # 🔥 APPLY FALSE POSITIVE CONTROL
    score = reduce_false_positives(text, score)

    score = min(score, 100)

    risk_label, color, severity = get_risk_band(score)

    return {
        "version": VERSION,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "original_text": text,
        "risk_score": score,
        "risk_level": risk_label,
        "risk_color": color,
        "severity": severity,
        "scam_type": classify_fraud_type(cat_scores),
        "keyword_hits": hits,
        "category_scores": cat_scores,
        "features": features,
        "urgency_phrases": detect_urgency(text),
        "authority_entities": detect_authority(text),
        "recommendation": _generate_recommendation(severity),
        "signals": {
            "keyword_score": round(kw_score, 1),
            "context_score": round(ctx_score, 1),
            "url_score":     round(url_score, 1),
            "feature_score": round(feat_score, 1),
        },
    }
def financial_loss_estimator(score):
    """
    Estimate potential financial loss based on fraud score
    (simple heuristic for demo purposes)
    """
    if score >= 80:
        return "₹50,000+ (High Risk)"
    elif score >= 60:
        return "₹10,000 - ₹50,000"
    elif score >= 40:
        return "₹1,000 - ₹10,000"
    else:
        return "Minimal / Safe"


def sandwich_vowel(word):
    """
    Illustrative program: returns vowels surrounded by consonants
    (kept for syllabus / demo compatibility)
    """
    vowels = "aeiou"
    result = []

    word = word.lower()

    for i in range(1, len(word) - 1):
        if (word[i] in vowels and
            word[i - 1] not in vowels and
            word[i + 1] not in vowels):
            result.append(word[i])

    return result