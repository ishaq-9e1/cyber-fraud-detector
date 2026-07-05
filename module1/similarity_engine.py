"""
similarity_engine.py — Scam Similarity Matching Engine
Module 1 | Unit II + III
Covers: Sets (Jaccard), lists as vectors (cosine), file reading, regex
Illustrative: Count and Say Problem (Unit II)
"""

import re
import math
from collections import Counter

SCAM_TEMPLATES = [
    {"id":"T01","category":"Banking Fraud","severity":"CRITICAL",
     "template":"sbi account blocked verify kyc otp immediately link",
     "description":"SBI KYC/account block phishing",
     "keywords":{"sbi","account","blocked","kyc","otp","verify","immediately"}},
    {"id":"T02","category":"Banking Fraud","severity":"CRITICAL",
     "template":"hdfc unusual login detected verify credentials otp suspend",
     "description":"HDFC login alert phishing",
     "keywords":{"hdfc","login","detected","credentials","otp","suspend"}},
    {"id":"T03","category":"Lottery Fraud","severity":"HIGH",
     "template":"congratulations lucky draw prize claim 24 hours processing fee",
     "description":"Lucky draw prize with upfront fee",
     "keywords":{"congratulations","won","lucky","prize","claim","fee","hours"}},
    {"id":"T04","category":"Shopping Fraud","severity":"HIGH",
     "template":"amazon order cancelled refund verify account payment pending",
     "description":"Fake Amazon order/refund phish",
     "keywords":{"amazon","order","cancelled","refund","verify","payment"}},
    {"id":"T05","category":"Shopping Fraud","severity":"HIGH",
     "template":"flipkart delivery failed parcel customs pay fee release",
     "description":"Fake delivery/customs fee scam",
     "keywords":{"delivery","failed","parcel","customs","pay","fee"}},
    {"id":"T06","category":"Crypto Fraud","severity":"CRITICAL",
     "template":"bitcoin giveaway send eth receive double binance wallet seed",
     "description":"Crypto doubling / seed phrase scam",
     "keywords":{"bitcoin","send","receive","double","binance","wallet","seed"}},
    {"id":"T07","category":"Job Fraud","severity":"HIGH",
     "template":"work home earn daily no experience registration fee advance",
     "description":"Fake WFH job with upfront fee",
     "keywords":{"work","home","earn","experience","registration","fee","advance"}},
    {"id":"T08","category":"Loan Fraud","severity":"CRITICAL",
     "template":"instant loan approved no cibil processing fee gst rbi disburse",
     "description":"Fake instant loan with processing fee",
     "keywords":{"loan","approved","cibil","processing","fee","gst","rbi"}},
    {"id":"T09","category":"Banking Fraud","severity":"CRITICAL",
     "template":"upi payment pending pin approve transaction urgent",
     "description":"Fake UPI approval request",
     "keywords":{"upi","payment","pending","pin","approve","transaction"}},
    {"id":"T10","category":"Lottery Fraud","severity":"HIGH",
     "template":"income tax refund bank account update aadhar pan link",
     "description":"Fake IT refund / bank update scam",
     "keywords":{"income","tax","refund","bank","account","aadhar","pan"}},
]

STOPWORDS = {
    "the","and","for","are","but","not","you","all","can","was",
    "one","has","its","new","how","may","say","she","they","this",
    "that","will","with","from","have","been","your","more","than",
    "also","into","then","over","any","get","let","now","use","way",
    "per","via","our","him","her","his",
}


def _tokenize(text: str) -> list:
    text = re.sub(r'[^\w\s]', ' ', text.lower())
    text = re.sub(r'\d+', 'NUM', text)
    return [w for w in text.split() if len(w) > 2 and w not in STOPWORDS]


def jaccard_similarity(a: set, b: set) -> float:
    """
    |A∩B| / |A∪B|  — Unit II: set operations
    """
    if not a or not b:
        return 0.0
    return round(len(a & b) / len(a | b), 4)


def cosine_similarity(va: list, vb: list) -> float:
    """
    Manual cosine similarity — no external libraries.
    Unit I: math, loops
    """
    dot  = sum(x*y for x, y in zip(va, vb))
    magA = math.sqrt(sum(x**2 for x in va))
    magB = math.sqrt(sum(x**2 for x in vb))
    return round(dot / (magA * magB), 4) if magA and magB else 0.0


def _build_idf(templates: list) -> dict:
    N  = len(templates)
    df = Counter()
    for t in templates:
        for tok in set(_tokenize(t["template"])):
            df[tok] += 1
    return {w: math.log(N / c) for w, c in df.items()}


_IDF  = _build_idf(SCAM_TEMPLATES)
_VOCAB = sorted(_IDF)


def _tfidf_vector(tokens: list) -> list:
    tf = Counter(tokens)
    n  = max(len(tokens), 1)
    return [(tf.get(w, 0) / n) * _IDF.get(w, 1.0) for w in _VOCAB]


def find_similar_scams(message: str, top_n: int = 3) -> list:
    """
    Compare message against all templates using Jaccard + cosine.
    Combined = 0.4 × jaccard_keywords + 0.25 × jaccard_tokens + 0.35 × cosine
    Unit II: sets, lists | Unit I: functions
    """
    msg_tokens = _tokenize(message)
    msg_set    = set(msg_tokens)
    msg_vec    = _tfidf_vector(msg_tokens)
    results    = []

    for tmpl in SCAM_TEMPLATES:
        t_tokens  = _tokenize(tmpl["template"])
        t_set     = set(t_tokens)
        t_vec     = _tfidf_vector(t_tokens)

        jac_kw    = jaccard_similarity(msg_set, tmpl["keywords"])
        jac_tok   = jaccard_similarity(msg_set, t_set)
        cos       = cosine_similarity(msg_vec, t_vec)
        combined  = 0.40*jac_kw + 0.25*jac_tok + 0.35*cos

        if combined > 0.05:
            results.append({
                "template_id":    tmpl["id"],
                "category":       tmpl["category"],
                "severity":       tmpl["severity"],
                "description":    tmpl["description"],
                "match_percent":  round(combined * 100, 1),
                "matched_keywords": list(msg_set & tmpl["keywords"]),
            })

    results.sort(key=lambda x: x["match_percent"], reverse=True)
    return results[:top_n]


def get_similarity_verdict(matches: list) -> str:
    if not matches:
        return "No known scam pattern matched."
    top = matches[0]
    pct = top["match_percent"]
    if pct >= 60:
        return f"Strongly resembles '{top['description']}' ({pct}% match)"
    elif pct >= 35:
        return f"Partially matches '{top['description']}' ({pct}% match)"
    return f"Weak similarity to '{top['description']}' ({pct}% match)"


# ─── ILLUSTRATIVE: Count and Say Problem (Unit II requirement) ────────────────

def count_and_say(n: int) -> str:
    """
    Count and Say sequence — Unit II illustrative program.
    Applied as message fingerprinting for deduplication.
    """
    result = "1"
    for _ in range(n - 1):
        new, i = "", 0
        while i < len(result):
            d, c = result[i], 1
            while i + c < len(result) and result[i+c] == d:
                c += 1
            new += str(c) + d
            i   += c
        result = new
    return result


def message_fingerprint(message: str) -> str:
    """Creates a compact fingerprint of a message using token frequency."""
    freq = Counter(_tokenize(message)).most_common(6)
    return "-".join(f"{c}{w[0]}" for w, c in freq)
