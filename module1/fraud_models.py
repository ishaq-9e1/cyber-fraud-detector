"""
fraud_models.py — OOP Fraud Case Hierarchy + MongoDB Integration
Module 1 | Unit III + IV
Covers: Files, exception handling, OOP (class, constructor, inheritance,
        abstraction, polymorphism, encapsulation), MongoDB CRUD, PyMongo
Illustrative: Bank Management using File concept (Unit III requirement)
"""

import json
import os
from abc import ABC, abstractmethod
from datetime import datetime

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fraud_cases.log")
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME   = "cyberfraud_db"

# ─── ABSTRACT BASE CLASS ──────────────────────────────────────────────────────

class FraudCase(ABC):
    """
    Abstract base. Unit IV: abstraction, encapsulation, constructor.
    """
    _counter = 0

    def __init__(self, parse_result: dict, scan_result: dict,
                 similarity: list = None):
        FraudCase._counter += 1
        self.__parse  = parse_result        # encapsulated
        self.__scan   = scan_result
        self.__sim    = similarity or []
        self.case_id  = f"{self._prefix()}-{datetime.now().strftime('%Y%m%d%H%M%S')}-{FraudCase._counter:04d}"
        self.timestamp= datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.date     = datetime.now().strftime("%Y-%m-%d")

    def _prefix(self) -> str: return "CASE"

    @property
    def scan_result(self):  return self.__scan
    @property
    def parse_result(self): return self.__parse

    @abstractmethod
    def get_warning(self) -> str: pass     # polymorphism

    @abstractmethod
    def get_action_steps(self) -> list: pass

    def confidence_breakdown(self) -> dict:
        signals = self.__scan.get("signals", {})
        total   = sum(signals.values()) or 1
        return {k: round(v/total*100, 1) for k, v in signals.items() if v > 0}

    def to_dict(self) -> dict:
        s = self.__scan
        p = self.__parse
        return {
            "case_id":              self.case_id,
            "timestamp":            self.timestamp,
            "date":                 self.date,
            "fraud_class":          self.__class__.__name__,
            "text":                 s.get("original_text", ""),
            "risk_score":           s.get("risk_score", 0),
            "risk_level":           s.get("risk_level", ""),
            "severity":             s.get("severity", ""),
            "scam_type":            s.get("scam_type", ""),
            "category_scores":      s.get("category_scores", {}),
            "keyword_hits":         s.get("keyword_hits", []),
            "urgency_phrases":      s.get("urgency_phrases", []),
            "authority_entities":   s.get("authority_entities", []),
            "recommendation":       s.get("recommendation", ""),
            "warning":              self.get_warning(),
            "action_steps":         self.get_action_steps(),
            "confidence_breakdown": self.confidence_breakdown(),
            "channel":              p.get("channel", "unknown"),
            "is_forwarded":         p.get("is_forwarded", False),
            "urgency_escalation":   p.get("urgency_escalation", False),
            "phones":               p.get("phones", []),
            "similarity_matches":   self.__sim[:3],
        }

    def __str__(self):
        return (f"[{self.case_id}] {self.__class__.__name__} | "
                f"Score: {self.__scan.get('risk_score')}/100 | "
                f"{self.__scan.get('severity')}")


# ─── 6 FRAUD SUBCLASSES (Unit IV: inheritance, polymorphism) ─────────────────

class BankingFraud(FraudCase):
    def _prefix(self): return "BANK"
    def get_warning(self): return "Your bank NEVER asks for OTP, PIN, or CVV via SMS or WhatsApp."
    def get_action_steps(self): return [
        "Do not click any link or share OTP",
        "Block the sender immediately",
        "Call your bank's official helpline (back of card)",
        "If OTP was shared — call bank to freeze account now",
        "Report at cybercrime.gov.in or call 1930",
    ]

class ShoppingFraud(FraudCase):
    def _prefix(self): return "SHOP"
    def get_warning(self): return "Amazon/Flipkart never collect payments via WhatsApp or external links."
    def get_action_steps(self): return [
        "Check order status on official app only",
        "Do not pay customs fees via SMS links",
        "Report to the brand's official support channel",
        "If paid: raise chargeback with your bank immediately",
        "Report at cybercrime.gov.in",
    ]

class CryptoFraud(FraudCase):
    def _prefix(self): return "CRPT"
    def get_warning(self): return "Never share your seed phrase or private key. No legit platform asks for it."
    def get_action_steps(self): return [
        "Do NOT send any cryptocurrency",
        "Never share wallet seed phrase or private key",
        "Move funds to a new wallet if seed was compromised",
        "Report to your crypto exchange",
        "Report at cybercrime.gov.in",
    ]

class JobFraud(FraudCase):
    def _prefix(self): return "JOBF"
    def get_warning(self): return "Legitimate employers NEVER charge registration fees or security deposits."
    def get_action_steps(self): return [
        "Do not pay any registration or joining fee",
        "Verify company on MCA21 portal",
        "Check job on official LinkedIn/Naukri",
        "Report to the job portal where ad appeared",
        "Report at cybercrime.gov.in",
    ]

class LoanFraud(FraudCase):
    def _prefix(self): return "LOAN"
    def get_warning(self): return "RBI-regulated lenders NEVER ask for upfront payment before disbursement."
    def get_action_steps(self): return [
        "Do not pay any processing fee or GST advance",
        "Verify lender on RBI's NBFC list at rbi.org.in",
        "If paid: dispute transaction with your bank",
        "Report to RBI Banking Ombudsman if bank is impersonated",
        "Report at cybercrime.gov.in",
    ]

class LotteryFraud(FraudCase):
    def _prefix(self): return "LTRY"
    def get_warning(self): return "You cannot win a lottery you never entered. The 'fee to claim' IS the scam."
    def get_action_steps(self): return [
        "Delete the message — there is no prize",
        "Block the sender",
        "Never pay any 'processing' or 'tax' fee",
        "Warn family members — elderly are primary targets",
        "Report at cybercrime.gov.in",
    ]


# ─── FACTORY FUNCTION ─────────────────────────────────────────────────────────

def create_fraud_case(parse_result: dict, scan_result: dict,
                      similarity: list = None) -> FraudCase:
    """Returns correct subclass based on scan result. Unit IV: OOP pattern."""
    t    = scan_result.get("scam_type", "").lower()
    args = (parse_result, scan_result, similarity)
    if "banking" in t:  return BankingFraud(*args)
    if "shopping" in t: return ShoppingFraud(*args)
    if "crypto" in t:   return CryptoFraud(*args)
    if "job" in t:      return JobFraud(*args)
    if "loan" in t:     return LoanFraud(*args)
    if "lottery" in t:  return LotteryFraud(*args)
    return BankingFraud(*args)


# ─── FILE I/O (Unit III: Bank Management file concept adapted) ────────────────

def log_to_file(case_dict: dict):
    """Appends case as JSON line. Unit III: file writing, format operator."""
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(case_dict, ensure_ascii=False) + "\n")
    except IOError as e:
        raise IOError(f"[FileLog] Cannot write: {e}")


def read_all_logs() -> list:
    """Reads all cases from log. Unit III: file reading, exception handling."""
    if not os.path.exists(LOG_FILE):
        return []
    cases = []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        cases.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except IOError as e:
        print(f"[FileLog] Read error: {e}")
    return cases


def get_log_summary() -> dict:
    """Builds summary stats from log. Unit II: dict operations."""
    cases = read_all_logs()
    if not cases:
        return {"total": 0, "by_severity": {}, "by_type": {}, "avg_score": 0,
                "high_risk": 0, "suspicious": 0}
    scores = [c.get("risk_score", 0) for c in cases]
    by_sev, by_type = {}, {}
    for c in cases:
        s = c.get("severity", "UNKNOWN")
        t = c.get("scam_type", "Unknown")
        by_sev[s]  = by_sev.get(s, 0) + 1
        by_type[t] = by_type.get(t, 0) + 1
    return {
        "total":      len(cases),
        "by_severity":by_sev,
        "by_type":    by_type,
        "avg_score":  round(sum(scores)/len(scores), 1),
        "high_risk":  sum(1 for c in cases if c.get("severity") in ("HIGH","CRITICAL")),
        "suspicious": sum(1 for c in cases if c.get("severity") == "MEDIUM"),
    }


# ─── MONGODB CRUD (Unit IV: Python DB connectivity) ───────────────────────────

def _get_db():
    """Returns MongoDB database. Unit IV: MongoDB environmental setup."""
    try:
        from pymongo import MongoClient
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
        client.server_info()
        return client[DB_NAME]
    except Exception:
        return None


def mongo_insert(case_dict: dict) -> bool:
    """Create — inserts one fraud case."""
    db = _get_db()
    if db is None:
        return False
    try:
        db.fraud_cases.insert_one({k: v for k, v in case_dict.items() if k != "_id"})
        return True
    except Exception as e:
        print(f"[MongoDB] Insert failed: {e}")
        return False


def mongo_read_all(filters: dict = None) -> list:
    """Read — fetches cases with optional filter."""
    db = _get_db()
    if db is None:
        return []
    try:
        return list(db.fraud_cases.find(filters or {}, {"_id": 0}).sort("timestamp", -1).limit(200))
    except Exception:
        return []


def mongo_update_notes(case_id: str, notes: str) -> bool:
    """Update — adds analyst notes to a case."""
    db = _get_db()
    if db is None:
        return False
    try:
        r = db.fraud_cases.update_one({"case_id": case_id}, {"$set": {"notes": notes}})
        return r.modified_count > 0
    except Exception:
        return False


def mongo_delete(case_id: str) -> bool:
    """Delete — removes a case by ID."""
    db = _get_db()
    if db is None:
        return False
    try:
        return db.fraud_cases.delete_one({"case_id": case_id}).deleted_count > 0
    except Exception:
        return False


def mongo_aggregate_stats() -> dict:
    """Aggregation pipeline — scam stats by type."""
    db = _get_db()
    if db is None:
        return {}
    try:
        pipeline = [{"$group": {
            "_id": "$scam_type",
            "count": {"$sum": 1},
            "avg_score": {"$avg": "$risk_score"},
            "critical": {"$sum": {"$cond": [{"$eq": ["$severity","CRITICAL"]}, 1, 0]}}
        }}]
        return {r["_id"]: r for r in db.fraud_cases.aggregate(pipeline)}
    except Exception:
        return {}


# ─── MASTER SAVE ──────────────────────────────────────────────────────────────

def save_case(parse_result: dict, scan_result: dict,
              similarity: list = None) -> FraudCase:
    """Creates case → saves to file + MongoDB → returns case object."""
    case      = create_fraud_case(parse_result, scan_result, similarity)
    case_dict = case.to_dict()
    log_to_file(case_dict)
    mongo_insert(case_dict)
    return case
