"""
message_parser.py — SMS / WhatsApp Message Parser
Module 1 | Unit I + III + IV
Covers: Regex, modules, OOP class + constructor, exception handling
"""

import re

WA_FORWARDED = [
    r'forwarded\s+(?:many\s+times|message|as\s+received)',
    r'please\s+forward\s+this', r'share\s+this\s+with\s+everyone',
    r'send\s+this\s+to\s+\d+\s+(?:people|contacts)',
    r'copy\s+and\s+share', r'must\s+forward',
]

URGENCY_SEQUENCE = [
    ("alert",       r'blocked|suspended|failed|expired|warning|alert'),
    ("ask",         r'verify|confirm|validate|update|provide|share'),
    ("action",      r'click|tap|visit|call|whatsapp|send|download'),
    ("consequence", r'immediately|24\s*hours|legal\s*action|permanent|cancel'),
]

HINDI_WORDS = {
    "aapka","account","band","ho","jayega","jaldi","karo","abhi",
    "turant","karen","kijiye","nahi","toh","aap","ka","ko","hai",
}


class MessageParser:
    """
    Parses and pre-classifies a raw message before fraud engine processes it.
    Unit IV: OOP — class, constructor, encapsulation, methods
    """

    def __init__(self, raw_text: str, sender_id: str = ""):
        self.__raw      = raw_text          # private — encapsulation
        self.__sender   = sender_id
        self._cleaned   = self._clean(raw_text)
        self._flags     = []
        self._pre_score = 0
        self._meta      = {}

    def _clean(self, text: str) -> str:
        text = re.sub(r'\s+', ' ', text.strip())
        return re.sub(r'[*_~`]{2,}', '', text)

    def parse(self) -> dict:
        """Runs all parsers. Returns metadata dict."""
        self._detect_channel()
        self._classify_sender()
        self._detect_forwarded()
        self._detect_urgency_sequence()
        self._detect_language_mix()
        self._extract_contacts()
        self._check_formatting()
        return {
            "channel":           self._meta.get("channel", "unknown"),
            "sender_type":       self._meta.get("sender_type", "unknown"),
            "is_forwarded":      self._meta.get("is_forwarded", False),
            "urgency_sequence":  self._meta.get("urgency_sequence", []),
            "urgency_escalation":self._meta.get("urgency_escalation", False),
            "language_mixing":   self._meta.get("language_mixing", False),
            "phones":            self._meta.get("phones", []),
            "upi_ids":           self._meta.get("upi_ids", []),
            "urls":              self._meta.get("urls", []),
            "word_count":        len(self._cleaned.split()),
            "pre_flags":         self._flags,
            "pre_score":         self._pre_score,
            "cleaned_text":      self._cleaned,
        }

    def _detect_channel(self):
        t = self.__raw.lower()
        if any(x in t for x in ["forwarded","whatsapp","wa.me"]):
            self._meta["channel"] = "whatsapp"
        elif re.match(r'[A-Z]{2}-[A-Z]{4,6}', self.__sender):
            self._meta["channel"] = "sms_dlt"
        else:
            self._meta["channel"] = "mobile"

    def _classify_sender(self):
        s = self.__sender.upper()
        if not s:
            self._meta["sender_type"] = "unknown"; return
        if re.match(r'^[A-Z]{2}-[A-Z]{4,6}$', s):
            self._meta["sender_type"] = "dlt_registered"
        elif re.match(r'^\+?\d{10,13}$', s):
            self._meta["sender_type"] = "mobile_number"
            self._flags.append("Sender is a mobile number, not a registered service")
            self._pre_score += 15
        else:
            self._meta["sender_type"] = "suspicious"
            self._flags.append(f"Unusual sender format: {self.__sender}")
            self._pre_score += 20

    def _detect_forwarded(self):
        t = self.__raw.lower()
        for p in WA_FORWARDED:
            if re.search(p, t):
                self._meta["is_forwarded"] = True
                self._flags.append("WhatsApp forwarded message detected")
                self._pre_score += 15
                break

    def _detect_urgency_sequence(self):
        t = self.__raw.lower()
        found = [name for name, pat in URGENCY_SEQUENCE if re.search(pat, t)]
        self._meta["urgency_sequence"] = found
        if len(found) >= 3:
            self._meta["urgency_escalation"] = True
            self._flags.append(f"Urgency escalation: {' → '.join(found)}")
            self._pre_score += 20 if len(found) == 4 else 12

    def _detect_language_mix(self):
        tokens = set(self.__raw.lower().split())
        hits = tokens & HINDI_WORDS
        if len(hits) >= 2:
            self._meta["language_mixing"] = True
            self._flags.append(f"Hinglish mixing: {list(hits)[:3]}")
            self._pre_score += 5

    def _extract_contacts(self):
        phones  = re.findall(r'(?<!\d)[6-9]\d{9}(?!\d)', self.__raw)
        upi_ids = re.findall(r'[a-zA-Z0-9.\-_]{2,30}@[a-zA-Z]{2,10}', self.__raw)
        urls    = re.findall(r'https?://[^\s<>"]+|www\.[^\s]+', self.__raw)
        self._meta["phones"]  = phones
        self._meta["upi_ids"] = upi_ids
        self._meta["urls"]    = urls
        if phones: self._pre_score += 5 * min(len(phones), 2)

    def _check_formatting(self):
        t = self.__raw
        if sum(1 for c in t if c.isupper()) / max(len(t), 1) > 0.3:
            self._flags.append("Excessive CAPS — pressure tactic")
            self._pre_score += 8
        if t.count("!") >= 3:
            self._flags.append(f"{t.count('!')} exclamation marks")
            self._pre_score += 5


def parse_message(text: str, sender_id: str = "") -> dict:
    """Convenience wrapper. Unit IV: OOP usage."""
    return MessageParser(text, sender_id).parse()
