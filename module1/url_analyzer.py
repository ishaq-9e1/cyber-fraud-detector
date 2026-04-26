"""
url_analyzer.py — Deep URL Analysis Engine
Module 1 | Unit I + III
Covers: Regex, urllib module, math (Shannon entropy), exception handling
"""

import re
import math
import urllib.parse
from collections import Counter

LEGITIMATE_DOMAINS = {
    "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com",
    "axisbank.com", "paytm.com", "phonepe.com", "amazon.in",
    "amazon.com", "flipkart.com", "npci.org.in", "uidai.gov.in",
    "incometax.gov.in", "binance.com", "coinbase.com",
}

BRAND_KEYWORDS = {
    "sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "amazon",
    "flipkart", "npci", "uidai", "rbi", "binance", "metamask",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".icu", ".tk", ".ml", ".ga", ".cf",
    ".pw", ".work", ".click", ".link", ".win", ".loan", ".download",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "rb.gy", "cutt.ly", "shorturl.at",
}


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text.lower())
    length = len(text)
    return round(-sum((c/length) * math.log2(c/length)
                      for c in freq.values()), 3)


def detect_homograph(url: str) -> tuple:
    try:
        domain = urllib.parse.urlparse(url).netloc.lower()
        if "xn--" in domain:
            return True, f"Punycode IDN detected: {domain}"

        cyrillic = {'а':'a','е':'e','о':'o','р':'p','с':'c','х':'x','у':'y'}
        for ch in domain:
            if ch in cyrillic:
                return True, f"Homograph char '{ch}' in domain"

        if re.search(r'[\u200b\u200c\u200d]', url):
            return True, "Zero-width character injection"

        return False, ""
    except Exception:
        return False, ""


def analyze_url(url: str) -> dict:
    flags, score = [], 0
    try:
        if url.startswith("www."):
            url = "https://" + url

        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")
        path   = parsed.path.lower()
        scheme = parsed.scheme.lower()
        base   = domain.split(":")[0]

        if base in LEGITIMATE_DOMAINS:
            return {"flags": [], "score": 0, "domain": base, "entropy": 0}

        if re.match(r'^\d{1,3}(\.\d{1,3}){3}(:\d+)?$', base):
            flags.append("IP-based URL — banks never use raw IPs")
            score += 35

        if base in URL_SHORTENERS:
            flags.append(f"Shortened URL ({base}) hides real destination")
            score += 25

        for tld in SUSPICIOUS_TLDS:
            if base.endswith(tld) or f"{tld}/" in domain:
                flags.append(f"High-risk TLD: {tld}")
                score += 20
                break

        for brand in BRAND_KEYWORDS:
            if brand in domain and not (
                domain.startswith(f"{brand}.") or
                domain.endswith(f".{brand}.com")
            ):
                flags.append(f"Brand '{brand}' in suspicious domain position")
                score += 25
                break

        sld = base.split(".")[0]
        entropy = shannon_entropy(sld)

        if entropy > 3.8:
            flags.append(f"High entropy domain ({entropy}) — likely auto-generated")
            score += 20
        elif entropy > 3.2:
            flags.append(f"Moderate entropy domain ({entropy})")
            score += 10

        is_homo, reason = detect_homograph(url)
        if is_homo:
            flags.append(reason)
            score += 30

        phish_words = ["login","signin","verify","secure","kyc","validate","account"]
        hits = [w for w in phish_words if w in path]
        if len(hits) >= 2:
            flags.append(f"Phishing path keywords: {hits}")
            score += 15

        if base.count("-") >= 2:
            flags.append(f"Excessive hyphens ({base.count('-')}) in domain")
            score += 10

        if re.search(r'[a-z]\d[a-z]', sld):
            flags.append("Numeric substitution in domain (e.g. 'g00gle')")
            score += 15

        port_m = re.search(r':(\d{2,5})$', domain)
        if port_m and int(port_m.group(1)) not in (80, 443, 8080):
            flags.append(f"Non-standard port {port_m.group(1)}")
            score += 20

        if scheme != "https":
            flags.append(f"Non-HTTPS scheme: {scheme}")
            score += 15

        return {
            "flags": flags,
            "score": min(score, 100),
            "domain": base,
            "entropy": entropy
        }

    except Exception as e:
        return {
            "flags": [f"Parse error: {str(e)[:40]}"],
            "score": 5,
            "domain": "",
            "entropy": 0
        }


def analyze_all_urls(text: str) -> dict:
    """
    FIXED extraction:
    - https://example.com
    - www.example.com
    - example.com  ← now supported
    """

    url_re = re.compile(
        r'(https?://[^\s<>"{}]+|'
        r'www\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}[^\s]*|'
        r'\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b)'
    )

    raw_urls = url_re.findall(text)

    urls = []
    for u in raw_urls:
        if not u.startswith(("http://", "https://", "www.")):
            u = "https://" + u
        urls.append(u)

    if not urls:
        return {"urls": [], "max_score": 0, "all_flags": [], "analyses": []}

    analyses, all_flags, max_score = [], [], 0

    for url in urls[:5]:
        r = analyze_url(url)
        analyses.append({"url": url, **r})
        all_flags.extend(r["flags"])
        max_score = max(max_score, r["score"])

    return {
        "urls": urls,
        "max_score": max_score,
        "all_flags": list(set(all_flags)),
        "analyses": analyses,
    }


def kadane_max_window(scores: list) -> dict:
    if not scores:
        return {"max_sum": 0, "start": 0, "end": 0}

    max_here = max_so_far = scores[0]
    start = end = temp_start = 0

    for i in range(1, len(scores)):
        if scores[i] > max_here + scores[i]:
            max_here = scores[i]
            temp_start = i
        else:
            max_here += scores[i]

        if max_here > max_so_far:
            max_so_far = max_here
            start = temp_start
            end = i

    return {
        "max_sum": round(max_so_far, 2),
        "start": start,
        "end": end
    }