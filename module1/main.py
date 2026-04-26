"""
main.py — Module 1 CLI Entry Point
Run this to test the entire detection engine without Django.
Usage: python3 main.py
"""

from fraud_engine    import scan_message, financial_loss_estimator, sandwich_vowel
from url_analyzer    import analyze_all_urls, kadane_max_window
from message_parser  import parse_message
from similarity_engine import find_similar_scams, get_similarity_verdict, count_and_say
from fraud_models    import save_case, read_all_logs, get_log_summary
from fraud_analytics import numpy_stats, pandas_insights, load_dataframe, generate_sample_data

DIVIDER = "─" * 60

TEST_MESSAGES = [
    {
        "label": "Banking Fraud",
        "text":  "URGENT: Your SBI account has been BLOCKED! "
                 "Share OTP immediately to restore. Click http://sbi-kyc.xyz/verify "
                 "or account closes in 24 hours! Call 9876543210.",
        "sender": "9876543210"
    },
    {
        "label": "Crypto Fraud",
        "text":  "Binance official giveaway! Send 0.1 ETH to receive 1 ETH back. "
                 "Connect your MetaMask wallet seed phrase now. Limited time.",
        "sender": ""
    },
    {
        "label": "Job Fraud",
        "text":  "Work from home! Earn ₹50,000/month. No experience required. "
                 "Pay ₹999 registration fee. Immediate joining. Google hiring urgently.",
        "sender": "VM-JOBSCO"
    },
    {
        "label": "Loan Fraud",
        "text":  "Instant loan ₹5 lakh approved! No CIBIL check. "
                 "Pay ₹2000 GST processing fee to get disbursement today. RBI approved.",
        "sender": ""
    },
    {
        "label": "Safe Message",
        "text":  "Hi, are you coming to office tomorrow? Lunch at 1pm?",
        "sender": "9123456789"
    },
]


def run_full_scan(msg_data: dict):
    text   = msg_data["text"]
    sender = msg_data["sender"]
    label  = msg_data["label"]

    print(f"\n{DIVIDER}")
    print(f"  TEST: {label}")
    print(DIVIDER)
    print(f"  Input: {text[:80]}...")

    # Layer 1: Parse
    parse  = parse_message(text, sender)
    print(f"\n  [Parser]   Channel: {parse['channel']} | "
          f"Forwarded: {parse['is_forwarded']} | "
          f"Urgency escalation: {parse['urgency_escalation']}")
    if parse["pre_flags"]:
        print(f"             Flags: {parse['pre_flags'][:2]}")

    # Layer 2: URLs
    url_res = analyze_all_urls(text)
    if url_res["urls"]:
        print(f"  [URL]      Score: {url_res['max_score']}/100 | "
              f"Flags: {url_res['all_flags'][:2]}")

    # Layer 3: Core scan
    scan = scan_message(text, url_score=url_res["max_score"])
    print(f"\n  [Engine]   Score: {scan['risk_score']}/100 | "
          f"{scan['severity']} — {scan['risk_level']}")
    print(f"             Type:  {scan['scam_type']}")
    print(f"             Keywords: {scan['keyword_hits'][:3]}")
    if scan["urgency_phrases"]:
        print(f"             Urgency: {scan['urgency_phrases'][:2]}")
    if scan["authority_entities"]:
        print(f"             Authority impersonation: {scan['authority_entities']}")

    # Layer 4: Similarity
    matches  = find_similar_scams(text, top_n=2)
    verdict  = get_similarity_verdict(matches)
    print(f"\n  [Similar]  {verdict}")

    # Layer 5: Save
    case = save_case(parse, scan, matches)
    print(f"\n  [Saved]    {case}")
    print(f"  [Warning]  {case.get_warning()}")
    print(f"  [Action 1] {case.get_action_steps()[0]}")


def show_stats():
    print(f"\n{DIVIDER}")
    print("  LOG SUMMARY")
    print(DIVIDER)
    summary = get_log_summary()
    print(f"  Total cases   : {summary['total']}")
    print(f"  High risk     : {summary['high_risk']}")
    print(f"  Suspicious    : {summary['suspicious']}")
    print(f"  Avg score     : {summary['avg_score']}")
    print(f"  By type       : {summary['by_type']}")

    # NumPy stats
    all_cases = read_all_logs()
    if all_cases:
        stats = numpy_stats(all_cases)
        print(f"\n  [NumPy]  Mean={stats.get('mean')} | "
              f"Median={stats.get('median')} | "
              f"Std={stats.get('std')} | "
              f"P90={stats.get('p90')}")

    # Pandas insights
    sample = generate_sample_data(20) + all_cases
    df = load_dataframe(sample)
    if df is not None:
        ins = pandas_insights(df)
        print(f"  [Pandas] Type dist: {ins.get('type_dist', {})}")


def show_illustrative():
    print(f"\n{DIVIDER}")
    print("  ILLUSTRATIVE PROGRAMS")
    print(DIVIDER)

    # Sandwich vowel (Unit I)
    word = "scammed"
    result = sandwich_vowel(word)
    print(f"  Sandwich vowel in '{word}': {result}")

    # Count and Say (Unit II)
    for n in [1, 2, 3, 4]:
        print(f"  Count and Say ({n}): {count_and_say(n)}")

    # Kadane's (Unit II)
    signal_scores = [5, 8, 2, 15, 20, 3, 10, 7]
    k = kadane_max_window(signal_scores)
    print(f"  Kadane's on {signal_scores}: max={k['max_sum']} "
          f"from index {k['start']} to {k['end']}")

    # Financial estimator (Unit I)
    # Pass a representative score to the estimator
    sample_score = 85  # represents a high-risk scam scenario
    impact = financial_loss_estimator(sample_score)
    print(f"  Financial impact (score={sample_score}): {impact}")


if __name__ == "__main__":
    print("\n" + "="*60)
    print("   CYBER FRAUD DETECTION SYSTEM — Module 1")
    print("="*60)

    for msg in TEST_MESSAGES:
        run_full_scan(msg)

    show_stats()
    show_illustrative()

    print(f"\n{'='*60}")
    print("  Module 1 complete. Run Module 2 (Django) for web UI.")
    print("  cd ../module2 && python3 manage.py runserver")
    print("="*60 + "\n")
