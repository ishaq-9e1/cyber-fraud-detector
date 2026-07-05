"""
views.py — Django Web Application Views
Module 2 | Unit V
Covers: Django MVT architecture, generic views, HTML templates
Imports: Module 1 detection engine
"""

import sys, os, json

# ── Import Module 1 ──────────────────────────────────────────────────────────
MODULE1_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'module1')
sys.path.insert(0, os.path.abspath(MODULE1_PATH))

from fraud_engine      import scan_message
from url_analyzer      import analyze_all_urls
from message_parser    import parse_message
from similarity_engine import find_similar_scams, get_similarity_verdict
from fraud_models      import save_case, read_all_logs, get_log_summary
from fraud_analytics   import (generate_charts, load_dataframe,
                                pandas_insights, numpy_stats,
                                generate_sample_data)

from django.shortcuts import render, redirect
from django.http      import JsonResponse
from django.views     import View


# ─── HOME ─────────────────────────────────────────────────────────────────────

def home(request):
    return render(request, "fraud_app/home.html")


# ─── SCAN ─────────────────────────────────────────────────────────────────────

def scan(request):
    if request.method != "POST":
        return render(request, "fraud_app/home.html")

    text      = request.POST.get("message", "").strip()
    sender_id = request.POST.get("sender_id", "").strip()

    if not text:
        return render(request, "fraud_app/home.html",
                      {"error": "Please enter a message to scan."})

    # 5-layer pipeline from Module 1
    parse_result    = parse_message(text, sender_id)
    url_analysis    = analyze_all_urls(text)
    scan_result     = scan_message(text, url_score=url_analysis.get("max_score", 0))
    scan_result["url_analysis"] = url_analysis
    similarity      = find_similar_scams(text, top_n=3)
    sim_verdict     = get_similarity_verdict(similarity)
    case            = save_case(parse_result, scan_result, similarity)

    return render(request, "fraud_app/result.html", {
        "scan":               scan_result,
        "case":               case.to_dict(),
        "parse":              parse_result,
        "url_analysis":       url_analysis,
        "similarity_matches": similarity,
        "sim_verdict":        sim_verdict,
        "warning":            case.get_warning(),
        "action_steps":       case.get_action_steps(),
        "confidence_breakdown": case.confidence_breakdown(),
        "category_scores":    scan_result.get("category_scores", {}),
    })


# ─── DASHBOARD ────────────────────────────────────────────────────────────────

def dashboard(request):
    real_cases  = read_all_logs()
    use_demo    = len(real_cases) < 8
    all_cases   = generate_sample_data(40) + real_cases if use_demo else real_cases

    summary     = get_log_summary()
    generate_charts(all_cases)

    df          = load_dataframe(all_cases)
    np_stats    = numpy_stats(all_cases)
    pd_insights = pandas_insights(df) if df is not None else {}
    recent      = sorted(real_cases, key=lambda x: x.get("timestamp",""), reverse=True)[:10]

    return render(request, "fraud_app/dashboard.html", {
        "summary":        summary,
        "numpy_stats":    np_stats,
        "pd_insights":    pd_insights,
        "recent_cases":   recent,
        "using_demo":     use_demo,
    })


# ─── HISTORY ──────────────────────────────────────────────────────────────────

def history(request):
    sev_filter  = request.GET.get("severity", "all")
    type_filter = request.GET.get("type", "all")
    all_cases   = read_all_logs()
    filtered    = all_cases

    if sev_filter != "all":
        filtered = [c for c in filtered if c.get("severity") == sev_filter]
    if type_filter != "all":
        filtered = [c for c in filtered if type_filter.lower() in c.get("scam_type","").lower()]

    filtered    = sorted(filtered, key=lambda x: x.get("timestamp",""), reverse=True)
    scam_types  = sorted({c.get("scam_type","") for c in all_cases})

    return render(request, "fraud_app/history.html", {
        "cases":       filtered,
        "sev_filter":  sev_filter,
        "type_filter": type_filter,
        "scam_types":  scam_types,
        "total":       len(filtered),
    })


# ─── CASE DETAIL ──────────────────────────────────────────────────────────────

def case_detail(request, case_id):
    case = next((c for c in read_all_logs() if c.get("case_id") == case_id), None)
    if not case:
        return redirect("history")
    return render(request, "fraud_app/case_detail.html", {"case": case})


# ─── LIVE SCAN API (Unit V: class-based generic view) ─────────────────────────

class QuickScanAPI(View):
    def post(self, request):
        text = request.POST.get("message","").strip()
        if len(text) < 5:
            return JsonResponse({"risk_score":0,"severity":"LOW","scam_type":"—"})
        parse   = parse_message(text)
        url_res = analyze_all_urls(text)
        result  = scan_message(text, url_score=url_res.get("max_score",0))
        matches = find_similar_scams(text, top_n=1)
        return JsonResponse({
            "risk_score":   result["risk_score"],
            "risk_level":   result["risk_level"],
            "severity":     result["severity"],
            "scam_type":    result["scam_type"],
            "keywords":     result["keyword_hits"][:4],
            "urgency":      result["urgency_phrases"][:2],
            "url_flags":    url_res.get("all_flags",[])[:2],
            "pre_flags":    parse.get("pre_flags",[])[:2],
            "top_match":    matches[0] if matches else None,
            "recommendation": result["recommendation"][:120],
        })
