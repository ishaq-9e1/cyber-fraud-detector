"""
fraud_analytics.py — Data Analysis & Chart Generation
Module 1 | Unit V
Covers: NumPy (arrays, aggregations), Pandas (DataFrames, groupby, missing data),
        Matplotlib (bar, pie, line, scatter plots)
"""

import os
import random
from datetime import datetime, timedelta


def load_dataframe(cases: list):
    """
    Loads cases into Pandas DataFrame.
    Unit V: Pandas objects, data indexing, handling missing data
    """
    try:
        import pandas as pd
        if not cases:
            return None
        df = pd.DataFrame(cases)
        df["timestamp"]  = pd.to_datetime(df.get("timestamp", pd.Series()), errors="coerce")
        df["risk_score"] = pd.to_numeric(df.get("risk_score", 0), errors="coerce").fillna(0)
        df["scam_type"]  = df.get("scam_type", pd.Series()).fillna("Unknown")
        df["severity"]   = df.get("severity", pd.Series()).fillna("UNKNOWN")
        df["date"]       = df["timestamp"].dt.date
        return df
    except ImportError:
        return None


def numpy_stats(cases: list) -> dict:
    """
    Unit V: NumPy — basics, universal functions, aggregations (min, max, mean, std, percentile)
    """
    try:
        import numpy as np
        scores = np.array([c.get("risk_score", 0) for c in cases], dtype=float)
        if len(scores) == 0:
            return {}
        return {
            "mean":   round(float(np.mean(scores)), 1),
            "median": round(float(np.median(scores)), 1),
            "std":    round(float(np.std(scores)), 1),
            "min":    int(np.min(scores)),
            "max":    int(np.max(scores)),
            "p75":    round(float(np.percentile(scores, 75)), 1),
            "p90":    round(float(np.percentile(scores, 90)), 1),
            "high_risk_count": int(np.sum(scores >= 66)),
        }
    except ImportError:
        return {}


def pandas_insights(df) -> dict:
    """
    Unit V: Pandas — data operations, groupby, value_counts, selection
    """
    try:
        import pandas as pd
        return {
            "type_dist":        df["scam_type"].value_counts().to_dict(),
            "severity_dist":    df["severity"].value_counts().to_dict(),
            "avg_by_type":      df.groupby("scam_type")["risk_score"].mean().round(1).to_dict(),
            "daily_counts":     df.groupby("date").size().to_dict(),
            "channel_dist":     df.get("channel", pd.Series()).value_counts().to_dict(),
            "forwarded_ratio":  round(df.get("is_forwarded", pd.Series(False)).mean() * 100, 1),
        }
    except Exception:
        return {}


def generate_charts(cases: list, out: str = None) -> bool:
    if out is None:
        # Always resolve relative to this file so it works from any working directory
        base = os.path.dirname(os.path.abspath(__file__))
        out = os.path.join(base, "..", "module2", "fraud_app", "static", "fraud_app")
        out = os.path.normpath(out)
    os.makedirs(out, exist_ok=True)
    """
    Unit V: Matplotlib — bar, pie, line, scatter plots
    """
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np

        df = load_dataframe(cases)
        if df is None or df.empty:
            return False

        COLORS = ["#e74c3c","#e67e22","#3498db","#2ecc71","#9b59b6","#1abc9c"]
        BG = "#0f0f1a"
        plt.rcParams.update({
            "figure.facecolor": BG, "axes.facecolor": "#161625",
            "axes.edgecolor": "#2a2a3e", "axes.labelcolor": "#888",
            "xtick.color": "#888", "ytick.color": "#888",
            "text.color": "#ccc", "grid.color": "#1f1f30",
        })

        # ── Bar chart — scam type distribution
        fig, ax = plt.subplots(figsize=(7, 4))
        dist = df["scam_type"].value_counts().head(6)
        bars = ax.barh(dist.index, dist.values, color=COLORS[:len(dist)],
                       edgecolor="none", height=0.6)
        for bar, val in zip(bars, dist.values):
            ax.text(bar.get_width()+0.2, bar.get_y()+bar.get_height()/2,
                    str(val), va="center", fontsize=9, color="#ccc")
        ax.set_title("Scam Type Distribution", fontsize=12, color="#fff", pad=10)
        ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
        plt.tight_layout()
        plt.savefig(f"{out}/chart_bar.png", dpi=130, bbox_inches="tight", facecolor=BG)
        plt.close()

        # ── Donut chart — severity split
        fig, ax = plt.subplots(figsize=(5, 5))
        order  = ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"]
        colors_map = {"CRITICAL":"#c0392b","HIGH":"#e74c3c","MEDIUM":"#e67e22",
                      "LOW":"#2ecc71","UNKNOWN":"#555"}
        sc     = df["severity"].value_counts()
        labels = [s for s in order if s in sc.index]
        vals   = [sc[s] for s in labels]
        cols   = [colors_map[s] for s in labels]
        wedges, texts, autotexts = ax.pie(
            vals, labels=labels, colors=cols, autopct="%1.0f%%", startangle=90,
            wedgeprops={"width":0.55,"edgecolor":BG,"linewidth":2},
            textprops={"color":"#ccc","fontsize":9}
        )
        for at in autotexts: at.set_color("#fff"); at.set_fontsize(8)
        ax.set_title("Severity Breakdown", fontsize=12, color="#fff", pad=10)
        plt.tight_layout()
        plt.savefig(f"{out}/chart_pie.png", dpi=130, bbox_inches="tight", facecolor=BG)
        plt.close()

        # ── Line chart — daily trend
        fig, ax = plt.subplots(figsize=(8, 3.5))
        df["date_str"] = df["timestamp"].dt.strftime("%m/%d")
        daily = df.groupby("date_str").size()
        x = range(len(daily))
        ax.fill_between(x, daily.values, alpha=0.15, color="#e74c3c")
        ax.plot(x, daily.values, color="#e74c3c", linewidth=2,
                marker="o", markersize=4)
        ax.set_xticks(x); ax.set_xticklabels(daily.index, rotation=45, fontsize=8)
        ax.set_title("Daily Scam Reports", fontsize=12, color="#fff", pad=10)
        ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
        plt.tight_layout()
        plt.savefig(f"{out}/chart_line.png", dpi=130, bbox_inches="tight", facecolor=BG)
        plt.close()

        # ── Scatter — score vs type (Unit V: Simple Scatter Plot)
        fig, ax = plt.subplots(figsize=(7, 4))
        cats = df["scam_type"].unique()[:6]
        for i, cat in enumerate(cats):
            sub = df[df["scam_type"] == cat]
            ax.scatter([cat]*len(sub), sub["risk_score"],
                       color=COLORS[i % len(COLORS)], alpha=0.6, s=40, edgecolors="none")
            ax.plot([cat], [sub["risk_score"].mean()],
                    marker="_", color="white", markersize=20, linewidth=2)
        ax.set_title("Risk Score Scatter by Type", fontsize=12, color="#fff", pad=10)
        ax.set_ylabel("Risk Score", fontsize=9)
        ax.tick_params(axis="x", rotation=30)
        ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
        plt.tight_layout()
        plt.savefig(f"{out}/chart_scatter.png", dpi=130, bbox_inches="tight", facecolor=BG)
        plt.close()

        return True
    except Exception as e:
        print(f"[Charts] {e}")
        return False


def generate_sample_data(n: int = 40) -> list:
    """Generates demo cases for dashboard when log is empty."""
    types = [("Banking Fraud","CRITICAL"),("Shopping Fraud","HIGH"),
             ("Crypto Fraud","CRITICAL"),("Job Fraud","HIGH"),
             ("Loan Fraud","CRITICAL"),("Lottery Fraud","HIGH")]
    base  = datetime.now()
    cases = []
    for i in range(n):
        st, _ = random.choice(types)
        sev   = random.choices(["CRITICAL","HIGH","MEDIUM","LOW"],[3,4,2,1])[0]
        lo, hi = {"CRITICAL":(81,100),"HIGH":(66,80),"MEDIUM":(46,65),"LOW":(0,45)}[sev]
        cases.append({
            "case_id":   f"DEMO-{i:04d}",
            "timestamp": (base - timedelta(days=random.randint(0,21),
                                           hours=random.randint(0,23))).strftime("%Y-%m-%d %H:%M:%S"),
            "scam_type": st, "severity": sev,
            "risk_score": random.randint(lo, hi),
            "channel":    random.choice(["whatsapp","sms_dlt","mobile"]),
            "is_forwarded": random.random() > 0.6,
        })
    return cases
