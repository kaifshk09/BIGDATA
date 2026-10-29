"""
PhishGuard — Streamlit Application
===================================
AI & Heuristic Phishing URL Detection System
Zero-network static URL analysis with real-time risk scoring, explainable AI heuristics,
interactive analytics, and audit logging.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from urllib.parse import urlparse
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from core import config
from core.analysis import (
    BRAND_NAMES,
    BRAND_OFFICIAL_DOMAINS,
    SUPPORTED_SCHEMES,
    SUSPICIOUS_HOST_WORDS,
    SUSPICIOUS_PATH_WORDS,
    AnalysisResult,
    analyze_url,
)
from core import database as db

# ---------------------------------------------------------------------------
# Page Configuration & Styling
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="PhishGuard — Phishing URL Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for polished, cyber-defense dashboard aesthetics
st.markdown(
    """
    <style>
    /* Metric Card Enhancements */
    div[data-testid="stMetric"] {
        background-color: #1E293B;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 14px 18px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
    }
    div[data-testid="stMetric"]:hover {
        border-color: #3B82F6;
        transition: border-color 0.2s ease-in-out;
    }
    div[data-testid="stMetricLabel"] p {
        color: #94A3B8 !important;
        font-weight: 500 !important;
        font-size: 0.85rem !important;
    }
    div[data-testid="stMetricValue"] div {
        color: #F8FAFC !important;
        font-weight: 700 !important;
    }

    /* Verdict Alert Badges */
    .verdict-banner {
        padding: 18px 22px;
        border-radius: 10px;
        margin-bottom: 20px;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .verdict-high {
        background: linear-gradient(135deg, rgba(239, 68, 68, 0.2) 0%, rgba(185, 28, 28, 0.1) 100%);
        border: 1px solid #EF4444;
        color: #FCA5A5;
    }
    .verdict-suspicious {
        background: linear-gradient(135deg, rgba(245, 158, 11, 0.2) 0%, rgba(180, 83, 9, 0.1) 100%);
        border: 1px solid #F59E0B;
        color: #FCD34D;
    }
    .verdict-low {
        background: linear-gradient(135deg, rgba(16, 185, 129, 0.2) 0%, rgba(4, 120, 87, 0.1) 100%);
        border: 1px solid #10B981;
        color: #6EE7B7;
    }
    .verdict-invalid {
        background: linear-gradient(135deg, rgba(100, 116, 139, 0.2) 0%, rgba(71, 85, 105, 0.1) 100%);
        border: 1px solid #64748B;
        color: #CBD5E1;
    }

    /* Finding Item Card */
    .finding-card {
        background-color: #1E293B;
        border-left: 4px solid #3B82F6;
        border-radius: 6px;
        padding: 12px 16px;
        margin-bottom: 10px;
    }
    .finding-high { border-left-color: #EF4444; }
    .finding-medium { border-left-color: #F59E0B; }
    .finding-low { border-left-color: #3B82F6; }

    /* Footer Styling */
    .footer-text {
        text-align: center;
        color: #64748B;
        font-size: 0.8rem;
        margin-top: 40px;
        padding-top: 20px;
        border-top: 1px solid #334155;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Initialize Database
try:
    db.init_db()
except Exception as e:
    st.error(f"Database initialization warning: {e}")

# ---------------------------------------------------------------------------
# Helper Visualizations
# ---------------------------------------------------------------------------

def create_gauge_chart(score: int, verdict: str) -> go.Figure:
    """Create a semi-circular cyber gauge chart for risk score."""
    if score >= 50:
        bar_color = "#EF4444"  # Red
    elif score >= 25:
        bar_color = "#F59E0B"  # Amber
    else:
        bar_color = "#10B981"  # Emerald

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            number={"suffix": "/100", "font": {"size": 36, "color": "#F8FAFC"}},
            title={"text": f"<b>Verdict: {verdict}</b>", "font": {"size": 18, "color": bar_color}},
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#64748B"},
                "bar": {"color": bar_color, "thickness": 0.3},
                "bgcolor": "#0F172A",
                "borderwidth": 1,
                "bordercolor": "#334155",
                "steps": [
                    {"range": [0, 24], "color": "rgba(16, 185, 129, 0.15)"},
                    {"range": [25, 49], "color": "rgba(245, 158, 11, 0.15)"},
                    {"range": [50, 100], "color": "rgba(239, 68, 68, 0.15)"},
                ],
                "threshold": {
                    "line": {"color": "#FFFFFF", "width": 3},
                    "thickness": 0.8,
                    "value": score,
                },
            },
        )
    )
    fig.update_layout(
        height=240,
        margin=dict(l=20, r=20, t=40, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        font={"color": "#F8FAFC", "family": "sans-serif"},
    )
    return fig


# ---------------------------------------------------------------------------
# Sidebar Navigation & Presets
# ---------------------------------------------------------------------------

st.sidebar.markdown("## 🛡️ **PhishGuard**")
st.sidebar.caption("Phishing Detection & Security Analyzer")

# Fetch quick stats for sidebar counter
try:
    stats = db.get_stats()
except Exception:
    stats = {"total": 0, "high": 0, "suspicious": 0, "lower": 0, "average_score": 0}

nav_choice = st.sidebar.radio(
    "Navigation",
    ["🔍 URL Scanner", "📊 Security Analytics", "📜 Audit History", "📖 Detection Rules & About"],
    index=0,
)

st.sidebar.markdown("---")
st.sidebar.markdown("### ⚡ Quick Test Presets")

preset_options = {
    "None": "",
    "🔴 PayPal Authority Impersonation": "http://paypal.com@0x7f000001/signin-verify.php?claim=gift",
    "🔴 Punycode Cyrillic Phish": "https://apple.com-account-verify.xn--e1afmkfd.org/login",
    "🟡 Suspicious Banking Form": "http://update-secure-netbanking.com/login?token=9283718",
    "🟢 Legitimate Google Search": "https://www.google.com/search?q=cybersecurity+defense",
    "🟢 GitHub Official Repository": "https://github.com/kaifshk09/BigData",
}

selected_preset = st.sidebar.selectbox("Load sample URL:", list(preset_options.keys()))

st.sidebar.markdown("---")
st.sidebar.markdown("### 📈 Live Stats")
col_s1, col_s2 = st.sidebar.columns(2)
col_s1.metric("Total Scans", stats.get("total", 0))
col_s2.metric("Avg Score", f"{stats.get('average_score', 0)}/100")
st.sidebar.caption("Safe Heuristic Engine: zero network requests sent.")


# ---------------------------------------------------------------------------
# View 1: URL Scanner
# ---------------------------------------------------------------------------

if nav_choice == "🔍 URL Scanner":
    st.markdown("## 🔍 Phishing URL Detection & Analyzer")
    st.markdown(
        "Analyze any URL instantly using **19 explainable heuristic rules**, brand spoofing checks, "
        "and obfuscation detection. *Safe analysis: URLs are parsed strictly in memory and never pinged or downloaded.*"
    )

    scanner_mode = st.radio("Scan Mode:", ["Single URL Scanner", "Batch / Bulk URL Scanner"], horizontal=True)

    if scanner_mode == "Single URL Scanner":
        default_val = preset_options.get(selected_preset, "")

        with st.form("scan_form", clear_on_submit=False):
            url_input = st.text_input(
                "Enter URL to analyze:",
                value=default_val,
                placeholder="https://example.com/login or paste a suspicious link",
                help="Accepts complete URLs with or without http/https protocol",
            )
            col_btn, _ = st.columns([1, 4])
            with col_btn:
                scan_submitted = st.form_submit_button("⚡ Analyze URL", use_container_width=True, type="primary")

        # Auto-trigger if a sample was picked from the sidebar
        should_run = scan_submitted or (default_val and "last_preset" not in st.session_state)
        if default_val:
            st.session_state["last_preset"] = default_val

        target_url = url_input.strip()

        if target_url and (scan_submitted or should_run):
            if len(target_url) > config.MAX_URL_LENGTH:
                st.error(f"URL exceeds maximum allowed length ({config.MAX_URL_LENGTH} characters).")
            else:
                with st.spinner("Analyzing URL structure and heuristics..."):
                    result: AnalysisResult = analyze_url(target_url)
                    # Persist scan to SQLite
                    try:
                        db.save_scan(result)
                    except Exception:
                        pass

                # Display Results
                st.markdown("---")

                # Verdict Banner
                slug = result.level_slug
                banner_class = f"verdict-{slug}"
                verdict_title = result.verdict
                summary_text = config.VERDICT_META.get(verdict_title, {}).get(
                    "summary", "Analysis completed."
                )

                st.markdown(
                    f"""
                    <div class="verdict-banner {banner_class}">
                        <div>
                            <h3 style="margin: 0; color: inherit; font-size: 1.4rem;">{verdict_title} (Risk Score: {result.score}/100)</h3>
                            <p style="margin: 4px 0 0 0; opacity: 0.9;">{summary_text}</p>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                # Metrics row & Gauge
                col_metric_1, col_metric_2, col_metric_3, col_gauge = st.columns([1, 1, 1, 1.6])

                with col_metric_1:
                    st.metric("Risk Score", f"{result.score} / 100")
                    st.metric("Protocol Scheme", result.scheme.upper() if result.scheme else "None")

                with col_metric_2:
                    st.metric("Safety Status", result.verdict)
                    st.metric("Host Length", f"{len(result.hostname)} chars")

                with col_metric_3:
                    st.metric("Heuristics Triggered", len(result.findings))
                    st.metric("Target Hostname", result.hostname[:22] + "..." if len(result.hostname) > 22 else (result.hostname or "N/A"))

                with col_gauge:
                    gauge_fig = create_gauge_chart(result.score, result.verdict)
                    st.plotly_chart(gauge_fig, use_container_width=True)

                # Findings & Recommendations
                st.markdown("### 📋 Detailed Inspection & Heuristic Findings")

                tab_findings, tab_recs, tab_tech = st.tabs(["⚠️ Indicators & Findings", "💡 Recommendations", "🔬 Technical Breakdown"])

                with tab_findings:
                    if not result.findings:
                        st.success("✅ **No malicious or suspicious indicators were detected in this URL.**")
                        st.info("Note: PhishGuard evaluates observable URL structure. Always verify unknown senders before submitting confidential credentials.")
                    else:
                        for finding in result.findings:
                            points = finding.points
                            severity_css = "finding-high" if points >= 20 else ("finding-medium" if points >= 10 else "finding-low")
                            st.markdown(
                                f"""
                                <div class="finding-card {severity_css}">
                                    <div style="display: flex; justify-content: space-between; align-items: center;">
                                        <b style="color: #F8FAFC; font-size: 1rem;">{finding.title}</b>
                                        <span style="background-color: rgba(255,255,255,0.1); padding: 3px 8px; border-radius: 4px; font-size: 0.85rem; font-weight: bold; color: #38BDF8;">
                                            +{points} pts
                                        </span>
                                    </div>
                                    <div style="color: #94A3B8; font-size: 0.9rem; margin-top: 6px;">
                                        {finding.detail}
                                    </div>
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )

                with tab_recs:
                    if result.recommendations:
                        for rec in result.recommendations:
                            st.markdown(f"- 🛡️ {rec}")
                    else:
                        st.markdown("- ✅ This URL looks standard. Always ensure HTTPS is active before typing sensitive passwords.")

                with tab_tech:
                    parsed = urlparse(result.normalized_url or target_url)
                    tech_data = {
                        "Property": ["Original Input", "Normalized URL", "Scheme", "Hostname", "Port", "Path", "Query String"],
                        "Value": [
                            target_url,
                            result.normalized_url or "N/A",
                            parsed.scheme or "None",
                            parsed.hostname or "None",
                            str(parsed.port or "Default (80/443)"),
                            parsed.path or "/",
                            parsed.query or "None",
                        ],
                    }
                    st.table(pd.DataFrame(tech_data))

    elif scanner_mode == "Batch / Bulk URL Scanner":
        st.markdown("#### Analyze Multiple URLs at Once")
        st.caption("Paste a list of URLs (one per line) or upload a plain text/CSV file.")

        batch_text = st.text_area(
            "Paste URLs (one per line):",
            height=150,
            placeholder="https://google.com\nhttp://paypal.com@192.168.1.1/login\nhttp://free-prize-claim.xyz/update",
        )

        uploaded_file = st.file_uploader("Or upload .txt / .csv file:", type=["txt", "csv"])

        urls_to_scan = []
        if batch_text:
            urls_to_scan.extend([line.strip() for line in batch_text.splitlines() if line.strip()])
        if uploaded_file is not None:
            content = uploaded_file.read().decode("utf-8", errors="ignore")
            urls_to_scan.extend([line.strip() for line in content.splitlines() if line.strip()])

        urls_to_scan = list(dict.fromkeys(urls_to_scan))[:100]  # Deduplicate, cap at 100

        if st.button("🚀 Run Batch Analysis", type="primary", disabled=len(urls_to_scan) == 0):
            progress_bar = st.progress(0)
            batch_results = []

            for idx, u in enumerate(urls_to_scan):
                res = analyze_url(u)
                try:
                    db.save_scan(res)
                except Exception:
                    pass
                batch_results.append({
                    "URL": u,
                    "Verdict": res.verdict,
                    "Score": res.score,
                    "Hostname": res.hostname,
                    "Findings Count": len(res.findings),
                })
                progress_bar.progress((idx + 1) / len(urls_to_scan))

            st.success(f"Batch scan completed for {len(batch_results)} URLs.")
            df_batch = pd.DataFrame(batch_results)

            # Summary metrics
            col_b1, col_b2, col_b3, col_b4 = st.columns(4)
            col_b1.metric("Scanned", len(df_batch))
            col_b2.metric("High Risk", len(df_batch[df_batch["Verdict"] == "High Risk"]))
            col_b3.metric("Suspicious", len(df_batch[df_batch["Verdict"] == "Suspicious"]))
            col_b4.metric("Lower Risk", len(df_batch[df_batch["Verdict"] == "Lower Risk"]))

            st.dataframe(df_batch, use_container_width=True)

            # Download CSV
            csv_data = df_batch.to_csv(index=False).encode("utf-8")
            st.download_button(
                "📥 Download Batch Report (CSV)",
                data=csv_data,
                file_name=f"phishguard_batch_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
            )


# ---------------------------------------------------------------------------
# View 2: Security Analytics
# ---------------------------------------------------------------------------

elif nav_choice == "📊 Security Analytics":
    st.markdown("## 📊 PhishGuard Security Analytics")
    st.markdown("Real-time telemetry and distribution of scans performed on this node.")

    try:
        stats = db.get_stats()
        all_scans = db.get_history(limit=500)
    except Exception as e:
        st.error(f"Could not load analytics from database: {e}")
        stats = {"total": 0, "high": 0, "suspicious": 0, "lower": 0, "average_score": 0, "top_score": 0}
        all_scans = []

    # KPI Metric Cards
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total Scans", stats.get("total", 0))
    col2.metric("High Risk Scans", stats.get("high", 0))
    col3.metric("Suspicious Scans", stats.get("suspicious", 0))
    col4.metric("Lower Risk Scans", stats.get("lower", 0))
    col5.metric("Avg Risk Score", f"{stats.get('average_score', 0)}/100")

    st.markdown("---")

    if not all_scans:
        st.info("No scan data available yet. Scan URLs to generate interactive analytics charts.")
    else:
        df_scans = pd.DataFrame([dict(row) for row in all_scans])

        col_ch1, col_ch2 = st.columns(2)

        with col_ch1:
            st.markdown("### 🍩 Risk Verdict Distribution")
            verdict_counts = df_scans["verdict"].value_counts().reset_index()
            verdict_counts.columns = ["Verdict", "Count"]

            color_map = {
                "High Risk": "#EF4444",
                "Suspicious": "#F59E0B",
                "Lower Risk": "#10B981",
                "Invalid URL": "#64748B",
            }

            fig_donut = px.pie(
                verdict_counts,
                values="Count",
                names="Verdict",
                hole=0.55,
                color="Verdict",
                color_discrete_map=color_map,
            )
            fig_donut.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font={"color": "#F8FAFC"},
                margin=dict(t=20, b=20, l=20, r=20),
            )
            st.plotly_chart(fig_donut, use_container_width=True)

        with col_ch2:
            st.markdown("### 📊 Score Distribution (0 - 100)")
            fig_hist = px.histogram(
                df_scans,
                x="score",
                nbins=20,
                color="verdict",
                color_discrete_map=color_map,
                labels={"score": "Risk Score", "count": "Number of Scans"},
            )
            fig_hist.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font={"color": "#F8FAFC"},
                bargap=0.1,
                margin=dict(t=20, b=20, l=20, r=20),
            )
            st.plotly_chart(fig_hist, use_container_width=True)

        # Top flagged indicators
        st.markdown("### 🚩 Most Frequent Indicator Flags")
        indicator_list = []
        for row in all_scans:
            try:
                findings = db.load_findings(row)
                for f in findings:
                    indicator_list.append(f.get("title") or "Unknown indicator")
            except Exception:
                pass

        if indicator_list:
            s_indicators = pd.Series(indicator_list).value_counts().head(10).reset_index()
            s_indicators.columns = ["Heuristic Flag", "Occurrences"]
            fig_bar = px.bar(
                s_indicators,
                x="Occurrences",
                y="Heuristic Flag",
                orientation="h",
                color_discrete_sequence=["#3B82F6"],
            )
            fig_bar.update_layout(
                yaxis={"categoryorder": "total ascending"},
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font={"color": "#F8FAFC"},
                margin=dict(t=20, b=20, l=20, r=20),
            )
            st.plotly_chart(fig_bar, use_container_width=True)


# ---------------------------------------------------------------------------
# View 3: Audit History & Logs
# ---------------------------------------------------------------------------

elif nav_choice == "📜 Audit History":
    st.markdown("## 📜 Scan History & Audit Logs")
    st.markdown("Search, inspect, and export past scans stored in the persistent database.")

    col_f1, col_f2, col_f3 = st.columns([2, 1, 1])
    with col_f1:
        search_kw = st.text_input("🔍 Search by URL or Hostname:", placeholder="e.g. paypal, google, 192.168...")
    with col_f2:
        risk_filter = st.selectbox("Filter Risk:", ["all", "high", "suspicious", "lower"], format_func=lambda x: x.capitalize())
    with col_f3:
        record_limit = st.selectbox("Max rows:", [25, 50, 100, 250], index=1)

    try:
        history_rows = db.get_history(search=search_kw, mode=risk_filter, limit=record_limit)
    except Exception as e:
        st.error(f"Database query error: {e}")
        history_rows = []

    if not history_rows:
        st.info("No matching records found in scan history.")
    else:
        table_data = []
        for r in history_rows:
            table_data.append({
                "ID": r["id"],
                "URL": r["url"],
                "Verdict": r["verdict"],
                "Risk Score": r["score"],
                "Scanned At": db.format_time(r["scanned_at"]),
            })
        df_history = pd.DataFrame(table_data)

        st.dataframe(df_history, use_container_width=True, hide_index=True)

        col_act1, col_act2 = st.columns([2, 2])
        with col_act1:
            csv_export = df_history.to_csv(index=False).encode("utf-8")
            st.download_button(
                "📥 Export History to CSV",
                data=csv_export,
                file_name=f"phishguard_audit_export_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv",
            )
        with col_act2:
            if config.ALLOW_CLEAR_HISTORY:
                with st.expander("🗑️ Clear Audit History"):
                    st.warning("This will permanently delete all stored scan history from the database.")
                    confirm_check = st.checkbox("I confirm I want to wipe history")
                    if st.button("Permanently Clear History", type="secondary", disabled=not confirm_check):
                        deleted_count = db.clear_history()
                        st.success(f"History cleared: {deleted_count} records removed.")
                        st.rerun()


# ---------------------------------------------------------------------------
# View 4: Detection Rules & About
# ---------------------------------------------------------------------------

elif nav_choice == "📖 Detection Rules & About":
    st.markdown("## 📖 Heuristic Engine & Detection Rules")
    st.markdown(
        """
        PhishGuard evaluates URLs through **transparent, explainable heuristics** designed from actual
        phishing campaign patterns. Rather than being an opaque black-box, every point added to the
        risk score corresponds to an identifiable deception technique.
        """
    )

    tab_rules, tab_brands, tab_arch = st.tabs(["🛡️ Scoring Rules", "🏢 Brand Protection", "⚙️ Architecture & Safety"])

    with tab_rules:
        st.markdown("### The 19 Heuristic Rules & Scoring Weights")
        rules_data = [
            {"Points": "+40", "Technique": "Authority `@` Trick", "Description": "Exploits userinfo syntax to make the browser connect to an attacker host after `@` (e.g., trusted.com@evil.com)."},
            {"Points": "+30", "Technique": "Punycode (IDN) Spoofing", "Description": "Contains `xn--` Cyrillic/Greek characters that visually impersonate Latin letters (homograph attacks)."},
            {"Points": "+30", "Technique": "Hexadecimal / Dotted-Int Host", "Description": "Uses obfuscated host representations (e.g. `0x7f.0.0.1` or raw 32-bit integers) to bypass filters."},
            {"Points": "+25", "Technique": "Raw IP Address Host", "Description": "Direct IPv4/IPv6 address instead of a legitimate registered domain name."},
            {"Points": "+20", "Technique": "Brand Impersonation", "Description": "Recognized brand name (e.g. PayPal, Apple, Google, SBI) embedded inside an unofficial foreign domain."},
            {"Points": "+20", "Technique": "Embedded Credentials", "Description": "Contains username/password credentials in `user:pass@host` format."},
            {"Points": "+15", "Technique": "Dangerous File Extension", "Description": "Direct download link for risky executables/archives (.exe, .apk, .scr, .zip, .docm)."},
            {"Points": "+15", "Technique": "Excessive Subdomains", "Description": "4 or more subdomains preceding the root domain (deep nesting used to disguise destination)."},
            {"Points": "+12", "Technique": "Unusual Port Number", "Description": "Explicit non-standard web ports (standard ports are 80 for HTTP and 443 for HTTPS)."},
            {"Points": "+12", "Technique": "Long Hostname (>30 chars)", "Description": "Abnormally lengthy domain name designed to overflow address bars on mobile browsers."},
            {"Points": "+12", "Technique": "Dangerous URI Schemes", "Description": "Data, blob, or javascript URIs designed to execute client-side payloads (`data:`, `blob:`, `javascript:`)."},
            {"Points": "+10", "Technique": "Unencrypted HTTP Scheme", "Description": "Plaintext communication vulnerable to eavesdropping and credential sniffing."},
            {"Points": "+10", "Technique": "Multiple Host Hyphens (≥3)", "Description": "Dashes frequently chained together in phishing domains (e.g. `paypal-secure-login-portal.com`)."},
            {"Points": "+10", "Technique": "Suspicious Host Keywords", "Description": "Contains urgency bait words like `verify`, `billing`, `wallet`, `kyc`, `otp`, `refund` in hostname."},
            {"Points": "+10", "Technique": "Double URL Encoding", "Description": "Nested percentage encodings (`%2520`) intended to evade security gateways and firewalls."},
            {"Points": "+10", "Technique": "URL Length > 100 chars", "Description": "Padding and tracking garbage designed to hide query parameters off screen."},
            {"Points": "+8", "Technique": "Suspicious Path Words", "Description": "Landing page path keywords like `/login`, `/banking`, `/webscr`, `/confirm`."},
            {"Points": "+8", "Technique": "Excessive Query Parameters (≥6)", "Description": "Complex tracking or state payloads used in credential harvesting redirects."},
            {"Points": "+5", "Technique": "URL Shortener Redirection", "Description": "Obfuscating redirect services (bit.ly, tinyurl, t.co) masking destination."},
        ]
        st.table(pd.DataFrame(rules_data))

    with tab_brands:
        st.markdown("### Monitored Brands")
        st.markdown(
            "PhishGuard monitors high-value targets commonly abused in phishing lures (financial services, tech ecosystems, cloud providers)."
        )
        brands_col1, brands_col2 = st.columns(2)
        with brands_col1:
            st.markdown("**Global Brands:** PayPal, Apple, Microsoft, Google, Amazon, Netflix, Meta / Facebook, Instagram, WhatsApp, LinkedIn, Dropbox, Adobe, Binance, Coinbase, Steam.")
        with brands_col2:
            st.markdown("**Banking & Logistics:** SBI, ICICI, HDFC, Axis, PhonePe, Paytm, GPay, State Bank, IRCTC, DHL, FedEx, Bank of America.")

    with tab_arch:
        st.markdown("### Safety Architecture Contract")
        st.info(
            """
            **Zero-Network Static Safety Guarantee**:
            PhishGuard never makes an outbound socket connection, DNS query, or HTTP request to submitted URLs.
            This prevents triggering malicious drive-by downloads, notifying attackers that a lure was accessed,
            or exposing your machine's IP address.
            """
        )

# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------

st.markdown(
    f"""
    <div class="footer-text">
        PhishGuard • College Project Cybersecurity Demonstration • {config.DISCLAIMER}
    </div>
    """,
    unsafe_allow_html=True,
)
