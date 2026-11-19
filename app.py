from pathlib import Path
from urllib.parse import urlparse
import json
import re
import sqlite3
from datetime import datetime, timezone

import joblib
import pandas as pd
import streamlit as st

from threat_engine import evaluate_url_threat

ROOT = Path(__file__).resolve().parent
MODEL_PATH = ROOT / "models" / "url_model.joblib"
DB_PATH = ROOT / "data" / "scans.db"

st.set_page_config(
    page_title="IntelliGuard | URL Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling matching the clean, trusted Image 2 appearance
st.markdown("""<style>
/* Main Dark Navy Background */
.stApp {
    background: linear-gradient(135deg, #071527 0%, #0b1e38 55%, #102a4d 100%);
    color: #f1f5f9;
}

[data-testid="stSidebar"] {
    background: #08162b;
    border-right: 1px solid #1a3960;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 3rem;
    max-width: 1100px;
}

/* Top Banner Header */
.top-header-banner {
    background: linear-gradient(90deg, #133966 0%, #1e4a7d 100%);
    border: 1px solid #295b96;
    border-radius: 10px;
    padding: 10px 18px;
    color: #dbeafe;
    font-size: 0.92rem;
    margin-bottom: 22px;
    display: inline-block;
    width: 100%;
}

/* Metric Cards */
div[data-testid="stMetric"] {
    background: #0f2a4a;
    border: 1px solid #1f4773;
    border-radius: 12px;
    padding: 16px 20px;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.25);
}

div[data-testid="stMetric"] label {
    color: #94b8db !important;
    font-size: 0.92rem !important;
    font-weight: 600 !important;
}

div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
    color: #ffffff !important;
    font-size: 1.95rem !important;
    font-weight: 800 !important;
}

/* Primary Button (Orange/Coral accent matching Image 2) */
.stButton>button {
    background: linear-gradient(90deg, #ea580c 0%, #f97316 100%) !important;
    color: #ffffff !important;
    border: none !important;
    border-radius: 9px !important;
    font-weight: 700 !important;
    font-size: 1.02rem !important;
    padding: 0.55rem 1.4rem !important;
    box-shadow: 0 4px 12px rgba(234, 88, 12, 0.35) !important;
    transition: all 0.2s ease !important;
}

.stButton>button:hover {
    background: linear-gradient(90deg, #c2410c 0%, #ea580c 100%) !important;
    color: #ffffff !important;
    box-shadow: 0 6px 18px rgba(234, 88, 12, 0.5) !important;
    transform: translateY(-1px) !important;
}

/* Sample preset buttons */
.preset-btn button {
    background: #102947 !important;
    border: 1px solid #234d7d !important;
    color: #cbd5e1 !important;
    font-size: 0.85rem !important;
    padding: 0.35rem 0.8rem !important;
    box-shadow: none !important;
}

.preset-btn button:hover {
    background: #16365d !important;
    border-color: #38bdf8 !important;
    color: #ffffff !important;
}

/* Progress bar color */
.stProgress > div > div > div > div {
    border-radius: 6px;
}

/* Dataframe clean borders */
div[data-testid="stDataFrame"] {
    border-radius: 10px;
    overflow: hidden;
    border: 1px solid #1f4773;
}
</style>
""", unsafe_allow_html=True)

def init_db():
    DB_PATH.parent.mkdir(exist_ok=True)
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at TEXT NOT NULL,
            url TEXT NOT NULL,
            verdict TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            phishing_probability REAL NOT NULL,
            indicators TEXT NOT NULL
        )
        """)
init_db()

@st.cache_resource
def load_model():
    if not MODEL_PATH.exists():
        return None
    try:
        return joblib.load(MODEL_PATH)
    except Exception:
        return None

def normalize_tier(verdict: str) -> str:
    v = str(verdict).strip()
    if v in ["High Risk", "Likely phishing"]:
        return "High Risk"
    if v in ["Suspicious"]:
        return "Suspicious"
    if v in ["Low Risk"]:
        return "Low Risk"
    return "Safe"

def validate_url(raw: str):
    value = raw.strip()
    if not value:
        return None, "Please enter a website link first."
    if len(value) > 2048:
        return None, "Website address is too long."
    if not re.match(r"^https?://", value, flags=re.I):
        value = "https://" + value
    try:
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return None, "Please enter a valid website address (e.g. google.com)."
        if any(ord(ch) < 32 or ch.isspace() for ch in value):
            return None, "Website address contains spaces or invalid characters."
        return value, None
    except Exception:
        return None, "Could not read this website address format."

def save_scan(url: str, verdict: str, risk: int, prob: float, indicators: list):
    with sqlite3.connect(DB_PATH) as con:
        con.execute(
            "INSERT INTO scans(scanned_at, url, verdict, risk_score, phishing_probability, indicators) VALUES(?,?,?,?,?,?)",
            (
                datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
                url,
                verdict,
                int(risk),
                float(prob),
                json.dumps(indicators)
            )
        )

def read_history(limit=250):
    with sqlite3.connect(DB_PATH) as con:
        df = pd.read_sql_query(
            "SELECT id, scanned_at, url, verdict, risk_score, phishing_probability FROM scans ORDER BY id DESC LIMIT ?",
            con, params=(limit,)
        )
        if not df.empty:
            df["Risk Level"] = df["verdict"].apply(normalize_tier)
        return df

model = load_model()

# ================= SIDEBAR =================
with st.sidebar:
    st.markdown("## 🛡️ IntelliGuard")
    st.caption("URL Security Workspace")
    
    page = st.radio(
        "Navigation",
        ["Analyse a URL", "Batch Scanner", "Scan History"],
        label_visibility="collapsed"
    )
    
    st.divider()
    st.markdown("""
    <div style="font-size:0.85rem; line-height:1.6; color:#94a3b8;">
        <b style="color:#f1f5f9;">About IntelliGuard:</b><br>
        IntelliGuard inspects website links to detect fake imitations, scams, and unsafe sites before you click on them.
    </div>
    """, unsafe_allow_html=True)
    st.caption("Local analysis • Does not visit submitted websites.")

if model is None:
    st.error("⚠️ The safety engine model file is missing. Please run `python train_model.py` first.")
    st.stop()

# ================= PAGE 1: ANALYSE A URL (MATCHING IMAGE 2) =================
if page == "Analyse a URL":
    # Top banner matching Image 2
    st.markdown('<div class="top-header-banner">🛡️ <b>IntelliGuard</b> • Intelligent URL detection • Phishing indicators • Machine-learning risk assessment</div>', unsafe_allow_html=True)
    
    st.markdown("## Analyse a URL")
    st.write("Paste a link below. IntelliGuard analyses its text and structure without opening the website.")

    # Sample presets
    st.write("**Try a sample link:**")
    ex1, ex2, ex3, ex4, ex5 = st.columns(5)
    preset_url = None
    with ex1:
        if st.button("🟢 Google", use_container_width=True):
            preset_url = "https://google.com/login"
    with ex2:
        if st.button("🟢 GitHub", use_container_width=True):
            preset_url = "https://github.com/AnjanaKsanthosh"
    with ex3:
        if st.button("🔴 Fake PayPal", use_container_width=True):
            preset_url = "https://paypal.com.verify-user-security.ru/signin"
    with ex4:
        if st.button("🔴 Fake Bank", use_container_width=True):
            preset_url = "http://secure-banking-alert.xyz/account/login"
    with ex5:
        if st.button("🟠 Short Link", use_container_width=True):
            preset_url = "https://bit.ly/3xYz123"

    if preset_url:
        st.session_state["active_input_link"] = preset_url

    default_value = st.session_state.get("active_input_link", "")

    # URL Input Form matching Image 2
    with st.form("analyse_form"):
        raw_input = st.text_input(
            "Website URL",
            value=default_value,
            placeholder="Paste any website link here (e.g. http://example.com/login)..."
        )
        submitted = st.form_submit_button("🛡️ Analyse URL", use_container_width=True)

    if submitted and raw_input.strip():
        st.session_state["active_input_link"] = raw_input.strip()

    target_to_scan = raw_input.strip() if submitted else (preset_url or default_value.strip())
    should_run = (submitted and bool(raw_input.strip())) or (preset_url is not None)

    if should_run and target_to_scan:
        clean_url, error = validate_url(target_to_scan)
        if error:
            st.error(error)
        else:
            with st.spinner("Analysing link..."):
                res = evaluate_url_threat(model, clean_url)

            # Save scan record
            save_scan(
                clean_url,
                res["risk_tier"],
                res["risk_score"],
                res["phishing_probability"],
                res["indicators"]
            )

            risk = res["risk_score"]
            tier = res["risk_tier"]
            prob = res["phishing_probability"]
            features = res["features"]

            # 3 Clean Metric Cards matching Image 2
            col1, col2, col3 = st.columns(3)
            col1.metric("Risk score", f"{risk}/100")
            col2.metric("Model phishing score", f"{prob*100:.1f}%")
            col3.metric("Detection", tier)

            # Native Streamlit Progress Bar matching Image 2
            st.progress(risk / 100)

            # Status Banner Alert matching Image 2
            if tier == "Safe":
                st.success("✅ Clean link. This website looks genuine and safe to visit.")
            elif tier == "Low Risk":
                st.info("ℹ️ Low risk. This website appears normal with no scam signals detected.")
            elif tier == "Suspicious":
                st.warning("⚠️ Some suspicious characteristics were found. Verify the destination independently before entering passwords.")
            else:
                st.error("🚨 High-risk indicators detected. Do not enter passwords, payment details, or personal information.")

            # What to do (plain language guidance)
            st.markdown(f"**Action advice:** {res['action_advice']}")

            # URL Profile Section matching Image 2
            st.markdown("### URL profile")
            u1, u2, u3 = st.columns(3)
            u1.write(f"**Hostname:** {features['hostname']}")
            u2.write(f"**Protocol:** {features['scheme'].upper()}")
            u3.write(f"**Length:** {len(clean_url)} characters")

            # Detection Explanations / Indicators Section matching Image 2
            st.markdown("### Detection explanations")
            if res["indicators"]:
                for ind in res["indicators"]:
                    sev = ind.get("severity", "info")
                    icon = "🚨" if sev == "critical" else ("⚠️" if sev == "warning" else ("✅" if sev == "safe" else "ℹ️"))
                    st.write(f"{icon} **{ind['title']}:** {ind['description']}")
            else:
                st.write("✅ No warning indicators triggered.")

# ================= PAGE 2: BATCH SCANNER =================
elif page == "Batch Scanner":
    st.markdown('<div class="top-header-banner">📁 <b>Batch Scanner</b> • Check Multiple URLs Simultaneously</div>', unsafe_allow_html=True)
    st.markdown("## Batch URL analysis")
    st.write("Upload a CSV file containing a column named `url` or paste links below.")

    input_mode = st.radio("Choose input method:", ["Paste links (one per line)", "Upload a CSV file"], horizontal=True)

    urls_list = []
    if input_mode == "Paste links (one per line)":
        pasted = st.text_area(
            "Paste URLs (one per line)",
            height=140,
            placeholder="https://google.com\nhttps://paypal.com.verify-user.ru\nhttps://github.com"
        )
        if pasted:
            urls_list = [line.strip() for line in pasted.strip().split("\n") if line.strip()]
    else:
        uploaded_file = st.file_uploader("Upload CSV file", type=["csv"])
        if uploaded_file:
            try:
                frame = pd.read_csv(uploaded_file)
                url_col = next((c for c in frame.columns if str(c).strip().lower() in ["url", "link", "website"]), None)
                if url_col:
                    urls_list = frame[url_col].dropna().astype(str).tolist()
                    st.success(f"Loaded {len(urls_list)} URLs from CSV.")
                else:
                    st.error("CSV must contain a column named 'url' or 'link'.")
            except Exception as exc:
                st.error(f"Error reading CSV: {exc}")

    if urls_list:
        st.write(f"**Total URLs to analyse:** {len(urls_list)}")
        if st.button("🚀 Analyse All URLs", use_container_width=True):
            prog = st.progress(0)
            batch_data = []

            for i, raw in enumerate(urls_list):
                url, err = validate_url(raw)
                if err:
                    batch_data.append({
                        "URL": raw,
                        "Detection": "Invalid URL",
                        "Risk score": 0,
                        "Phishing score": "0.0%",
                        "Key Indicator": err
                    })
                else:
                    eval_res = evaluate_url_threat(model, url)
                    save_scan(url, eval_res["risk_tier"], eval_res["risk_score"], eval_res["phishing_probability"], eval_res["indicators"])
                    first_ind = eval_res["indicators"][0]["title"] if eval_res["indicators"] else "Clean"
                    batch_data.append({
                        "URL": url,
                        "Detection": eval_res["risk_tier"],
                        "Risk score": eval_res["risk_score"],
                        "Phishing score": f"{eval_res['phishing_probability']*100:.1f}%",
                        "Key Indicator": first_ind
                    })
                prog.progress((i + 1) / len(urls_list))

            st.success("✅ Batch analysis completed!")
            out_df = pd.DataFrame(batch_data)
            st.dataframe(out_df, use_container_width=True, hide_index=True)

            csv_exp = out_df.to_csv(index=False).encode("utf-8")
            st.download_button("⬇️ Download Report (CSV)", csv_exp, "intelliguard_batch_report.csv", "text/csv")

# ================= PAGE 3: SCAN HISTORY =================
elif page == "Scan History":
    st.markdown('<div class="top-header-banner">🕒 <b>Scan History</b> • Previously Checked Links Log</div>', unsafe_allow_html=True)
    st.markdown("## Local scan history")
    
    history_df = read_history(limit=250)
    if history_df.empty:
        st.info("No scan records available yet.")
    else:
        st.write(f"Showing **{len(history_df)}** recorded scans.")
        
        filter_opt = st.selectbox("Filter by Detection:", ["All", "High Risk", "Suspicious", "Low Risk", "Safe"])
        
        filtered = history_df.copy()
        if filter_opt != "All":
            filtered = filtered[filtered["Risk Level"] == filter_opt]
            
        show_table = filtered[["scanned_at", "url", "Risk Level", "risk_score"]].copy()
        show_table.columns = ["Time Scanned", "Website URL", "Detection", "Risk Score"]
        
        st.dataframe(show_table, use_container_width=True, hide_index=True)

        d1, d2 = st.columns(2)
        with d1:
            csv_data = history_df.to_csv(index=False).encode("utf-8")
            st.download_button("⬇️ Export Full History (CSV)", csv_data, "intelliguard_history.csv", "text/csv")
        with d2:
            if st.button("🗑️ Clear All Scan History"):
                with sqlite3.connect(DB_PATH) as con:
                    con.execute("DELETE FROM scans")
                st.success("History cleared. Refresh the page to update.")

st.divider()
st.caption("IntelliGuard • Intelligent URL Detection System • Local Academic Prototype")
