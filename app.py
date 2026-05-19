import streamlit as st
import tempfile
import os
from modules.malware_analyzer import predict_file
from modules.pentest_assistant import analyze_target
from modules.llm_explainer import explain_malware_result, explain_pentest_analysis

st.set_page_config(
    page_title="CyberMind — AI Cybersecurity Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── CSS PROFESSIONNEL ──
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');

    * { font-family: 'Inter', sans-serif; }

    .stApp {
        background: linear-gradient(135deg, #020818 0%, #0a1628 50%, #020818 100%);
        color: #e2e8f0;
    }

    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0d1f3c 0%, #071223 100%);
        border-right: 1px solid rgba(99, 179, 237, 0.2);
    }

    .hero-section {
        text-align: center;
        padding: 3rem 0 2rem 0;
    }

    .hero-badge {
        display: inline-block;
        background: rgba(99, 179, 237, 0.1);
        border: 1px solid rgba(99, 179, 237, 0.3);
        color: #63b3ed;
        padding: 0.3rem 1rem;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
        letter-spacing: 2px;
        text-transform: uppercase;
        margin-bottom: 1rem;
    }

    .hero-title {
        font-size: 3.5rem;
        font-weight: 800;
        background: linear-gradient(135deg, #ffffff 0%, #63b3ed 50%, #9f7aea 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        line-height: 1.1;
        margin-bottom: 0.5rem;
    }

    .hero-subtitle {
        color: #718096;
        font-size: 1.1rem;
        font-weight: 300;
        margin-bottom: 2rem;
    }

    .stat-card {
        background: linear-gradient(135deg, rgba(13, 31, 60, 0.8), rgba(7, 18, 35, 0.8));
        border: 1px solid rgba(99, 179, 237, 0.15);
        border-radius: 16px;
        padding: 1.5rem;
        text-align: center;
        transition: all 0.3s ease;
        backdrop-filter: blur(10px);
    }

    .stat-number {
        font-size: 2rem;
        font-weight: 800;
        color: #63b3ed;
    }

    .stat-label {
        font-size: 0.85rem;
        color: #718096;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    .section-title {
        font-size: 1.8rem;
        font-weight: 700;
        color: #ffffff;
        margin-bottom: 0.5rem;
    }

    .section-subtitle {
        color: #718096;
        font-size: 0.95rem;
        margin-bottom: 2rem;
    }

    .verdict-malware {
        background: linear-gradient(135deg, #c53030, #e53e3e);
        color: white;
        padding: 1rem 2rem;
        border-radius: 12px;
        font-size: 1.3rem;
        font-weight: 700;
        display: inline-block;
        box-shadow: 0 0 30px rgba(229, 62, 62, 0.4);
        animation: pulse-red 2s infinite;
    }

    .verdict-benin {
        background: linear-gradient(135deg, #276749, #38a169);
        color: white;
        padding: 1rem 2rem;
        border-radius: 12px;
        font-size: 1.3rem;
        font-weight: 700;
        display: inline-block;
        box-shadow: 0 0 30px rgba(56, 161, 105, 0.4);
    }

    @keyframes pulse-red {
        0% { box-shadow: 0 0 20px rgba(229, 62, 62, 0.4); }
        50% { box-shadow: 0 0 40px rgba(229, 62, 62, 0.8); }
        100% { box-shadow: 0 0 20px rgba(229, 62, 62, 0.4); }
    }

    .feature-card {
        background: rgba(13, 31, 60, 0.6);
        border: 1px solid rgba(99, 179, 237, 0.15);
        border-radius: 12px;
        padding: 1.5rem;
        margin-bottom: 1rem;
        backdrop-filter: blur(10px);
    }

    .cve-card {
        background: rgba(13, 31, 60, 0.5);
        border-left: 3px solid #63b3ed;
        border-radius: 8px;
        padding: 0.8rem 1rem;
        margin-bottom: 0.5rem;
    }

    .cve-critical { border-left-color: #e53e3e; }
    .cve-high { border-left-color: #ed8936; }
    .cve-medium { border-left-color: #ecc94b; }
    .cve-low { border-left-color: #48bb78; }

    .nav-item {
        color: #a0aec0;
        font-size: 0.9rem;
        padding: 0.5rem;
    }

    .divider {
        border: none;
        height: 1px;
        background: linear-gradient(90deg, transparent, rgba(99, 179, 237, 0.3), transparent);
        margin: 1.5rem 0;
    }

    .stButton > button {
        background: linear-gradient(135deg, #2b6cb0, #3182ce) !important;
        color: white !important;
        border: none !important;
        border-radius: 10px !important;
        padding: 0.6rem 2rem !important;
        font-weight: 600 !important;
        font-size: 0.95rem !important;
        width: 100% !important;
        transition: all 0.3s ease !important;
        box-shadow: 0 4px 15px rgba(49, 130, 206, 0.3) !important;
    }

    .stButton > button:hover {
        background: linear-gradient(135deg, #3182ce, #4299e1) !important;
        box-shadow: 0 6px 20px rgba(49, 130, 206, 0.5) !important;
        transform: translateY(-2px) !important;
    }

    .stTextArea textarea, .stTextInput input {
        background: rgba(13, 31, 60, 0.8) !important;
        border: 1px solid rgba(99, 179, 237, 0.2) !important;
        color: #e2e8f0 !important;
        border-radius: 10px !important;
    }

    [data-testid="stMetric"] {
        background: rgba(13, 31, 60, 0.6);
        border: 1px solid rgba(99, 179, 237, 0.15);
        border-radius: 12px;
        padding: 1rem;
        backdrop-filter: blur(10px);
    }

    [data-testid="stMetricValue"] {
        color: #63b3ed !important;
        font-weight: 700 !important;
    }

    .stProgress > div > div {
        background: linear-gradient(90deg, #3182ce, #e53e3e) !important;
        border-radius: 10px !important;
    }

    .stTabs [data-baseweb="tab"] {
        background: transparent !important;
        color: #718096 !important;
        border-radius: 8px !important;
        font-weight: 500 !important;
    }

    .stTabs [aria-selected="true"] {
        background: rgba(49, 130, 206, 0.2) !important;
        color: #63b3ed !important;
        border-bottom: 2px solid #63b3ed !important;
    }

    [data-testid="stExpander"] {
        background: rgba(13, 31, 60, 0.5) !important;
        border: 1px solid rgba(99, 179, 237, 0.15) !important;
        border-radius: 10px !important;
    }

    .stAlert {
        border-radius: 10px !important;
        border: none !important;
    }

    ::-webkit-scrollbar { width: 6px; }
    ::-webkit-scrollbar-track { background: #020818; }
    ::-webkit-scrollbar-thumb { background: #2b6cb0; border-radius: 3px; }
</style>
""", unsafe_allow_html=True)

# ── SIDEBAR ──
with st.sidebar:
    st.markdown("""
    <div style='text-align:center; padding: 1rem 0;'>
        <div style='font-size:2.5rem;'>🛡️</div>
        <div style='font-size:1.3rem; font-weight:800; color:#ffffff;'>CyberMind</div>
        <div style='font-size:0.75rem; color:#63b3ed; letter-spacing:2px;'>AI SECURITY PLATFORM</div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<hr class='divider'>", unsafe_allow_html=True)
    
    st.markdown("<div style='color:#718096; font-size:0.75rem; letter-spacing:1px; text-transform:uppercase; margin-bottom:0.5rem;'>Navigation</div>", unsafe_allow_html=True)
    
    module = st.radio("", [
        "🦠 Malware Analysis",
        "🔍 Pentest Assistant",
        "📊 Big Data Dashboard"
    ], label_visibility="collapsed")
    
    st.markdown("<hr class='divider'>", unsafe_allow_html=True)
    
    st.markdown("""
    <div style='color:#718096; font-size:0.75rem; letter-spacing:1px; text-transform:uppercase; margin-bottom:0.8rem;'>Tech Stack</div>
    <div style='font-size:0.85rem; color:#a0aec0; line-height:2;'>
        🐍 Python 3.11<br>
        🤖 LLaMA 3.3 — Groq<br>
        🧠 ChromaDB RAG<br>
        🌲 Random Forest ML<br>
        📊 Streamlit<br>
        ⚡ Kafka + Elasticsearch
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<hr class='divider'>", unsafe_allow_html=True)
    st.markdown("<div style='color:#4a5568; font-size:0.75rem; text-align:center;'>CyberMind v1.0 — Enterprise Project<br>Cybersecurity · AI · Big Data</div>", unsafe_allow_html=True)

# ── HERO HEADER ──
st.markdown("""
<div class='hero-section'>
    <div class='hero-badge'>🔒 AI-Powered Cybersecurity</div>
    <div class='hero-title'>CyberMind</div>
    <div class='hero-subtitle'>
        Plateforme intelligente de détection de cybermenaces<br>
        <span style='color:#63b3ed;'>Malware Detection · Pentest Assistant · Real-Time Analytics</span>
    </div>
</div>
""", unsafe_allow_html=True)

st.markdown("<hr class='divider'>", unsafe_allow_html=True)

# ── MODULE 1 : MALWARE ──
if module == "🦠 Malware Analysis":
    
    st.markdown("""
    <div class='section-title'>🦠 Malware Analysis Engine</div>
    <div class='section-subtitle'>Upload an executable file — our ML model detects threats in seconds / Uploadez un fichier exécutable pour détecter les menaces</div>
    """, unsafe_allow_html=True)

    col_upload, col_info = st.columns([2, 1])

    with col_upload:
        uploaded_file = st.file_uploader(
            "📁 Drop your file here / Déposez votre fichier ici",
            type=["exe", "dll", "bin"],
            help="Supported formats: .exe, .dll, .bin"
        )

    with col_info:
        st.markdown("""
        <div class='feature-card'>
            <div style='color:#63b3ed; font-weight:600; margin-bottom:0.8rem;'>⚡ How it works</div>
            <div style='color:#a0aec0; font-size:0.85rem; line-height:2;'>
                1️⃣ Upload the file<br>
                2️⃣ ML extracts PE features<br>
                3️⃣ Random Forest predicts<br>
                4️⃣ AI generates report
            </div>
        </div>
        """, unsafe_allow_html=True)

    if uploaded_file:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(uploaded_file.read())
            tmp_path = tmp.name

        with st.spinner("🔬 Analyzing file... / Analyse en cours..."):
            result, error = predict_file(tmp_path)
        os.unlink(tmp_path)

        if error:
            st.error(f"❌ Error: {error}")
        else:
            st.markdown("<hr class='divider'>", unsafe_allow_html=True)
            
            col_verdict, col_metrics = st.columns([1, 2])
            
            with col_verdict:
                st.markdown("<div style='color:#a0aec0; font-size:0.85rem; margin-bottom:0.8rem;'>VERDICT</div>", unsafe_allow_html=True)
                if result["label"] == "MALWARE":
                    st.markdown('<div class="verdict-malware">☠️ MALWARE DETECTED</div>', unsafe_allow_html=True)
                else:
                    st.markdown('<div class="verdict-benin">✅ FILE IS SAFE</div>', unsafe_allow_html=True)

            with col_metrics:
                c1, c2, c3 = st.columns(3)
                c1.metric("🎯 Confidence", f"{result['confidence']}%")
                c2.metric("☠️ Malware Score", f"{result['proba_malware']}%")
                c3.metric("✅ Safe Score", f"{result['proba_benign']}%")

            st.markdown("<div style='color:#a0aec0; font-size:0.85rem; margin: 1rem 0 0.3rem;'>Threat Level</div>", unsafe_allow_html=True)
            st.progress(result["proba_malware"] / 100)

            with st.expander("🔬 Technical Details — PE Features Extracted"):
                st.json(result["features"])

            st.markdown("<hr class='divider'>", unsafe_allow_html=True)

            with st.spinner("🤖 AI generating analysis report..."):
                explanation = explain_malware_result(result, uploaded_file.name)

            st.markdown("""
            <div style='color:#63b3ed; font-size:1.1rem; font-weight:600; margin-bottom:1rem;'>
                🤖 AI Analysis Report / Rapport d'analyse IA
            </div>
            """, unsafe_allow_html=True)
            st.markdown(explanation)

            try:
                from modules.bigdata_pipeline import send_to_kafka
                send_to_kafka("malware_results", {
                    "file": uploaded_file.name,
                    "label": result["label"],
                    "confidence": result["confidence"],
                    "proba_malware": result["proba_malware"]
                })
                st.success("✅ Result sent to Big Data pipeline")
            except:
                st.info("ℹ️ Big Data pipeline not connected yet")

# ── MODULE 2 : PENTEST ──
elif module == "🔍 Pentest Assistant":

    st.markdown("""
    <div class='section-title'>🔍 Pentest Assistant</div>
    <div class='section-subtitle'>Analyze network scans and identify vulnerabilities with AI / Analysez vos scans et identifiez les vulnérabilités</div>
    """, unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["📡 Nmap Scan Analysis", "💬 Free Question / Question libre"])

    with tab1:
        st.markdown("<div style='color:#a0aec0; margin-bottom:0.5rem;'>Paste your nmap scan output below / Collez votre scan nmap ci-dessous</div>", unsafe_allow_html=True)
        
        nmap_output = st.text_area(
            "",
            placeholder="22/tcp  open  ssh     OpenSSH 7.9\n80/tcp  open  http    Apache 2.4.38\n443/tcp open  https   Apache 2.4.38\n3306/tcp open mysql   MySQL 5.7",
            height=200,
            label_visibility="collapsed"
        )

        if st.button("🔍 Analyze Target / Analyser la cible") and nmap_output:
            with st.spinner("🔎 Searching for vulnerabilities / Recherche de vulnérabilités..."):
                target_data = analyze_target(nmap_output=nmap_output)
                report = explain_pentest_analysis(
                    target_data,
                    "Analyze this nmap scan and identify security risks"
                )

            st.markdown("<hr class='divider'>", unsafe_allow_html=True)
            st.markdown("<div style='color:#63b3ed; font-size:1.1rem; font-weight:600; margin-bottom:1rem;'>📋 Pentest Report / Rapport de Pentest</div>", unsafe_allow_html=True)
            st.markdown(report)

            if target_data.get("relevant_cves"):
                st.markdown("<hr class='divider'>", unsafe_allow_html=True)
                st.markdown("<div style='color:#ed8936; font-size:1.1rem; font-weight:600; margin-bottom:1rem;'>⚠️ Relevant CVEs Detected</div>", unsafe_allow_html=True)
                for cve in target_data["relevant_cves"][:5]:
                    severity = cve["severity"]
                    css_class = {
                        "CRITICAL": "cve-critical",
                        "HIGH": "cve-high",
                        "MEDIUM": "cve-medium",
                        "LOW": "cve-low"
                    }.get(severity, "")
                    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")
                    st.markdown(f"""
                    <div class='cve-card {css_class}'>
                        {icon} <strong>{cve['id']}</strong> 
                        <span style='color:#718096; font-size:0.8rem;'>[{severity}]</span><br>
                        <span style='color:#a0aec0; font-size:0.85rem;'>{cve['description'][:220]}...</span>
                    </div>
                    """, unsafe_allow_html=True)

    with tab2:
        st.markdown("<div style='color:#a0aec0; margin-bottom:0.5rem;'>Ask any cybersecurity question / Posez votre question</div>", unsafe_allow_html=True)
        question = st.text_input(
            "",
            placeholder="Ex: What are the vulnerabilities of Apache 2.4? / Quelles sont les failles d'Apache 2.4 ?",
            label_visibility="collapsed"
        )
        if st.button("💬 Ask AI / Demander à l'IA") and question:
            with st.spinner("🤖 AI analyzing... / Analyse en cours..."):
                target_data = analyze_target(target_description=question)
                answer = explain_pentest_analysis(target_data, question)
            st.markdown("<hr class='divider'>", unsafe_allow_html=True)
            st.markdown(answer)

# ── MODULE 3 : BIG DATA ──
elif module == "📊 Big Data Dashboard":

    st.markdown("""
    <div class='section-title'>📊 Big Data Dashboard</div>
    <div class='section-subtitle'>Real-time analytics of all threat detections / Statistiques en temps réel de toutes les détections</div>
    """, unsafe_allow_html=True)

    try:
        from modules.bigdata_pipeline import get_stats, get_recent_analyses
        import plotly.express as px
        import pandas as pd

        stats = get_stats()

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("🔍 Total Analyses", stats.get("total", 0))
        c2.metric("🔴 Malwares Detected", stats.get("malwares", 0))
        c3.metric("🟢 Safe Files", stats.get("benign", 0))
        c4.metric("⚠️ Threat Rate", f"{stats.get('rate', 0)}%")

        st.markdown("<hr class='divider'>", unsafe_allow_html=True)

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("<div style='color:#63b3ed; font-weight:600; margin-bottom:1rem;'>Threat Distribution</div>", unsafe_allow_html=True)
            if stats.get("total", 0) > 0:
                fig = px.pie(
                    values=[stats["malwares"], stats["benign"]],
                    names=["Malwares", "Safe Files"],
                    color_discrete_sequence=["#e53e3e", "#38a169"],
                    hole=0.5
                )
                fig.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#a0aec0",
                    legend=dict(bgcolor="rgba(0,0,0,0)")
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No data available yet / Aucune donnée disponible")

        with col2:
            st.markdown("<div style='color:#63b3ed; font-weight:600; margin-bottom:1rem;'>Recent Analyses / Dernières analyses</div>", unsafe_allow_html=True)
            recent = get_recent_analyses(size=10)
            if recent:
                df = pd.DataFrame(recent)
                st.dataframe(df, use_container_width=True, hide_index=True)
            else:
                st.info("No recent analyses / Aucune analyse récente")

        if st.button("🔄 Refresh / Rafraîchir"):
            st.rerun()

    except Exception as e:
        st.markdown("""
        <div class='feature-card' style='text-align:center; padding:3rem;'>
            <div style='font-size:3rem;'>⚡</div>
            <div style='color:#63b3ed; font-size:1.2rem; font-weight:600; margin:1rem 0;'>
                Big Data Pipeline — Coming Soon
            </div>
            <div style='color:#718096;'>
                En attente de la connexion Kafka + Elasticsearch<br>
                Waiting for Kafka + Elasticsearch connection
            </div>
        </div>
        """, unsafe_allow_html=True)