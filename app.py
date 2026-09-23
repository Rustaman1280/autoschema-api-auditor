"""
AutoSchema & API Auditor - Streamlit Web Application
Autonomous Security Engineer & Database Performance Architect
Powered by Nebius Token Factory, NVIDIA Nemotron, and Tavily Search API
"""

import os
import sys
import time
from datetime import datetime
from pathlib import Path
import streamlit as st

# Ensure project root is on sys.path
BASE_DIR = Path(__file__).parent.resolve()
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from config import Config
from agent import AutoSchemaAuditorAgent
from tools import ALL_TOOLS, OFFLINE_KNOWLEDGE_BASE
from system_prompt import MASTER_SYSTEM_PROMPT

# Configure Streamlit page
st.set_page_config(
    page_title="AutoSchema & API Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS styling for modern cybersecurity / developer look
st.markdown("""
<style>
    .main-title {
        font-size: 2.2rem;
        font-weight: 800;
        margin-bottom: 0.2rem;
        color: #1E293B;
    }
    .badge-pill {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        font-size: 0.85rem;
        font-weight: 600;
        border-radius: 9999px;
        background: linear-gradient(135deg, #6366F1, #8B5CF6);
        color: #ffffff;
        margin-bottom: 1rem;
        letter-spacing: 0.03em;
    }
    .badge-sub {
        display: inline-block;
        padding: 0.2rem 0.6rem;
        font-size: 0.8rem;
        font-weight: 600;
        border-radius: 6px;
        background-color: #0F172A;
        color: #38BDF8;
        margin-left: 0.5rem;
    }
    .risk-critical {
        background-color: #FEE2E2;
        color: #991B1B;
        padding: 0.4rem 0.8rem;
        border-radius: 6px;
        font-weight: 700;
        display: inline-block;
    }
    .stTextArea textarea {
        font-family: 'Fira Code', 'Courier New', monospace;
        font-size: 0.88rem;
    }
</style>
""", unsafe_allow_html=True)

# Initialize Session State
if "schema_content" not in st.session_state:
    st.session_state["schema_content"] = ""
if "api_content" not in st.session_state:
    st.session_state["api_content"] = ""
if "audit_report" not in st.session_state:
    st.session_state["audit_report"] = None
if "audit_target_name" not in st.session_state:
    st.session_state["audit_target_name"] = "audit_report"

# Helper to load sample files
def load_sample_file(relative_path: str) -> str:
    file_path = BASE_DIR / relative_path
    if file_path.exists():
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    return ""

# ==============================================================================
# SIDEBAR CONFIGURATION
# ==============================================================================
with st.sidebar:
    st.image("https://img.icons8.com/isometric/100/database-administrator.png", width=64)
    st.title("Audit Settings")
    st.markdown("Configure runtime execution & intelligence providers.")

    # Execution Mode
    mode_selection = st.radio(
        "Execution Mode",
        options=["Simulation / Dry-Run", "Live API (Nebius + Tavily)"],
        index=0 if not Config.is_nebius_configured() else 1,
        help="Simulation mode uses high-fidelity deterministic engine with verified offline CVE cache. Live mode calls Nebius Token Factory and Tavily directly."
    )
    is_mock = (mode_selection == "Simulation / Dry-Run")

    st.divider()

    # API Credentials (Collapsible or visible if live)
    with st.expander("API Keys & Engine Parameters", expanded=(not is_mock)):
        nebius_key_input = st.text_input(
            "Nebius API Key",
            value=Config.NEBIUS_API_KEY,
            type="password",
            placeholder="api-key-here",
            help="Your Nebius Studio Token Factory key"
        )
        tavily_key_input = st.text_input(
            "Tavily API Key",
            value=Config.TAVILY_API_KEY,
            type="password",
            placeholder="tvly-...",
            help="Tavily Search API key for live CVE/advisory search"
        )
        model_choice = st.selectbox(
            "Reasoning Engine (Nebius)",
            options=[
                "nvidia/nemotron-3-super-120b-instruct",
                "meta-llama/llama-3.1-70b-instruct",
                "meta-llama/llama-3.1-405b-instruct"
            ],
            index=0,
            help="Recommended: NVIDIA Nemotron on Nebius Token Factory for tool-calling discipline"
        )
        temp_slider = st.slider(
            "Sampling Temperature",
            min_value=0.0,
            max_value=1.0,
            value=Config.TEMPERATURE,
            step=0.05,
            help="Keep between 0.1 - 0.2 for strict SQL syntax and format compliance"
        )

    st.divider()

    # Quick Samples
    st.subheader("Quick Test Samples")
    st.caption("Load realistic test cases containing known security and performance flaws:")

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        if st.button("Schema Sample", use_container_width=True, help="Load ecommerce_schema.sql (Unindexed FKs, plaintext passwords/cards, missing RLS)"):
            sample_sql = load_sample_file("sample_inputs/ecommerce_schema.sql")
            st.session_state["schema_content"] = sample_sql
            st.session_state["audit_target_name"] = "ecommerce_schema"
            st.session_state["audit_report"] = None
            st.rerun()

    with col_btn2:
        if st.button("API Sample", use_container_width=True, help="Load order_controller.ts (SQL injection, BOLA/IDOR, N+1 query loop)"):
            sample_ts = load_sample_file("sample_inputs/order_controller.ts")
            st.session_state["api_content"] = sample_ts
            st.session_state["audit_target_name"] = "order_controller"
            st.session_state["audit_report"] = None
            st.rerun()

    st.markdown("""
    ---
    **Standard References:**
    - OWASP Top 10 & API Security 2023
    - CWE-89 (SQLi) & CWE-312 (Cleartext)
    - PostgreSQL Concurrency & Non-blocking DDL
    """)

# ==============================================================================
# MAIN VIEW: HEADER
# ==============================================================================
st.markdown('<div class="main-title">AutoSchema & API Auditor 🛡️⚡</div>', unsafe_allow_html=True)
st.markdown(
    '<span class="badge-pill">Powered by Nebius Token Factory & NVIDIA Nemotron</span>'
    '<span class="badge-sub">Tavily Verified Intelligence</span>',
    unsafe_allow_html=True
)

st.write(
    "Autonomous security engineer and database performance architect. "
    "Analyzes schemas and API controllers, verifies threats in real-time, and outputs production-ready non-blocking migrations & hardened code."
)

st.write("")

# ==============================================================================
# MAIN TABS: SCHEMA vs API AUDIT
# ==============================================================================
tab_schema, tab_api = st.tabs(["📊 Database Schema Audit", "⚡ API Endpoint Audit"])

target_content = ""
current_audit_type = "schema"

with tab_schema:
    st.markdown("#### Input Database Schema (SQL DDL / Prisma)")
    uploaded_sql = st.file_uploader(
        "Upload Schema File (.sql, .ddl, .prisma)",
        type=["sql", "ddl", "prisma"],
        key="uploader_sql"
    )
    if uploaded_sql is not None:
        try:
            st.session_state["schema_content"] = uploaded_sql.read().decode("utf-8")
            st.session_state["audit_target_name"] = Path(uploaded_sql.name).stem
        except Exception as e:
            st.error(f"Error reading uploaded file: {e}")

    schema_text = st.text_area(
        "Schema Definition (DDL / Table Constraints)",
        value=st.session_state["schema_content"],
        height=280,
        placeholder="CREATE TABLE users (\n    id UUID PRIMARY KEY,\n    email VARCHAR(255) NOT NULL,\n    password VARCHAR(255) NOT NULL -- Plaintext risk\n);",
        key="schema_text_input"
    )
    st.session_state["schema_content"] = schema_text

with tab_api:
    st.markdown("#### Input API Controller / Query Handler")
    uploaded_api = st.file_uploader(
        "Upload Controller File (.ts, .js, .py, .java)",
        type=["ts", "js", "py", "java"],
        key="uploader_api"
    )
    if uploaded_api is not None:
        try:
            st.session_state["api_content"] = uploaded_api.read().decode("utf-8")
            st.session_state["audit_target_name"] = Path(uploaded_api.name).stem
        except Exception as e:
            st.error(f"Error reading uploaded file: {e}")

    api_text = st.text_area(
        "Handler Code (TypeScript / JavaScript / Python / SQL queries)",
        value=st.session_state["api_content"],
        height=280,
        placeholder="export async function getOrder(req, res) {\n    const id = req.params.id;\n    const order = await db.query(`SELECT * FROM orders WHERE id = '${id}'`);\n    return res.json(order);\n}",
        key="api_text_input"
    )
    st.session_state["api_content"] = api_text

# Determine active target based on content presence
if tab_schema and st.session_state["schema_content"].strip():
    target_content = st.session_state["schema_content"].strip()
    current_audit_type = "Database Schema"
elif tab_api and st.session_state["api_content"].strip():
    target_content = st.session_state["api_content"].strip()
    current_audit_type = "API Endpoint"
else:
    # Fallback to whichever has text
    if st.session_state["schema_content"].strip():
        target_content = st.session_state["schema_content"].strip()
        current_audit_type = "Database Schema"
    elif st.session_state["api_content"].strip():
        target_content = st.session_state["api_content"].strip()
        current_audit_type = "API Endpoint"

# Action Button
st.write("")
col_run, col_clear, col_info = st.columns([1.5, 0.8, 3.7])

with col_run:
    run_btn = st.button("🚀 Run Autonomous Audit", type="primary", use_container_width=True)

with col_clear:
    if st.button("🧹 Clear", use_container_width=True):
        st.session_state["schema_content"] = ""
        st.session_state["api_content"] = ""
        st.session_state["audit_report"] = None
        st.rerun()

with col_info:
    if is_mock:
        st.info("ℹ️ Mode: **Simulation / Dry-Run** (Instant verification with built-in threat intelligence cache).")
    else:
        st.success(f"⚡ Mode: **Live Nebius Token Factory** (`{model_choice}`)")

# ==============================================================================
# AUDIT EXECUTION ENGINE
# ==============================================================================
if run_btn:
    if not target_content:
        st.warning("⚠️ Please provide a database schema (SQL) or API controller code first, or click 'Load Sample' in the sidebar.")
    else:
        status_box = st.status("Initializing AutoSchema & API Auditor...", expanded=True)
        live_steps = []

        def agent_callback(event: str, data: dict):
            if event == "step_start":
                status_box.update(label=f"Phase 1: Intake & Triage (Analyzing AST & Risk Vectors)...", state="running")
                live_steps.append("🔍 **Intake & Triage**: Parsed AST data models, constraints, and auth boundaries.")
            elif event == "tool_call":
                query = data.get("args", {}).get("query", "")
                status_box.update(label=f"Phase 2: Live Intelligence Research via Tavily...", state="running")
                live_steps.append(f"🌐 **Tavily Query**: `{query}`")
            elif event == "tool_result":
                out_snippet = str(data.get("output", ""))[:120].replace("\n", " ")
                live_steps.append(f"📚 **Verified Threat Data**: *\"{out_snippet}...\"*")
            elif event == "completed":
                status_box.update(label="Phase 3: Impact Evaluation & Patch Synthesis Complete!", state="complete")
                live_steps.append("✅ **Synthesis Finished**: Non-blocking UP/DOWN SQL scripts and hardened controller ready.")

        try:
            # Configure agent instance
            agent = AutoSchemaAuditorAgent(
                api_key=nebius_key_input if not is_mock else "",
                model_name=model_choice,
                temperature=temp_slider
            )

            # Update status box in real-time
            status_box.write("⚙️ Initializing autonomous execution loop...")
            time.sleep(0.3)

            report = agent.audit(
                input_content=target_content,
                on_step_callback=agent_callback,
                force_simulation=is_mock
            )

            for step in live_steps:
                status_box.write(step)

            status_box.update(label="Audit Process Finished Successfully!", state="complete", expanded=False)
            st.session_state["audit_report"] = report

        except Exception as err:
            status_box.update(label="Audit encountered an error", state="error", expanded=True)
            st.error(f"Execution Error: {err}")

# ==============================================================================
# REPORT RENDERING & EXPORT
# ==============================================================================
if st.session_state["audit_report"]:
    st.divider()
    col_rep_head, col_rep_dl = st.columns([4, 1.2])
    with col_rep_head:
        st.subheader("📑 Production Audit & Remediation Report")
    with col_rep_dl:
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_name = f"audit_report_{st.session_state['audit_target_name']}_{timestamp_str}.md"
        st.download_button(
            label="📥 Download Report (.md)",
            data=st.session_state["audit_report"],
            file_name=file_name,
            mime="text/markdown",
            use_container_width=True
        )

    # Render report markdown with rich code block support
    st.markdown(st.session_state["audit_report"])
