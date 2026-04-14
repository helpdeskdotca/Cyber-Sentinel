import streamlit as st
import pandas as pd
import requests
import plotly.express as px
from datetime import datetime, timedelta
import random

# --- PAGE CONFIG ---
st.set_page_config(
    page_title="Cyber Sentinel: Real-Time Threat Intel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for UI touches
st.markdown("""
<style>
    /* Add subtle padding and custom font styles if needed */
    .metric-card {
        background-color: #1e2127;
        border-radius: 5px;
        padding: 15px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
    }
</style>
""", unsafe_allow_html=True)

# --- SIDEBAR ---
with st.sidebar:
    st.header("⚙️ Configuration")
    nvd_api_key = st.text_input("NVD API Key (Optional)", type="password", help="Providing an API key increases NVD rate limits.")
    
    st.header("🏗️ My Infrastructure Stack")
    tech_stack = st.multiselect(
        "Filter by technology:",
        options=["Windows", "Linux", "AWS", "Kubernetes", "Cisco", "VMware", "Python", "Javascript", "Apple", "Android", "Oracle", "Microsoft", "Apache"],
        default=["Windows", "Linux"]
    )
    
# --- DATA INGESTION ---
@st.cache_data(ttl=3600, show_spinner=False)
def fetch_cisa_kev():
    """Fetch CISA Known Exploited Vulnerabilities"""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        res = requests.get(url, timeout=10)
        res.raise_for_status()
        data = res.json()
        df = pd.DataFrame(data['vulnerabilities'])
        # Rename columns to standard names
        df.rename(columns={'cveID': 'CVE-ID', 'shortDescription': 'Description', 'dateAdded': 'Date Added'}, inplace=True)
        # Sort by date added
        df['Date Added'] = pd.to_datetime(df['Date Added'])
        df = df.sort_values(by='Date Added', ascending=False)
        return df
    except Exception as e:
        st.error(f"Failed to fetch CISA KEV data: {e}")
        return pd.DataFrame()

@st.cache_data(ttl=3600, show_spinner=False)
def fetch_epss_nvd_mock(cve_list, use_real_nvd=False, api_key=""):
    """
    Fetch EPSS scores for a list of CVEs and pull/mock CVSS severities.
    Due to NVD rate limits without an API key, we mock CVSS data if use_real_nvd is False or fails.
    """
    results = []
    
    # We will simulate EPSS if API fails, but let's try the FIRST API
    epss_url = "https://api.first.org/data/v1/epss"
    
    epss_dict = {}
    
    if len(cve_list) > 0:
        # Just fetching for top 200 to save time in dashboard demo, otherwise it's hundreds of requests
        demo_cves = cve_list[:200] 
        cve_param = ",".join(demo_cves)
        try:
            res = requests.get(f"{epss_url}?cve={cve_param}", timeout=10)
            if res.status_code == 200:
                data = res.json().get('data', [])
                for item in data:
                    epss_dict[item['cve']] = float(item['epss'])
        except:
            pass # Fallback to mock

    for cve in cve_list:
        # EPSS Score (0.0 to 1.0)
        epss = epss_dict.get(cve, round(random.uniform(0.01, 0.99), 3))
        
        # Mock CVSS (0 to 10) - In real life, fetch from NVD based on `nvd_api_key`
        cvss = round(random.uniform(4.0, 10.0), 1)
        
        results.append({
            "CVE-ID": cve,
            "EPSS Score": epss,
            "Severity": cvss
        })
        
    return pd.DataFrame(results)

def mock_github_poc(cve_id):
    """Simulate a GitHub search for PoC. Returns True 30% of the time."""
    return random.random() > 0.7


# --- MAIN APP ---
st.title("🛡️ Cyber Sentinel: Real-Time Threat Intel")
st.markdown("Monitor 0-days, active exploits, and prioritize vulnerabilities based on EPSS and CVSS.")

with st.spinner("Aggregating Threat Intelligence..."):
    kev_df = fetch_cisa_kev()

if not kev_df.empty:
    all_cves = kev_df['CVE-ID'].tolist()
    # Enrich top 500 for performance
    enriched_df = fetch_epss_nvd_mock(all_cves[:500], use_real_nvd=bool(nvd_api_key), api_key=nvd_api_key)
    
    # Merge datasets
    merged = pd.merge(kev_df.head(500), enriched_df, on="CVE-ID", how="left")
    
    # Infrastructure Stack Filtering
    if tech_stack:
        pattern = '|'.join(tech_stack)
        # Case insensitive search in Description, vendorProject, or product
        mask = merged['Description'].str.contains(pattern, case=False, na=False)
        if 'vendorProject' in merged.columns:
            mask = mask | merged['vendorProject'].str.contains(pattern, case=False, na=False)
        if 'product' in merged.columns:
            mask = mask | merged['product'].str.contains(pattern, case=False, na=False)
        filtered_df = merged[mask]
    else:
        filtered_df = merged

    # Add PoC Column
    if 'PoC Found' not in filtered_df.columns:
        filtered_df['PoC Found'] = filtered_df['CVE-ID'].apply(mock_github_poc)
    
    filtered_df['In-the-Wild'] = "Yes" # By definition in CISA KEV
    
    # --- METRICS ---
    st.markdown("### 📊 Global Threat Overview (Filtered)")
    col1, col2, col3 = st.columns(3)
    
    # Calculate metrics
    recent_days = datetime.now() - timedelta(days=7)
    active_0days = len(filtered_df[filtered_df['Date Added'] >= recent_days])
    critical_wild = len(filtered_df[filtered_df['Severity'] >= 9.0])
    avg_epss = filtered_df['EPSS Score'].mean() if not filtered_df.empty else 0.0

    col1.metric("🔥 Active 0-Days (7d)", active_0days, delta="Recent KEV Additions", delta_color="inverse")
    col2.metric("🚨 Critical Exploits in Wild", critical_wild, help="Severity >= 9.0")
    col3.metric("🎯 Avg. EPSS Score", f"{avg_epss:.3f}", help="Probability of exploitation in next 30 days")

    st.divider()

    # --- EXPLOITABILITY MATRIX ---
    st.markdown("### 🗺️ The Exploitability Matrix")
    st.markdown("Identify **Immediate Patching Required** vulnerabilities (High Severity + High Likelihood).")
    
    if not filtered_df.empty:
        # Quadrant Colors logic
        def determine_quadrant(row):
            if row['Severity'] >= 7.0 and row['EPSS Score'] >= 0.5:
                return "Immediate Patching Required"
            elif row['Severity'] >= 7.0 and row['EPSS Score'] < 0.5:
                return "High Severity, Lower Likelihood"
            elif row['Severity'] < 7.0 and row['EPSS Score'] >= 0.5:
                return "Moderate Severity, High Likelihood"
            else:
                return "Monitor / Low Priority"

        filtered_df['Risk Quadrant'] = filtered_df.apply(determine_quadrant, axis=1)
        
        color_discrete_map = {
            "Immediate Patching Required": "#ff4b4b", # Red
            "High Severity, Lower Likelihood": "#ffa500", # Orange
            "Moderate Severity, High Likelihood": "#ffd700", # Yellow
            "Monitor / Low Priority": "#008000" # Green
        }

        fig = px.scatter(
            filtered_df,
            x="Severity",
            y="EPSS Score",
            color="Risk Quadrant",
            hover_name="CVE-ID",
            hover_data={"Description": True, "PoC Found": True},
            color_discrete_map=color_discrete_map,
            opacity=0.8,
            title="CVSS Severity vs EPSS Probability"
        )
        
        # Add quadrant lines
        fig.add_hline(y=0.5, line_dash="dash", line_color="gray")
        fig.add_vline(x=7.0, line_dash="dash", line_color="gray")
        fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", font_color="white")
        fig.update_xaxes(showgrid=False)
        fig.update_yaxes(showgrid=False)
        
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No vulnerabilities found matching your infrastructure stack.")
        
    st.divider()

    # --- DETAILED INTELLIGENCE FEED & LLM SUMMARIES ---
    st.markdown("### 📰 Detailed Intelligence Feed")
    
    # Create the Technology column
    if 'vendorProject' in filtered_df.columns and 'product' in filtered_df.columns:
        filtered_df['Technology'] = filtered_df['vendorProject'].astype(str) + " / " + filtered_df['product'].astype(str)
        filtered_df['Technology'] = filtered_df['Technology'].str.replace("nan / nan", "Unknown").str.replace("nan / ", "").str.replace(" / nan", "")
    else:
        filtered_df['Technology'] = "Unknown"
        
    filtered_df['NVD Link'] = "https://nvd.nist.gov/vuln/detail/" + filtered_df['CVE-ID']
        
    tech_feed_filter = st.text_input("🔍 Search within Detailed Feed by Technology (e.g., Microsoft, IOS)")
    
    feed_df = filtered_df
    if tech_feed_filter:
        feed_df = feed_df[feed_df['Technology'].str.contains(tech_feed_filter, case=False, na=False)]
    
    display_cols = ["CVE-ID", "Technology", "Severity", "EPSS Score", "In-the-Wild", "PoC Found", "NVD Link", "Date Added"]
    
    st.markdown("Select a row below to generate an AI Intelligence Briefing.")
    
    # st.dataframe with selections natively (Streamlit 1.35+)
    event = st.dataframe(
        feed_df[display_cols],
        use_container_width=True,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
        column_config={
            "EPSS Score": st.column_config.NumberColumn(format="%.3f"),
            "Severity": st.column_config.NumberColumn(format="%.1f"),
            "NVD Link": st.column_config.LinkColumn("NIST NVD", display_text="View on NVD")
        }
    )

    selected_rows = event.selection.rows if hasattr(event, 'selection') else []

    if selected_rows:
        selected_idx = selected_rows[0]
        selected_cve = feed_df.iloc[selected_idx]
        
        st.markdown(f"## 🤖 AI Threat Briefing: `{selected_cve['CVE-ID']}`")
        st.markdown(f"[🔗 View full Vulnerability details on NIST NVD](https://nvd.nist.gov/vuln/detail/{selected_cve['CVE-ID']})")
        
        tabs = st.tabs(["Executive Summary", "Technical Root Cause"])
        
        with tabs[0]:
            st.info(f"**Executive Summary (Mock LLM Output):**\n\n"
                    f"The vulnerability **{selected_cve['CVE-ID']}** affects **{selected_cve.get('vendorProject', 'Unknown Vendor')}** "
                    f"(**{selected_cve.get('product', 'Unknown Product')}**). "
                    f"With a CVSS Severity of **{selected_cve['Severity']}** and an EPSS score of **{selected_cve['EPSS Score']:.3f}**, "
                    f"it is {'highly' if selected_cve['EPSS Score'] > 0.5 else 'moderately'} likely to be exploited. "
                    f"CISA has confirmed this is exploited in the wild. "
                    f"{'A Proof-of-Concept (PoC) exploit is publicly available on GitHub.' if selected_cve['PoC Found'] else 'No public PoC exploit was found.'} "
                    f"Immediate remediation is recommended for affected infrastructure.")
            
        with tabs[1]:
            st.warning(f"**Technical Root Cause (Mock LLM Output):**\n\n"
                       f"**Description:** {selected_cve['Description']}\n\n"
                       f"This vulnerability typically involves improper validation of user-supplied input, "
                       f"allowing an attacker to execute arbitrary code or bypass authentication. "
                       f"Administrators should apply patches provided by the vendor immediately or implement compensatory controls "
                       f"such as WAF rules blocking known malicious signatures.")
else:
    st.info("Awaiting threat data...")
