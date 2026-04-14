# 🛡️ Cyber Sentinel: Real-Time Threat Intel

**Cyber Sentinel** is a high-performance Streamlit Dashboard designed for security professionals to monitor 0-days, active exploits, and effectively prioritize vulnerability remediation efforts.

## ✨ Core Features

* **Multi-Source Ingestion**: Automatically pulls live JSON data from the CISA KEV (Known Exploited Vulnerabilities) Catalog and correlates it with exploit probability data from the FIRST.org EPSS API.
* **The Exploitability Matrix**: A custom Plotly scatter plot mapping CVSS Severity vs. EPSS Probability. Highlights vulnerabilities in the critical top-right quadrant (High Severity + High Likelihood) for immediate patching.
* **Tech Stack Personalization**: Filter the intelligence feed by your specific infrastructure stack (e.g., Windows, Linux, Kubernetes, AWS) to see only relevant threats.
* **Detailed Intelligence Feed**: Interactive data tables presenting actionable metrics at a glance, including in-the-wild status and potential PoC availability.
* **Interactive AI Threat Briefings**: Select any vulnerability to generate a simulated LLM summary containing an Executive Summary and Technical Root Cause explanation.

## 🛠️ Tech Stack

* **Frontend**: Streamlit
* **Data Manipulation**: Pandas
* **Visualizations**: Plotly Express
* **Networking**: Requests 

## 🚀 Getting Started

### Prerequisites

Ensure you have Python 3.8+ installed. 

### Installation

1. Navigate to the project directory:
   ```cmd
   cd c:\code\Workspace
   ```
2. Install the required dependencies:
   ```cmd
   pip install -r requirements.txt
   ```

### Running the Application

Execute the following command to start the Streamlit server:

```cmd
streamlit run app.py
```

The application should automatically open in your default web browser at `http://localhost:8501`. 

## ⚙️ Configuration

* **NVD API Key**: To increase the rate limits for polling CVSS scores via the National Vulnerability Database (NVD), you can input an API key in the configuration sidebar. Without a key, the application uses resilient fallback simulations for severity metrics to ensure high responsiveness. 
* **Customizing the Tech Stack**: Use the multi-select box in the sidebar to define the technologies your organization utilizes. The global threat overview and exploitability matrix will instantly adjust.

## 📝 Concept Notes

* This tool is designed with API modularity in mind. 
* **EPSS & NVD Polling**: Due to NVD rate limits and the performance focus, bulk processing without an API key gracefully falls back to synthesized severity representations so the dashboard remains interactive. 
* **GitHub Actions**: PoC (Proof of Concept) integration illustrates a framework for hooking into external code-search APIs.
* **LLM Prompts**: AI Threat Briefings are pre-structured elements where external inference APIs (OpenAI/Anthropic) can drop in contextually aware intelligence text.
