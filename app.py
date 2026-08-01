import streamlit as st
import pandas as pd
from scraper.scoring import calculate_risk

st.set_page_config(page_title="Threat Intel Scraper", page_icon="🛡️", layout="wide")

st.title("🛡️ Automated Domain Threat Intelligence Scraper")
st.markdown("Enter a domain name to quickly assess its infrastructure risk based on WHOIS, DNS, TLS, and HTTP security headers.")

domain = st.text_input("Target Domain (e.g., example.com)", "")

if st.button("Scan Domain"):
    if not domain:
        st.warning("Please enter a domain.")
    else:
        domain = domain.strip().lower()
        if domain.startswith("http://") or domain.startswith("https://"):
            domain = domain.split("//")[1].split("/")[0]

        with st.spinner(f"Scanning {domain}..."):
            result = calculate_risk(domain)
        
        score = result["score"]
        warnings = result["warnings"]
        data = result["data"]
        
        st.subheader("Risk Assessment")
        
        if score < 30:
            st.success(f"**Risk Score: {score}/100** (Low Risk)")
        elif score < 70:
            st.warning(f"**Risk Score: {score}/100** (Medium Risk)")
        else:
            st.error(f"**Risk Score: {score}/100** (High Risk)")
            
        if warnings:
            st.markdown("### ⚠️ Key Warnings")
            for w in warnings:
                st.markdown(f"- {w}")
        else:
            st.markdown("### ✅ No major warnings found")
            
        st.markdown("---")
        st.subheader("Raw Telemetry")
        
        col1, col2 = st.columns(2)
        
        with col1:
            with st.expander("📝 WHOIS Data", expanded=True):
                whois_data = data["whois"]
                if whois_data.get("error"):
                    st.error(whois_data["error"])
                else:
                    st.json({k: v for k, v in whois_data.items() if v is not None and k != "error"})
                    
            with st.expander("🌐 DNS Records"):
                dns_records = data["dns"]
                if dns_records.get("error"):
                    st.error(dns_records["error"])
                else:
                    for r_type in ["A", "AAAA", "MX", "NS", "TXT"]:
                        if dns_records.get(r_type):
                            st.markdown(f"**{r_type} Records:**")
                            for r in dns_records[r_type]:
                                st.code(r)
                                
        with col2:
            with st.expander("🔒 TLS Certificate", expanded=True):
                tls_info = data["tls"]
                if tls_info.get("error"):
                    st.error(tls_info["error"])
                else:
                    st.json({k: v for k, v in tls_info.items() if k != "error"})
                    
            with st.expander("🛡️ HTTP Security Headers"):
                headers_info = data["headers"]
                if headers_info.get("error"):
                    st.error(headers_info["error"])
                else:
                    st.json(headers_info.get("headers", {}))
