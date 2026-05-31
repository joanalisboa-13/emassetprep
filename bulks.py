import ipaddress
import re
import pandas as pd
import streamlit as st

# --- APP CONFIGURATION & CONSTANTS ---
st.set_page_config(page_title="EM Bulk Upload Tool", page_icon="⚙️", layout="wide")

# --- ADVANCED BITSIGHT BRANDING & LAYOUT STYLING ---
st.markdown(
    """
    <style>
    /* Global Page Settings */
    .stApp {
        background-color: #FFFFFF;
        color: #111111;
    }
    
    /* Elegant Frame for Content Blocks */
    div[data-testid="stVerticalBlock"] > div {
        background-color: #FAFAFA;
        padding: 1.5rem;
        border-radius: 8px;
        box-shadow: 0px 2px 6px rgba(0,0,0,0.05);
        margin-bottom: 1rem;
    }
    
    /* Clean Headers */
    h1 {
        color: #111111 !important;
        font-family: 'Helvetica Neue', Arial, sans-serif;
        font-weight: 800;
        letter-spacing: -0.5px;
    }
    
    h2, h3, h4 {
        color: #111111 !important;
        font-family: 'Helvetica Neue', Arial, sans-serif;
        font-weight: 600;
    }
    
    /* BitSight Orange Horizontal Rule Accent */
    hr {
        border-top: 3px solid #FF6600 !important;
        margin-top: 1rem !important;
        margin-bottom: 2rem !important;
    }
    
    /* Input Control Customization */
    .stTextArea textarea, .stSelectbox div, .stTextInput input {
        border: 1.5px solid #E0E0E0 !important;
        border-radius: 6px !important;
        color: #111111 !important;
        background-color: #FFFFFF !important;
    }
    
    /* Active Input Highlights */
    .stTextArea textarea:focus, .stTextInput input:focus {
        border-color: #FF6600 !important;
        box-shadow: 0 0 0 2px rgba(255, 102, 0, 0.2) !important;
    }
    
    /* Command Execution Button (Black -> Orange Hover) */
    div.stButton > button:first-child {
        background-color: #111111 !important;
        color: #FFFFFF !important;
        border: none !important;
        border-radius: 6px !important;
        font-weight: 700 !important;
        letter-spacing: 0.5px;
        transition: all 0.25s ease-in-out;
        padding: 0.6rem 2.5rem !important;
        width: 100%;
    }
    
    div.stButton > button:first-child:hover {
        background-color: #FF6600 !important;
        color: #FFFFFF !important;
        box-shadow: 0px 6px 15px rgba(255, 102, 0, 0.35);
        transform: translateY(-1px);
    }
    
    /* Direct Extraction Download Button (Always Orange -> Black Hover) */
    div[data-testid="stDownloadButton"] > button {
        background-color: #FF6600 !important;
        color: #FFFFFF !important;
        border: none !important;
        border-radius: 6px !important;
        font-weight: 700 !important;
        transition: all 0.25s ease-in-out;
        padding: 0.6rem 2.5rem !important;
    }
    
    div[data-testid="stDownloadButton"] > button:hover {
        background-color: #111111 !important;
        color: #FFFFFF !important;
        box-shadow: 0px 4px 12px rgba(0, 0, 0, 0.15);
    }
    
    /* Custom Styling for Radio Buttons Layout */
    div[data-baseweb="radio"] {
        gap: 1.5rem !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

VALID_DOMAIN_TYPES = [
    "primary_domain",
    "secondary_domain",
    "graph_domain",
    "graph_owned_domain",
    "graph_registered_domain",
    "redirect_domain",
    "owned_domain",
    "managed_nameserver",
    "shared_nameserver",
    "registered_domain",
    "subsidiary_domain",
    "customer_provided",
    "dce_domain",
]

# --- UTILITY & SANITIZATION FUNCTIONS ---


def is_valid_domain(domain):
    pattern = (
        r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,11}$"  # lowercase handled prior
    )
    return bool(re.match(pattern, domain)) and "," not in domain


def sanitize_ip_cidr(asset):
    if asset.endswith("/32"):
        asset = asset[:-3]

    try:
        if "/" not in asset:
            ip = ipaddress.IPv4Address(asset)
            if ip.is_private or ip.is_reserved or ip.is_loopback:
                return None, "Reserved/Private IP"
            return str(ip), "IP"
        else:
            network = ipaddress.IPv4Network(asset, strict=False)
            if network.network_address.is_private or network.network_address.is_reserved:
                return None, "Reserved/Private CIDR"

            prefix = network.prefixlen
            last_octet = int(str(network.network_address).split(".")[-1])

            if prefix == 28 and (last_octet % 2 != 0):
                return (
                    None,
                    "Invalid CIDR: /28 range must have an even number in the last octet",
                )
            if prefix == 23 and not str(network.network_address).endswith("0"):
                return None, "Invalid CIDR: /23 range must end in 0"

            return str(network), "CIDR"
    except ValueError:
        return None, "Malformed IP/CIDR"


def process_assets(raw_input):
    lines = [line.strip() for line in re.split(r"[\n,]+", raw_input) if line.strip()]
    unique_lines = list(dict.fromkeys(lines))

    domains, ips_cidrs, rejected = [], [], []

    for asset in unique_lines:
        if re.search(r"[a-zA-Z]", asset) and not any(
            c in asset for c in [":", "/"]
        ):
            lower_domain = asset.lower()
            if is_valid_domain(lower_domain):
                domains.append(lower_domain)
            else:
                rejected.append((asset, "Invalid/Malformed Domain"))
        else:
            sanitized, error_msg = sanitize_ip_cidr(asset)
            if sanitized:
                ips_cidrs.append(sanitized)
            else:
                rejected.append((asset, error_msg))

    return domains, ips_cidrs, rejected


# --- MAIN APPLICATION HEADER ---
st.title("⚙️ EM Bulk Upload Tool")
st.caption("High-performance data sanitization engine built tailored to the Entity Management system framework.")
st.write("---")

# --- BLOCK 1: WORKFLOW SPECIFICATION ---
st.subheader("🛠️ Step 1: Target Profile Selection")
workflow = st.radio(
    "Identify your target execution destination profile:",
    ("Workflow A: EM Platform Uploads (With Headers)", "Workflow B: Python Bulk Script Tagger (No Headers)"),
    label_visibility="collapsed"
)

# --- BLOCK 2: PARAMETER CONFIGURATION ---
action = ""
tag_slug = ""
script_tag_type = ""
sub_workflow = ""
end_date = ""
domain_type = ""

st.write("")
st.subheader("📋 Step 2: Context Configuration")

if "Workflow A" in workflow:
    sub_workflow = st.selectbox(
        "Select Specific Action Sub-Workflow Target:",
        [
            "1. Entity Tags",
            "2. Entity Domain Tags",
            "3. End-Date Entity Domains",
            "4. Entity Domain Grace Periods",
            "5. Domain Tags (Global)",
            "6. CIDR Tags",
            "7. End-Date CIDRs",
            "8. CIDR Grace Periods",
            "9. CIDR Guest Networks",
        ],
    )

    col1, col2 = st.columns(2)
    with col1:
        if sub_workflow in [
            "1. Entity Tags",
            "2. Entity Domain Tags",
            "5. Domain Tags (Global)",
            "6. CIDR Tags",
        ]:
            action = st.selectbox("Action Operation Type:", ["", "add", "remove"])
            tag_slug = st.text_input("Target System Tag Slug Name:")
        elif sub_workflow in ["3. End-Date Entity Domains", "7. End-Date CIDRs"]:
            end_date = st.text_input("Assignment New End Date (YYYY-MM-DD):")
            domain_type = st.selectbox("Domain Type Classification (Optional):", [""] + VALID_DOMAIN_TYPES)
        elif sub_workflow in ["4. Entity Domain Grace Periods", "8. CIDR Grace Periods"]:
            end_date = st.text_input("Grace Period Finalization Date (YYYY-MM-DD or '-' to remove):")
        elif sub_workflow == "9. CIDR Guest Networks":
            end_date = st.text_input("Guest Network Expiration Target Date (YYYY-MM-DD or '-' to remove):")

    with col2:
        if sub_workflow == "1. Entity Tags":
            entity_id = st.text_input("Target Platform Entity ID:")

else:
    col1, col2 = st.columns(2)
    with col1:
        script_tag_type = st.selectbox("Script Visibility Parameter (Public vs Private):", ["", "Public", "Private"])
    with col2:
        tag_slug = st.text_input("Script Pipeline Target Tag Slug:")

# --- BLOCK 3: ASSET STREAM INGESTION ---
st.write("")
st.subheader("📥 Step 3: Raw Asset Ingestion")
raw_assets_input = st.text_area(
    "Drop system lines here (Accepts unique newline entries or raw comma strings):",
    placeholder="example.com\n192.0.2.1/24\nsubdomain.example.net",
    height=180,
    label_visibility="collapsed"
)

# --- EXECUTION SYSTEM PIPELINE ---
st.write("")
if st.button("⚡ Execute Structural Data Cleansing"):
    if not raw_assets_input.strip():
        st.error("Operation Aborted: Raw asset ingestion field cannot be submitted blank.")
    else:
        domains, ips_cidrs, rejected = process_assets(raw_assets_input)

        if domains and ips_cidrs:
            st.error(
                "🚨 **Asset Separation Alert:** Mixed profiles tracked! Domains and CIDRs/IPs cannot be compressed into the same file array. Split inputs."
            )

        has_missing_info = False
        output_str = ""
        filename_suggestion = "bulk_upload.csv"

        if "Workflow A" in workflow:
            if sub_workflow in ["1. Entity Tags", "2. Entity Domain Tags", "5. Domain Tags (Global)", "6. CIDR Tags"] and (not action or not tag_slug):
                st.error("❌ Process Halting Error: Target Operations or Tag Slugs require validation entries.")
                has_missing_info = True
            if sub_workflow in ["3. End-Date Entity Domains", "7. End-Date CIDRs", "4. Entity Domain Grace Periods", "8. CIDR Grace Periods", "9. CIDR Guest Networks"] and not end_date:
                st.error("❌ Process Halting Error: Required Expiration Reference Date Missing.")
                has_missing_info = True

            if not has_missing_info:
                if sub_workflow == "1. Entity Tags":
                    if not entity_id:
                        st.error("❌ Structural Hold: Target Platform Entity ID entry required.")
                    else:
                        output_str = "entity_id,action,tag_slug\n"
                        for d in domains:
                            output_str += f"{entity_id},{action},{tag_slug}\n"
                
                elif sub_workflow == "2. Entity Domain Tags":
                    output_str = "domain,action,tag_slug\n"
                    for d in domains:
                        output_str += f"{d},{action},{tag_slug}\n"

                elif sub_workflow == "3. End-Date Entity Domains":
                    output_str = "domain,new_end_date,current_end_date,current_start_date,domain_type\n"
                    for d in domains:
                        output_str += f"{d},{end_date},,,{domain_type}\n"

                elif sub_workflow == "4. Entity Domain Grace Periods":
                    output_str = "domain,grace_period_end_date,source,domain_type,start_date,end_date\n"
                    for d in domains:
                        output_str += f"{d},{end_date},,,,\n"

                elif sub_workflow == "5. Domain Tags (Global)":
                    output_str = "domain,action,tag_slug\n"
                    for d in domains:
                        output_str += f"{d},{action},{tag_slug}\n"

                elif sub_workflow == "6. CIDR Tags":
                    output_str = "net_cidr,action,tag_slug\n"
                    for ip in ips_cidrs:
                        output_str += f"{ip},{action},{tag_slug}\n"

                elif sub_workflow == "7. End-Date CIDRs":
                    output_str = "net_cidr,new_end_date\n"
                    for ip in ips_cidrs:
                        output_str += f"{ip},{end_date}\n"

                elif sub_workflow == "8. CIDR Grace Periods":
                    output_str = "net_cidr,grace_period_end_date\n"
                    for ip in ips_cidrs:
                        output_str += f"{ip},{end_date}\n"

                elif sub_workflow == "9. CIDR Guest Networks":
                    output_str = "net_cidr,guest_network_end_date\n"
                    for ip in ips_cidrs:
                        output_str += f"{ip},{end_date}\n"

        else:
            if not script_tag_type or not tag_slug:
                st.error("❌ Process Halting Error: Core Tagger Python variables must be selected before file compilation.")
                has_missing_info = True
            else:
                filename_suggestion = "tags.txt"
                target_assets = domains if domains else ips_cidrs
                for asset in target_assets:
                    output_str += f"{asset},{tag_slug}\n"

        # Output Rendering Context
        if not has_missing_info and output_str:
            st.success("🎉 Matrix Configuration Mapping Success!")
            
            st.subheader("📋 Output Stream (Prerender View)")
            st.code(output_str, language="csv")

            st.download_button(
                label=f"📥 Download Normalized Configuration ({filename_suggestion})",
                data=output_str,
                file_name=filename_suggestion,
                mime="text/plain" if filename_suggestion.endswith(".txt") else "text/csv"
            )

        # Rejected Elements Logger
        if rejected:
            st.write("")
            st.subheader("🚫 Exception Handling Logs (Assets Scrubbed)")
            rejected_df = pd.DataFrame(rejected, columns=["Raw Element Processed", "Scrubbing Engine Reason Rule"])
            st.dataframe(rejected_df, use_container_width=True)
