import ipaddress
import re
import pandas as pd
import streamlit as st

# --- APP CONFIGURATION & CONSTANTS ---
st.set_page_config(page_title="EM Asset Prep Tool", layout="wide")

# --- BITSIGHT BRANDING STYLING ---
st.markdown(
    """
    <style>
    /* Main App Background and Text colors */
    .stApp {
        background-color: #FFFFFF;
        color: #111111;
    }
    
    /* Headers & Title */
    h1, h2, h3, h4 {
        color: #111111 !important;
        font-family: 'Helvetica Neue', Arial, sans-serif;
        font-weight: 700;
    }
    
    /* Horizontal lines */
    hr {
        border-top: 2px solid #FF6600 !important;
    }
    
    /* Inputs, text areas, dropdowns */
    .stTextArea textarea, .stSelectbox div, .stTextInput input, div[data-baseweb="radio"] {
        border-color: #111111 !important;
        color: #111111 !important;
    }
    
    /* Highlight/Focus on text elements */
    .stTextArea textarea:focus {
        border-color: #FF6600 !important;
        box-shadow: 0 0 0 1px #FF6600 !important;
    }
    
    /* Customizing the main action buttons */
    div.stButton > button:first-child {
        background-color: #111111 !important;
        color: #FFFFFF !important;
        border: 2px solid #111111 !important;
        font-weight: bold;
        transition: all 0.3s ease;
        padding: 0.5rem 2rem;
    }
    
    div.stButton > button:first-child:hover {
        background-color: #FF6600 !important;
        border-color: #FF6600 !important;
        color: #FFFFFF !important;
        box-shadow: 0px 4px 10px rgba(255, 102, 0, 0.3);
    }
    
    /* Customizing the Download button */
    div[data-testid="stDownloadButton"] > button {
        background-color: #FF6600 !important;
        color: #FFFFFF !important;
        border: 2px solid #FF6600 !important;
        font-weight: bold;
        padding: 0.5rem 2rem;
    }
    
    div[data-testid="stDownloadButton"] > button:hover {
        background-color: #111111 !important;
        border-color: #111111 !important;
        color: #FFFFFF !important;
    }
    
    /* Alerts and Status tweaks */
    .stAlert {
        border-left: 5px solid #FF6600 !important;
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


# --- UI LAYOUT ---
st.title("🛡️ EM Asset Prep Helper")
st.caption(
    "Sanitize and format raw assets for EM Platform Bulk Uploads or Python Bulk Scripts."
)

st.write("---")

# Core workflow choices
workflow = st.radio(
    "Select Target Workflow:",
    ("Workflow A: EM Platform Uploads (With Headers)", "Workflow B: Python Bulk Script Tagger (No Headers)"),
)

st.write("---")

# Input Fields
raw_assets_input = st.text_area(
    "Paste Raw Assets here (one per line, or comma-separated):", height=200
)

# Contextual forms based on choice
action = ""
tag_slug = ""
script_tag_type = ""
sub_workflow = ""
end_date = ""
domain_type = ""

if "Workflow A" in workflow:
    sub_workflow = st.selectbox(
        "Select Sub-Workflow Format:",
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
            action = st.selectbox("Action:", ["", "add", "remove"])
            tag_slug = st.text_input("Tag Slug:")
        elif sub_workflow in ["3. End-Date Entity Domains", "7. End-Date CIDRs"]:
            end_date = st.text_input("New End Date (YYYY-MM-DD):")
            domain_type = st.selectbox("Domain Type (Optional):", [""] + VALID_DOMAIN_TYPES)
        elif sub_workflow in ["4. Entity Domain Grace Periods", "8. CIDR Grace Periods"]:
            end_date = st.text_input("Grace Period End Date (YYYY-MM-DD or - to remove):")
        elif sub_workflow == "9. CIDR Guest Networks":
            end_date = st.text_input("Guest Network End Date (YYYY-MM-DD or - to remove):")

    with col2:
        if sub_workflow == "1. Entity Tags":
            entity_id = st.text_input("Entity ID:")

else:
    script_tag_type = st.selectbox("Are these tags Public or Private?", ["", "Public", "Private"])
    tag_slug = st.text_input("Tag Slug:")

# --- PROCESSING TRIGGER ---
if st.button("⚡ Generate & Format Asset Configuration"):
    if not raw_assets_input.strip():
        st.error("Please provide a list of raw assets to process.")
    else:
        domains, ips_cidrs, rejected = process_assets(raw_assets_input)

        if domains and ips_cidrs:
            st.error(
                "🚨 **Asset Separation Alert:** Mixed list detected! Domains and CIDRs/IPs cannot be mixed in the same output file. Please process them separately."
            )

        has_missing_info = False
        output_str = ""
        filename_suggestion = "bulk_upload.csv"

        if "Workflow A" in workflow:
            if sub_workflow in ["1. Entity Tags", "2. Entity Domain Tags", "5. Domain Tags (Global)", "6. CIDR Tags"] and (not action or not tag_slug):
                st.error("❌ Stop Processing: Missing 'Action' or 'Tag Slug' values.")
                has_missing_info = True
            if sub_workflow in ["3. End-Date Entity Domains", "7. End-Date CIDRs", "4. Entity Domain Grace Periods", "8. CIDR Grace Periods", "9. CIDR Guest Networks"] and not end_date:
                st.error("❌ Stop Processing: Missing Required Target Date.")
                has_missing_info = True

            if not has_missing_info:
                if sub_workflow == "1. Entity Tags":
                    if not entity_id:
                        st.error("❌ Stop Processing: Missing 'Entity ID'.")
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
                st.error("❌ Stop Processing: You must specify if the tags are Public/Private and define a Tag Slug.")
                has_missing_info = True
            else:
                filename_suggestion = "bulk_script_upload.txt"
                target_assets = domains if domains else ips_cidrs
                for asset in target_assets:
                    output_str += f"{asset},{tag_slug}\n"

        if not has_missing_info and output_str:
            st.success("✅ File generated perfectly!")
            
            st.subheader("📋 Output Content (Ready to Copy)")
            st.code(output_str, language="csv")

            st.download_button(
                label="📥 Download Output File",
                data=output_str,
                file_name=filename_suggestion,
                mime="text/csv" if "csv" in filename_suggestion else "text/plain"
            )

        if rejected:
            st.subheader("🚫 Rejected Assets (Removed during validation)")
            rejected_df = pd.DataFrame(rejected, columns=["Asset Passed", "Reason Removed"])
            st.dataframe(rejected_df, use_container_width=True)
