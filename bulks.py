import ipaddress
import re
import pandas as pd
import streamlit as st

# --- APP CONFIGURATION & CONSTANTS ---
st.set_page_config(page_title="EM Asset Prep Tool", layout="wide")

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
    # Regex for a general valid domain layout
    pattern = (
        r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,11}$"  # lowercase handled prior
    )
    return bool(re.match(pattern, domain)) and "," not in domain


def sanitize_ip_cidr(asset):
    # Strip /32 from single IP addresses
    if asset.endswith("/32"):
        asset = asset[:-3]

    try:
        # Check if it's a valid individual IP
        if "/" not in asset:
            ip = ipaddress.IPv4Address(asset)
            if ip.is_private or ip.is_reserved or ip.is_loopback:
                return None, "Reserved/Private IP"
            return str(ip), "IP"
        else:
            # Check CIDR
            network = ipaddress.IPv4Network(asset, strict=False)
            if network.network_address.is_private or network.network_address.is_reserved:
                return None, "Reserved/Private CIDR"

            # Specific rule checks
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
    # Split by newlines/commas and conceptually TRIM
    lines = [line.strip() for line in re.split(r"[\n,]+", raw_input) if line.strip()]
    # Conceptually UNIQUE
    unique_lines = list(dict.fromkeys(lines))

    domains, ips_cidrs, rejected = [], [], []

    for asset in unique_lines:
        # Determine if looks like IP/CIDR or Domain
        if re.search(r"[a-zA-Z]", asset) and not any(
            c in asset for c in [":", "/"]
        ):
            # Domain processing
            lower_domain = asset.lower()
            if is_valid_domain(lower_domain):
                domains.append(lower_domain)
            else:
                rejected.append((asset, "Invalid/Malformed Domain"))
        else:
            # IP / CIDR processing
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

# Sidebar Reminders
st.sidebar.header("⚠️ Mandatory Reminders")
st.sidebar.warning(
    "**Authorization:** Verify user permissions before running bulk tags. If tag management restrictions are enabled, request must come from an Admin/Group Admin."
)
st.sidebar.info(
    "**File Naming:** Filenames must contain ONLY numbers and letters (no spaces or special characters)."
)
st.sidebar.info(
    "**Script Notice:** New assets (e.g., subdomains with '?' on dates) will not be created automatically via the Python script on the Infrastructure page (Requires RP Eng Ticket)."
)
st.sidebar.success(
    "**Propagation:** Changes may take up to 24 hours to reflect on the platform."
)

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

    # Dynamic inputs depending on rules
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
    # Workflow B
    script_tag_type = st.selectbox("Are these tags Public or Private?", ["", "Public", "Private"])
    tag_slug = st.text_input("Tag Slug:")

# --- PROCESSING TRIGGER ---
if st.button("⚡ Generate & Format Asset Configuration"):
    if not raw_assets_input.strip():
        st.error("Please provide a list of raw assets to process.")
    else:
        domains, ips_cidrs, rejected = process_assets(raw_assets_input)

        # Mixed Asset validation alert
        if domains and ips_cidrs:
            st.error(
                "🚨 **Asset Separation Alert:** Mixed list detected! Domains and CIDRs/IPs cannot be mixed in the same output file. Please process them separately."
            )

        # Determine target list to use
        has_missing_info = False
        output_str = ""
        filename_suggestion = "bulk_upload.csv"

        # Check Missing Parameters & Structure Outputs
        if "Workflow A" in workflow:
            # Check global missing parameters
            if sub_workflow in ["1. Entity Tags", "2. Entity Domain Tags", "5. Domain Tags (Global)", "6. CIDR Tags"] and (not action or not tag_slug):
                st.error("❌ Stop Processing: Missing 'Action' or 'Tag Slug' values.")
                has_missing_info = True
            if sub_workflow in ["3. End-Date Entity Domains", "7. End-Date CIDRs", "4. Entity Domain Grace Periods", "8. CIDR Grace Periods", "9. CIDR Guest Networks"] and not end_date:
                st.error("❌ Stop Processing: Missing Required Target Date.")
                has_missing_info = True

            if not has_missing_info:
                # 1. Entity Tags
                if sub_workflow == "1. Entity Tags":
                    if not entity_id:
                        st.error("❌ Stop Processing: Missing 'Entity ID'.")
                    else:
                        output_str = "entity_id,action,tag_slug\n"
                        for d in domains:
                            output_str += f"{entity_id},{action},{tag_slug}\n"
                
                # 2. Entity Domain Tags
                elif sub_workflow == "2. Entity Domain Tags":
                    output_str = "domain,action,tag_slug\n"
                    for d in domains:
                        output_str += f"{d},{action},{tag_slug}\n"

                # 3. End-Date Entity Domains
                elif sub_workflow == "3. End-Date Entity Domains":
                    output_str = "domain,new_end_date,current_end_date,current_start_date,domain_type\n"
                    for d in domains:
                        output_str += f"{d},{end_date},,,{domain_type}\n"

                # 4. Entity Domain Grace Periods
                elif sub_workflow == "4. Entity Domain Grace Periods":
                    output_str = "domain,grace_period_end_date,source,domain_type,start_date,end_date\n"
                    for d in domains:
                        output_str += f"{d},{end_date},,,,\n"

                # 5. Domain Tags (Global)
                elif sub_workflow == "5. Domain Tags (Global)":
                    output_str = "domain,action,tag_slug\n"
                    for d in domains:
                        output_str += f"{d},{action},{tag_slug}\n"

                # 6. CIDR Tags
                elif sub_workflow == "6. CIDR Tags":
                    output_str = "net_cidr,action,tag_slug\n"
                    for ip in ips_cidrs:
                        output_str += f"{ip},{action},{tag_slug}\n"

                # 7. End-Date CIDRs
                elif sub_workflow == "7. End-Date CIDRs":
                    output_str = "net_cidr,new_end_date\n"
                    for ip in ips_cidrs:
                        output_str += f"{ip},{end_date}\n"

                # 8. CIDR Grace Periods
                elif sub_workflow == "8. CIDR Grace Periods":
                    output_str = "net_cidr,grace_period_end_date\n"
                    for ip in ips_cidrs:
                        output_str += f"{ip},{end_date}\n"

                # 9. CIDR Guest Networks
                elif sub_workflow == "9. CIDR Guest Networks":
                    output_str = "net_cidr,guest_network_end_date\n"
                    for ip in ips_cidrs:
                        output_str += f"{ip},{end_date}\n"

        else:
            # Workflow B Processing
            if not script_tag_type or not tag_slug:
                st.error("❌ Stop Processing: You must specify if the tags are Public/Private and define a Tag Slug.")
                has_missing_info = True
            else:
                filename_suggestion = "bulk_script_upload.txt"
                # Handle target dataset natively without mixing
                target_assets = domains if domains else ips_cidrs
                for asset in target_assets:
                    output_str += f"{asset},{tag_slug}\n"

        # --- OUTPUT DISPLAY ---
        if not has_missing_info and output_str:
            st.success("✅ File generated perfectly!")
            
            st.subheader("📋 Output Content (Ready to Copy)")
            st.code(output_str, language="csv")

            # Download Button
            st.download_button(
                label="📥 Download Output File",
                data=output_str,
                file_name=filename_suggestion,
                mime="text/csv" if "csv" in filename_suggestion else "text/plain"
            )

        # Rejected Entries display
        if rejected:
            st.subheader("🚫 Rejected Assets (Removed during validation)")
            rejected_df = pd.DataFrame(rejected, columns=["Asset Passed", "Reason Removed"])
            st.dataframe(rejected_df, use_container_width=True)