import json
import re
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import pandas as pd
import requests
import streamlit as st


API_URL = "https://socradar.io/free-tools/api/fortibleed/search-fortibleed"

HEADERS = {
    "accept": "application/json, text/plain, */*",
    "content-type": "application/json",
    "origin": "https://socradar.io",
    "referer": "https://socradar.io/free-tools/fortibleed/",
    "user-agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0 Safari/537.36"
    ),
}


def split_targets(text: str) -> list[str]:
    """
    Accept newline, comma, semicolon, tab, or space separated IP/CIDR values.
    """
    if not text:
        return []

    items = re.split(r"[\s,;]+", text.strip())
    return [item.strip() for item in items if item.strip()]


def normalize_target(target: str) -> str:
    """
    Validate and normalize IP or CIDR.
    Example:
    103.40.132.1     -> 103.40.132.1
    103.40.132.5/22  -> 103.40.132.0/22
    """
    target = target.strip()

    if "/" in target:
        return str(ipaddress.ip_network(target, strict=False))

    return str(ipaddress.ip_address(target))


def validate_targets(raw_targets: list[str]) -> tuple[list[str], list[dict]]:
    valid = []
    invalid = []

    for target in raw_targets:
        try:
            valid.append(normalize_target(target))
        except ValueError as e:
            invalid.append({
                "target": target,
                "error": str(e),
            })

    # Deduplicate while preserving order
    valid = list(dict.fromkeys(valid))

    return valid, invalid


def get_target_range(target: str) -> tuple[str, str]:
    """
    Return start IP and end IP for either IP or CIDR.
    """
    if "/" in target:
        network = ipaddress.ip_network(target, strict=False)
        return str(network.network_address), str(network.broadcast_address)

    ip = ipaddress.ip_address(target)
    return str(ip), str(ip)


def is_ip_inside_target(ip_value: str, target: str) -> bool:
    """
    Confirm whether a returned leaked IP is inside the submitted IP/CIDR.
    """
    try:
        ip = ipaddress.ip_address(ip_value)

        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            return ip in network

        return ip == ipaddress.ip_address(target)

    except ValueError:
        return False


def extract_fortibleed_result(target: str, data: dict) -> dict:
    """
    Extract clean fields from FortiBleed API response.

    Expected response shape:

    {
      "is_detected": true,
      "match_count": 1,
      "matches": [
        {
          "tags": ["credential", "fortinet", "ssh", "vpn"],
          "value": "103.40.134.178",
          "value_type": "ip"
        }
      ],
      "detected_categories": [
        { "count": 1, "detected": true, "label": "VPN" },
        { "count": 1, "detected": true, "label": "Credentials" },
        { "count": 1, "detected": true, "label": "SSH" }
      ]
    }
    """

    is_detected = bool(data.get("is_detected", False))
    match_count = data.get("match_count", 0)

    matches = data.get("matches", [])
    categories = data.get("detected_categories", [])

    leaked_ips = []
    leaked_ip_details = []

    for match in matches:
        value = match.get("value")
        value_type = match.get("value_type")
        tags = match.get("tags", [])

        if value_type == "ip" and value:
            inside_range = is_ip_inside_target(value, target)

            leaked_ips.append(value)
            leaked_ip_details.append({
                "target": target,
                "leaked_ip": value,
                "value_type": value_type,
                "tags": ", ".join(tags),
                "inside_submitted_range": inside_range,
            })

    detected_categories = []

    for category in categories:
        if category.get("detected") is True:
            detected_categories.append({
                "label": category.get("label"),
                "count": category.get("count", 0),
            })

    exposure_labels = [item["label"] for item in detected_categories if item["label"]]

    range_start, range_end = get_target_range(target)

    if is_detected:
        status = "DETECTED"
    else:
        status = "NOT_DETECTED"

    return {
        "target": target,
        "range_start": range_start,
        "range_end": range_end,
        "status": status,
        "is_detected": is_detected,
        "match_count": match_count,
        "leaked_ip_count": len(leaked_ips),
        "leaked_ips": ", ".join(leaked_ips),
        "exposure_type_count": len(exposure_labels),
        "exposure_types": ", ".join(exposure_labels),
        "detected_categories_json": json.dumps(detected_categories, ensure_ascii=False),
        "leaked_ip_details_json": json.dumps(leaked_ip_details, ensure_ascii=False),
        "raw_response": json.dumps(data, ensure_ascii=False),
    }


def query_fortibleed(target: str, timeout: int = 20, retries: int = 2) -> dict:
    payload = {"query": target}

    for attempt in range(retries + 1):
        started = time.time()

        try:
            response = requests.post(
                API_URL,
                headers=HEADERS,
                json=payload,
                timeout=timeout,
            )

            elapsed = round(time.time() - started, 3)

            try:
                data = response.json()
            except Exception:
                data = {
                    "raw_text": response.text[:3000],
                }

            if response.status_code == 200:
                result = extract_fortibleed_result(target, data)
                result["http_status"] = response.status_code
                result["elapsed_sec"] = elapsed
                result["checked_at"] = datetime.utcnow().isoformat() + "Z"
                result["error"] = ""
                return result

            if response.status_code in [429, 500, 502, 503, 504] and attempt < retries:
                time.sleep(2 * (attempt + 1))
                continue

            return {
                "target": target,
                "status": "ERROR",
                "is_detected": False,
                "match_count": 0,
                "leaked_ip_count": 0,
                "leaked_ips": "",
                "exposure_type_count": 0,
                "exposure_types": "",
                "http_status": response.status_code,
                "elapsed_sec": elapsed,
                "checked_at": datetime.utcnow().isoformat() + "Z",
                "error": f"HTTP {response.status_code}",
                "raw_response": json.dumps(data, ensure_ascii=False),
            }

        except requests.RequestException as e:
            if attempt < retries:
                time.sleep(2 * (attempt + 1))
                continue

            return {
                "target": target,
                "status": "ERROR",
                "is_detected": False,
                "match_count": 0,
                "leaked_ip_count": 0,
                "leaked_ips": "",
                "exposure_type_count": 0,
                "exposure_types": "",
                "http_status": None,
                "elapsed_sec": None,
                "checked_at": datetime.utcnow().isoformat() + "Z",
                "error": str(e),
                "raw_response": "",
            }


def run_parallel_scan(targets: list[str], max_workers: int, timeout: int, retries: int) -> pd.DataFrame:
    results = []

    progress_bar = st.progress(0)
    status_area = st.empty()

    total = len(targets)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(query_fortibleed, target, timeout, retries): target
            for target in targets
        }

        for index, future in enumerate(as_completed(future_map), start=1):
            result = future.result()
            results.append(result)

            progress_bar.progress(index / total)
            status_area.info(
                f"Checked {index}/{total}: {result['target']} → {result['status']}"
            )

    return pd.DataFrame(results)


def build_ip_detail_table(df: pd.DataFrame) -> pd.DataFrame:
    """
    Convert leaked_ip_details_json into a separate table:
    one row per leaked IP.
    """
    rows = []

    for _, row in df.iterrows():
        details_json = row.get("leaked_ip_details_json", "[]")

        try:
            details = json.loads(details_json)
        except Exception:
            details = []

        for item in details:
            rows.append(item)

    return pd.DataFrame(rows)


st.set_page_config(
    page_title="FortiBleed Exposure Checker",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ FortiBleed Exposure Checker by IP / CIDR")

st.caption(
    "Input public IPs or CIDR ranges that you own or are authorized to assess. "
    "The app calls the FortiBleed API directly and extracts detected IPs, exposure categories, and range validation."
)

with st.sidebar:
    st.header("Scan Settings")

    max_workers = st.slider(
        "Parallel requests",
        min_value=1,
        max_value=20,
        value=8,
        help="For 132 subnets, 8-10 is usually reasonable. Reduce if you get HTTP 429.",
    )

    timeout = st.slider(
        "Timeout per request",
        min_value=5,
        max_value=60,
        value=20,
    )

    retries = st.slider(
        "Retries",
        min_value=0,
        max_value=5,
        value=2,
    )

st.subheader("Input IP / CIDR")

default_example = "103.40.132.0/22"

input_text = st.text_area(
    "Paste IPs or CIDRs",
    value=default_example,
    height=180,
    help="One per line, or separated by comma/space.",
)

uploaded_file = st.file_uploader(
    "Optional: upload TXT or CSV file",
    type=["txt", "csv"],
)

uploaded_text = ""

if uploaded_file is not None:
    uploaded_text = uploaded_file.read().decode("utf-8", errors="ignore")

raw_targets = split_targets(input_text + "\n" + uploaded_text)
valid_targets, invalid_targets = validate_targets(raw_targets)

col1, col2 = st.columns(2)
col1.metric("Valid targets", len(valid_targets))
col2.metric("Invalid inputs", len(invalid_targets))

if invalid_targets:
    with st.expander("Invalid inputs"):
        st.dataframe(pd.DataFrame(invalid_targets), use_container_width=True)

with st.expander("Targets to scan"):
    st.write(valid_targets)

if st.button("Start FortiBleed Check", type="primary", disabled=len(valid_targets) == 0):
    df = run_parallel_scan(
        targets=valid_targets,
        max_workers=max_workers,
        timeout=timeout,
        retries=retries,
    )

    st.subheader("Summary")

    summary_df = (
        df.groupby("status")
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
    )

    st.dataframe(summary_df, use_container_width=True)

    detected_df = df[df["status"] == "DETECTED"]
    not_detected_df = df[df["status"] == "NOT_DETECTED"]
    error_df = df[df["status"] == "ERROR"]

    if len(detected_df) > 0:
        st.error(f"Detected exposure in {len(detected_df)} target(s).")
    else:
        st.success("No detected exposure found in the scanned targets.")

    st.subheader("Per Subnet / IP Result")

    display_columns = [
        "target",
        "range_start",
        "range_end",
        "status",
        "match_count",
        "leaked_ip_count",
        "leaked_ips",
        "exposure_type_count",
        "exposure_types",
        "http_status",
        "elapsed_sec",
        "checked_at",
        "error",
    ]

    existing_display_columns = [c for c in display_columns if c in df.columns]
    st.dataframe(df[existing_display_columns], use_container_width=True)

    ip_detail_df = build_ip_detail_table(df)

    st.subheader("Specific Leaked IP Details")

    if len(ip_detail_df) > 0:
        st.dataframe(ip_detail_df, use_container_width=True)
    else:
        st.info("No leaked IP details returned.")

    with st.expander("Raw API Responses"):
        st.dataframe(df[["target", "raw_response"]], use_container_width=True)

    csv_summary = df.to_csv(index=False).encode("utf-8-sig")
    st.download_button(
        "Download Summary CSV",
        data=csv_summary,
        file_name=f"fortibleed_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
    )

    if len(ip_detail_df) > 0:
        csv_ip_detail = ip_detail_df.to_csv(index=False).encode("utf-8-sig")
        st.download_button(
            "Download Leaked IP Detail CSV",
            data=csv_ip_detail,
            file_name=f"fortibleed_leaked_ip_detail_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
        )
