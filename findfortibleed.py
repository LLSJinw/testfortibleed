import json
import re
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import pandas as pd
import requests
import streamlit as st


# ============================================================
# CONFIG
# ============================================================

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


# ============================================================
# INPUT / VALIDATION FUNCTIONS
# ============================================================

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

    Examples:
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
            normalized = normalize_target(target)
            valid.append(normalized)
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


# ============================================================
# API RESPONSE EXTRACTION
# ============================================================

def extract_fortibleed_result(target: str, response_json: dict) -> dict:
    """
    Correct parser for real SOCRadar FortiBleed API response.

    Real response structure:

    {
      "data": {
        "categories": [...],
        "is_detected": true,
        "match_count": 1,
        "matches": [...],
        "query": "103.40.132.0/22",
        "query_type": "cidr",
        "tags": [...],
        "truncated": false
      },
      "error": null,
      "is_success": true,
      "message": "Success",
      "response_code": 200
    }

    Important:
    Useful fields are inside response_json["data"].
    """

    data = response_json.get("data", {})

    if data is None:
        data = {}

    api_is_success = response_json.get("is_success", False)
    api_message = response_json.get("message", "")
    api_error = response_json.get("error", None)
    api_response_code = response_json.get("response_code", "")

    query = data.get("query", target)
    query_type = data.get("query_type", "")

    is_detected = data.get("is_detected", False)
    match_count = data.get("match_count", 0)

    matches = data.get("matches", [])
    categories = data.get("categories", [])

    # Fallback, in case API name changes again
    if not categories:
        categories = data.get("detected_categories", [])

    top_level_tags = data.get("tags", [])
    truncated = data.get("truncated", False)

    leaked_ips = []
    leaked_ip_details = []

    for match in matches:
        if not isinstance(match, dict):
            continue

        value = match.get("value", "")
        value_type = match.get("value_type", "")
        match_tags = match.get("tags", [])

        if value_type == "ip" and value:
            inside_range = is_ip_inside_target(value, target)

            leaked_ips.append(value)

            leaked_ip_details.append({
                "target": target,
                "query": query,
                "query_type": query_type,
                "leaked_ip": value,
                "value_type": value_type,
                "tags": ", ".join(match_tags),
                "inside_submitted_range": inside_range,
            })

    detected_categories = []

    for category in categories:
        if not isinstance(category, dict):
            continue

        if category.get("detected") is True:
            detected_categories.append({
                "target": target,
                "label": category.get("label", ""),
                "count": category.get("count", 0),
                "detected": category.get("detected", False),
            })

    exposure_types = [
        item["label"]
        for item in detected_categories
        if item.get("label")
    ]

    range_start, range_end = get_target_range(target)

    status = "DETECTED" if is_detected else "NOT_DETECTED"

    if not api_is_success:
        status = "API_ERROR"

    return {
        "target": target,
        "query": query,
        "query_type": query_type,
        "range_start": range_start,
        "range_end": range_end,

        "status": status,
        "is_detected": is_detected,
        "match_count": match_count,

        "leaked_ip_count": len(leaked_ips),
        "leaked_ips": ", ".join(leaked_ips),

        "exposure_type_count": len(exposure_types),
        "exposure_types": ", ".join(exposure_types),

        "api_is_success": api_is_success,
        "api_message": api_message,
        "api_error": "" if api_error is None else str(api_error),
        "api_response_code": api_response_code,
        "api_truncated": truncated,

        "all_tags": ", ".join(top_level_tags),

        "detected_categories_json": json.dumps(detected_categories, ensure_ascii=False),
        "leaked_ip_details_json": json.dumps(leaked_ip_details, ensure_ascii=False),
        "raw_response": json.dumps(response_json, ensure_ascii=False),
    }


# ============================================================
# API CALL FUNCTION
# ============================================================

def query_fortibleed(
    target: str,
    timeout: int = 20,
    retries: int = 2,
    retry_sleep: float = 2.0,
) -> dict:
    payload = {
        "query": target
    }

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
                response_json = response.json()
            except Exception:
                response_json = {
                    "data": {},
                    "is_success": False,
                    "message": "Invalid JSON response",
                    "response_code": response.status_code,
                    "error": response.text[:3000],
                }

            if response.status_code == 200:
                result = extract_fortibleed_result(target, response_json)
                result["http_status"] = response.status_code
                result["elapsed_sec"] = elapsed
                result["checked_at"] = datetime.now(timezone.utc).isoformat()
                result["error"] = ""
                return result

            if response.status_code in [429, 500, 502, 503, 504] and attempt < retries:
                time.sleep(retry_sleep * (attempt + 1))
                continue

            return {
                "target": target,
                "query": target,
                "query_type": "",
                "range_start": "",
                "range_end": "",

                "status": "HTTP_ERROR",
                "is_detected": False,
                "match_count": 0,

                "leaked_ip_count": 0,
                "leaked_ips": "",

                "exposure_type_count": 0,
                "exposure_types": "",

                "api_is_success": False,
                "api_message": "",
                "api_error": f"HTTP {response.status_code}",
                "api_response_code": response.status_code,
                "api_truncated": False,
                "all_tags": "",

                "detected_categories_json": "[]",
                "leaked_ip_details_json": "[]",
                "raw_response": json.dumps(response_json, ensure_ascii=False),

                "http_status": response.status_code,
                "elapsed_sec": elapsed,
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "error": f"HTTP {response.status_code}",
            }

        except requests.RequestException as e:
            if attempt < retries:
                time.sleep(retry_sleep * (attempt + 1))
                continue

            return {
                "target": target,
                "query": target,
                "query_type": "",
                "range_start": "",
                "range_end": "",

                "status": "REQUEST_ERROR",
                "is_detected": False,
                "match_count": 0,

                "leaked_ip_count": 0,
                "leaked_ips": "",

                "exposure_type_count": 0,
                "exposure_types": "",

                "api_is_success": False,
                "api_message": "",
                "api_error": str(e),
                "api_response_code": "",
                "api_truncated": False,
                "all_tags": "",

                "detected_categories_json": "[]",
                "leaked_ip_details_json": "[]",
                "raw_response": "",

                "http_status": None,
                "elapsed_sec": None,
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "error": str(e),
            }


# ============================================================
# PARALLEL SCAN
# ============================================================

def run_parallel_scan(
    targets: list[str],
    max_workers: int,
    timeout: int,
    retries: int,
    retry_sleep: float,
) -> pd.DataFrame:
    results = []

    progress_bar = st.progress(0)
    status_area = st.empty()

    total = len(targets)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(
                query_fortibleed,
                target,
                timeout,
                retries,
                retry_sleep,
            ): target
            for target in targets
        }

        for index, future in enumerate(as_completed(future_map), start=1):
            target = future_map[future]

            try:
                result = future.result()
            except Exception as e:
                result = {
                    "target": target,
                    "query": target,
                    "query_type": "",
                    "range_start": "",
                    "range_end": "",

                    "status": "LOCAL_ERROR",
                    "is_detected": False,
                    "match_count": 0,

                    "leaked_ip_count": 0,
                    "leaked_ips": "",

                    "exposure_type_count": 0,
                    "exposure_types": "",

                    "api_is_success": False,
                    "api_message": "",
                    "api_error": str(e),
                    "api_response_code": "",
                    "api_truncated": False,
                    "all_tags": "",

                    "detected_categories_json": "[]",
                    "leaked_ip_details_json": "[]",
                    "raw_response": "",

                    "http_status": None,
                    "elapsed_sec": None,
                    "checked_at": datetime.now(timezone.utc).isoformat(),
                    "error": str(e),
                }

            results.append(result)

            progress_bar.progress(index / total)
            status_area.info(
                f"Checked {index}/{total}: {result['target']} → {result['status']}"
            )

    return pd.DataFrame(results)


# ============================================================
# DETAIL TABLE BUILDERS
# ============================================================

def build_leaked_ip_detail_table(df: pd.DataFrame) -> pd.DataFrame:
    rows = []

    for _, row in df.iterrows():
        raw_json = row.get("leaked_ip_details_json", "[]")

        try:
            details = json.loads(raw_json)
        except Exception:
            details = []

        if isinstance(details, list):
            rows.extend(details)

    return pd.DataFrame(rows)


def build_category_detail_table(df: pd.DataFrame) -> pd.DataFrame:
    rows = []

    for _, row in df.iterrows():
        raw_json = row.get("detected_categories_json", "[]")

        try:
            details = json.loads(raw_json)
        except Exception:
            details = []

        if isinstance(details, list):
            rows.extend(details)

    return pd.DataFrame(rows)


# ============================================================
# STREAMLIT UI
# ============================================================

st.set_page_config(
    page_title="FortiBleed Exposure Checker",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ FortiBleed Exposure Checker by IP / CIDR")

st.caption(
    "Use only for public IPs or CIDR ranges that you own or are authorized to assess. "
    "This app calls the FortiBleed checker API directly and extracts detected IPs, "
    "exposure categories, and range validation."
)

with st.sidebar:
    st.header("Scan Settings")

    max_workers = st.slider(
        "Parallel requests",
        min_value=1,
        max_value=20,
        value=8,
        help="For around 132 subnets, 8-10 is usually reasonable. Reduce if you get HTTP 429.",
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

    retry_sleep = st.slider(
        "Retry backoff seconds",
        min_value=0.5,
        max_value=10.0,
        value=2.0,
        step=0.5,
    )

    st.divider()

    st.write("API Endpoint")
    st.code(API_URL)


st.subheader("Input IP / CIDR")

default_input = "103.40.132.0/22"

input_text = st.text_area(
    "Paste IPs or CIDRs",
    value=default_input,
    height=200,
    help="One per line, or separated by comma, semicolon, tab, or space.",
)

uploaded_file = st.file_uploader(
    "Optional: upload TXT or CSV file containing IPs/CIDRs",
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


start_scan = st.button(
    "Start FortiBleed Check",
    type="primary",
    disabled=len(valid_targets) == 0,
)


if start_scan:
    st.warning(
        "Scanning started. If you see HTTP 429 or unstable results, reduce parallel requests."
    )

    df = run_parallel_scan(
        targets=valid_targets,
        max_workers=max_workers,
        timeout=timeout,
        retries=retries,
        retry_sleep=retry_sleep,
    )

    st.session_state["result_df"] = df


# ============================================================
# DISPLAY RESULTS
# ============================================================

if "result_df" in st.session_state:
    df = st.session_state["result_df"]

    st.subheader("Scan Summary")

    summary_df = (
        df.groupby("status")
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
    )

    st.dataframe(summary_df, use_container_width=True)

    detected_df = df[df["status"] == "DETECTED"]
    not_detected_df = df[df["status"] == "NOT_DETECTED"]
    error_df = df[
        df["status"].isin(
            ["API_ERROR", "HTTP_ERROR", "REQUEST_ERROR", "LOCAL_ERROR"]
        )
    ]

    col1, col2, col3 = st.columns(3)
    col1.metric("Detected targets", len(detected_df))
    col2.metric("Not detected targets", len(not_detected_df))
    col3.metric("Error targets", len(error_df))

    if len(detected_df) > 0:
        st.error(
            f"Detected exposure in {len(detected_df)} target(s). "
            "Treat these as incident-response candidates."
        )
    else:
        st.success("No detected exposure found in the scanned targets.")

    st.subheader("Per Target Results")

    display_columns = [
        "target",
        "query",
        "query_type",
        "range_start",
        "range_end",
        "status",
        "is_detected",
        "match_count",
        "leaked_ip_count",
        "leaked_ips",
        "exposure_type_count",
        "exposure_types",
        "api_truncated",
        "http_status",
        "elapsed_sec",
        "checked_at",
        "error",
    ]

    existing_display_columns = [
        col for col in display_columns
        if col in df.columns
    ]

    st.dataframe(
        df[existing_display_columns],
        use_container_width=True,
    )

    leaked_ip_detail_df = build_leaked_ip_detail_table(df)
    category_detail_df = build_category_detail_table(df)

    st.subheader("Specific Leaked IP Details")

    if len(leaked_ip_detail_df) > 0:
        st.dataframe(leaked_ip_detail_df, use_container_width=True)
    else:
        st.info("No leaked IP details returned.")

    st.subheader("Detected Exposure Categories")

    if len(category_detail_df) > 0:
        st.dataframe(category_detail_df, use_container_width=True)
    else:
        st.info("No detected categories returned.")

    with st.expander("Raw API Responses"):
        st.dataframe(
            df[["target", "raw_response"]],
            use_container_width=True,
        )

    st.subheader("Download Reports")

    csv_summary = df.to_csv(index=False).encode("utf-8-sig")

    st.download_button(
        "Download Summary CSV",
        data=csv_summary,
        file_name=f"fortibleed_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
    )

    if len(leaked_ip_detail_df) > 0:
        csv_ip_detail = leaked_ip_detail_df.to_csv(index=False).encode("utf-8-sig")

        st.download_button(
            "Download Leaked IP Detail CSV",
            data=csv_ip_detail,
            file_name=f"fortibleed_leaked_ip_detail_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
        )

    if len(category_detail_df) > 0:
        csv_category_detail = category_detail_df.to_csv(index=False).encode("utf-8-sig")

        st.download_button(
            "Download Exposure Category CSV",
            data=csv_category_detail,
            file_name=f"fortibleed_exposure_categories_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
        )
