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


IPV4_PATTERN = r"(?:\d{1,3}\.){3}\d{1,3}"

TOKEN_PATTERN = re.compile(
    rf"{IPV4_PATTERN}\s*-\s*{IPV4_PATTERN}"      # 192.168.1.20-192.168.1.25
    rf"|{IPV4_PATTERN}/\d{{1,2}}"                # 192.168.1.0/24
    rf"|{IPV4_PATTERN}\s*-\s*\d{{1,3}}"          # 192.168.1.20-25
    rf"|{IPV4_PATTERN}"                          # 192.168.1.1
)


# ============================================================
# INPUT PARSING / EXPANSION
# ============================================================

def extract_input_tokens(text: str) -> list[str]:
    """
    Extract IP-like tokens from free text.

    Supports:
        192.168.1.1
        192.168.1.0/24
        192.168.1.20-25
        192.168.1.20-192.168.1.25
        A.192.168.1.0/24
        B. 192.168.1.0/24

    Because it uses regex search, labels like A. or B. are ignored automatically.
    """

    if not text:
        return []

    found = []

    for match in TOKEN_PATTERN.finditer(text):
        token = match.group(0)
        token = token.replace(" ", "")
        token = token.strip().strip(",;")
        found.append(token)

    return found


def expand_single_token(
    token: str,
    cidr_mode: str,
    max_ips_per_token: int,
) -> tuple[list[dict], dict | None]:
    """
    Expand a single IP/CIDR/range token into scan targets.

    Supports:
        192.168.1.1                  -> single IP
        192.168.1.0/24                -> CIDR
        192.168.1.20-25               -> last-octet range
        192.168.1.20-192.168.1.25     -> full IP range

    cidr_mode:
        - "expand": expand CIDR into individual host IPs
        - "keep": keep CIDR as one API query
    """

    token = token.strip()

    try:
        # CIDR
        if "/" in token:
            network = ipaddress.ip_network(token, strict=False)
            normalized_cidr = str(network)

            if cidr_mode == "keep":
                return [
                    {
                        "source_token": token,
                        "scan_target": normalized_cidr,
                        "input_type": "cidr",
                        "expansion_type": "kept_as_cidr",
                    }
                ], None

            # Expand CIDR into host IPs
            if network.num_addresses == 1:
                ip_list = [str(network.network_address)]
            else:
                ip_list = [str(ip) for ip in network.hosts()]

            if len(ip_list) > max_ips_per_token:
                return [], {
                    "source_token": token,
                    "reason": (
                        f"CIDR expands to {len(ip_list)} host IPs, "
                        f"above per-token limit {max_ips_per_token}"
                    ),
                }

            expanded = [
                {
                    "source_token": token,
                    "scan_target": ip,
                    "input_type": "cidr",
                    "expansion_type": "expanded_from_cidr",
                }
                for ip in ip_list
            ]

            return expanded, None

        # Range
        if "-" in token:
            start_str, end_str = [part.strip() for part in token.split("-", 1)]

            start_ip = ipaddress.ip_address(start_str)

            # Full range: 192.168.1.20-192.168.1.25
            if "." in end_str:
                end_ip = ipaddress.ip_address(end_str)

            # Last-octet shorthand: 192.168.1.20-25
            else:
                base_parts = start_str.split(".")
                base_parts[-1] = end_str
                end_ip = ipaddress.ip_address(".".join(base_parts))

            start_int = int(start_ip)
            end_int = int(end_ip)

            if end_int < start_int:
                start_int, end_int = end_int, start_int

            count = end_int - start_int + 1

            if count > max_ips_per_token:
                return [], {
                    "source_token": token,
                    "reason": (
                        f"Range expands to {count} IPs, "
                        f"above per-token limit {max_ips_per_token}"
                    ),
                }

            ip_list = [
                str(ipaddress.ip_address(ip_int))
                for ip_int in range(start_int, end_int + 1)
            ]

            expanded = [
                {
                    "source_token": token,
                    "scan_target": ip,
                    "input_type": "range",
                    "expansion_type": "expanded_from_range",
                }
                for ip in ip_list
            ]

            return expanded, None

        # Single IP
        ip = ipaddress.ip_address(token)

        return [
            {
                "source_token": token,
                "scan_target": str(ip),
                "input_type": "single_ip",
                "expansion_type": "single_ip",
            }
        ], None

    except ValueError as e:
        return [], {
            "source_token": token,
            "reason": str(e),
        }


def build_scan_targets(
    tokens: list[str],
    cidr_mode: str,
    max_ips_per_token: int,
    max_total_targets: int,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Expand all input tokens and deduplicate scan targets.
    """

    expanded_rows = []
    skipped_rows = []

    for token in tokens:
        expanded, skipped = expand_single_token(
            token=token,
            cidr_mode=cidr_mode,
            max_ips_per_token=max_ips_per_token,
        )

        expanded_rows.extend(expanded)

        if skipped:
            skipped_rows.append(skipped)

    if not expanded_rows:
        return pd.DataFrame(), pd.DataFrame(skipped_rows)

    # Deduplicate by scan_target while preserving first source token
    dedup = {}

    for row in expanded_rows:
        target = row["scan_target"]

        if target not in dedup:
            dedup[target] = row.copy()
            dedup[target]["all_source_tokens"] = row["source_token"]
        else:
            existing_tokens = dedup[target]["all_source_tokens"].split(", ")
            if row["source_token"] not in existing_tokens:
                existing_tokens.append(row["source_token"])
            dedup[target]["all_source_tokens"] = ", ".join(existing_tokens)

    dedup_rows = list(dedup.values())

    if len(dedup_rows) > max_total_targets:
        skipped_rows.append({
            "source_token": "TOTAL_LIMIT",
            "reason": (
                f"Expanded target count is {len(dedup_rows)}, "
                f"above total limit {max_total_targets}. "
                f"Increase the limit or use CIDR keep mode."
            ),
        })

        dedup_rows = dedup_rows[:max_total_targets]

    return pd.DataFrame(dedup_rows), pd.DataFrame(skipped_rows)


# ============================================================
# TARGET RANGE / VALIDATION HELPERS
# ============================================================

def get_target_range(target: str) -> tuple[str, str]:
    """
    Return start IP and end IP for either single IP or CIDR.
    """

    if "/" in target:
        network = ipaddress.ip_network(target, strict=False)
        return str(network.network_address), str(network.broadcast_address)

    ip = ipaddress.ip_address(target)
    return str(ip), str(ip)


def is_ip_inside_target(ip_value: str, target: str) -> bool:
    """
    Confirm whether a returned leaked IP is inside the submitted scan target.
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

def extract_fortibleed_result(
    scan_target: str,
    source_token: str,
    input_type: str,
    expansion_type: str,
    all_source_tokens: str,
    response_json: dict,
) -> dict:
    """
    Correct parser for real SOCRadar FortiBleed API response.

    Real structure:

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

    query = data.get("query", scan_target)
    query_type = data.get("query_type", "")

    is_detected = data.get("is_detected", False)
    match_count = data.get("match_count", 0)

    matches = data.get("matches", [])
    categories = data.get("categories", [])

    # Fallback in case API field name changes
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
            inside_range = is_ip_inside_target(value, scan_target)

            leaked_ips.append(value)

            leaked_ip_details.append({
                "source_token": source_token,
                "all_source_tokens": all_source_tokens,
                "scan_target": scan_target,
                "input_type": input_type,
                "expansion_type": expansion_type,
                "query": query,
                "query_type": query_type,
                "leaked_ip": value,
                "value_type": value_type,
                "tags": ", ".join(match_tags),
                "inside_submitted_target": inside_range,
            })

    detected_categories = []

    for category in categories:
        if not isinstance(category, dict):
            continue

        if category.get("detected") is True:
            detected_categories.append({
                "source_token": source_token,
                "scan_target": scan_target,
                "label": category.get("label", ""),
                "count": category.get("count", 0),
                "detected": category.get("detected", False),
            })

    exposure_types = [
        item["label"]
        for item in detected_categories
        if item.get("label")
    ]

    range_start, range_end = get_target_range(scan_target)

    status = "DETECTED" if is_detected else "NOT_DETECTED"

    if not api_is_success:
        status = "API_ERROR"

    return {
        "source_token": source_token,
        "all_source_tokens": all_source_tokens,
        "scan_target": scan_target,
        "input_type": input_type,
        "expansion_type": expansion_type,
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
# API CALL
# ============================================================

def query_fortibleed(
    target_row: dict,
    timeout: int = 20,
    retries: int = 2,
    retry_sleep: float = 2.0,
) -> dict:
    scan_target = target_row["scan_target"]
    source_token = target_row.get("source_token", scan_target)
    input_type = target_row.get("input_type", "")
    expansion_type = target_row.get("expansion_type", "")
    all_source_tokens = target_row.get("all_source_tokens", source_token)

    payload = {
        "query": scan_target
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
                result = extract_fortibleed_result(
                    scan_target=scan_target,
                    source_token=source_token,
                    input_type=input_type,
                    expansion_type=expansion_type,
                    all_source_tokens=all_source_tokens,
                    response_json=response_json,
                )

                result["http_status"] = response.status_code
                result["elapsed_sec"] = elapsed
                result["checked_at"] = datetime.now(timezone.utc).isoformat()
                result["error"] = ""
                return result

            if response.status_code in [429, 500, 502, 503, 504] and attempt < retries:
                time.sleep(retry_sleep * (attempt + 1))
                continue

            return build_error_result(
                source_token=source_token,
                all_source_tokens=all_source_tokens,
                scan_target=scan_target,
                input_type=input_type,
                expansion_type=expansion_type,
                status="HTTP_ERROR",
                error=f"HTTP {response.status_code}",
                http_status=response.status_code,
                elapsed_sec=elapsed,
                raw_response=response_json,
            )

        except requests.RequestException as e:
            if attempt < retries:
                time.sleep(retry_sleep * (attempt + 1))
                continue

            return build_error_result(
                source_token=source_token,
                all_source_tokens=all_source_tokens,
                scan_target=scan_target,
                input_type=input_type,
                expansion_type=expansion_type,
                status="REQUEST_ERROR",
                error=str(e),
                http_status=None,
                elapsed_sec=None,
                raw_response={},
            )


def build_error_result(
    source_token: str,
    all_source_tokens: str,
    scan_target: str,
    input_type: str,
    expansion_type: str,
    status: str,
    error: str,
    http_status,
    elapsed_sec,
    raw_response: dict,
) -> dict:
    return {
        "source_token": source_token,
        "all_source_tokens": all_source_tokens,
        "scan_target": scan_target,
        "input_type": input_type,
        "expansion_type": expansion_type,
        "query": scan_target,
        "query_type": "",
        "range_start": "",
        "range_end": "",

        "status": status,
        "is_detected": False,
        "match_count": 0,

        "leaked_ip_count": 0,
        "leaked_ips": "",

        "exposure_type_count": 0,
        "exposure_types": "",

        "api_is_success": False,
        "api_message": "",
        "api_error": error,
        "api_response_code": "",
        "api_truncated": False,
        "all_tags": "",

        "detected_categories_json": "[]",
        "leaked_ip_details_json": "[]",
        "raw_response": json.dumps(raw_response, ensure_ascii=False),

        "http_status": http_status,
        "elapsed_sec": elapsed_sec,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "error": error,
    }


# ============================================================
# PARALLEL SCAN
# ============================================================

def run_parallel_scan(
    scan_df: pd.DataFrame,
    max_workers: int,
    timeout: int,
    retries: int,
    retry_sleep: float,
) -> pd.DataFrame:
    results = []

    progress_bar = st.progress(0)
    status_area = st.empty()

    target_rows = scan_df.to_dict(orient="records")
    total = len(target_rows)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(
                query_fortibleed,
                target_row,
                timeout,
                retries,
                retry_sleep,
            ): target_row
            for target_row in target_rows
        }

        for index, future in enumerate(as_completed(future_map), start=1):
            target_row = future_map[future]

            try:
                result = future.result()
            except Exception as e:
                result = build_error_result(
                    source_token=target_row.get("source_token", ""),
                    all_source_tokens=target_row.get("all_source_tokens", ""),
                    scan_target=target_row.get("scan_target", ""),
                    input_type=target_row.get("input_type", ""),
                    expansion_type=target_row.get("expansion_type", ""),
                    status="LOCAL_ERROR",
                    error=str(e),
                    http_status=None,
                    elapsed_sec=None,
                    raw_response={},
                )

            results.append(result)

            progress_bar.progress(index / total)
            status_area.info(
                f"Checked {index}/{total}: {result['scan_target']} → {result['status']}"
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

st.title("🛡️ FortiBleed Exposure Checker by IP / CIDR / Range")

st.caption(
    "Use only for public IPs or CIDR ranges that you own or are authorized to assess. "
    "This app supports single IP, CIDR, last-octet range, and full IP range input."
)

with st.sidebar:
    st.header("Scan Settings")

    cidr_mode_label = st.radio(
        "CIDR handling",
        options=[
            "Expand CIDR to individual host IPs",
            "Keep CIDR as one API query",
        ],
        index=0,
        help=(
            "Expand mode checks each host IP. "
            "Keep mode is faster for large subnet lists because the API accepts CIDR."
        ),
    )

    cidr_mode = "expand" if cidr_mode_label.startswith("Expand") else "keep"

    max_ips_per_token = st.number_input(
        "Max expanded IPs per input token",
        min_value=1,
        max_value=1_000_000,
        value=4096,
        step=100,
        help="Prevents accidental huge expansion such as /8.",
    )

    max_total_targets = st.number_input(
        "Max total scan targets",
        min_value=1,
        max_value=1_000_000,
        value=50000,
        step=1000,
        help="Overall safety limit after expansion and deduplication.",
    )

    max_workers = st.slider(
        "Parallel requests",
        min_value=1,
        max_value=30,
        value=8,
        help="For public/free APIs, start with 5-10. Reduce if you get HTTP 429.",
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


st.subheader("Input IP / CIDR / Range")

default_input = """103.40.132.0/22
192.168.1.1
192.168.1.20-25
192.168.1.20-192.168.1.25
A.192.168.2.0/30
"""

input_text = st.text_area(
    "Paste IPs, CIDRs, or ranges",
    value=default_input,
    height=240,
    help=(
        "Supported formats: single IP, CIDR, last-octet range, full IP range. "
        "Labels like A. or B. before the IP are okay."
    ),
)

uploaded_file = st.file_uploader(
    "Optional: upload TXT or CSV file containing IPs/CIDRs/ranges",
    type=["txt", "csv"],
)

uploaded_text = ""

if uploaded_file is not None:
    uploaded_text = uploaded_file.read().decode("utf-8", errors="ignore")


combined_text = input_text + "\n" + uploaded_text

tokens = extract_input_tokens(combined_text)

scan_df, skipped_df = build_scan_targets(
    tokens=tokens,
    cidr_mode=cidr_mode,
    max_ips_per_token=int(max_ips_per_token),
    max_total_targets=int(max_total_targets),
)

col1, col2, col3 = st.columns(3)
col1.metric("Parsed input tokens", len(tokens))
col2.metric("Scan targets after expansion", len(scan_df))
col3.metric("Skipped inputs", len(skipped_df))

with st.expander("Parsed input tokens"):
    if tokens:
        st.dataframe(pd.DataFrame({"token": tokens}), use_container_width=True)
    else:
        st.info("No valid IP-like tokens found.")

with st.expander("Expanded scan targets"):
    if len(scan_df) > 0:
        st.dataframe(scan_df, use_container_width=True)
    else:
        st.info("No scan targets generated.")

if len(skipped_df) > 0:
    with st.expander("Skipped inputs / expansion warnings"):
        st.dataframe(skipped_df, use_container_width=True)

start_scan = st.button(
    "Start FortiBleed Check",
    type="primary",
    disabled=len(scan_df) == 0,
)


if start_scan:
    st.warning(
        "Scanning started. If you see HTTP 429 or unstable results, reduce parallel requests. "
        "For many large CIDRs, consider using 'Keep CIDR as one API query'."
    )

    df = run_parallel_scan(
        scan_df=scan_df,
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
            f"Detected exposure in {len(detected_df)} scan target(s). "
            "Treat these as incident-response candidates."
        )
    else:
        st.success("No detected exposure found in the scanned targets.")

    st.subheader("Per Target Results")

    display_columns = [
        "source_token",
        "all_source_tokens",
        "scan_target",
        "input_type",
        "expansion_type",
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
        raw_cols = ["scan_target", "raw_response"]
        raw_cols = [col for col in raw_cols if col in df.columns]
        st.dataframe(df[raw_cols], use_container_width=True)

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
