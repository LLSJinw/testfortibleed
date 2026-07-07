"""
Fortinet Exposure Triage Helper

A defensive Streamlit helper for asset owners or authorized security teams to
perform a first-pass review of Fortinet-related public exposure signals.

Responsible-use notes:
- Use only for assets you own or are explicitly authorized to assess.
- Results are informational signals, not definitive proof of compromise.
- Validate findings through official vendor guidance, patch status, asset
  ownership records, vulnerability management, and incident response procedures.
"""

import json
import re
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

import pandas as pd
import requests
import streamlit as st


# ============================================================
# CONFIG
# ============================================================

APP_NAME = "Fortinet Exposure Triage Helper"
APP_VERSION = "1.0-public-safe"

# Public SOCRadar FortiBleed free-tool endpoint.
# This endpoint may change or rate-limit requests. Respect the provider's terms
# and reduce parallelism if you receive HTTP 429 or unstable results.
API_URL = "https://socradar.io/free-tools/api/fortibleed/search-fortibleed"

HEADERS = {
    "accept": "application/json, text/plain, */*",
    "content-type": "application/json",
    "user-agent": f"{APP_NAME.replace(' ', '')}/{APP_VERSION}",
}

IPV4_PATTERN = r"(?:\d{1,3}\.){3}\d{1,3}"

TOKEN_PATTERN = re.compile(
    rf"{IPV4_PATTERN}\s*-\s*{IPV4_PATTERN}"      # 192.0.2.20-192.0.2.25
    rf"|{IPV4_PATTERN}/\d{{1,2}}"                # 198.51.100.0/30
    rf"|{IPV4_PATTERN}\s*-\s*\d{{1,3}}"          # 203.0.113.10-12
    rf"|{IPV4_PATTERN}"                          # 192.0.2.1
)


# ============================================================
# INPUT PARSING / EXPANSION
# ============================================================

def extract_input_tokens(text: str) -> list[str]:
    """
    Extract IP-like tokens from free text.

    Supported formats:
        192.0.2.1
        198.51.100.0/30
        203.0.113.10-12
        203.0.113.10-203.0.113.12
        A. 192.0.2.1
        B.198.51.100.0/30

    Labels before IPs are ignored automatically because the parser searches
    only for IP-like tokens.
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
) -> tuple[list[dict[str, Any]], dict[str, str] | None]:
    """
    Expand a single IP/CIDR/range token into review targets.

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
                        "review_target": normalized_cidr,
                        "input_type": "cidr",
                        "expansion_type": "kept_as_cidr",
                    }
                ], None

            # Expand CIDR into host IPs.
            if network.num_addresses == 1:
                ip_list = [str(network.network_address)]
            else:
                ip_list = [str(ip) for ip in network.hosts()]

            if len(ip_list) > max_ips_per_token:
                return [], {
                    "source_token": token,
                    "reason": (
                        f"CIDR expands to {len(ip_list)} host IPs, "
                        f"above per-token limit {max_ips_per_token}. "
                        "Use CIDR keep mode or reduce the range."
                    ),
                }

            expanded = [
                {
                    "source_token": token,
                    "review_target": ip,
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

            # Full range: 203.0.113.10-203.0.113.12
            if "." in end_str:
                end_ip = ipaddress.ip_address(end_str)

            # Last-octet shorthand: 203.0.113.10-12
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
                        f"above per-token limit {max_ips_per_token}. "
                        "Reduce the range before review."
                    ),
                }

            ip_list = [
                str(ipaddress.ip_address(ip_int))
                for ip_int in range(start_int, end_int + 1)
            ]

            expanded = [
                {
                    "source_token": token,
                    "review_target": ip,
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
                "review_target": str(ip),
                "input_type": "single_ip",
                "expansion_type": "single_ip",
            }
        ], None

    except ValueError as e:
        return [], {
            "source_token": token,
            "reason": str(e),
        }


def build_review_targets(
    tokens: list[str],
    cidr_mode: str,
    max_ips_per_token: int,
    max_total_targets: int,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Expand all input tokens and deduplicate review targets.
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

    # Deduplicate by review_target while preserving source-token history.
    dedup: dict[str, dict[str, Any]] = {}

    for row in expanded_rows:
        target = row["review_target"]

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
                "Only the first targets were kept. Increase the limit carefully "
                "or use CIDR keep mode."
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
    Confirm whether a returned IP signal is inside the submitted target.
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

def extract_signal_result(
    review_target: str,
    source_token: str,
    input_type: str,
    expansion_type: str,
    all_source_tokens: str,
    response_json: dict[str, Any],
) -> dict[str, Any]:
    """
    Parse the SOCRadar FortiBleed free-tool response.

    Results are expressed as potential signals, not as definitive validation.
    """

    data = response_json.get("data", {})

    if data is None:
        data = {}

    api_is_success = response_json.get("is_success", False)
    api_message = response_json.get("message", "")
    api_error = response_json.get("error", None)
    api_response_code = response_json.get("response_code", "")

    query = data.get("query", review_target)
    query_type = data.get("query_type", "")

    signal_found = data.get("is_detected", False)
    match_count = data.get("match_count", 0)

    matches = data.get("matches", [])
    categories = data.get("categories", []) or data.get("detected_categories", [])

    top_level_tags = data.get("tags", [])
    truncated = data.get("truncated", False)

    returned_ips = []
    returned_ip_details = []

    for match in matches:
        if not isinstance(match, dict):
            continue

        value = match.get("value", "")
        value_type = match.get("value_type", "")
        match_tags = match.get("tags", [])

        if value_type == "ip" and value:
            inside_target = is_ip_inside_target(value, review_target)

            returned_ips.append(value)

            returned_ip_details.append({
                "source_token": source_token,
                "all_source_tokens": all_source_tokens,
                "review_target": review_target,
                "input_type": input_type,
                "expansion_type": expansion_type,
                "query": query,
                "query_type": query_type,
                "returned_ip": value,
                "value_type": value_type,
                "tags": ", ".join(match_tags),
                "inside_submitted_target": inside_target,
            })

    detected_categories = []

    for category in categories:
        if not isinstance(category, dict):
            continue

        if category.get("detected") is True:
            detected_categories.append({
                "source_token": source_token,
                "review_target": review_target,
                "label": category.get("label", ""),
                "count": category.get("count", 0),
                "detected": category.get("detected", False),
            })

    signal_categories = [
        item["label"]
        for item in detected_categories
        if item.get("label")
    ]

    range_start, range_end = get_target_range(review_target)

    status = "POTENTIAL_SIGNAL" if signal_found else "NO_SIGNAL_FOUND"

    if not api_is_success:
        status = "API_ERROR"

    return {
        "source_token": source_token,
        "all_source_tokens": all_source_tokens,
        "review_target": review_target,
        "input_type": input_type,
        "expansion_type": expansion_type,
        "query": query,
        "query_type": query_type,
        "range_start": range_start,
        "range_end": range_end,

        "status": status,
        "signal_found": signal_found,
        "match_count": match_count,

        "returned_ip_count": len(returned_ips),
        "returned_ips": ", ".join(returned_ips),

        "signal_category_count": len(signal_categories),
        "signal_categories": ", ".join(signal_categories),

        "api_is_success": api_is_success,
        "api_message": api_message,
        "api_error": "" if api_error is None else str(api_error),
        "api_response_code": api_response_code,
        "api_truncated": truncated,
        "all_tags": ", ".join(top_level_tags),

        "signal_categories_json": json.dumps(detected_categories, ensure_ascii=False),
        "returned_ip_details_json": json.dumps(returned_ip_details, ensure_ascii=False),
        # Kept internally for troubleshooting but deliberately excluded from UI/downloads.
        "raw_response_internal": json.dumps(response_json, ensure_ascii=False),
    }


# ============================================================
# API CALL
# ============================================================

def query_signal_source(
    target_row: dict[str, Any],
    timeout: int = 20,
    retries: int = 2,
    retry_sleep: float = 2.0,
) -> dict[str, Any]:
    review_target = target_row["review_target"]
    source_token = target_row.get("source_token", review_target)
    input_type = target_row.get("input_type", "")
    expansion_type = target_row.get("expansion_type", "")
    all_source_tokens = target_row.get("all_source_tokens", source_token)

    payload = {
        "query": review_target
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
                    "error": response.text[:1000],
                }

            if response.status_code == 200:
                result = extract_signal_result(
                    review_target=review_target,
                    source_token=source_token,
                    input_type=input_type,
                    expansion_type=expansion_type,
                    all_source_tokens=all_source_tokens,
                    response_json=response_json,
                )

                result["http_status"] = response.status_code
                result["elapsed_sec"] = elapsed
                result["checked_at_utc"] = datetime.now(timezone.utc).isoformat()
                result["error"] = ""
                return result

            if response.status_code in [429, 500, 502, 503, 504] and attempt < retries:
                time.sleep(retry_sleep * (attempt + 1))
                continue

            return build_error_result(
                source_token=source_token,
                all_source_tokens=all_source_tokens,
                review_target=review_target,
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
                review_target=review_target,
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
    review_target: str,
    input_type: str,
    expansion_type: str,
    status: str,
    error: str,
    http_status: int | None,
    elapsed_sec: float | None,
    raw_response: dict[str, Any],
) -> dict[str, Any]:
    return {
        "source_token": source_token,
        "all_source_tokens": all_source_tokens,
        "review_target": review_target,
        "input_type": input_type,
        "expansion_type": expansion_type,
        "query": review_target,
        "query_type": "",
        "range_start": "",
        "range_end": "",

        "status": status,
        "signal_found": False,
        "match_count": 0,

        "returned_ip_count": 0,
        "returned_ips": "",

        "signal_category_count": 0,
        "signal_categories": "",

        "api_is_success": False,
        "api_message": "",
        "api_error": error,
        "api_response_code": "",
        "api_truncated": False,
        "all_tags": "",

        "signal_categories_json": "[]",
        "returned_ip_details_json": "[]",
        "raw_response_internal": json.dumps(raw_response, ensure_ascii=False),

        "http_status": http_status,
        "elapsed_sec": elapsed_sec,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "error": error,
    }


# ============================================================
# PARALLEL REVIEW
# ============================================================

def run_parallel_review(
    review_df: pd.DataFrame,
    max_workers: int,
    timeout: int,
    retries: int,
    retry_sleep: float,
) -> pd.DataFrame:
    results = []

    progress_bar = st.progress(0)
    status_area = st.empty()

    target_rows = review_df.to_dict(orient="records")
    total = len(target_rows)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(
                query_signal_source,
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
                    review_target=target_row.get("review_target", ""),
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
                f"Reviewed {index}/{total}: {result['review_target']} -> {result['status']}"
            )

    return pd.DataFrame(results)


# ============================================================
# DETAIL TABLE BUILDERS
# ============================================================

def build_returned_ip_detail_table(df: pd.DataFrame) -> pd.DataFrame:
    rows = []

    for _, row in df.iterrows():
        raw_json = row.get("returned_ip_details_json", "[]")

        try:
            details = json.loads(raw_json)
        except Exception:
            details = []

        if isinstance(details, list):
            rows.extend(details)

    return pd.DataFrame(rows)


def build_signal_category_table(df: pd.DataFrame) -> pd.DataFrame:
    rows = []

    for _, row in df.iterrows():
        raw_json = row.get("signal_categories_json", "[]")

        try:
            details = json.loads(raw_json)
        except Exception:
            details = []

        if isinstance(details, list):
            rows.extend(details)

    return pd.DataFrame(rows)


def make_public_export_df(df: pd.DataFrame) -> pd.DataFrame:
    """Remove internal/debug fields before user-facing download."""

    excluded_columns = {
        "raw_response_internal",
        "signal_categories_json",
        "returned_ip_details_json",
    }

    public_columns = [col for col in df.columns if col not in excluded_columns]
    return df[public_columns].copy()


# ============================================================
# STREAMLIT UI
# ============================================================

st.set_page_config(
    page_title=APP_NAME,
    page_icon="shield",
    layout="wide",
)

st.title(APP_NAME)
st.caption(
    "A defensive first-pass triage aid for Fortinet-related public exposure signals. "
    "For authorized asset review only."
)

st.info(
    "Responsible use: This tool is intended only for assets you own or are explicitly "
    "authorized to assess. Results are informational signals and must be validated "
    "through official vendor guidance, patch review, asset ownership records, "
    "vulnerability management, and incident response procedures."
)

with st.expander("What this tool does and does not do", expanded=True):
    st.markdown(
        """
        **Purpose**
        - Help asset owners and authorized security teams perform a quick first-pass review.
        - Accept IP, CIDR, and range inputs.
        - Query a public Fortinet-related exposure-signal source.
        - Export summary results for follow-up validation.

        **Limitations**
        - This is not a vulnerability scanner.
        - This is not proof of compromise.
        - This does not replace official Fortinet guidance, patch validation, vulnerability management, or incident response.
        - No signal found does not guarantee that an asset is safe.
        """
    )

with st.sidebar:
    st.header("Review Settings")

    cidr_mode_label = st.radio(
        "CIDR handling",
        options=[
            "Keep CIDR as one API query",
            "Expand CIDR to individual host IPs",
        ],
        index=0,
        help=(
            "Keep mode is safer and faster for large subnet lists because the source accepts CIDR. "
            "Expand mode checks each host IP and should be used carefully."
        ),
    )

    cidr_mode = "keep" if cidr_mode_label.startswith("Keep") else "expand"

    max_ips_per_token = st.number_input(
        "Max expanded IPs per input token",
        min_value=1,
        max_value=10000,
        value=1024,
        step=100,
        help="Safety guardrail to prevent accidental large expansion.",
    )

    max_total_targets = st.number_input(
        "Max total review targets",
        min_value=1,
        max_value=10000,
        value=1000,
        step=100,
        help="Overall public-use safety limit after expansion and deduplication.",
    )

    max_workers = st.slider(
        "Parallel requests",
        min_value=1,
        max_value=10,
        value=3,
        help="Start low for public/free sources. Reduce if you get HTTP 429.",
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
    with st.expander("Signal source"):
        st.write("Public Fortinet-related lookup source used by this helper:")
        st.code(API_URL)
        st.caption("The endpoint may change, throttle, or return unstable results. Validate independently.")


st.subheader("Input IP / CIDR / Range")

default_input = """192.0.2.1
198.51.100.0/30
203.0.113.10-12
203.0.113.10-203.0.113.12
"""

input_text = st.text_area(
    "Paste IPs, CIDRs, or ranges",
    value=default_input,
    height=220,
    help=(
        "Supported formats: single IP, CIDR, last-octet range, full IP range. "
        "Labels before the IP are okay. The default examples are documentation networks."
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

review_df, skipped_df = build_review_targets(
    tokens=tokens,
    cidr_mode=cidr_mode,
    max_ips_per_token=int(max_ips_per_token),
    max_total_targets=int(max_total_targets),
)

col1, col2, col3 = st.columns(3)
col1.metric("Parsed input tokens", len(tokens))
col2.metric("Review targets", len(review_df))
col3.metric("Skipped inputs", len(skipped_df))

with st.expander("Parsed input tokens"):
    if tokens:
        st.dataframe(pd.DataFrame({"token": tokens}), use_container_width=True)
    else:
        st.info("No valid IP-like tokens found.")

with st.expander("Expanded review targets"):
    if len(review_df) > 0:
        st.dataframe(review_df, use_container_width=True)
    else:
        st.info("No review targets generated.")

if len(skipped_df) > 0:
    with st.expander("Skipped inputs / expansion warnings"):
        st.dataframe(skipped_df, use_container_width=True)

acknowledged = st.checkbox(
    "I confirm that I will only review assets I own or am authorized to assess, "
    "and that I will validate results using official processes.",
    value=False,
)

start_review = st.button(
    "Start Exposure Triage Review",
    type="primary",
    disabled=(len(review_df) == 0 or not acknowledged),
)


if start_review:
    st.warning(
        "Review started. If you see HTTP 429 or unstable results, reduce parallel requests. "
        "For large CIDRs, use 'Keep CIDR as one API query'."
    )

    df = run_parallel_review(
        review_df=review_df,
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

    st.subheader("Review Summary")

    summary_df = (
        df.groupby("status")
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
    )

    st.dataframe(summary_df, use_container_width=True)

    signal_df = df[df["status"] == "POTENTIAL_SIGNAL"]
    no_signal_df = df[df["status"] == "NO_SIGNAL_FOUND"]
    error_df = df[
        df["status"].isin(
            ["API_ERROR", "HTTP_ERROR", "REQUEST_ERROR", "LOCAL_ERROR"]
        )
    ]

    col1, col2, col3 = st.columns(3)
    col1.metric("Potential signal targets", len(signal_df))
    col2.metric("No signal found targets", len(no_signal_df))
    col3.metric("Error targets", len(error_df))

    if len(signal_df) > 0:
        st.error(
            f"Potential exposure signal found in {len(signal_df)} target(s). "
            "Validate with official vendor guidance, asset ownership records, "
            "patch status, vulnerability management, and incident response procedures."
        )
    else:
        st.success(
            "No public signal found in the reviewed targets. This does not guarantee safety; "
            "continue normal patch validation and vulnerability management."
        )

    st.subheader("Per Target Results")

    display_columns = [
        "source_token",
        "all_source_tokens",
        "review_target",
        "input_type",
        "expansion_type",
        "query",
        "query_type",
        "range_start",
        "range_end",
        "status",
        "signal_found",
        "match_count",
        "returned_ip_count",
        "returned_ips",
        "signal_category_count",
        "signal_categories",
        "api_truncated",
        "http_status",
        "elapsed_sec",
        "checked_at_utc",
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

    returned_ip_detail_df = build_returned_ip_detail_table(df)
    signal_category_df = build_signal_category_table(df)

    st.subheader("Returned IP Signal Details")

    if len(returned_ip_detail_df) > 0:
        st.dataframe(returned_ip_detail_df, use_container_width=True)
    else:
        st.info("No returned IP signal details.")

    st.subheader("Reported Signal Categories")

    if len(signal_category_df) > 0:
        st.dataframe(signal_category_df, use_container_width=True)
    else:
        st.info("No reported signal categories.")

    st.subheader("Download Reports")

    public_df = make_public_export_df(df)
    csv_summary = public_df.to_csv(index=False).encode("utf-8-sig")

    st.download_button(
        "Download Summary CSV",
        data=csv_summary,
        file_name=f"fortinet_exposure_triage_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
    )

    if len(returned_ip_detail_df) > 0:
        csv_ip_detail = returned_ip_detail_df.to_csv(index=False).encode("utf-8-sig")

        st.download_button(
            "Download Returned IP Signal Detail CSV",
            data=csv_ip_detail,
            file_name=f"fortinet_returned_ip_signal_detail_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
        )

    if len(signal_category_df) > 0:
        csv_category_detail = signal_category_df.to_csv(index=False).encode("utf-8-sig")

        st.download_button(
            "Download Reported Signal Categories CSV",
            data=csv_category_detail,
            file_name=f"fortinet_signal_categories_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
        )
