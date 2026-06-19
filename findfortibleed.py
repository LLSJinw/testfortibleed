import json
import re
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import pandas as pd
import requests
import streamlit as st


API_URL_DEFAULT = "https://socradar.io/free-tools/api/fortibleed/search-fortibleed"

DEFAULT_HEADERS = {
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
    Accepts newline, comma, semicolon, tab, or space separated IP/CIDR values.
    """
    if not text:
        return []

    raw_items = re.split(r"[\s,;]+", text.strip())
    cleaned = []

    for item in raw_items:
        item = item.strip()
        if item:
            cleaned.append(item)

    return cleaned


def normalize_target(target: str) -> str:
    """
    Validate and normalize IP/CIDR.
    Keeps single IP as single IP.
    Keeps subnet as CIDR.
    """
    target = target.strip()

    if "/" in target:
        return str(ipaddress.ip_network(target, strict=False))

    return str(ipaddress.ip_address(target))


def parse_and_validate_targets(raw_targets: list[str]) -> tuple[list[str], list[dict]]:
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

    # Remove duplicates while preserving order
    valid = list(dict.fromkeys(valid))

    return valid, invalid


def expand_cidrs_to_ips(targets: list[str], max_ips_per_cidr: int) -> tuple[list[str], list[dict]]:
    """
    Optional mode. Disabled by default because the SOCRadar endpoint accepts CIDR.
    This is useful only if you specifically want per-IP lookup.
    """
    expanded = []
    skipped = []

    for target in targets:
        if "/" not in target:
            expanded.append(target)
            continue

        network = ipaddress.ip_network(target, strict=False)
        ip_count = network.num_addresses

        if ip_count > max_ips_per_cidr:
            skipped.append({
                "target": target,
                "reason": f"CIDR has {ip_count} IPs, above limit {max_ips_per_cidr}",
            })
            expanded.append(target)
            continue

        for ip in network.hosts():
            expanded.append(str(ip))

    return list(dict.fromkeys(expanded)), skipped


def detect_result_status(response_json) -> tuple[str, str]:
    """
    Best-effort parser because hidden/free APIs may change response format.

    Returns:
    - EXPOSED
    - NOT_FOUND
    - REVIEW
    """

    raw = json.dumps(response_json, ensure_ascii=False).lower()

    # Strong negative indicators
    negative_words = [
        "not found",
        "no record",
        "no result",
        "not leaked",
        "not exposed",
        "not affected",
        "not compromised",
    ]

    for word in negative_words:
        if word in raw:
            return "NOT_FOUND", word

    # Strong positive indicators
    positive_words = [
        "found",
        "leaked",
        "exposed",
        "compromised",
        "affected",
        "credential",
    ]

    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                key = str(k).lower()

                if key in [
                    "found",
                    "is_found",
                    "isfound",
                    "leaked",
                    "exposed",
                    "affected",
                    "compromised",
                    "is_compromised",
                    "iscompromised",
                    "success",
                    "match",
                    "matched",
                ]:
                    if v is True:
                        return True

                if key in ["data", "result", "results", "items", "records"]:
                    if isinstance(v, list) and len(v) > 0:
                        return True
                    if isinstance(v, dict) and len(v) > 0:
                        return True

                if walk(v):
                    return True

        elif isinstance(obj, list):
            if len(obj) > 0:
                # Non-empty list may mean records were returned
                return True

        return False

    if walk(response_json):
        return "EXPOSED", "structured positive match"

    for word in positive_words:
        if word in raw:
            return "REVIEW", f"contains keyword: {word}"

    return "REVIEW", "unrecognized response format"


def query_fortibleed(
    target: str,
    api_url: str,
    timeout: int,
    retries: int,
    retry_sleep: float,
) -> dict:
    payload = {"query": target}

    for attempt in range(retries + 1):
        started = time.time()

        try:
            response = requests.post(
                api_url,
                headers=DEFAULT_HEADERS,
                json=payload,
                timeout=timeout,
            )

            elapsed = round(time.time() - started, 3)

            try:
                response_json = response.json()
            except Exception:
                response_json = {
                    "raw_text": response.text[:2000],
                }

            if response.status_code == 200:
                status, reason = detect_result_status(response_json)

                return {
                    "target": target,
                    "status": status,
                    "http_status": response.status_code,
                    "reason": reason,
                    "elapsed_sec": elapsed,
                    "checked_at": datetime.utcnow().isoformat() + "Z",
                    "raw_response": json.dumps(response_json, ensure_ascii=False),
                }

            if response.status_code in [429, 500, 502, 503, 504] and attempt < retries:
                time.sleep(retry_sleep * (attempt + 1))
                continue

            return {
                "target": target,
                "status": "ERROR",
                "http_status": response.status_code,
                "reason": f"HTTP {response.status_code}",
                "elapsed_sec": elapsed,
                "checked_at": datetime.utcnow().isoformat() + "Z",
                "raw_response": json.dumps(response_json, ensure_ascii=False),
            }

        except requests.RequestException as e:
            if attempt < retries:
                time.sleep(retry_sleep * (attempt + 1))
                continue

            return {
                "target": target,
                "status": "ERROR",
                "http_status": None,
                "reason": str(e),
                "elapsed_sec": None,
                "checked_at": datetime.utcnow().isoformat() + "Z",
                "raw_response": "",
            }


def run_parallel_scan(
    targets: list[str],
    api_url: str,
    max_workers: int,
    timeout: int,
    retries: int,
    retry_sleep: float,
) -> pd.DataFrame:
    results = []
    progress = st.progress(0)
    status_box = st.empty()

    total = len(targets)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(
                query_fortibleed,
                target,
                api_url,
                timeout,
                retries,
                retry_sleep,
            ): target
            for target in targets
        }

        for idx, future in enumerate(as_completed(future_map), start=1):
            result = future.result()
            results.append(result)

            progress.progress(idx / total)
            status_box.info(f"Checked {idx}/{total}: {result['target']} -> {result['status']}")

    return pd.DataFrame(results)


st.set_page_config(
    page_title="FortiBleed Exposure Checker",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ FortiBleed Exposure Checker by IP / CIDR")
st.caption(
    "Use only for assets you own or are authorized to assess. "
    "This app calls the same style of backend endpoint used by the public checker, "
    "but with controlled batching instead of manual UI clicking."
)

with st.sidebar:
    st.header("Settings")

    api_url = st.text_input(
        "API endpoint",
        value=API_URL_DEFAULT,
    )

    max_workers = st.slider(
        "Parallel requests",
        min_value=1,
        max_value=20,
        value=8,
        help="Use lower value if you see rate limiting.",
    )

    timeout = st.slider(
        "Request timeout seconds",
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

    expand_cidr = st.checkbox(
        "Expand CIDR to individual IPs",
        value=False,
        help="Normally keep this OFF because the endpoint accepts CIDR queries.",
    )

    max_ips_per_cidr = st.number_input(
        "Max IPs to expand per CIDR",
        min_value=1,
        max_value=4096,
        value=256,
        disabled=not expand_cidr,
    )

st.subheader("Input IPs or CIDRs")

sample = """203.0.113.10
198.51.100.0/24
192.0.2.5
"""

input_text = st.text_area(
    "Paste IPs/CIDRs, one per line or comma-separated",
    value="",
    height=200,
    placeholder=sample,
)

uploaded_file = st.file_uploader(
    "Or upload TXT/CSV with IPs/CIDRs",
    type=["txt", "csv"],
)

uploaded_text = ""

if uploaded_file is not None:
    uploaded_text = uploaded_file.read().decode("utf-8", errors="ignore")

raw_targets = split_targets(input_text + "\n" + uploaded_text)
valid_targets, invalid_targets = parse_and_validate_targets(raw_targets)

if expand_cidr and valid_targets:
    valid_targets, skipped_expansion = expand_cidrs_to_ips(
        valid_targets,
        max_ips_per_cidr=int(max_ips_per_cidr),
    )
else:
    skipped_expansion = []

col1, col2, col3 = st.columns(3)
col1.metric("Valid targets", len(valid_targets))
col2.metric("Invalid inputs", len(invalid_targets))
col3.metric("Skipped CIDR expansion", len(skipped_expansion))

if invalid_targets:
    with st.expander("Invalid inputs"):
        st.dataframe(pd.DataFrame(invalid_targets), use_container_width=True)

if skipped_expansion:
    with st.expander("CIDRs not expanded"):
        st.dataframe(pd.DataFrame(skipped_expansion), use_container_width=True)

with st.expander("Targets to check"):
    st.write(valid_targets)

scan_button = st.button(
    "Start FortiBleed Check",
    type="primary",
    disabled=len(valid_targets) == 0,
)

if scan_button:
    st.warning(
        "Scanning started. Avoid very high parallelism against free public services. "
        "If you receive HTTP 429, reduce parallel requests."
    )

    df = run_parallel_scan(
        targets=valid_targets,
        api_url=api_url,
        max_workers=max_workers,
        timeout=timeout,
        retries=retries,
        retry_sleep=retry_sleep,
    )

    st.subheader("Summary")

    summary = (
        df.groupby("status")
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
    )

    st.dataframe(summary, use_container_width=True)

    exposed_df = df[df["status"] == "EXPOSED"]
    review_df = df[df["status"] == "REVIEW"]
    error_df = df[df["status"] == "ERROR"]

    if len(exposed_df) > 0:
        st.error(f"Found {len(exposed_df)} exposed / matched target(s). Treat as incident.")
        st.dataframe(exposed_df.drop(columns=["raw_response"]), use_container_width=True)
    else:
        st.success("No clear EXPOSED result detected by the parser.")

    if len(review_df) > 0:
        st.warning(
            f"{len(review_df)} result(s) need manual review because the API response format was ambiguous."
        )
        st.dataframe(review_df.drop(columns=["raw_response"]), use_container_width=True)

    if len(error_df) > 0:
        st.error(f"{len(error_df)} request(s) returned errors.")
        st.dataframe(error_df.drop(columns=["raw_response"]), use_container_width=True)

    st.subheader("Full Results")
    st.dataframe(df.drop(columns=["raw_response"]), use_container_width=True)

    with st.expander("Raw API Responses"):
        st.dataframe(df[["target", "status", "raw_response"]], use_container_width=True)

    csv_data = df.to_csv(index=False).encode("utf-8-sig")

    st.download_button(
        label="Download CSV Report",
        data=csv_data,
        file_name=f"fortibleed_check_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
    )
