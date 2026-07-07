# Fortinet Exposure Triage Helper

A small defensive Streamlit helper for asset owners or authorized security teams to perform a first-pass review of Fortinet-related public exposure signals.

## Purpose

This project helps security teams quickly triage whether IPs, CIDRs, or ranges have public exposure signals that may require additional validation.

It is designed for:

- Defensive exposure review
- Asset triage
- Vulnerability intelligence follow-up
- Risk-based remediation discussion
- Security advisory demonstration

## Responsible use

Use this tool only for assets you own or are explicitly authorized to assess.

Results are informational signals and are not proof of compromise. Findings should be validated through official vendor guidance, patch review, asset ownership records, vulnerability management, and incident response procedures.

## What it does

- Accepts single IPs, CIDRs, last-octet ranges, and full IP ranges
- Supports TXT/CSV upload
- Supports safe CIDR handling modes
- Queries a public Fortinet-related lookup source
- Normalizes results into summary and detail tables
- Exports CSV reports for follow-up validation

## What it does not do

- It is not a vulnerability scanner
- It does not exploit anything
- It does not confirm compromise
- It does not replace official vendor guidance
- It does not replace vulnerability management or incident response
- No signal found does not guarantee that an asset is safe

## Run locally

```bash
pip install streamlit pandas requests
streamlit run fortinet_exposure_triage_helper.py
```

## Suggested LinkedIn project wording

**Fortinet Exposure Triage Helper**

A small Streamlit-based side project built to support defensive exposure review during a Fortinet-related security incident. The tool allows asset owners or authorized security teams to input IPs, CIDRs, or ranges, review potential public exposure signals, and export a summary for validation.

The goal is not to replace official vendor guidance, vulnerability management, or incident response procedures. It is a practical triage aid for identifying assets that may require additional review.
