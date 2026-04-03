#!/usr/bin/env python3
"""
================================================================================
CrowdStrike Falcon Cloud Security - IOM Retrieval Tool
================================================================================
Endpoints:
  Step 1: GET /cloud-security-evaluations/queries/ioms/v1   -> Get IOM IDs
  Step 2: GET /cloud-security-evaluations/entities/ioms/v1  -> Get IOM details
  Optional: GET /cloud-security-evaluations/combined/ioms-by-rule/v1

Response structure (nested):
  finding.cloud.provider          -> cloud platform
  finding.cloud.region            -> region
  finding.cloud.account_id        -> account ID
  finding.cloud.account_name      -> account name
  finding.resource.service        -> cloud service
  finding.resource.resource_id    -> resource ID
  finding.resource.resource_type  -> resource type
  finding.evaluation.severity     -> severity
  finding.evaluation.status       -> status
  finding.evaluation.rule.name    -> rule name
  finding.evaluation.rule.threat  -> MITRE ATT&CK info
  finding.evaluation.rule.controls-> compliance frameworks

Required API Scope: Cloud Security API Detections (Read)

Credentials via environment variables:
  export FALCON_CLIENT_ID=\"<YOUR_FALCON_CLIENT_ID>\"
  export FALCON_CLIENT_SECRET=\"<YOUR_FALCON_CLIENT_SECRET>\"
  export FALCON_API_URL=\"<YOUR_BASE_URL>\"

Usage:
  python iom_retrieval.py
  python iom_retrieval.py --platform gcp
  python iom_retrieval.py --severity high,critical --output console
  python iom_retrieval.py --output csv --file my_ioms.csv
  python iom_retrieval.py --grouped-by-rule --output console
  python iom_retrieval.py --output console --limit 10
"""

import argparse
import csv
import json
import os
import sys
import requests
from datetime import datetime

try:
    from falconpy import OAuth2
except ImportError:
    print("[ERROR] FalconPy not installed: pip install crowdstrike-falconpy")
    sys.exit(1)

# ============================================================
# CONSTANTS
# ============================================================
IOM_QUERY_ENDPOINT    = "/cloud-security-evaluations/queries/ioms/v1"
IOM_ENTITY_ENDPOINT   = "/cloud-security-evaluations/entities/ioms/v1"
IOM_COMBINED_ENDPOINT = "/cloud-security-evaluations/combined/ioms-by-rule/v1"

VALID_PLATFORMS  = ["aws", "azure", "gcp"]
VALID_SEVERITIES = ["critical", "high", "medium", "low", "informational"]
QUERY_PAGE_SIZE  = 1000
ENTITY_BATCH     = 100
DEFAULT_LIMIT    = 10000

# ============================================================
# FIELD EXTRACTION HELPERS
# Handles the nested response structure:
#   cloud.provider, cloud.region, cloud.account_id, cloud.account_name
#   resource.service, resource.resource_id, resource.resource_type
#   evaluation.severity, evaluation.status
#   evaluation.rule.name, evaluation.rule.id
#   evaluation.rule.threat.tactic.name
#   evaluation.rule.threat.technique.name
#   evaluation.rule.controls[].framework
# ============================================================
def get_cloud(f):
    return f.get("cloud") or {}

def get_resource(f):
    return f.get("resource") or {}

def get_evaluation(f):
    return f.get("evaluation") or {}

def get_rule(f):
    return get_evaluation(f).get("rule") or {}

def get_threat(f):
    return get_rule(f).get("threat") or {}

def get_tactic(f):
    return get_threat(f).get("tactic") or {}

def get_technique(f):
    return get_threat(f).get("technique") or {}

def get_controls(f):
    return get_rule(f).get("controls") or []

def extract_field(finding, field):
    """
    Extract a field value from a finding using the nested structure.
    Returns the value or empty string if not found.
    """
    mapping = {
        # Top level
        "id"                  : lambda f: f.get("id", ""),
        "cid"                 : lambda f: f.get("cid", ""),
        # Cloud nested fields
        "cloud_provider"      : lambda f: get_cloud(f).get("provider", ""),
        "region"              : lambda f: get_cloud(f).get("region", ""),
        "account_id"          : lambda f: get_cloud(f).get("account_id", ""),
        "account_name"        : lambda f: get_cloud(f).get("account_name", ""),
        # Resource nested fields
        "resource_id"         : lambda f: get_resource(f).get("resource_id", ""),
        "resource_type"       : lambda f: get_resource(f).get("resource_type", ""),
        "resource_type_name"  : lambda f: get_resource(f).get("resource_type_name", ""),
        "resource_gcrn"       : lambda f: get_resource(f).get("gcrn", ""),
        "service"             : lambda f: get_resource(f).get("service", ""),
        "service_category"    : lambda f: get_resource(f).get("service_category", ""),
        "captured"            : lambda f: get_resource(f).get("captured", ""),
        # Evaluation nested fields
        "severity"            : lambda f: get_evaluation(f).get("severity", ""),
        "status"              : lambda f: get_evaluation(f).get("status", ""),
        "first_detected"      : lambda f: get_evaluation(f).get("first_detected", ""),
        "last_detected"       : lambda f: get_evaluation(f).get("last_detected", ""),
        "created"             : lambda f: get_evaluation(f).get("created", ""),
        "console_url"         : lambda f: get_evaluation(f).get("url", ""),
        "attack_types"        : lambda f: " | ".join(get_evaluation(f).get("attack_types") or []),
        # Rule nested fields
        "rule_id"             : lambda f: get_rule(f).get("id", ""),
        "rule_name"           : lambda f: get_rule(f).get("name", ""),
        "rule_description"    : lambda f: get_rule(f).get("description", ""),
        "rule_origin"         : lambda f: get_rule(f).get("origin", ""),
        "rule_policy_id"      : lambda f: str(get_rule(f).get("policy_id", "")),
        "rule_remediation"    : lambda f: get_rule(f).get("remediation", ""),
        "rule_alert_logic"    : lambda f: get_rule(f).get("alert_logic", ""),
        # MITRE ATT&CK
        "tactic_id"           : lambda f: get_tactic(f).get("id", ""),
        "tactic_name"         : lambda f: get_tactic(f).get("name", ""),
        "technique_id"        : lambda f: get_technique(f).get("id", ""),
        "technique_name"      : lambda f: get_technique(f).get("name", ""),
        "mitre_framework"     : lambda f: get_threat(f).get("framework", ""),
        # Compliance frameworks (first one for simple fields)
        "framework"           : lambda f: get_controls(f)[0].get("framework", "") if get_controls(f) else "",
        "frameworks_all"      : lambda f: " | ".join(
                                    sorted(set(c.get("framework","") for c in get_controls(f)))
                                ),
        # Extension
        "extension_status"    : lambda f: (f.get("extension") or {}).get("status", ""),
    }

    fn = mapping.get(field)
    if fn:
        try:
            return fn(finding)
        except Exception:
            return ""
    return str(finding.get(field, ""))


# CSV column definitions - flat fields for CSV output
FINDINGS_CSV_FIELDS = [
    "id",
    "rule_name",
    "rule_id",
    "rule_policy_id",
    "rule_origin",
    "severity",
    "cloud_provider",
    "service",
    "service_category",
    "status",
    "extension_status",
    "account_id",
    "account_name",
    "region",
    "resource_id",
    "resource_type",
    "resource_type_name",
    "resource_gcrn",
    "first_detected",
    "last_detected",
    "created",
    "attack_types",
    "tactic_id",
    "tactic_name",
    "technique_id",
    "technique_name",
    "mitre_framework",
    "frameworks_all",
    "console_url",
    "rule_remediation",
    "cid",
]

RULE_CSV_FIELDS = [
    "cid",
    "cloud_provider",
    "account_id",
    "region",
    "misconfigurations",
    "assessed_assets",
    "severity",
    "rule_id",
    "rule_name",
    "rule_service",
    "rule_description",
    "compliance_frameworks",
    "compliance_requirements",
    "tags",
]

SEVERITY_COLORS = {
    "critical"     : "\033[91m",
    "high"         : "\033[93m",
    "medium"       : "\033[94m",
    "low"          : "\033[96m",
    "informational": "\033[97m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"


# ============================================================
# CREDENTIALS
# ============================================================
def load_credentials():
    cid     = os.environ.get("FALCON_CLIENT_ID")
    secret  = os.environ.get("FALCON_CLIENT_SECRET")
    baseurl = os.environ.get("FALCON_API_URL", "https://api.crowdstrike.com")
    errors  = []
    if not cid:
        errors.append("FALCON_CLIENT_ID is not set")
    if not secret:
        errors.append("FALCON_CLIENT_SECRET is not set")
    if errors:
        print("\n[ERROR] Missing environment variables:")
        for e in errors:
            print(f"  - {e}")
        print("\n  export FALCON_CLIENT_ID=\"<id>\"")
        print("  export FALCON_CLIENT_SECRET=\"<secret>\"")
        sys.exit(1)
    return cid, secret, baseurl


# ============================================================
# ARGUMENT PARSING
# ============================================================
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="CrowdStrike Falcon - IOM Retrieval Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Output Formats:
  json     Save full findings + summary to JSON file (default)
  csv      Save findings to CSV file (flat, one row per IOM)
  console  Print summary + findings to terminal

FQL Filter Fields:
  account_id, account_name, cloud_provider, severity, status,
  region, policy_id, policy_name, resource_id, resource_type,
  service, framework, rule_id, rule_name, first_detected,
  last_detected, attack_type, business_impact, tags

Examples:
  python iom_retrieval.py
  python iom_retrieval.py --platform gcp
  python iom_retrieval.py --severity critical,high --output console
  python iom_retrieval.py --output csv --file my_ioms.csv
  python iom_retrieval.py --grouped-by-rule --output csv
  python iom_retrieval.py --output console --limit 10
  python iom_retrieval.py --fql \"severity:'high'+cloud_provider:'gcp'\"
        """
    )
    parser.add_argument("--platform", default="all",
        help="Cloud platform: all, aws, azure, gcp (default: all)")
    parser.add_argument("--severity", default="all",
        help="Comma-separated: all, critical, high, medium, low, informational")
    parser.add_argument("--status", default="all",
        help="IOM status filter (default: all)")
    parser.add_argument("--region", default=None,
        help="Filter by region")
    parser.add_argument("--account-id", default=None,
        help="Filter by cloud account ID")
    parser.add_argument("--policy-id", default=None,
        help="Filter by policy ID")
    parser.add_argument("--service", default=None,
        help="Filter by cloud service")
    parser.add_argument("--framework", default=None,
        help="Filter by compliance framework")
    parser.add_argument("--fql", default=None,
        help="Raw FQL filter string (overrides other filters)")
    parser.add_argument("--sort", default="last_detected|desc",
        help="Sort field and direction (default: last_detected|desc)")
    parser.add_argument("--grouped-by-rule", action="store_true",
        help="Return IOMs grouped by rule instead of individual findings")
    parser.add_argument("--output", choices=["json", "csv", "console"],
        default="json",
        help="Output format: json, csv, or console (default: json)")
    parser.add_argument("--file", default=None,
        help="Output filename. Defaults to ioms_TIMESTAMP.json/csv")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT,
        help=f"Max IOMs to retrieve (default: {DEFAULT_LIMIT})")
    return parser.parse_args()


def validate_arguments(args):
    errors = []
    if args.platform.lower() != "all" and args.platform.lower() not in VALID_PLATFORMS:
        errors.append(f"Invalid platform: {args.platform}")
    if args.limit < 1:
        errors.append("--limit must be > 0")
    if errors:
        for e in errors:
            print(f"[ERROR] {e}")
        sys.exit(1)


# ============================================================
# AUTHENTICATION
# ============================================================
def get_access_token(client_id, client_secret, base_url):
    print("[*] Authenticating...")
    print(f"    Client ID : {client_id[:8]}...{client_id[-4:]}")
    print(f"    Base URL  : {base_url}")
    try:
        auth  = OAuth2(client_id=client_id, client_secret=client_secret, base_url=base_url)
        token = auth.token()
        if token["status_code"] == 201:
            print("[OK] Authentication successful")
            return token["body"]["access_token"]
        else:
            print(f"[ERROR] Auth failed (HTTP {token['status_code']}): {token['body']}")
            sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Auth exception: {e}")
        sys.exit(1)


# ============================================================
# FQL FILTER BUILDER
# ============================================================
def build_fql_filter(args):
    if args.fql:
        return args.fql
    filters = []
    if args.platform.lower() != "all":
        filters.append(f"cloud_provider:'{args.platform.lower()}'")
    if args.severity.lower() != "all":
        sev_list = [s.strip().lower() for s in args.severity.split(",")]
        if len(sev_list) == 1:
            filters.append(f"severity:'{sev_list[0]}'")
        else:
            sev_parts = ",".join([f"'{s}'" for s in sev_list])
            filters.append(f"severity:[{sev_parts}]")
    if args.status.lower() != "all":
        filters.append(f"status:'{args.status.lower()}'")
    if args.region:
        filters.append(f"region:'{args.region}'")
    if args.account_id:
        filters.append(f"account_id:'{args.account_id}'")
    if args.policy_id:
        filters.append(f"policy_id:'{args.policy_id}'")
    if args.service:
        filters.append(f"service:'{args.service}'")
    if args.framework:
        filters.append(f"framework:'{args.framework}'")
    return "+".join(filters) if filters else None


# ============================================================
# API: GET IOM IDs
# ============================================================
def get_iom_ids(access_token, base_url, fql_filter=None,
                sort="last_detected|desc", limit=DEFAULT_LIMIT):
    print(f"\n{'='*60}")
    print(f"[STEP 1] Retrieving IOM IDs")
    print(f"{'='*60}")
    print(f"  Endpoint : GET {IOM_QUERY_ENDPOINT}")
    print(f"  Filter   : {fql_filter or 'None (all IOMs)'}")
    print(f"  Sort     : {sort}")
    print(f"  Max      : {limit}")

    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
    all_ids     = []
    offset      = 0
    after_token = None
    total_avail = None
    page_num    = 1
    page_size   = min(QUERY_PAGE_SIZE, limit)

    while True:
        print(f"\n[*] Fetching page {page_num} (offset={offset}, size={page_size})...")
        params = {"limit": page_size, "sort": sort}
        if fql_filter:
            params["filter"] = fql_filter
        if after_token:
            params = {"limit": page_size, "after": after_token}
        else:
            params["offset"] = offset

        try:
            r = requests.get(f"{base_url}{IOM_QUERY_ENDPOINT}",
                             headers=headers, params=params, timeout=30)
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] {e}")
            sys.exit(1)

        if r.status_code == 401:
            print("[ERROR] Auth failed")
            sys.exit(1)
        elif r.status_code == 403:
            print("[ERROR] Forbidden - check scope: Cloud Security API Detections: Read")
            sys.exit(1)
        elif r.status_code == 400:
            errs = r.json().get("errors", [])
            for e in errs:
                print(f"[ERROR] {e.get('code')}: {e.get('message')}")
            sys.exit(1)
        elif r.status_code != 200:
            print(f"[ERROR] HTTP {r.status_code}: {r.text[:200]}")
            sys.exit(1)

        body       = r.json()
        resources  = body.get("resources") or []
        pagination = body.get("meta", {}).get("pagination", {})

        if total_avail is None:
            total_avail = pagination.get("total", 0)
            print(f"[*] Total IOMs available: {total_avail}")
            if total_avail == 0:
                print("[!] No IOMs found.")
                return []

        if not resources:
            print("[*] No more results.")
            break

        all_ids.extend(resources)
        print(f"    Retrieved: {len(all_ids)} / {min(limit, total_avail)}")

        after_token = pagination.get("after")

        if len(all_ids) >= limit:
            all_ids = all_ids[:limit]
            print(f"[*] Reached limit of {limit}.")
            break
        if len(all_ids) >= total_avail:
            print(f"[*] All IOMs retrieved.")
            break
        if not after_token:
            offset   += page_size
            remaining = min(limit - len(all_ids), total_avail - len(all_ids))
            page_size = min(QUERY_PAGE_SIZE, remaining)
        page_num += 1

    print(f"\n[OK] Total IOM IDs: {len(all_ids)}")
    return all_ids


# ============================================================
# API: GET IOM DETAILS
# ============================================================
def get_iom_details(access_token, base_url, iom_ids):
    if not iom_ids:
        return []

    print(f"\n{'='*60}")
    print(f"[STEP 2] Retrieving IOM Details")
    print(f"{'='*60}")
    print(f"  Endpoint   : GET {IOM_ENTITY_ENDPOINT}")
    print(f"  Total IDs  : {len(iom_ids)}")
    print(f"  Batch size : {ENTITY_BATCH}")

    headers     = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
    all_details = []
    batches     = [iom_ids[i:i+ENTITY_BATCH] for i in range(0, len(iom_ids), ENTITY_BATCH)]

    for i, batch in enumerate(batches, 1):
        print(f"[*] Batch {i}/{len(batches)} ({len(batch)} IDs)...")
        params = [("ids", iid) for iid in batch]
        try:
            r = requests.get(f"{base_url}{IOM_ENTITY_ENDPOINT}",
                             headers=headers, params=params, timeout=30)
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Batch {i}: {e}")
            continue

        if r.status_code not in [200]:
            print(f"[ERROR] HTTP {r.status_code}: {r.text[:200]}")
            continue

        resources = r.json().get("resources") or []
        all_details.extend(resources)
        print(f"    Details so far: {len(all_details)} / {len(iom_ids)}")

    print(f"\n[OK] Total IOM details: {len(all_details)}")
    return all_details


# ============================================================
# API: GET IOMs GROUPED BY RULE
# ============================================================
def get_ioms_by_rule(access_token, base_url, fql_filter=None,
                     sort="misconfigurations|desc", limit=DEFAULT_LIMIT):
    print(f"\n{'='*60}")
    print(f"[STEP] Retrieving IOMs Grouped by Rule")
    print(f"{'='*60}")
    print(f"  Endpoint : GET {IOM_COMBINED_ENDPOINT}")
    print(f"  Filter   : {fql_filter or 'None (all)'}")

    headers   = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
    all_rules = []
    offset    = 0
    total_avail = None
    page_num  = 1
    page_size = min(1000, limit)

    while True:
        print(f"[*] Fetching page {page_num} (offset={offset})...")
        params = {"limit": page_size, "offset": offset, "sort": sort}
        if fql_filter:
            params["filter"] = fql_filter

        try:
            r = requests.get(f"{base_url}{IOM_COMBINED_ENDPOINT}",
                             headers=headers, params=params, timeout=30)
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] {e}")
            sys.exit(1)

        if r.status_code != 200:
            print(f"[ERROR] HTTP {r.status_code}: {r.text[:200]}")
            break

        body       = r.json()
        resources  = body.get("resources") or []
        pagination = body.get("meta", {}).get("pagination", {})

        if total_avail is None:
            total_avail = pagination.get("total", 0)
            print(f"[*] Total rules: {total_avail}")
            if total_avail == 0:
                return []

        if not resources:
            break

        all_rules.extend(resources)
        print(f"    Retrieved: {len(all_rules)} / {min(limit, total_avail)}")

        if len(all_rules) >= limit or len(all_rules) >= total_avail:
            break

        offset   += page_size
        remaining = min(limit - len(all_rules), total_avail - len(all_rules))
        page_size = min(1000, remaining)
        page_num += 1

    print(f"\n[OK] Total rules: {len(all_rules)}")
    return all_rules


# ============================================================
# SUMMARY BUILDERS - uses extract_field for nested access
# ============================================================
def build_summary(findings):
    """
    Build summary using nested field extraction.
    All values extracted via extract_field() which handles
    the nested cloud/resource/evaluation structure.
    """
    summary = {
        "total_findings": len(findings),
        "by_severity"   : {},
        "by_platform"   : {},
        "by_status"     : {},
        "by_service"    : {},
        "by_region"     : {},
        "by_account"    : {},
        "by_framework"  : {},
        "by_rule"       : {},
        "by_tactic"     : {},
    }

    for f in findings:
        def inc(key, field):
            val = extract_field(f, field)
            val = str(val).strip() if val else "unknown"
            if not val:
                val = "unknown"
            summary[key][val] = summary[key].get(val, 0) + 1

        inc("by_severity",  "severity")
        inc("by_platform",  "cloud_provider")
        inc("by_status",    "status")
        inc("by_service",   "service")
        inc("by_region",    "region")
        inc("by_account",   "account_id")
        inc("by_rule",      "rule_name")
        inc("by_tactic",    "tactic_name")

        # Framework - all frameworks from controls array
        controls = get_controls(f)
        frameworks = sorted(set(c.get("framework","") for c in controls if c.get("framework")))
        for fw in frameworks:
            summary["by_framework"][fw] = summary["by_framework"].get(fw, 0) + 1

    for key in summary:
        if isinstance(summary[key], dict):
            summary[key] = dict(
                sorted(summary[key].items(), key=lambda x: x[1], reverse=True)
            )
    return summary


def build_rule_summary(rules):
    summary = {
        "total_rules"            : len(rules),
        "total_misconfigurations": sum(r.get("misconfigurations", 0) for r in rules),
        "by_severity"            : {},
        "by_platform"            : {},
        "by_service"             : {},
    }
    for r in rules:
        rule = r.get("rule", {}) or {}
        sev  = rule.get("severity", r.get("severity", "unknown"))
        svc  = rule.get("service",  r.get("service", "unknown"))
        plat = str(r.get("cloud_provider", "unknown")).upper()
        summary["by_severity"][sev]  = summary["by_severity"].get(sev, 0) + 1
        summary["by_platform"][plat] = summary["by_platform"].get(plat, 0) + 1
        summary["by_service"][svc]   = summary["by_service"].get(svc, 0) + 1
    for key in ["by_severity", "by_platform", "by_service"]:
        summary[key] = dict(
            sorted(summary[key].items(), key=lambda x: x[1], reverse=True)
        )
    return summary


# ============================================================
# CSV HELPERS
# ============================================================
def flatten_finding_for_csv(finding):
    """Flatten a nested IOM finding into a flat dict for CSV output"""
    row = {}
    for field in FINDINGS_CSV_FIELDS:
        val = extract_field(finding, field)
        if isinstance(val, list):
            val = " | ".join(str(v) for v in val)
        elif isinstance(val, dict):
            val = json.dumps(val)
        elif val is None:
            val = ""
        row[field] = val
    return row


def flatten_rule_for_csv(rule):
    rule_obj = rule.get("rule", {}) or {}

    # Handle rule being a non-dict
    if not isinstance(rule_obj, dict):
        rule_obj = {}

    compliance    = rule.get("compliance", []) or []
    frameworks    = " | ".join(
        c.get("framework", "") for c in compliance
        if isinstance(c, dict)
    )
    requirements  = " | ".join(
        c.get("requirement", c.get("name", "")) for c in compliance
        if isinstance(c, dict)
    )

    # Handle tags as dict or list
    tags     = rule.get("tags") or []
    if isinstance(tags, dict):
        tags_str = " | ".join(f"{k}={v}" for k, v in tags.items())
    elif isinstance(tags, list):
        tags_str = " | ".join(str(t) for t in tags)
    else:
        tags_str = str(tags) if tags else ""

    # Rule name/id may be at top level or nested in rule dict
    rule_name = (
        rule_obj.get("name") or
        rule_obj.get("rule_name") or
        rule.get("rule_name") or
        ""
    )
    rule_id = (
        rule_obj.get("id") or
        rule_obj.get("rule_id") or
        rule.get("rule_id") or
        ""
    )

    return {
        "cid"                    : rule.get("cid", ""),
        "cloud_provider"         : rule.get("cloud_provider", ""),
        "account_id"             : rule.get("account_id", ""),
        "region"                 : rule.get("region", ""),
        "misconfigurations"      : rule.get("misconfigurations", 0),
        "assessed_assets"        : rule.get("assessed_assets", 0),
        "severity"               : rule.get("severity", rule_obj.get("severity", "")),
        "rule_id"                : rule_id,
        "rule_name"              : rule_name,
        "rule_service"           : rule_obj.get("service", ""),
        "rule_description"       : rule_obj.get("description", ""),
        "compliance_frameworks"  : frameworks,
        "compliance_requirements": requirements,
        "tags"                   : tags_str,
    }



def write_csv(rows, fieldnames, filename):
    try:
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames,
                                    extrasaction="ignore", quoting=csv.QUOTE_ALL)
            writer.writeheader()
            writer.writerows(rows)
        print(f"\n[OK] CSV saved to   : {filename}")
        print(f"[OK] Rows written    : {len(rows)}")
        print(f"[OK] Columns         : {len(fieldnames)}")
    except IOError as e:
        print(f"[ERROR] Cannot write CSV: {e}")
        sys.exit(1)


# ============================================================
# SUMMARY PRINTERS
# ============================================================
def print_iom_summary(summary):
    print(f"\n{BOLD}{'='*65}{RESET}")
    print(f"{BOLD}  IOM SUMMARY{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"  Total Findings : {summary['total_findings']}")

    print(f"\n  By Severity:")
    for sev in ["critical","high","medium","low","informational","unknown"]:
        if sev in summary["by_severity"]:
            count = summary["by_severity"][sev]
            color = SEVERITY_COLORS.get(sev.lower(), "")
            bar   = chr(9608) * min(count, 40)
            print(f"    {color}{sev.upper():<15}{RESET} {count:>6}  {color}{bar}{RESET}")

    print(f"\n  By Platform:")
    for p, c in summary["by_platform"].items():
        print(f"    {str(p).upper():<15} {c:>6}")

    print(f"\n  By Status:")
    for s, c in summary["by_status"].items():
        print(f"    {str(s):<25} {c:>6}")

    print(f"\n  Top 10 Services:")
    for s, c in list(summary["by_service"].items())[:10]:
        print(f"    {str(s):<35} {c:>6}")

    print(f"\n  Top 10 Regions:")
    for r, c in list(summary["by_region"].items())[:10]:
        print(f"    {str(r):<25} {c:>6}")

    print(f"\n  Top 10 Accounts:")
    for a, c in list(summary["by_account"].items())[:10]:
        print(f"    {str(a):<35} {c:>6}")

    if summary.get("by_framework"):
        print(f"\n  By Compliance Framework:")
        for fw, c in list(summary["by_framework"].items())[:15]:
            print(f"    {str(fw):<20} {c:>6}")

    if summary.get("by_tactic"):
        print(f"\n  By MITRE Tactic:")
        for t, c in list(summary["by_tactic"].items())[:10]:
            if t != "unknown":
                print(f"    {str(t):<35} {c:>6}")

    print(f"{BOLD}{'='*65}{RESET}\n")


def print_rule_summary(summary):
    print(f"\n{BOLD}{'='*65}{RESET}")
    print(f"{BOLD}  IOM GROUPED BY RULE - SUMMARY{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"  Total Rules            : {summary['total_rules']}")
    print(f"  Total Misconfigurations: {summary['total_misconfigurations']}")

    print(f"\n  By Severity:")
    for sev, c in summary["by_severity"].items():
        color = SEVERITY_COLORS.get(str(sev).lower(), "")
        print(f"    {color}{str(sev).upper():<15}{RESET} {c:>6}")

    print(f"\n  By Platform:")
    for p, c in summary["by_platform"].items():
        print(f"    {str(p):<15} {c:>6}")

    print(f"\n  Top 10 Services:")
    for s, c in list(summary["by_service"].items())[:10]:
        print(f"    {str(s):<35} {c:>6}")

    print(f"{BOLD}{'='*65}{RESET}\n")


# ============================================================
# OUTPUT: FINDINGS
# ============================================================
def output_findings_json(findings, summary, base_url, filename=None):
    if not filename:
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ioms_{ts}.json"
    out = {
        "metadata": {
            "tool"           : "CrowdStrike Falcon - IOM Retrieval Tool",
            "generated_at"   : datetime.now().isoformat(),
            "mode"           : "findings",
            "total_findings" : len(findings),
            "falcon_base_url": base_url,
            "endpoints_used" : [IOM_QUERY_ENDPOINT, IOM_ENTITY_ENDPOINT],
        },
        "summary" : summary,
        "findings": findings
    }
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, default=str)
        print(f"\n[OK] JSON saved to  : {filename}")
        print(f"[OK] Total findings : {len(findings)}")
    except IOError as e:
        print(f"[ERROR] Cannot write JSON: {e}")
        sys.exit(1)
    print_iom_summary(summary)


def output_findings_csv(findings, summary, filename=None):
    if not filename:
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ioms_{ts}.csv"
    rows = [flatten_finding_for_csv(f) for f in findings]
    write_csv(rows, FINDINGS_CSV_FIELDS, filename)
    print_iom_summary(summary)


def output_findings_console(findings, summary):
    print(f"\n{'='*70}")
    print(f"{BOLD}  IOM FINDINGS REPORT{RESET}")
    print(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"{'='*70}")
    print_iom_summary(summary)

    print(f"{BOLD}  INDIVIDUAL FINDINGS ({len(findings)} total){RESET}")
    print(f"{'─'*70}")

    for i, f in enumerate(findings, 1):
        sev   = extract_field(f, "severity").lower()
        color = SEVERITY_COLORS.get(sev, "")

        print(f"\n[{i:04d}] {'─'*54}")
        print(f"  IOM ID          : {f.get('id', 'N/A')}")
        print(f"  Rule Name       : {extract_field(f, 'rule_name')}")
        print(f"  Rule ID         : {extract_field(f, 'rule_id')}")
        print(f"  Policy ID       : {extract_field(f, 'rule_policy_id')}")
        print(f"  Severity        : {color}{sev.upper()}{RESET}")
        print(f"  Cloud Platform  : {extract_field(f, 'cloud_provider').upper()}")
        print(f"  Service         : {extract_field(f, 'service')}")
        print(f"  Service Category: {extract_field(f, 'service_category')}")
        print(f"  Status          : {extract_field(f, 'status')}")
        print(f"  Ext Status      : {extract_field(f, 'extension_status')}")
        print(f"  Account ID      : {extract_field(f, 'account_id')}")
        print(f"  Account Name    : {extract_field(f, 'account_name')}")
        print(f"  Region          : {extract_field(f, 'region')}")
        print(f"  Resource ID     : {extract_field(f, 'resource_id')}")
        print(f"  Resource Type   : {extract_field(f, 'resource_type_name')}")
        print(f"  First Detected  : {extract_field(f, 'first_detected')}")
        print(f"  Last Detected   : {extract_field(f, 'last_detected')}")

        attack = extract_field(f, "attack_types")
        if attack:
            print(f"  Attack Types    : {attack}")

        tactic = extract_field(f, "tactic_name")
        if tactic:
            print(f"  Tactic          : {extract_field(f,'tactic_id')} - {tactic}")

        technique = extract_field(f, "technique_name")
        if technique:
            print(f"  Technique       : {extract_field(f,'technique_id')} - {technique}")

        frameworks = extract_field(f, "frameworks_all")
        if frameworks:
            print(f"  Frameworks      : {frameworks}")

        console_url = extract_field(f, "console_url")
        if console_url:
            print(f"  Console URL     : {console_url}")

        remediation = extract_field(f, "rule_remediation")
        if remediation:
            rem = str(remediation)
            if len(rem) > 300:
                rem = rem[:300] + "..."
            print(f"  Remediation     : {rem}")

    print(f"\n{'='*70}")
    print(f"  END OF REPORT - {len(findings)} findings")
    print(f"{'='*70}\n")


# ============================================================
# OUTPUT: RULES
# ============================================================
def output_rules_json(rules, summary, base_url, filename=None):
    if not filename:
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ioms_by_rule_{ts}.json"
    out = {
        "metadata": {
            "tool"           : "CrowdStrike Falcon - IOM Retrieval Tool",
            "generated_at"   : datetime.now().isoformat(),
            "mode"           : "grouped_by_rule",
            "total_rules"    : len(rules),
            "falcon_base_url": base_url,
            "endpoints_used" : [IOM_COMBINED_ENDPOINT],
        },
        "summary": summary,
        "rules"  : rules
    }
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, default=str)
        print(f"\n[OK] JSON saved to : {filename}")
        print(f"[OK] Total rules   : {len(rules)}")
    except IOError as e:
        print(f"[ERROR] Cannot write JSON: {e}")
        sys.exit(1)
    print_rule_summary(summary)


def output_rules_csv(rules, summary, filename=None):
    if not filename:
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ioms_by_rule_{ts}.csv"
    rows = [flatten_rule_for_csv(r) for r in rules]
    write_csv(rows, RULE_CSV_FIELDS, filename)
    print_rule_summary(summary)


def output_rules_console(rules, summary):
    print(f"\n{'='*70}")
    print(f"{BOLD}  IOM BY RULE REPORT{RESET}")
    print(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"{'='*70}")
    print_rule_summary(summary)

    print(f"{BOLD}  RULES ({len(rules)} total){RESET}")
    print(f"{'─'*70}")

    for i, r in enumerate(rules, 1):
        # ── Handle different possible rule field structures ──────
        # The combined endpoint may return rule as a dict, string, or None
        rule_raw = r.get("rule") or {}

        if isinstance(rule_raw, dict):
            rule_name = (
                rule_raw.get("name") or
                rule_raw.get("rule_name") or
                rule_raw.get("title") or
                r.get("rule_name") or
                r.get("policy_name") or
                "N/A"
            )
            rule_id = (
                rule_raw.get("id") or
                rule_raw.get("rule_id") or
                rule_raw.get("uuid") or
                r.get("rule_id") or
                "N/A"
            )
        else:
            rule_name = str(rule_raw) if rule_raw else r.get("rule_name", "N/A")
            rule_id   = r.get("rule_id", "N/A")

        # Severity - may be at top level or inside rule
        sev = (
            r.get("severity") or
            (rule_raw.get("severity") if isinstance(rule_raw, dict) else None) or
            "unknown"
        ).lower()

        color  = SEVERITY_COLORS.get(sev, "")
        miscs  = r.get("misconfigurations", 0)
        assets = r.get("assessed_assets", 0)

        print(f"\n[{i:04d}] {'─'*54}")
        print(f"  Rule Name        : {rule_name}")
        print(f"  Rule ID          : {rule_id}")
        print(f"  Severity         : {color}{sev.upper()}{RESET}")
        print(f"  Misconfigurations: {miscs}")
        print(f"  Assessed Assets  : {assets}")
        print(f"  Cloud Platform   : {str(r.get('cloud_provider','N/A')).upper()}")
        print(f"  Account ID       : {r.get('account_id', 'N/A')}")
        print(f"  Region           : {r.get('region', 'N/A')}")

        # ── Compliance - handle list of dicts ────────────────────
        compliance = r.get("compliance") or []
        if isinstance(compliance, list):
            for c in compliance[:3]:
                if isinstance(c, dict):
                    fw  = c.get("framework", "N/A")
                    req = c.get("requirement", c.get("name", "N/A"))
                    print(f"  Compliance       : {fw} - {req}")

        # ── Tags - handle dict OR list ───────────────────────────
        tags = r.get("tags")
        if tags:
            if isinstance(tags, dict):
                # Tags as dict: {key: value, ...}
                tag_items = [f"{k}={v}" for k, v in list(tags.items())[:5]]
                print(f"  Tags             : {', '.join(tag_items)}")
            elif isinstance(tags, list):
                tag_items = [str(t) for t in tags[:5]]
                print(f"  Tags             : {', '.join(tag_items)}")

    print(f"\n{'='*70}")
    print(f"  END OF REPORT - {len(rules)} rules")
    print(f"{'='*70}\n")



# ============================================================
# MAIN
# ============================================================
def main():
    print()
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"{BOLD}  CrowdStrike Falcon Cloud Security{RESET}")
    print(f"{BOLD}  IOM Retrieval Tool{RESET}")
    print(f"{BOLD}  Endpoint: /cloud-security-evaluations/{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    print()

    client_id, client_secret, base_url = load_credentials()
    args = parse_arguments()
    validate_arguments(args)

    print(f"[*] Configuration:")
    print(f"    Client ID   : {client_id[:8]}...{client_id[-4:]}")
    print(f"    Platform    : {args.platform.upper()}")
    print(f"    Severity    : {args.severity.upper()}")
    print(f"    Status      : {args.status.upper()}")
    print(f"    Region      : {args.region or 'ALL'}")
    print(f"    Account ID  : {args.account_id or 'ALL'}")
    print(f"    Service     : {args.service or 'ALL'}")
    print(f"    Framework   : {args.framework or 'ALL'}")
    print(f"    Grouped     : {args.grouped_by_rule}")
    print(f"    Sort        : {args.sort}")
    print(f"    Output      : {args.output.upper()}")
    print(f"    Limit       : {args.limit}")
    if args.fql:
        print(f"    FQL         : {args.fql}")
    print()

    access_token = get_access_token(client_id, client_secret, base_url)
    fql_filter   = build_fql_filter(args)

    if args.grouped_by_rule:
        rules = get_ioms_by_rule(access_token=access_token,
                                  base_url=base_url,
                                  fql_filter=fql_filter,
                                  limit=args.limit)
        if not rules:
            print("\n[!] No rules found.")
            sys.exit(0)
        summary = build_rule_summary(rules)
        if args.output == "json":
            output_rules_json(rules, summary, base_url, args.file)
        elif args.output == "csv":
            output_rules_csv(rules, summary, args.file)
        else:
            output_rules_console(rules, summary)

    else:
        iom_ids = get_iom_ids(access_token=access_token,
                               base_url=base_url,
                               fql_filter=fql_filter,
                               sort=args.sort,
                               limit=args.limit)
        if not iom_ids:
            print("\n[!] No IOMs found.")
            sys.exit(0)

        findings = get_iom_details(access_token=access_token,
                                    base_url=base_url,
                                    iom_ids=iom_ids)
        if not findings:
            print("\n[!] No IOM details returned.")
            sys.exit(0)

        print(f"\n[OK] Final IOM count: {len(findings)}")
        summary = build_summary(findings)

        if args.output == "json":
            output_findings_json(findings, summary, base_url, args.file)
        elif args.output == "csv":
            output_findings_csv(findings, summary, args.file)
        else:
            output_findings_console(findings, summary)

    print(f"\n{BOLD}[OK] Run complete{RESET}\n")


if __name__ == "__main__":
    main()

