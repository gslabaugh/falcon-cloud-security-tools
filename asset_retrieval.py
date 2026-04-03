#!/usr/bin/env python3
"""
================================================================================
CrowdStrike Falcon Cloud Security - Cloud Asset Retrieval Tool
================================================================================
Retrieves cloud assets from Falcon Cloud Security using:

  Step 1: GET /cloud-security-assets/queries/resources/v1  → Get Asset IDs
  Step 2: GET /cloud-security-assets/entities/resources/v1 → Get Asset Details

Ref: CrowdStrike API Documentation - Page 163-164 of 266

Required API Client Scope:
  Cloud Security API Assets (Read)

Credentials via environment variables:
  export FALCON_CLIENT_ID="<YOUR_FALCON_CLIENT_ID>"
  export FALCON_CLIENT_SECRET="<YOUR_FALCON_CLIENT_SECRET>"
  export FALCON_API_URL="<YOUR_BASE_URL>"  # Optional, defaults to US-1

Usage Examples:
  python asset_retrieval.py
  python asset_retrieval.py --platform aws
  python asset_retrieval.py --platform azure --output console
  python asset_retrieval.py --platform gcp --limit 50
  python asset_retrieval.py --active-only --output console
  python asset_retrieval.py --platform aws --region us-east-1
  python asset_retrieval.py --output json --file my_assets.json

Requirements:
  pip install crowdstrike-falconpy
================================================================================
"""

import argparse
import json
import os
import sys
import requests
from datetime import datetime

try:
    from falconpy import OAuth2
except ImportError:
    print("[ERROR] FalconPy is not installed.")
    print("[ERROR] Install it with: pip install crowdstrike-falconpy")
    sys.exit(1)


# ============================================================
# CONSTANTS
# Ref: Page 163-164 of 266
# ============================================================
VALID_PLATFORMS = ["aws", "azure", "gcp"]

# Valid FQL filter fields per Page 164 of 266
VALID_FILTER_FIELDS = [
    "account_id",
    "account_name",
    "active",
    "azure.vm_id",
    "business_impact",
    "cloud_group",
    "cloud_label",
    "cloud_label_id",
    "cloud_provider",
    "cloud_scope",
    "cluster_id",
    "cluster_name",
    "compartment_ocid",
    "compliant.benchmark_name",
    "compliant.benchmark_version",
    "region",
    "resource_type",
    "service",
]

ASSET_QUERY_ENDPOINT  = "/cloud-security-assets/queries/resources/v1"
ASSET_ENTITY_ENDPOINT = "/cloud-security-assets/entities/resources/v1"

QUERY_PAGE_SIZE = 100   # API default max per Page 164 of 266
ENTITY_BATCH    = 100   # Max IDs per entity detail call
DEFAULT_LIMIT   = 5000

# ============================================================
# DISPLAY COLORS
# ============================================================
PLATFORM_COLORS = {
    "aws"  : "\033[93m",  # Yellow
    "azure": "\033[94m",  # Blue
    "gcp"  : "\033[92m",  # Green
}
IMPACT_COLORS = {
    "high"    : "\033[91m",  # Red
    "moderate": "\033[93m",  # Yellow
    "low"     : "\033[96m",  # Cyan
}
RESET_COLOR = "\033[0m"
BOLD        = "\033[1m"


# ============================================================
# CREDENTIALS FROM ENVIRONMENT VARIABLES
# Ref: Page 335 of 968
# ============================================================
def load_credentials():
    """
    Load credentials from environment variables.
    Ref: Page 335 of 968
    """
    client_id     = os.environ.get("FALCON_CLIENT_ID")
    client_secret = os.environ.get("FALCON_CLIENT_SECRET")
    base_url      = os.environ.get("FALCON_API_URL", "https://api.crowdstrike.com")

    errors = []
    if not client_id:
        errors.append("FALCON_CLIENT_ID is not set")
    if not client_secret:
        errors.append("FALCON_CLIENT_SECRET is not set")

    if errors:
        print("\n[ERROR] Missing required environment variables:")
        for error in errors:
            print(f"  - {error}")
        print()
        print("  Set them with:")
        print('  export FALCON_CLIENT_ID="<YOUR_FALCON_CLIENT_ID>"')
        print('  export FALCON_CLIENT_SECRET="<YOUR_FALCON_CLIENT_SECRET>"')
        print('  export FALCON_API_URL="<YOUR_BASE_URL>"  # Optional')
        print()
        print("  Ref: Page 335 of 968")
        sys.exit(1)

    return client_id, client_secret, base_url


# ============================================================
# ARGUMENT PARSING
# ============================================================
def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="CrowdStrike Falcon - Cloud Asset Retrieval Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Credentials (required environment variables):
  export FALCON_CLIENT_ID="<YOUR_FALCON_CLIENT_ID>"
  export FALCON_CLIENT_SECRET="<YOUR_FALCON_CLIENT_SECRET>"
  export FALCON_API_URL="<YOUR_BASE_URL>"  # Optional, defaults to US-1

Examples:
  python asset_retrieval.py
  python asset_retrieval.py --platform aws
  python asset_retrieval.py --platform azure --output console
  python asset_retrieval.py --platform gcp --limit 50 --output console
  python asset_retrieval.py --active-only
  python asset_retrieval.py --platform aws --region us-east-1
  python asset_retrieval.py --account-id 123456789012
  python asset_retrieval.py --resource-type ec2 --output console
  python asset_retrieval.py --output json --file my_assets.json

FQL Filter Fields (Ref: Page 164 of 266):
        """
        + "\n  ".join(VALID_FILTER_FIELDS)
    )

    # ── Platform ─────────────────────────────────────────────────
    parser.add_argument(
        "--platform",
        type=str,
        default="all",
        help=(
            f"Cloud platform filter. "
            f"Options: all, {', '.join(VALID_PLATFORMS)} "
            f"(default: all)"
        )
    )

    # ── Active Filter ────────────────────────────────────────────
    parser.add_argument(
        "--active-only",
        action="store_true",
        default=False,
        help="Return only active assets (default: all assets)"
    )

    # ── Account ID ───────────────────────────────────────────────
    parser.add_argument(
        "--account-id",
        type=str,
        default=None,
        metavar="ACCOUNT_ID",
        help=(
            "Filter by cloud account ID. "
            "Ref: Page 164 of 266 - account_id filter field"
        )
    )

    # ── Region ───────────────────────────────────────────────────
    parser.add_argument(
        "--region",
        type=str,
        default=None,
        metavar="REGION",
        help=(
            "Filter by cloud region. "
            "e.g. us-east-1 (AWS), UK South (Azure), us-east1 (GCP). "
            "Ref: Page 164 of 266 - region filter field"
        )
    )

    # ── Resource Type ────────────────────────────────────────────
    parser.add_argument(
        "--resource-type",
        type=str,
        default=None,
        metavar="TYPE",
        help=(
            "Filter by resource type. "
            "e.g. ec2, s3, vm, storage_account. "
            "Ref: Page 164 of 266 - resource_type filter field"
        )
    )

    # ── Business Impact ──────────────────────────────────────────
    parser.add_argument(
        "--business-impact",
        type=str,
        default=None,
        choices=["high", "moderate", "low"],
        metavar="IMPACT",
        help=(
            "Filter by business impact level. "
            "Options: high, moderate, low. "
            "Ref: Page 89 of 266 - business_impact filter field"
        )
    )

    # ── Cloud Group ──────────────────────────────────────────────
    parser.add_argument(
        "--cloud-group",
        type=str,
        default=None,
        metavar="GROUP",
        help=(
            "Filter by cloud group name. "
            "Ref: Page 164 of 266 - cloud_group filter field"
        )
    )

    # ── Cluster Name ─────────────────────────────────────────────
    parser.add_argument(
        "--cluster",
        type=str,
        default=None,
        metavar="CLUSTER",
        help=(
            "Filter by Kubernetes cluster name. "
            "Ref: Page 164 of 266 - cluster_name filter field"
        )
    )

    # ── Sort ─────────────────────────────────────────────────────
    parser.add_argument(
        "--sort",
        type=str,
        default="cloud_provider|asc",
        metavar="SORT",
        help=(
            "Sort field and direction. "
            "Format: field|asc or field|desc. "
            "(default: cloud_provider|asc)"
        )
    )

    # ── Output ───────────────────────────────────────────────────
    parser.add_argument(
        "--output",
        type=str,
        choices=["json", "console"],
        default="json",
        help="Output format: json (saves to file) or console (default: json)"
    )

    # ── File ─────────────────────────────────────────────────────
    parser.add_argument(
        "--file",
        type=str,
        default=None,
        metavar="FILENAME",
        help="JSON output filename (default: assets_YYYYMMDD_HHMMSS.json)"
    )

    # ── Limit ────────────────────────────────────────────────────
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        metavar="N",
        help=f"Maximum number of assets to retrieve (default: {DEFAULT_LIMIT})"
    )

    return parser.parse_args()


# ============================================================
# ARGUMENT VALIDATION
# ============================================================
def validate_arguments(args):
    """Validate command line arguments"""
    errors = []

    if args.platform.lower() != "all":
        if args.platform.lower() not in VALID_PLATFORMS:
            errors.append(
                f"Invalid platform '{args.platform}'. "
                f"Valid: all, {', '.join(VALID_PLATFORMS)}"
            )

    if args.limit < 1:
        errors.append("--limit must be greater than 0")

    if errors:
        print("\n[ERROR] Argument validation failed:")
        for error in errors:
            print(f"  - {error}")
        sys.exit(1)

    return args


# ============================================================
# AUTHENTICATION
# Ref: Page 335 of 968
# ============================================================
def get_access_token(client_id, client_secret, base_url):
    """Retrieve OAuth2 access token using FalconPy"""
    print("[*] Authenticating with CrowdStrike API...")
    print(f"    Base URL  : {base_url}")
    print(f"    Client ID : {client_id[:8]}...{client_id[-4:]}")
    print(f"    Scope     : Cloud Security API Assets (Read)")
    print(f"    Ref       : Page 163 of 266")

    try:
        auth  = OAuth2(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url
        )
        token = auth.token()

        if token["status_code"] == 201:
            print("[✓] Authentication successful")
            return token["body"]["access_token"]
        elif token["status_code"] == 401:
            print("[ERROR] Authentication failed - invalid credentials")
            print("[ERROR] Check FALCON_CLIENT_ID and FALCON_CLIENT_SECRET")
            sys.exit(1)
        else:
            print(f"[ERROR] Authentication failed (HTTP {token['status_code']})")
            print(f"        {token['body']}")
            sys.exit(1)

    except Exception as e:
        print(f"[ERROR] Authentication exception: {e}")
        sys.exit(1)


# ============================================================
# FQL FILTER BUILDER
# Ref: Page 164 of 266 - Valid FQL filter fields
# ============================================================
def build_fql_filter(platform, active_only, account_id,
                     region, resource_type, business_impact, cloud_group, cluster):
    """
    Build FQL filter string for /cloud-security-assets/queries/resources/v1
    Ref: Page 164 of 266 - Supported FQL filter fields

    Valid fields:
      account_id, account_name, active, azure.vm_id, business_impact,
      cloud_group, cloud_label, cloud_label_id, cloud_provider, cloud_scope,
      cluster_id, cluster_name, compartment_ocid, compliant.benchmark_name,
      compliant.benchmark_version, region, resource_type, service
    """
    filters = []

    # cloud_provider filter
    # Ref: Page 164 of 266 - cloud_provider field
    # Values: aws, azure, gcp
    if platform.lower() != "all":
        filters.append(f"cloud_provider:'{platform.lower()}'")

    # active filter
    # Ref: Page 164 of 266 - active field
    if active_only:
        filters.append("active:'1'")

    # account_id filter
    # Ref: Page 164 of 266 - account_id field
    if account_id:
        filters.append(f"account_id:'{account_id}'")

    # region filter
    # Ref: Page 164 of 266 - region field
    if region:
        filters.append(f"region:'{region}'")

    # resource_type filter
    # Ref: Page 164 of 266 - resource_type field
    if resource_type:
        filters.append(f"resource_type:'{resource_type}'")

    # business_impact filter
    # Ref: Page 89 of 266 - business_impact field
    # Values: low, moderate, high
    if business_impact:
        filters.append(f"business_impact:'{business_impact.lower()}'")

    # cloud_group filter
    # Ref: Page 164 of 266 - cloud_group field
    if cloud_group:
        filters.append(f"cloud_group:'{cloud_group}'")

    # cluster_name filter
    # Ref: Page 164 of 266 - cluster_name field
    if cluster:
        filters.append(f"cluster_name:'{cluster}'")

    return "+".join(filters) if filters else None


# ============================================================
# STEP 1: GET ASSET IDs
# Ref: Page 163-164 of 266
# Endpoint: GET /cloud-security-assets/queries/resources/v1
# Required scope: Cloud Security API Assets (Read)
# ============================================================
def get_asset_ids(access_token, base_url, fql_filter=None,
                  sort="cloud_provider|asc", limit=DEFAULT_LIMIT):
    """
    Retrieve asset IDs from /cloud-security-assets/queries/resources/v1
    Handles pagination automatically.
    Ref: Page 163 of 266
    """
    print(f"\n{'='*60}")
    print(f"[STEP 1] Retrieving Asset IDs")
    print(f"{'='*60}")
    print(f"  Endpoint : GET {ASSET_QUERY_ENDPOINT}")
    print(f"  Scope    : Cloud Security API Assets (Read)")
    print(f"  Filter   : {fql_filter if fql_filter else 'None (all assets)'}")
    print(f"  Sort     : {sort}")
    print(f"  Max      : {limit}")
    print(f"  Ref      : Page 163 of 266")
    print()

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept"       : "application/json"
    }

    all_ids     = []
    offset      = 0
    total_avail = None
    page_num    = 1
    page_size   = min(QUERY_PAGE_SIZE, limit)

    while True:
        print(f"[*] Fetching asset ID page {page_num} "
              f"(offset: {offset}, page size: {page_size})...")

        params = {
            "limit" : page_size,
            "offset": offset,
            "sort"  : sort
        }
        if fql_filter:
            params["filter"] = fql_filter

        try:
            response = requests.get(
                f"{base_url}{ASSET_QUERY_ENDPOINT}",
                headers=headers,
                params=params,
                timeout=30
            )
        except requests.exceptions.ConnectionError:
            print(f"[ERROR] Cannot connect to {base_url}")
            sys.exit(1)
        except requests.exceptions.Timeout:
            print("[ERROR] Request timed out")
            sys.exit(1)

        # ── Error Handling ──────────────────────────────────────
        if response.status_code == 401:
            print("[ERROR] Authentication failed - token expired")
            sys.exit(1)
        elif response.status_code == 403:
            print("[ERROR] Authorization failed.")
            print("[ERROR] Ensure FALCON_CLIENT_ID has scope:")
            print("        Cloud Security API Assets: Read")
            print("        Ref: Page 163 of 266")
            sys.exit(1)
        elif response.status_code == 400:
            errors = response.json().get("errors", [])
            print(f"[ERROR] Bad request (HTTP 400):")
            for err in errors:
                print(f"        {err.get('code','N/A')}: "
                      f"{err.get('message','Unknown')}")
            sys.exit(1)
        elif response.status_code == 429:
            print("[ERROR] Rate limit exceeded (HTTP 429)")
            sys.exit(1)
        elif response.status_code != 200:
            print(f"[ERROR] API call failed (HTTP {response.status_code})")
            print(f"        {response.text}")
            sys.exit(1)

        # ── Parse Response ──────────────────────────────────────
        body       = response.json()
        resources  = body.get("resources", []) or []
        pagination = body.get("meta", {}).get("pagination", {})

        if total_avail is None:
            total_avail = pagination.get("total", 0)
            print(f"\n[*] Total assets available matching filter: {total_avail}")
            if total_avail == 0:
                print("[!] No assets found matching criteria.")
                return []
            print()

        if not resources:
            print("[*] No more asset IDs returned.")
            break

        all_ids.extend(resources)
        print(f"    Retrieved: {len(all_ids)} / {min(limit, total_avail)} asset IDs")

        # ── Pagination Control ──────────────────────────────────
        if len(all_ids) >= limit:
            print(f"\n[*] Reached specified limit of {limit} records.")
            all_ids = all_ids[:limit]
            break

        if len(all_ids) >= total_avail:
            print(f"\n[*] All available asset IDs retrieved.")
            break

        offset    += page_size
        remaining  = min(limit - len(all_ids), total_avail - len(all_ids))
        page_size  = min(QUERY_PAGE_SIZE, remaining)
        page_num  += 1

    print(f"\n[✓] Total asset IDs retrieved: {len(all_ids)}")
    return all_ids


# ============================================================
# STEP 2: GET ASSET DETAILS
# Ref: Page 164 of 266
# Endpoint: GET /cloud-security-assets/entities/resources/v1
# Required scope: Cloud Security API Assets (Read)
# ============================================================
def get_asset_details(access_token, base_url, asset_ids):
    """
    Retrieve full asset details from /cloud-security-assets/entities/resources/v1
    Processes IDs in batches.
    Ref: Page 164 of 266
    """
    if not asset_ids:
        return []

    print(f"\n{'='*60}")
    print(f"[STEP 2] Retrieving Asset Details")
    print(f"{'='*60}")
    print(f"  Endpoint   : GET {ASSET_ENTITY_ENDPOINT}")
    print(f"  Total IDs  : {len(asset_ids)}")
    print(f"  Batch size : {ENTITY_BATCH}")
    print(f"  Ref        : Page 164 of 266")
    print()

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept"       : "application/json"
    }

    all_assets    = []
    batches       = [
        asset_ids[i:i + ENTITY_BATCH]
        for i in range(0, len(asset_ids), ENTITY_BATCH)
    ]
    total_batches = len(batches)

    for batch_num, batch in enumerate(batches, 1):
        print(f"[*] Processing batch {batch_num}/{total_batches} "
              f"({len(batch)} IDs)...")

        params = [("ids", asset_id) for asset_id in batch]

        try:
            response = requests.get(
                f"{base_url}{ASSET_ENTITY_ENDPOINT}",
                headers=headers,
                params=params,
                timeout=30
            )
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Request failed on batch {batch_num}: {e}")
            continue

        if response.status_code == 401:
            print("[ERROR] Authentication failed - token expired")
            sys.exit(1)
        elif response.status_code == 403:
            print("[ERROR] Authorization failed.")
            print("[ERROR] Ensure API client has: Cloud Security API Assets: Read")
            sys.exit(1)
        elif response.status_code == 429:
            print("[ERROR] Rate limit exceeded.")
            sys.exit(1)
        elif response.status_code != 200:
            print(f"[ERROR] Failed to retrieve asset details "
                  f"(HTTP {response.status_code})")
            print(f"        {response.text}")
            continue

        resources = response.json().get("resources", []) or []
        all_assets.extend(resources)
        print(f"    Retrieved details: {len(all_assets)} / {len(asset_ids)}")

    print(f"\n[✓] Total asset details retrieved: {len(all_assets)}")
    return all_assets


# ============================================================
# SUMMARY BUILDER
# ============================================================
def build_summary(assets):
    """Build summary breakdown of cloud assets"""
    summary = {
        "total_assets"      : len(assets),
        "by_platform"       : {},
        "by_region"         : {},
        "by_account"        : {},
        "by_resource_type"  : {},
        "by_service"        : {},
        "by_business_impact": {},
        "by_active_status"  : {},
        "by_cloud_group"    : {},
    }

    for asset in assets:
        def inc(key, field, transform=None):
            val = asset.get(field, "unknown")
            if transform:
                val = transform(val)
            if val is None or val == "":
                val = "unknown"
            summary[key][val] = summary[key].get(val, 0) + 1

        inc("by_platform",        "cloud_provider", lambda v: str(v).upper())
        inc("by_region",          "region")
        inc("by_account",         "account_id")
        inc("by_resource_type",   "resource_type")
        inc("by_service",         "service")
        inc("by_business_impact", "business_impact")
        inc("by_cloud_group",     "cloud_group")

        # Active status
        active = asset.get("active", None)
        if active is True or active == "1" or active == 1:
            status = "active"
        elif active is False or active == "0" or active == 0:
            status = "inactive"
        else:
            status = "unknown"
        summary["by_active_status"][status] = (
            summary["by_active_status"].get(status, 0) + 1
        )

    # Sort all breakdowns by count descending
    for key in summary:
        if isinstance(summary[key], dict):
            summary[key] = dict(
                sorted(summary[key].items(), key=lambda x: x[1], reverse=True)
            )

    return summary


# ============================================================
# CONSOLE OUTPUT
# ============================================================
def print_summary(summary):
    """Print formatted asset summary"""
    print(f"\n{BOLD}{'='*65}{RESET_COLOR}")
    print(f"{BOLD}  CLOUD ASSET SUMMARY{RESET_COLOR}")
    print(f"{BOLD}{'='*65}{RESET_COLOR}")
    print(f"  Total Assets : {summary['total_assets']}")

    print(f"\n  By Cloud Platform:")
    for platform, count in summary["by_platform"].items():
        color = PLATFORM_COLORS.get(str(platform).lower(), "")
        bar   = "█" * min(count, 40)
        print(
            f"    {color}{str(platform).upper():<10}{RESET_COLOR} "
            f"{count:>6}  {color}{bar}{RESET_COLOR}"
        )

    print(f"\n  By Active Status:")
    for status, count in summary["by_active_status"].items():
        color = "\033[92m" if status == "active" else "\033[91m"
        print(f"    {color}{status:<10}{RESET_COLOR} {count:>6}")

    print(f"\n  By Business Impact:")
    for impact, count in summary["by_business_impact"].items():
        color = IMPACT_COLORS.get(str(impact).lower(), "")
        print(f"    {color}{str(impact).upper():<12}{RESET_COLOR} {count:>6}")

    print(f"\n  Top 10 Regions:")
    for region, count in list(summary["by_region"].items())[:10]:
        print(f"    {str(region):<30} {count:>6}")

    print(f"\n  Top 10 Resource Types:")
    for rtype, count in list(summary["by_resource_type"].items())[:10]:
        print(f"    {str(rtype):<35} {count:>6}")

    print(f"\n  Top 10 Services:")
    for svc, count in list(summary["by_service"].items())[:10]:
        print(f"    {str(svc):<35} {count:>6}")

    print(f"\n  Top 10 Accounts:")
    for account, count in list(summary["by_account"].items())[:10]:
        print(f"    {str(account):<30} {count:>6}")

    if summary["by_cloud_group"]:
        print(f"\n  By Cloud Group:")
        for group, count in list(summary["by_cloud_group"].items())[:10]:
            print(f"    {str(group):<30} {count:>6}")

    print(f"{BOLD}{'='*65}{RESET_COLOR}\n")


def output_console(assets, summary):
    """Print all assets to console"""
    print(f"\n{'='*70}")
    print(f"{BOLD}  CLOUD ASSET REPORT{RESET_COLOR}")
    print(f"  Generated : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Ref       : Page 163-164 of 266")
    print(f"{'='*70}")

    print_summary(summary)

    print(f"{BOLD}{'='*70}{RESET_COLOR}")
    print(f"{BOLD}  INDIVIDUAL ASSETS ({len(assets)} total){RESET_COLOR}")
    print(f"{BOLD}{'='*70}{RESET_COLOR}")

    for i, asset in enumerate(assets, 1):
        platform      = str(asset.get("cloud_provider", "unknown")).lower()
        platform_disp = str(asset.get("cloud_provider", "N/A")).upper()
        color         = PLATFORM_COLORS.get(platform, "")

        active        = asset.get("active", None)
        active_disp   = (
            "\033[92mACTIVE\033[0m" if active in [True, 1, "1"]
            else "\033[91mINACTIVE\033[0m"
        )

        impact        = str(asset.get("business_impact", "")).lower()
        impact_color  = IMPACT_COLORS.get(impact, "")
        impact_disp   = (
            f"{impact_color}{str(asset.get('business_impact','N/A')).upper()}{RESET_COLOR}"
            if impact else "N/A"
        )

        print(f"\n[{i:04d}] {'─'*56}")
        print(f"  Resource ID      : {asset.get('id', 'N/A')}")
        print(f"  Resource Type    : {asset.get('resource_type', 'N/A')}")
        print(f"  Service          : {asset.get('service', 'N/A')}")
        print(f"  Cloud Platform   : {color}{platform_disp}{RESET_COLOR}")
        print(f"  Account ID       : {asset.get('account_id', 'N/A')}")
        print(f"  Account Name     : {asset.get('account_name', 'N/A')}")
        print(f"  Region           : {asset.get('region', 'N/A')}")
        print(f"  Active           : {active_disp}")
        print(f"  Business Impact  : {impact_disp}")

        # Cloud group if present
        cloud_group = asset.get("cloud_group")
        if cloud_group:
            print(f"  Cloud Group      : {cloud_group}")

        # Cluster info if present
        cluster = asset.get("cluster_name")
        if cluster:
            print(f"  Cluster          : {cluster}")

        # Compliance info if present
        compliant = asset.get("compliant", {})
        if compliant:
            bench_name    = compliant.get("benchmark_name", "N/A")
            bench_version = compliant.get("benchmark_version", "N/A")
            print(f"  Benchmark        : {bench_name} v{bench_version}")

        # Cloud labels if present
        labels = asset.get("cloud_label", [])
        if labels:
            label_str = ", ".join(labels[:5])
            if len(labels) > 5:
                label_str += f" (+{len(labels)-5} more)"
            print(f"  Cloud Labels     : {label_str}")

        # Timestamps
        first_seen = asset.get("first_seen", asset.get("created_at", "N/A"))
        last_seen  = asset.get("last_seen",  asset.get("updated_at", "N/A"))
        print(f"  First Seen       : {first_seen}")
        print(f"  Last Seen        : {last_seen}")

    print(f"\n{'='*70}")
    print(f"  END OF REPORT - {len(assets)} assets")
    print(f"{'='*70}\n")


def output_json(assets, summary, base_url, filename=None):
    """Write assets and summary to a JSON file"""
    if not filename:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename  = f"assets_{timestamp}.json"

    output_data = {
        "metadata": {
            "tool"           : "CrowdStrike Falcon - Cloud Asset Retrieval Tool",
            "generated_at"   : datetime.utcnow().isoformat() + "Z",
            "total_assets"   : len(assets),
            "falcon_base_url": base_url,
            "endpoints_used" : [
                ASSET_QUERY_ENDPOINT,
                ASSET_ENTITY_ENDPOINT
            ],
            "ref"            : "Page 163-164 of 266"
        },
        "summary": summary,
        "assets" : assets
    }

    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2, default=str)
        print(f"\n[✓] Results saved to    : {filename}")
        print(f"[✓] Total assets written : {len(assets)}")
    except IOError as e:
        print(f"[ERROR] Failed to write output file: {e}")
        sys.exit(1)

    # Always print summary to console
    print_summary(summary)


# ============================================================
# MAIN
# ============================================================
def main():
    """Main entry point"""
    print()
    print(f"{BOLD}{'='*65}{RESET_COLOR}")
    print(f"{BOLD}  CrowdStrike Falcon Cloud Security{RESET_COLOR}")
    print(f"{BOLD}  Cloud Asset Retrieval Tool{RESET_COLOR}")
    print(f"{BOLD}  Ref: Page 163-164 of 266{RESET_COLOR}")
    print(f"{BOLD}{'='*65}{RESET_COLOR}")
    print()

    # ── Load Credentials ──────────────────────────────────────────
    client_id, client_secret, base_url = load_credentials()

    # ── Parse & Validate Arguments ───────────────────────────────
    args = parse_arguments()
    validate_arguments(args)

    print(f"[*] Configuration:")
    print(f"    Client ID       : {client_id[:8]}...{client_id[-4:]}")
    print(f"    Base URL        : {base_url}")
    print(f"    Platform        : {args.platform.upper()}")
    print(f"    Active Only     : {args.active_only}")
    print(f"    Account ID      : {args.account_id or 'ALL'}")
    print(f"    Region          : {args.region or 'ALL'}")
    print(f"    Resource Type   : {args.resource_type or 'ALL'}")
    print(f"    Business Impact : {args.business_impact or 'ALL'}")
    print(f"    Cloud Group     : {args.cloud_group or 'ALL'}")
    print(f"    Cluster         : {args.cluster or 'ALL'}")
    print(f"    Sort            : {args.sort}")
    print(f"    Output          : {args.output.upper()}")
    print(f"    Max Assets      : {args.limit}")
    print()

    # ── Authenticate ──────────────────────────────────────────────
    access_token = get_access_token(client_id, client_secret, base_url)

    # ── Build FQL Filter ─────────────────────────────────────────
    # Ref: Page 164 of 266 - Valid FQL filter fields
    fql_filter = build_fql_filter(
        platform        = args.platform,
        active_only     = args.active_only,
        account_id      = args.account_id,
        region          = args.region,
        resource_type   = args.resource_type,
        business_impact = args.business_impact,
        cloud_group     = args.cloud_group,
        cluster         = args.cluster
    )

    # ── Step 1: Get Asset IDs ─────────────────────────────────────
    # Ref: Page 163 of 266 - GET /cloud-security-assets/queries/resources/v1
    asset_ids = get_asset_ids(
        access_token = access_token,
        base_url     = base_url,
        fql_filter   = fql_filter,
        sort         = args.sort,
        limit        = args.limit
    )

    if not asset_ids:
        print("\n[!] No assets found matching the specified criteria.")
        print("[!] Try broadening your filters.")
        sys.exit(0)

    # ── Step 2: Get Asset Details ─────────────────────────────────
    # Ref: Page 164 of 266 - GET /cloud-security-assets/entities/resources/v1
    assets = get_asset_details(
        access_token = access_token,
        base_url     = base_url,
        asset_ids    = asset_ids
    )

    if not assets:
        print("\n[!] No asset details returned.")
        sys.exit(0)

    print(f"\n[✓] Final asset count: {len(assets)}")

    # ── Build Summary ─────────────────────────────────────────────
    summary = build_summary(assets)

    # ── Output Results ────────────────────────────────────────────
    print(f"\n[*] Generating {args.output.upper()} output...")

    if args.output == "json":
        output_json(assets, summary, base_url, args.file)
    elif args.output == "console":
        output_console(assets, summary)

    print(f"\n{BOLD}[✓] Run complete{RESET_COLOR}\n")


if __name__ == "__main__":
    main()
