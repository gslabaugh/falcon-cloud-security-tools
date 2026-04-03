#!/usr/bin/env python3
"""
Functional scope test - tests actual API endpoint access.
JWT scope checking is unreliable as CrowdStrike validates
scopes server-side rather than embedding them in the JWT.
"""
import os
import sys
import json
import requests
from falconpy import OAuth2

CLIENT_ID     = os.environ.get("FALCON_CLIENT_ID")
CLIENT_SECRET = os.environ.get("FALCON_CLIENT_SECRET")
BASE_URL      = os.environ.get("FALCON_API_URL", "https://api.crowdstrike.com")

if not CLIENT_ID or not CLIENT_SECRET:
    print("\n[ERROR] Missing environment variables:")
    print('  export FALCON_CLIENT_ID="<YOUR_FALCON_CLIENT_ID>"')
    print('  export FALCON_CLIENT_SECRET="<YOUR_FALCON_CLIENT_SECRET>"')
    sys.exit(1)

# ── Authenticate ─────────────────────────────────────────────
print(f"\n[*] Authenticating...")
print(f"    Client ID : {CLIENT_ID[:8]}...{CLIENT_ID[-4:]}")

auth  = OAuth2(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, base_url=BASE_URL)
token = auth.token()

if token["status_code"] != 201:
    print(f"[ERROR] Auth failed: {token['body']}")
    sys.exit(1)

access_token = token["body"]["access_token"]
print(f"[✓] Authenticated - expires in {token['body'].get('expires_in')}s")
print(f"\n[*] NOTE: CrowdStrike validates scopes server-side.")
print(f"[*]       JWT scp field will always be empty - this is expected.")
print(f"[*]       Running functional endpoint tests instead...\n")

headers = {
    "Authorization": f"Bearer {access_token}",
    "Accept"       : "application/json"
}

def test_endpoint(label, url, params, scope, ref, ok_codes):
    """Test a single endpoint and return result"""
    try:
        r      = requests.get(url, headers=headers, params=params, timeout=15)
        status = r.status_code
        body   = r.json()
        errors = body.get("errors", [])
        msgs   = [e.get("message", "") for e in errors]

        if status == 403:
            return "❌ FORBIDDEN", "Scope missing - check Falcon Console"
        elif status == 401:
            return "❌ UNAUTHORIZED", "Token invalid"
        elif status == 404:
            return "⚠️  NOT FOUND", "Endpoint unavailable in this environment"
        elif status in ok_codes:
            total = body.get("meta", {}).get("pagination", {}).get("total", "N/A")
            if status == 400 and any("filter is required" in m for m in msgs):
                return "✅ ACCESS OK", "Endpoint reachable (filter required = auth confirmed)"
            elif status == 400 and any("property" in m for m in msgs):
                return "✅ ACCESS OK", f"Endpoint reachable (filter field error = auth confirmed)"
            elif status in [200, 207]:
                return "✅ ACCESS OK", f"HTTP {status} | Total records: {total}"
            else:
                return "✅ ACCESS OK", f"HTTP {status}"
        else:
            return f"⚠️  HTTP {status}", "; ".join(msgs) or "Unknown"

    except requests.exceptions.ConnectionError:
        return "❌ CONN ERROR", f"Cannot connect to {BASE_URL}"
    except requests.exceptions.Timeout:
        return "❌ TIMEOUT", "Request timed out"
    except Exception as e:
        return "❌ ERROR", str(e)


# ── Define Tests ──────────────────────────────────────────────
TESTS = [
    {
        "label"   : "IOM Query (v2)",
        "url"     : f"{BASE_URL}/detects/queries/iom/v2",
        "params"  : {"limit": 1},
        "scope"   : "Cloud Security API Detections: Read",
        "ref"     : "Page 130 of 266",
        "ok_codes": [200]
    },
    {
        "label"   : "IOM Entities (v2)",
        "url"     : f"{BASE_URL}/detects/entities/iom/v2",
        "params"  : {"limit": 1},
        "scope"   : "Cloud Security API Detections: Read",
        "ref"     : "Page 130 of 266",
        "ok_codes": [200, 400]
    },
    {
        "label"   : "IOA Query (v2)",
        "url"     : f"{BASE_URL}/detects/queries/ioa/v2",
        "params"  : {"limit": 1},
        "scope"   : "Cloud Security API Detections: Read",
        "ref"     : "Page 130 of 266",
        "ok_codes": [200]
    },
    {
        "label"   : "Cloud Assets Query",
        "url"     : f"{BASE_URL}/cloud-security-assets/queries/resources/v1",
        "params"  : {"limit": 1},
        "scope"   : "Cloud Security API Assets: Read",
        "ref"     : "Page 125 of 266",
        "ok_codes": [200]
    },
    {
        "label"   : "Cloud Assets Entities",
        "url"     : f"{BASE_URL}/cloud-security-assets/entities/resources/v1",
        "params"  : {"limit": 1},
        "scope"   : "Cloud Security API Assets: Read",
        "ref"     : "Page 126 of 266",
        "ok_codes": [200, 400]
    },
    {
        "label"   : "CSPM AWS Accounts",
        "url"     : f"{BASE_URL}/cloud-connect-cspm-aws/entities/account/v1",
        "params"  : {"limit": 1},
        "scope"   : "CSPM Registration: Read",
        "ref"     : "Page 67 of 968",
        "ok_codes": [200, 207]
    },
    {
        "label"   : "CSPM Azure Accounts",
        "url"     : f"{BASE_URL}/cloud-connect-cspm-azure/entities/account/v1",
        "params"  : {"limit": 1},
        "scope"   : "CSPM Registration: Read",
        "ref"     : "Page 150 of 968",
        "ok_codes": [200, 207]
    },
    {
        "label"   : "CSPM GCP Accounts",
        "url"     : f"{BASE_URL}/cloud-connect-cspm-gcp/entities/account/v1",
        "params"  : {"limit": 1},
        "scope"   : "CSPM Registration: Read",
        "ref"     : "Page 158 of 968",
        "ok_codes": [200, 207]
    },
    {
        "label"   : "Configuration Assessment",
        "url"     : f"{BASE_URL}/configuration-assessment/combined/assessments/v1",
        "params"  : {"limit": 1},
        "scope"   : "Configuration Assessment: Read",
        "ref"     : "Page 130 of 266",
        "ok_codes": [200, 400]
    },
    {
        "label"   : "Compliance Frameworks",
        "url"     : f"{BASE_URL}/cloud-policies/queries/compliance/frameworks/v1",
        "params"  : {"limit": 1},
        "scope"   : "cloud-security-policies: Read",
        "ref"     : "Page 519 of 968",
        "ok_codes": [200]
    },
]

# ── Run Tests ─────────────────────────────────────────────────
print(f"{'='*65}")
print(f"  {'Endpoint':<35} {'Status':<20} {'Scope'}")
print(f"  {'-'*35} {'-'*20} {'-'*20}")

results = []
for test in TESTS:
    status_str, detail = test_endpoint(
        label    = test["label"],
        url      = test["url"],
        params   = test["params"],
        scope    = test["scope"],
        ref      = test["ref"],
        ok_codes = test["ok_codes"]
    )
    results.append({**test, "status": status_str, "detail": detail})
    print(f"  {test['label']:<35} {status_str:<20} {test['scope']}")

# ── Detailed Results ──────────────────────────────────────────
print(f"\n{'='*65}")
print(f"  Detailed Results")
print(f"{'='*65}")

for r in results:
    print(f"\n  {r['status']} {r['label']}")
    print(f"    Scope  : {r['scope']}")
    print(f"    Detail : {r['detail']}")
    print(f"    Ref    : {r['ref']}")

# ── Summary ───────────────────────────────────────────────────
ok_count   = sum(1 for r in results if "✅" in r["status"])
warn_count = sum(1 for r in results if "⚠️"  in r["status"])
fail_count = sum(1 for r in results if "❌" in r["status"])

print(f"\n{'='*65}")
print(f"  SUMMARY")
print(f"{'='*65}")
print(f"  ✅ Accessible : {ok_count}/{len(results)}")
print(f"  ⚠️  Warning    : {warn_count}/{len(results)}")
print(f"  ❌ Denied     : {fail_count}/{len(results)}")

if fail_count == 0:
    print(f"\n  ✅ All endpoints accessible!")
    print(f"     Run: python iom_retrieval.py --output console --limit 10")
else:
    print(f"\n  ❌ Some endpoints denied. Add missing scopes:")
    print(f"     Falcon Console → Support & Resources → API Clients & Keys")
    print(f"     Client: {CLIENT_ID[:8]}...{CLIENT_ID[-4:]}")
    for r in results:
        if "❌" in r["status"]:
            print(f"     - Add scope: {r['scope']}")

print(f"\n{'='*65}\n")
