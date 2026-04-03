# Quick Start Guide

## 1. Install

```
git clone 
github.com
```

```
cd falcon-cloud-security-tools
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```


## 2. Configure API Client

In the Falcon Console:
1. Go to **Support and Resources > API Clients and Keys**
2. Click **Add new API client**
3. Add these scopes:
   - Cloud Security API Detections - Read
   - Cloud Security API Assets - Read
   - CSPM registration - Read
   - Configuration Assessment - Read
   - cloud-security-policies - Read
4. Copy your Client ID and Secret

Important: Create the API client in the correct CID where
your cloud accounts are registered.

## 3. Set Environment Variables

```
export FALCON_CLIENT_ID="your_client_id_here"  
export FALCON_CLIENT_SECRET="your_client_secret_here"  
export FALCON_API_URL="api.crowdstrike.com"  
```

## 4. Verify Access

```
python scope_test.py
```

All required endpoints should show ACCESS OK.

## 5. Run IOM Retrieval

All IOMs to JSON (default)  
```
python iom_retrieval.py
```

All IOMs to CSV  
```
python iom_retrieval.py --output csv
```

Quick console test - 10 results  
```
python iom_retrieval.py --output console --limit 10
```

IOMs grouped by rule  
```
python iom_retrieval.py --grouped-by-rule --output console
```

Cloud assets  
```
python asset_retrieval.py --output console --limit 10
```

## Common Filters

GCP critical and high only  
```
python iom_retrieval.py --platform gcp --severity critical,high --output csv
```

AWS all findings  
```
python iom_retrieval.py --platform aws --output json
```

Specific account  
```
python iom_retrieval.py --account-id projects/1065216519849
```

NIST framework  
```
python iom_retrieval.py --framework NIST --output csv
```

Raw FQL filter  
```
python iom_retrieval.py --fql "severity:'high'+cloud_provider:'gcp'"
```

## Notes

- Correct IOM endpoint: /cloud-security-evaluations/queries/ioms/v1
- Deprecated /detects/queries/iom/v2 returns 0 results
- CrowdStrike validates scopes server-side - JWT scp field is always empty
- Use scope_test.py to verify actual API access
- IOM response uses nested structure: cloud, resource, evaluation objects
