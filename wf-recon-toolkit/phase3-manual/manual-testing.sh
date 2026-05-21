#!/bin/bash
# ============================================================
# Phase 3: Manual Testing Preparation & Helpers
# ============================================================
# This script prepares your environment for manual testing:
# - Analyzes JS files for secrets and hidden endpoints
# - Generates IDOR test cases from discovered API endpoints
# - Creates wordlists for targeted fuzzing
# - Identifies 403 bypass candidates
# - Prepares Burp Suite project configuration
#
# Tools needed: linkfinder (or built-in grep), jq, curl
#
# Usage: ./manual-testing.sh <phase2-output-dir>
#   Example: ./manual-testing.sh ../output/phase2/20250521_120000
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/config.sh"

PHASE2_DIR="${1:-}"

if [[ -z "$PHASE2_DIR" || ! -d "$PHASE2_DIR" ]]; then
    log_error "Usage: $0 <phase2-output-directory>"
    log_error "Example: $0 ../output/phase2/20250521_120000"
    exit 1
fi

validate_config
setup_output

RUN_DIR="${PHASE3_OUTPUT}/${TIMESTAMP}"
mkdir -p "${RUN_DIR}"/{js-analysis,idor-tests,fuzz-wordlists,403-bypass,report-templates}

log_section "Phase 3: Manual Testing Preparation"
log_info "Phase 2 input: ${PHASE2_DIR}"
log_info "Output: ${RUN_DIR}"

# ============================================================
# 1. JavaScript File Analysis
# ============================================================
log_section "1. JavaScript Analysis (Secrets & Endpoints)"

JS_FILES="${PHASE2_DIR}/katana/js-files.txt"
JS_OUTPUT="${RUN_DIR}/js-analysis"

if [[ -s "$JS_FILES" ]]; then
    JS_COUNT=$(wc -l < "$JS_FILES")
    log_info "Analyzing ${JS_COUNT} JavaScript files..."

    # Download JS files for local analysis (with headers)
    mkdir -p "${JS_OUTPUT}/downloaded"
    
    while IFS= read -r js_url; do
        filename=$(echo "$js_url" | md5sum | awk '{print $1}').js
        curl -s -H "${H1_HEADER}" -H "${TOOL_HEADER_PREFIX}: curl" \
            --max-time 10 \
            "$js_url" -o "${JS_OUTPUT}/downloaded/${filename}" 2>/dev/null || true
        echo "${js_url} -> ${filename}" >> "${JS_OUTPUT}/js-url-mapping.txt"
    done < <(head -200 "$JS_FILES")  # Limit to top 200

    log_success "Downloaded JS files for analysis"

    # Extract endpoints from JS files
    log_info "Extracting API endpoints from JS..."
    grep -rhoP '["'"'"'](/[a-zA-Z0-9_/\-{}]+)["'"'"']' "${JS_OUTPUT}/downloaded/" 2>/dev/null | \
        tr -d "\"'" | sort -u | \
        grep -vE '\.(css|png|jpg|gif|svg|woff|ico)$' \
        > "${JS_OUTPUT}/endpoints-from-js.txt" 2>/dev/null || true

    # Extract potential API paths
    grep -rhoP '["'"'"'](https?://[^"'"'"'\s]+)["'"'"']' "${JS_OUTPUT}/downloaded/" 2>/dev/null | \
        tr -d "\"'" | sort -u \
        > "${JS_OUTPUT}/full-urls-from-js.txt" 2>/dev/null || true

    # Extract potential secrets
    log_info "Scanning for hardcoded secrets..."
    {
        # AWS keys
        grep -rhoP 'AKIA[0-9A-Z]{16}' "${JS_OUTPUT}/downloaded/" 2>/dev/null | \
            sed 's/^/[AWS_KEY] /' || true
        # JWT tokens
        grep -rhoP 'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+' "${JS_OUTPUT}/downloaded/" 2>/dev/null | \
            sed 's/^/[JWT] /' || true
        # API keys in assignment
        grep -rhoP '(?i)(api[_-]?key|apikey|api_secret|client_secret)\s*[=:]\s*['"'"'"][a-zA-Z0-9_\-]{16,}['"'"'"]' "${JS_OUTPUT}/downloaded/" 2>/dev/null | \
            sed 's/^/[API_KEY] /' || true
        # Internal IPs
        grep -rhoP '(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})' "${JS_OUTPUT}/downloaded/" 2>/dev/null | \
            sed 's/^/[INTERNAL_IP] /' || true
        # Database connection strings
        grep -rhoP '(?i)(mongodb|postgres|mysql|redis|amqp)://[^\s"'"'"'<>]+' "${JS_OUTPUT}/downloaded/" 2>/dev/null | \
            sed 's/^/[DB_CONN] /' || true
        # Google API keys
        grep -rhoP 'AIza[0-9A-Za-z_-]{35}' "${JS_OUTPUT}/downloaded/" 2>/dev/null | \
            sed 's/^/[GOOGLE_KEY] /' || true
        # Slack tokens
        grep -rhoP 'xox[baprs]-[0-9a-zA-Z-]+' "${JS_OUTPUT}/downloaded/" 2>/dev/null | \
            sed 's/^/[SLACK] /' || true
        # Private keys
        grep -rl 'BEGIN.*PRIVATE KEY' "${JS_OUTPUT}/downloaded/" 2>/dev/null | \
            sed 's/^/[PRIVATE_KEY_FILE] /' || true
    } | sort -u > "${JS_OUTPUT}/secrets-found.txt"

    if [[ -s "${JS_OUTPUT}/secrets-found.txt" ]]; then
        log_success "SECRETS FOUND: $(wc -l < "${JS_OUTPUT}/secrets-found.txt") potential leaks!"
        cat "${JS_OUTPUT}/secrets-found.txt"
    else
        log_info "No obvious hardcoded secrets found in JS files"
    fi

    [[ -s "${JS_OUTPUT}/endpoints-from-js.txt" ]] && \
        log_success "Endpoints from JS: $(wc -l < "${JS_OUTPUT}/endpoints-from-js.txt")"
    [[ -s "${JS_OUTPUT}/full-urls-from-js.txt" ]] && \
        log_success "Full URLs from JS: $(wc -l < "${JS_OUTPUT}/full-urls-from-js.txt")"

    # Use linkfinder if available
    if check_tool "linkfinder" 2>/dev/null; then
        log_info "Running linkfinder for deeper analysis..."
        while IFS= read -r js_url; do
            linkfinder -i "$js_url" -o cli 2>/dev/null \
                >> "${JS_OUTPUT}/linkfinder-results.txt" || true
        done < <(head -50 "$JS_FILES")
    fi
else
    log_warn "No JS files found from Phase 2. Run Phase 2 with katana first."
fi

# ============================================================
# 2. IDOR/BOLA Test Case Generation
# ============================================================
log_section "2. IDOR/BOLA Test Case Generation"

API_ENDPOINTS="${PHASE2_DIR}/katana/api-endpoints.txt"
IDOR_OUTPUT="${RUN_DIR}/idor-tests"

cat > "${IDOR_OUTPUT}/idor-testing-guide.md" << 'EOF'
# IDOR/BOLA Testing Guide for Wells Fargo

## What to Look For
IDOR (Insecure Direct Object Reference) / BOLA (Broken Object Level Authorization)
is when you can access another user's resources by changing an identifier.

## Testing Methodology

### Step 1: Identify Object References
Look for any ID in: URL path, query params, POST body, headers
- /api/account/12345 -> change 12345
- /api/user?id=abc-def -> change the UUID
- POST body: {"accountId": "999"} -> change 999

### Step 2: Create Two Test Accounts (YOUR OWN)
- Account A: Primary testing account
- Account B: Victim account (also yours)

### Step 3: Test Pattern
1. Login as Account A
2. Capture a request that fetches Account A's data
3. Change the ID to Account B's ID
4. If you get Account B's data -> IDOR!

### High-Value IDOR Targets for Banking:
- Account balance/details
- Transaction history
- Statements/documents
- Messages/notifications
- Beneficiary/payee lists
- Profile information (PII)
- Transfer initiation (CRITICAL if works)
- Bill pay details

### What Makes a Report High Severity:
- Access to financial data (balance, transactions) = HIGH
- Ability to perform actions as another user = CRITICAL
- Access to PII (SSN, full name, address) = HIGH
- Read access to non-sensitive data = MEDIUM

### ID Patterns to Try:
- Sequential integers: 1, 2, 3...
- UUIDs: try UUID of your other account
- Encoded IDs: Base64 decode, modify, re-encode
- Hashed IDs: if predictable (e.g., MD5 of email)
- Negative numbers: -1, 0
- Large numbers: 999999999
- Special values: null, undefined, admin, self, me

### Headers That Might Bypass Auth:
- Remove Authorization header entirely
- Use expired token
- Use token from Account B on Account A's endpoint
- Add X-User-Id or X-Account-Id headers
EOF

# Generate IDOR test URLs from discovered API endpoints
if [[ -s "$API_ENDPOINTS" ]]; then
    log_info "Generating IDOR test cases from $(wc -l < "$API_ENDPOINTS") API endpoints..."

    # Find endpoints with IDs in path
    grep -iE '/[0-9]+(/|$)|/[a-f0-9-]{36}(/|$)' "$API_ENDPOINTS" | sort -u \
        > "${IDOR_OUTPUT}/endpoints-with-ids.txt" 2>/dev/null || true

    # Find endpoints with ID parameters
    grep -iE '[?&](id|userId|accountId|account_id|user_id|customerId|docId|transactionId)=' "$API_ENDPOINTS" | sort -u \
        > "${IDOR_OUTPUT}/endpoints-with-id-params.txt" 2>/dev/null || true

    # Generate manipulation payloads
    if [[ -s "${IDOR_OUTPUT}/endpoints-with-ids.txt" ]]; then
        log_success "Endpoints with path IDs: $(wc -l < "${IDOR_OUTPUT}/endpoints-with-ids.txt")"
        log_info "For each: try changing the numeric ID to another value"
    fi
    if [[ -s "${IDOR_OUTPUT}/endpoints-with-id-params.txt" ]]; then
        log_success "Endpoints with ID params: $(wc -l < "${IDOR_OUTPUT}/endpoints-with-id-params.txt")"
    fi
else
    log_warn "No API endpoints from Phase 2. Generate by browsing the app in Burp."
fi

# ============================================================
# 3. 403 Bypass Candidate Preparation
# ============================================================
log_section "3. 403 Bypass Candidates"

FORBIDDEN_FILE="${PHASE2_DIR}/httpx/status-4xx.txt"
BYPASS_OUTPUT="${RUN_DIR}/403-bypass"

cat > "${BYPASS_OUTPUT}/bypass-techniques.md" << 'EOF'
# 403 Bypass Techniques

For each 403 URL, try these techniques manually in Burp Repeater:

## Path Manipulation
```
Original: GET /admin HTTP/1.1
Try:
  GET /admin/ 
  GET /admin/.
  GET //admin
  GET /./admin
  GET /admin..;/
  GET /%2fadmin
  GET /admin%20
  GET /admin%09
  GET /admin..%3b/
  GET /.;/admin
  GET /;/admin
  GET /admin;
```

## HTTP Method Override
```
Try: POST, PUT, PATCH, DELETE, OPTIONS, TRACE
X-HTTP-Method-Override: GET
X-Method-Override: POST
```

## Header Injection
```
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Host: localhost
X-Forwarded-Host: localhost
```

## Protocol/Version
```
Try HTTP/1.0 instead of HTTP/1.1
Try switching between HTTP and HTTPS
```

## URL Encoding Tricks
```
%2e = .
%2f = /
%252f = / (double encode)
%ef%bc%8f = / (unicode fullwidth)
..%3b = ..;
```
EOF

if [[ -s "$FORBIDDEN_FILE" ]]; then
    # Extract URLs that returned 403
    awk '{print $1}' "$FORBIDDEN_FILE" | sort -u \
        > "${BYPASS_OUTPUT}/403-urls.txt" 2>/dev/null || true
    log_success "403 bypass candidates: $(wc -l < "${BYPASS_OUTPUT}/403-urls.txt")"

    # Generate bypass test commands for Burp
    log_info "Generating bypass test payloads..."
    while IFS= read -r url; do
        path=$(echo "$url" | grep -oP 'https?://[^/]+\K.*' || echo "/")
        host=$(echo "$url" | grep -oP 'https?://\K[^/]+' || echo "")
        cat >> "${BYPASS_OUTPUT}/bypass-requests.txt" << HEREDOC

=== TARGET: ${url} ===
# Path tricks
GET ${path}/ HTTP/1.1
Host: ${host}

GET ${path}/. HTTP/1.1
Host: ${host}

GET /${path}// HTTP/1.1
Host: ${host}

GET ${path}..;/ HTTP/1.1
Host: ${host}

# Header tricks
GET ${path} HTTP/1.1
Host: ${host}
X-Original-URL: ${path}
X-Forwarded-For: 127.0.0.1

# Method override
POST ${path} HTTP/1.1
Host: ${host}
X-HTTP-Method-Override: GET
Content-Length: 0

HEREDOC
    done < <(head -30 "${BYPASS_OUTPUT}/403-urls.txt")
    log_success "Bypass requests generated: ${BYPASS_OUTPUT}/bypass-requests.txt"
else
    log_warn "No 403 responses found from Phase 2"
fi

# ============================================================
# 4. Custom Wordlist Generation
# ============================================================
log_section "4. Custom Wordlist Generation"

WORDLIST_DIR="${RUN_DIR}/fuzz-wordlists"

# Banking-specific directory wordlist
cat > "${WORDLIST_DIR}/banking-dirs.txt" << 'EOF'
account
accounts
admin
administration
api
api-docs
api/v1
api/v2
api/v3
app
application
auth
authenticate
authorization
balance
banking
beneficiary
bill-pay
billpay
callback
cards
checkout
client
config
connect
console
credit
customer
dashboard
debug
deposit
docs
document
documents
download
ebanking
employee
enrollment
env
export
external
files
finance
fund
funds
gateway
graphql
health
help
history
home
identity
import
inbox
info
internal
invest
investment
investor
json
jwt
legacy
loan
loans
login
logout
manage
management
member
message
messages
mobile
monitor
mortgage
notification
notifications
oauth
online
openapi
operations
otp
pay
payment
payments
payroll
personal
portfolio
private
profile
proxy
receipt
redirect
register
registration
report
reports
reset
rest
retirement
savings
search
secure
security
server-info
server-status
service
services
session
settings
signin
signup
sso
statement
statements
status
support
swagger
swagger-ui
system
token
transaction
transactions
transfer
transfers
trust
upload
user
users
verify
version
wealth
wire
withdraw
zelle
EOF

# Banking-specific parameter fuzzing wordlist
cat > "${WORDLIST_DIR}/banking-params.txt" << 'EOF'
id
userId
user_id
accountId
account_id
accountNumber
account_number
customerId
customer_id
transactionId
transaction_id
amount
balance
fromAccount
toAccount
from_account
to_account
beneficiary
beneficiaryId
payeeId
payee_id
routingNumber
routing_number
sortCode
bsb
iban
swift
memo
description
reference
type
status
date
startDate
endDate
start_date
end_date
limit
offset
page
size
sort
order
filter
search
query
token
session
redirect
returnUrl
return_url
callback
next
url
file
filename
document
documentId
doc_id
statementId
statement_id
format
export
download
action
method
cmd
command
debug
test
admin
role
permission
access
level
EOF

# Generate combined wordlist from Phase 2 discoveries
if [[ -s "${JS_OUTPUT}/endpoints-from-js.txt" ]]; then
    # Extract path segments from discovered endpoints
    cat "${JS_OUTPUT}/endpoints-from-js.txt" | \
        tr '/' '\n' | grep -v '^$' | sort -u \
        >> "${WORDLIST_DIR}/discovered-paths.txt" 2>/dev/null || true
fi

# Add GAU-discovered parameters if available
GAU_PARAMS="${PHASE2_DIR}/../../phase1/"*/gau-params.txt
if ls $GAU_PARAMS 1>/dev/null 2>&1; then
    for f in $GAU_PARAMS; do
        awk '{print $2}' "$f" >> "${WORDLIST_DIR}/discovered-params.txt" 2>/dev/null || true
    done
    dedup_file "${WORDLIST_DIR}/discovered-params.txt" 2>/dev/null || true
fi

log_success "Wordlists created:"
for wl in "${WORDLIST_DIR}"/*.txt; do
    [[ -f "$wl" ]] && echo "  $(basename "$wl"): $(wc -l < "$wl") entries"
done

# ============================================================
# 5. Report Templates
# ============================================================
log_section "5. Report Templates"

TEMPLATES_DIR="${RUN_DIR}/report-templates"

cat > "${TEMPLATES_DIR}/subdomain-takeover-report.md" << 'EOF'
# Subdomain Takeover: [subdomain.wellsfargo.com]

## Summary
The subdomain `[SUBDOMAIN]` has a CNAME record pointing to `[SERVICE]` which 
is no longer claimed. An attacker could register this resource and serve 
malicious content under the Wells Fargo domain.

## Severity
High (domain trust abuse, potential phishing, cookie theft)

## Steps to Reproduce
1. Run: `dig CNAME [SUBDOMAIN]`
2. Observe CNAME points to: `[CNAME_TARGET]`
3. Visit `https://[SUBDOMAIN]` - observe [SERVICE] error message: "[ERROR_MESSAGE]"
4. The [SERVICE] resource `[RESOURCE_NAME]` is unclaimed and available for registration

## Impact
- Attacker can serve content under *.wellsfargo.com domain
- Same-origin cookie access if cookies are set on .wellsfargo.com
- Phishing credibility (valid TLS cert via service)
- Potential for stored XSS via content injection

## Evidence
- DNS query output: [screenshot/paste]
- Error page indicating unclaimed resource: [screenshot]
- Service registration page showing availability: [screenshot]

## Remediation
Remove the dangling CNAME record from DNS or reclaim the external resource.
EOF

cat > "${TEMPLATES_DIR}/idor-report.md" << 'EOF'
# IDOR/BOLA: [Endpoint Description]

## Summary
The endpoint `[METHOD] [ENDPOINT]` allows authenticated users to access 
other users' [RESOURCE_TYPE] by modifying the `[PARAMETER]` parameter.
No authorization check validates that the requesting user owns the resource.

## Severity
[High/Critical] - Access to [financial data/PII/account actions]

## Steps to Reproduce

### Setup
- Account A (attacker): [username/email] 
- Account B (victim): [username/email]
- Both accounts are owned by the researcher

### Reproduction
1. Login as Account A
2. Navigate to [FEATURE] and capture the request in Burp
3. Observe request: `[METHOD] [ENDPOINT]` with parameter `[PARAM]=[VALUE_A]`
4. Change `[PARAM]` to Account B's value: `[VALUE_B]`
5. Forward the request
6. Observe: Account B's [RESOURCE] is returned

## Request (Account A accessing Account B's data)
```http
[METHOD] [ENDPOINT] HTTP/1.1
Host: [HOST]
Authorization: Bearer [TOKEN_A]
X-Bug-Bounty: HackerOne-[USERNAME]

[BODY if POST]
```

## Response (Account B's data leaked)
```json
{
  [SENSITIVE_DATA]
}
```

## Impact
- Attacker can enumerate and access [N] users' [RESOURCE_TYPE]
- Exposed data includes: [list fields]
- [If write IDOR]: Attacker can modify/delete other users' data

## Remediation
Implement server-side authorization check: verify the authenticated user 
owns the resource identified by `[PARAMETER]` before returning/modifying it.
EOF

cat > "${TEMPLATES_DIR}/ssrf-report.md" << 'EOF'
# SSRF: [Feature/Endpoint]

## Summary
The `[PARAMETER]` parameter in `[ENDPOINT]` is vulnerable to Server-Side 
Request Forgery. The server fetches attacker-controlled URLs, allowing 
access to internal services and metadata endpoints.

## Severity
High/Critical (depending on internal access achieved)

## Steps to Reproduce
1. Navigate to [FEATURE]
2. Intercept the request in Burp
3. Modify `[PARAMETER]` to point to attacker-controlled server: `[INTERACTSH_URL]`
4. Observe DNS/HTTP callback received from Wells Fargo infrastructure
5. [If internal access]: Modify to `http://169.254.169.254/latest/meta-data/` 
   and observe cloud metadata returned

## Request
```http
[METHOD] [ENDPOINT] HTTP/1.1
Host: [HOST]
Authorization: Bearer [TOKEN]
X-Bug-Bounty: HackerOne-[USERNAME]

[PARAMETER]=[PAYLOAD]
```

## Evidence
- Out-of-band interaction proof: [screenshot of interactsh/Burp Collaborator]
- Source IP of callback: [IP] (confirms server-side, not client redirect)
- [If applicable]: Internal data retrieved: [redacted screenshot]

## Impact
- Access to internal network services
- [If cloud]: Access to cloud metadata (potential credential theft)
- Potential port scanning of internal infrastructure
- Bypass of network-level access controls

## Remediation
- Validate and whitelist allowed URL schemes and destinations
- Block requests to internal/private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x)
- Use a URL parser that handles edge cases (DNS rebinding, redirects)
EOF

cat > "${TEMPLATES_DIR}/auth-bypass-report.md" << 'EOF'
# Authentication/Authorization Bypass: [Endpoint]

## Summary
The endpoint `[ENDPOINT]` can be accessed without proper authentication 
by [TECHNIQUE]. This exposes [WHAT_IS_EXPOSED] to unauthenticated attackers.

## Severity
[High/Critical]

## Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Original (Blocked) Request
```http
GET [ENDPOINT] HTTP/1.1
Host: [HOST]
X-Bug-Bounty: HackerOne-[USERNAME]

Response: 403 Forbidden
```

## Bypass Request
```http
[METHOD] [MODIFIED_PATH] HTTP/1.1
Host: [HOST]
[ADDITIONAL_HEADERS]
X-Bug-Bounty: HackerOne-[USERNAME]

Response: 200 OK
```

## Impact
- Unauthenticated access to [RESOURCE]
- Data exposed: [DETAILS]
- [If admin panel]: Full administrative control

## Remediation
- Implement authorization at the application layer, not just URL/path matching
- Ensure path normalization before authorization checks
- Test all HTTP methods, not just GET
EOF

log_success "Report templates created in: ${TEMPLATES_DIR}/"
ls "${TEMPLATES_DIR}/" | sed 's/^/  /'

# ============================================================
# 6. Priority Target Analysis
# ============================================================
log_section "6. Priority Target Checklist"

cat > "${RUN_DIR}/priority-checklist.md" << EOF
# Phase 3 Manual Testing Priority Checklist
# Generated: $(date)
# Target: ${TARGET_DOMAIN}
# Priority Target: ${PRIORITY_TARGET}

## Priority 1: Quick Wins (check first)
- [ ] Subdomain takeovers (from dns/potential-takeovers.txt)
- [ ] Exposed .git directories 
- [ ] Exposed .env files
- [ ] Exposed actuator/debug endpoints
- [ ] Secrets in JS files (check js-analysis/secrets-found.txt)

## Priority 2: Medium Effort, High Reward
- [ ] IDOR on API endpoints (see idor-tests/)
- [ ] 403 bypass on admin/internal paths (see 403-bypass/)
- [ ] SSRF via URL parameters
- [ ] Open redirects (chain with OAuth for account takeover)
- [ ] GraphQL introspection + unauthorized queries

## Priority 3: connect.secure.wellsfargo.com ($$$ target)
- [ ] Login flow analysis (password reset, MFA bypass)
- [ ] Session management (fixation, token leakage)
- [ ] IDOR on account/transaction/statement endpoints
- [ ] Business logic in transfer/payment flows
- [ ] Race conditions on financial transactions
- [ ] OAuth/SAML flow manipulation

## Priority 4: Deep Dive
- [ ] JS endpoint mining -> test each hidden endpoint
- [ ] Parameter tampering on discovered APIs
- [ ] HTTP request smuggling on load balancers
- [ ] Cache poisoning on CDN-fronted endpoints
- [ ] CORS misconfiguration on API endpoints
- [ ] WebSocket testing if discovered

## Testing Rules Reminder
- Header on EVERY request: ${H1_HEADER}
- Max rate: 500 req/s (stay at ${RATE_LIMIT})
- Only YOUR accounts for auth testing
- Stop immediately if you cause service impact
- One vuln type per report (unless chaining)
- Provide IP in critical/high reports
EOF

log_success "Priority checklist: ${RUN_DIR}/priority-checklist.md"

# ============================================================
# Summary
# ============================================================
log_section "PHASE 3 PREPARATION COMPLETE"
echo ""
echo "Output: ${RUN_DIR}"
echo ""
echo "Key files:"
echo "  js-analysis/secrets-found.txt    - Leaked secrets from JS"
echo "  js-analysis/endpoints-from-js.txt - Hidden API endpoints"
echo "  idor-tests/                       - IDOR testing guide & targets"
echo "  403-bypass/bypass-requests.txt    - Ready-to-paste bypass requests"
echo "  fuzz-wordlists/                   - Banking-specific wordlists"
echo "  report-templates/                 - HackerOne report templates"
echo "  priority-checklist.md             - What to test first"
echo ""
log_warn "Next steps:"
log_warn "1. Review secrets-found.txt for any valid leaks"
log_warn "2. Import bypass-requests.txt into Burp Repeater"
log_warn "3. Configure Burp with burp-config/match-replace.json"
log_warn "4. Start testing from priority-checklist.md top-down"
log_warn "5. Use report templates for clean HackerOne submissions"
