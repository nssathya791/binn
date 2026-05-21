#!/bin/bash
# ============================================================
# Module 04: Ghost Vulnerability Detection
# ============================================================
# Behavioral vuln detection that automated scanners miss:
#
# 1. Response Diffing Engine - detect subtle state leaks
# 2. Cache Poisoning Probe - unkeyed headers/params
# 3. HTTP Desync Detection - request smuggling indicators
# 4. CORS Deep Testing - beyond simple origin reflection
# 5. Host Header Injection - password reset poisoning
# 6. Path Traversal via Normalization Confusion
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/core.sh"
source "${SCRIPT_DIR}/../../lib/config.sh"


# ============================================================
# 1. Cache Poisoning Probe
# ============================================================
# Test for web cache poisoning via unkeyed inputs:
# - Unkeyed headers that reflect in response
# - Unkeyed query params
# - Fat GET requests (body in GET)
# Banks use heavy CDN caching = high-value target

ghost_cache_poison() {
    local url="$1"
    local output_dir="${GHOST_OUTPUT}/vulns/cache-poison"
    mkdir -p "$output_dir"

    ghost_log phase "Cache Poisoning Probe"
    ghost_log info "Testing: ${url}"

    local cache_buster="ghostcb$(date +%s)"
    local poison_marker="ghost-poisoned-$(head /dev/urandom | tr -dc a-z0-9 | head -c 8)"

    # Headers to test as unkeyed inputs
    local POISON_HEADERS=(
        "X-Forwarded-Host: ${poison_marker}.evil.com"
        "X-Host: ${poison_marker}.evil.com"
        "X-Forwarded-Scheme: nothttps"
        "X-Original-URL: /${poison_marker}"
        "X-Rewrite-URL: /${poison_marker}"
        "X-Forwarded-Port: 1337"
        "X-Forwarded-Proto: nothttps"
        "Transfer-Encoding: chunked"
        "X-Custom-Header: ${poison_marker}"
        "X-Forwarded-Server: ${poison_marker}"
        "Forwarded: host=${poison_marker}.evil.com"
    )

    # Test each header: send with header, then without, compare
    for header in "${POISON_HEADERS[@]}"; do
        ghost_rate_limit 0.2
        local header_name=$(echo "$header" | cut -d: -f1)

        # Request WITH the poison header (include cache buster)
        local poisoned_url="${url}?cb=${cache_buster}_${header_name}"
        local result_with=$(ghost_request "$poisoned_url" "GET" "" "$header")
        local status_with=$(echo "$result_with" | cut -d'|' -f1)
        local body_with=$(echo "$result_with" | cut -d'|' -f5)

        # Check if our poison marker appears in the response
        if [[ -f "$body_with" ]] && grep -q "$poison_marker" "$body_with" 2>/dev/null; then
            ghost_log hit "REFLECTED via ${header_name}! Potential cache poison vector"

            # Verify: request WITHOUT the header (same URL) - if marker present = cached!
            sleep 1
            ghost_rate_limit 0.2
            local result_without=$(ghost_request "$poisoned_url")
            local body_without=$(echo "$result_without" | cut -d'|' -f5)

            if [[ -f "$body_without" ]] && grep -q "$poison_marker" "$body_without" 2>/dev/null; then
                ghost_finding "critical" \
                    "Web Cache Poisoning via ${header_name}" \
                    "Header ${header_name} reflects in cached response. Poison persists without the header." \
                    "URL: ${poisoned_url}, Header: ${header}"
            else
                ghost_finding "medium" \
                    "Unkeyed header reflects (potential cache poison): ${header_name}" \
                    "Header reflects but may not be cached. Test with cache-friendly URL." \
                    "URL: ${url}, Header: ${header}"
            fi

            echo "${url}|${header_name}|reflected" >> "${output_dir}/poison-vectors.txt"
            rm -f "$body_without" 2>/dev/null
        fi

        rm -f "$body_with" 2>/dev/null
    done

    # Test unkeyed query parameters (some caches strip unknown params)
    ghost_log info "Testing unkeyed query parameters..."
    local PARAM_TESTS=(
        "utm_source=${poison_marker}"
        "utm_content=<script>alert(1)</script>"
        "callback=${poison_marker}"
        "jsonp=${poison_marker}"
        "_=${poison_marker}"
    )

    for param in "${PARAM_TESTS[@]}"; do
        ghost_rate_limit 0.2
        local param_name=$(echo "$param" | cut -d= -f1)
        local test_url="${url}?${param}&_cb=${cache_buster}_${param_name}"

        local result=$(ghost_request "$test_url")
        local body_file=$(echo "$result" | cut -d'|' -f5)

        if [[ -f "$body_file" ]] && grep -q "$poison_marker" "$body_file" 2>/dev/null; then
            ghost_log hit "Param ${param_name} reflects in response"
            echo "${url}|param:${param_name}|reflected" >> "${output_dir}/poison-vectors.txt"
        fi

        rm -f "$body_file" 2>/dev/null
    done

    [[ -s "${output_dir}/poison-vectors.txt" ]] && \
        ghost_log hit "Cache poison vectors: $(wc -l < "${output_dir}/poison-vectors.txt")"
}


# ============================================================
# 2. HTTP Request Smuggling/Desync Detection
# ============================================================
# Detect CL.TE / TE.CL / TE.TE desync between front-end and
# back-end servers. Banks use load balancers + app servers = prime target.

ghost_desync_detect() {
    local url="$1"
    local output_dir="${GHOST_OUTPUT}/vulns/desync"
    mkdir -p "$output_dir"

    ghost_log phase "HTTP Desync Detection"
    ghost_log info "Testing: ${url}"
    ghost_log warn "Using SAFE detection only (no actual smuggling)"

    local host=$(echo "$url" | grep -oP 'https?://\K[^/]+')

    # Test 1: CL.TE detection (safe - timing based)
    # Send ambiguous request, measure if back-end times out
    ghost_log info "Testing CL.TE..."

    local clte_time=$(curl -s -o /dev/null -w '%{time_total}' \
        -H "${H1_HEADER}" \
        -H "${TOOL_HEADER_PREFIX}: ghost-desync" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Content-Length: 4" \
        -H "Transfer-Encoding: chunked" \
        -d $'0\r\n\r\n' \
        --max-time 10 \
        "$url" 2>/dev/null || echo "10")

    ghost_log info "CL.TE response time: ${clte_time}s"

    # Test 2: TE.CL detection (safe - timing based)
    ghost_log info "Testing TE.CL..."

    local tecl_time=$(curl -s -o /dev/null -w '%{time_total}' \
        -H "${H1_HEADER}" \
        -H "${TOOL_HEADER_PREFIX}: ghost-desync" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Content-Length: 6" \
        -H "Transfer-Encoding: chunked" \
        -d $'0\r\n\r\nX' \
        --max-time 10 \
        "$url" 2>/dev/null || echo "10")

    ghost_log info "TE.CL response time: ${tecl_time}s"

    # Test 3: Transfer-Encoding obfuscation
    ghost_log info "Testing TE obfuscation variants..."

    local TE_VARIANTS=(
        "Transfer-Encoding: xchunked"
        "Transfer-Encoding : chunked"
        "Transfer-Encoding: chunked"
        "Transfer-encoding: cow"
        "Transfer-Encoding: chunk"
    )

    for te_header in "${TE_VARIANTS[@]}"; do
        ghost_rate_limit 0.3
        local variant_time=$(curl -s -o /dev/null -w '%{http_code}|%{time_total}' \
            -H "${H1_HEADER}" \
            -H "$te_header" \
            -H "Content-Length: 4" \
            -d "test" \
            --max-time 10 \
            "$url" 2>/dev/null || echo "000|10")

        local v_status=$(echo "$variant_time" | cut -d'|' -f1)
        local v_time=$(echo "$variant_time" | cut -d'|' -f2)

        # If server processes the malformed TE differently (different status/timing)
        echo "${te_header}|${v_status}|${v_time}" >> "${output_dir}/te-variants.txt"
    done

    # Analyze: if timing differs significantly between CL.TE and TE.CL, desync likely
    local time_diff=$(echo "scale=2; $tecl_time - $clte_time" | bc 2>/dev/null || echo "0")
    local abs_diff=$(echo "$time_diff" | tr -d '-')

    if (( $(echo "$abs_diff > 3" | bc -l 2>/dev/null || echo 0) )); then
        ghost_finding "critical" \
            "Potential HTTP request smuggling at ${url}" \
            "Timing difference between CL.TE (${clte_time}s) and TE.CL (${tecl_time}s) suggests desync." \
            "CL.TE: ${clte_time}s, TE.CL: ${tecl_time}s, Diff: ${time_diff}s"
        ghost_log hit "POTENTIAL DESYNC! Timing diff: ${time_diff}s"
    else
        ghost_log info "No obvious desync (timing diff: ${time_diff}s)"
    fi

    # Save results
    cat > "${output_dir}/desync-summary.txt" << EOF
HTTP Desync Detection Results
=============================
Target: ${url}
CL.TE timing: ${clte_time}s
TE.CL timing: ${tecl_time}s
Timing difference: ${time_diff}s
Verdict: $(if (( $(echo "$abs_diff > 3" | bc -l 2>/dev/null || echo 0) )); then echo "INVESTIGATE FURTHER"; else echo "Likely safe"; fi)

Next steps if suspicious:
1. Use Burp Suite's HTTP Request Smuggler extension
2. Try Turbo Intruder with smuggling scripts
3. Test with: https://portswigger.net/web-security/request-smuggling
EOF
}


# ============================================================
# 3. CORS Deep Testing
# ============================================================
# Beyond simple Origin reflection. Tests:
# - Subdomain trust (*.wellsfargo.com reflected?)
# - Null origin acceptance
# - Pre-domain bypass (evilwellsfargo.com)
# - Post-domain bypass (wellsfargo.com.evil.com)
# - Special chars in origin
# - Credentials inclusion

ghost_cors_deep() {
    local url="$1"
    local output_dir="${GHOST_OUTPUT}/vulns/cors"
    mkdir -p "$output_dir"

    ghost_log phase "CORS Deep Testing"
    ghost_log info "Target: ${url}"

    local target_domain=$(echo "$url" | grep -oP 'https?://\K[^/]+' | sed 's/:.*//')

    # Origins to test
    local ORIGINS=(
        "https://evil.com"
        "https://${target_domain}.evil.com"
        "https://evil${target_domain}"
        "https://evil.${target_domain}"
        "https://subdomain.${target_domain}"
        "null"
        "https://${target_domain}%60.evil.com"
        "https://${target_domain}'.evil.com"
        "http://${target_domain}"
        "https://not${target_domain}.com"
        "https://${target_domain}evil.com"
    )

    for origin in "${ORIGINS[@]}"; do
        ghost_rate_limit 0.15

        local header_file=$(mktemp)
        curl -s -o /dev/null -D "$header_file" \
            -H "${H1_HEADER}" \
            -H "Origin: ${origin}" \
            --max-time 10 \
            "$url" 2>/dev/null

        local acao=$(grep -i "access-control-allow-origin" "$header_file" 2>/dev/null | tr -d '\r\n')
        local acac=$(grep -i "access-control-allow-credentials" "$header_file" 2>/dev/null | tr -d '\r\n')

        if [[ -n "$acao" ]]; then
            local reflected_origin=$(echo "$acao" | awk -F': ' '{print $2}')

            # Check if our evil origin is reflected
            if [[ "$reflected_origin" == "$origin" || "$reflected_origin" == "*" ]]; then
                local severity="medium"
                local detail="Origin reflected"

                # Critical if credentials are allowed with reflected origin
                if echo "$acac" | grep -qi "true"; then
                    severity="high"
                    detail="Origin reflected WITH credentials=true"
                fi

                # Extra critical if null origin accepted with credentials
                if [[ "$origin" == "null" ]] && echo "$acac" | grep -qi "true"; then
                    severity="critical"
                    detail="null origin accepted with credentials. Exploitable via sandboxed iframe."
                fi

                ghost_log hit "CORS misconfiguration: ${origin} → ${reflected_origin} (${detail})"
                echo "${url}|${origin}|${reflected_origin}|${acac}|${severity}" >> "${output_dir}/cors-findings.txt"

                ghost_finding "$severity" \
                    "CORS misconfiguration: ${detail}" \
                    "Origin '${origin}' is reflected in ACAO header. ${detail}" \
                    "URL: ${url}, Origin: ${origin}, ACAO: ${acao}, ACAC: ${acac}"
            fi
        fi

        rm -f "$header_file" 2>/dev/null
    done

    [[ -s "${output_dir}/cors-findings.txt" ]] && \
        ghost_log hit "CORS issues found: $(wc -l < "${output_dir}/cors-findings.txt")"
}


# ============================================================
# 4. Host Header Injection (Password Reset Poisoning)
# ============================================================
# Inject malicious Host header to poison password reset links.
# If the app uses the Host header to build reset URLs, attacker
# can steal reset tokens.

ghost_host_header_injection() {
    local url="$1"
    local output_dir="${GHOST_OUTPUT}/vulns/host-header"
    mkdir -p "$output_dir"

    ghost_log phase "Host Header Injection"
    ghost_log info "Target: ${url}"

    local real_host=$(echo "$url" | grep -oP 'https?://\K[^/]+')
    local poison_host="evil-ghost.com"

    # Test variations
    local HOST_TESTS=(
        "Host: ${poison_host}"
        "Host: ${real_host}\r\nX-Forwarded-Host: ${poison_host}"
        "Host: ${real_host}\r\nHost: ${poison_host}"
        "Host: ${real_host}@${poison_host}"
        "Host: ${real_host}%00${poison_host}"
        "Host: ${real_host}%0d%0ainjected: header"
    )

    local EXTRA_HEADERS=(
        "X-Forwarded-Host: ${poison_host}"
        "X-Host: ${poison_host}"
        "X-Forwarded-Server: ${poison_host}"
        "Forwarded: host=${poison_host}"
        "X-HTTP-Host-Override: ${poison_host}"
    )

    for extra in "${EXTRA_HEADERS[@]}"; do
        ghost_rate_limit 0.2

        local body_file=$(mktemp)
        local header_file=$(mktemp)

        curl -s -o "$body_file" -D "$header_file" \
            -H "${H1_HEADER}" \
            -H "${TOOL_HEADER_PREFIX}: ghost-host" \
            -H "$extra" \
            --max-time 10 \
            "$url" 2>/dev/null

        # Check if poison host appears in response body or Location header
        if grep -qi "$poison_host" "$body_file" 2>/dev/null; then
            ghost_log hit "Host header reflected in body via: ${extra}"
            ghost_finding "high" \
                "Host header injection via $(echo "$extra" | cut -d: -f1)" \
                "The header '${extra}' causes '${poison_host}' to appear in response body. If this is a password reset page, tokens can be stolen." \
                "URL: ${url}, Header: ${extra}"
            echo "${url}|body|${extra}" >> "${output_dir}/host-injection.txt"
        fi

        if grep -qi "$poison_host" "$header_file" 2>/dev/null; then
            ghost_log hit "Host header reflected in response headers via: ${extra}"
            echo "${url}|header|${extra}" >> "${output_dir}/host-injection.txt"
        fi

        rm -f "$body_file" "$header_file" 2>/dev/null
    done

    [[ -s "${output_dir}/host-injection.txt" ]] && \
        ghost_log hit "Host injection vectors: $(wc -l < "${output_dir}/host-injection.txt")"
}


# ============================================================
# 5. Response Diffing Engine
# ============================================================
# Compare responses between authenticated/unauth, different users,
# different params to detect subtle information leakage.

ghost_response_diff() {
    local url="$1"
    local output_dir="${GHOST_OUTPUT}/vulns/response-diff"
    mkdir -p "$output_dir"

    ghost_log phase "Response Diffing Engine"
    ghost_log info "Comparing response variations for: ${url}"

    # Test 1: Authenticated vs Unauthenticated diff
    # (requires cookie/token passed as $2)
    local auth_header="${2:-}"

    ghost_rate_limit 0.2
    local unauth_result=$(ghost_request "$url")
    local unauth_status=$(echo "$unauth_result" | cut -d'|' -f1)
    local unauth_size=$(echo "$unauth_result" | cut -d'|' -f3)
    local unauth_body=$(echo "$unauth_result" | cut -d'|' -f5)

    if [[ -n "$auth_header" ]]; then
        ghost_rate_limit 0.2
        local auth_result=$(ghost_request "$url" "GET" "" "$auth_header")
        local auth_status=$(echo "$auth_result" | cut -d'|' -f1)
        local auth_size=$(echo "$auth_result" | cut -d'|' -f3)
        local auth_body=$(echo "$auth_result" | cut -d'|' -f5)

        local size_diff=$((auth_size - unauth_size))
        ghost_log info "Auth vs Unauth: status=${auth_status}/${unauth_status} size_diff=${size_diff}"

        # If unauth gets same data as auth = broken access control
        if [[ "$auth_status" == "200" && "$unauth_status" == "200" && $size_diff -lt 50 && $size_diff -gt -50 ]]; then
            # Compare actual content
            if diff "$unauth_body" "$auth_body" &>/dev/null; then
                ghost_finding "high" \
                    "No auth difference detected: ${url}" \
                    "Authenticated and unauthenticated requests return identical responses. Auth may not be enforced." \
                    "Auth size: ${auth_size}, Unauth size: ${unauth_size}"
            fi
        fi

        rm -f "$auth_body" 2>/dev/null
    fi

    # Test 2: User-Agent based response differences (mobile vs desktop)
    ghost_rate_limit 0.2
    local mobile_result=$(ghost_request "$url" "GET" "" \
        "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15")
    local mobile_size=$(echo "$mobile_result" | cut -d'|' -f3)
    local mobile_body=$(echo "$mobile_result" | cut -d'|' -f5)

    local ua_diff=$((mobile_size - unauth_size))
    [[ $ua_diff -lt 0 ]] && ua_diff=$((-ua_diff))

    if [[ $ua_diff -gt 500 ]]; then
        ghost_log hit "Different response for mobile UA (size diff: ${ua_diff})"
        ghost_log info "Mobile version may have different attack surface"
        echo "${url}|mobile_ua_diff|${ua_diff}" >> "${output_dir}/diff-findings.txt"
    fi

    # Test 3: Accept header manipulation (JSON vs HTML vs XML)
    local ACCEPT_TYPES=("application/json" "text/html" "application/xml" "text/plain" "*/*")

    for accept in "${ACCEPT_TYPES[@]}"; do
        ghost_rate_limit 0.15
        local result=$(ghost_request "$url" "GET" "" "Accept: ${accept}")
        local status=$(echo "$result" | cut -d'|' -f1)
        local size=$(echo "$result" | cut -d'|' -f3)
        local body_file=$(echo "$result" | cut -d'|' -f5)

        echo "${accept}|${status}|${size}" >> "${output_dir}/accept-variants.txt"

        # JSON responses from HTML pages = hidden API behavior
        if [[ "$accept" == "application/json" && "$status" == "200" ]]; then
            if [[ -f "$body_file" ]] && head -1 "$body_file" | grep -qE '^\s*[\[{]'; then
                ghost_log hit "Returns JSON with Accept: application/json"
                echo "${url}|json_response|${size}" >> "${output_dir}/diff-findings.txt"
            fi
        fi

        rm -f "$body_file" 2>/dev/null
    done

    rm -f "$unauth_body" "$mobile_body" 2>/dev/null

    [[ -s "${output_dir}/diff-findings.txt" ]] && \
        ghost_log hit "Response diff anomalies: $(wc -l < "${output_dir}/diff-findings.txt")"
}

# ============================================================
# Main Vulns Runner
# ============================================================
ghost_vulns_run() {
    local urls_file="${1:-}"
    local auth_token="${2:-}"

    ghost_log phase "GHOST VULNERABILITY DETECTION MODULE"

    if [[ -z "$urls_file" || ! -s "$urls_file" ]]; then
        ghost_log error "Usage: ghost_vulns_run <urls_file> [auth_token]"
        return 1
    fi

    while IFS= read -r url; do
        ghost_log info "━━━ Testing: ${url} ━━━"
        ghost_cache_poison "$url"
        ghost_cors_deep "$url"
        ghost_host_header_injection "$url"
        ghost_response_diff "$url" "$auth_token"
    done < <(head -15 "$urls_file")

    # Desync on top 5 only (heavy test)
    ghost_log info "Running desync detection on top targets..."
    while IFS= read -r url; do
        ghost_desync_detect "$url"
    done < <(head -5 "$urls_file")

    ghost_log phase "VULNERABILITY DETECTION COMPLETE"
    ghost_log info "Findings: ${GHOST_OUTPUT}/findings.json"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    ghost_vulns_run "$@"
fi
