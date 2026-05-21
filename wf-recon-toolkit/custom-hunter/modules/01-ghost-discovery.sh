#!/bin/bash
# ============================================================
# Module 01: Ghost Discovery
# ============================================================
# UNCONVENTIONAL subdomain/asset discovery that others skip:
#
# 1. Favicon Hash Hunting - Find related infra by favicon mmh3 hash
# 2. CT Log Diffing - Monitor for NEW certs (catch fresh deployments)
# 3. TLS Cert Correlation - Find hosts sharing same cert serial
# 4. DNS Wildcard Detection - Identify wildcard vs real responses
# 5. ASN Neighbor Discovery - Find forgotten hosts on same netblock
# 6. HTTP Response Clustering - Group hosts by behavior, find outliers
# 7. JARM Fingerprinting - Identify same server software across IPs
#
# WHY THIS FINDS DUPES-FREE BUGS:
# Other hunters scrape known sources. We find NEW/HIDDEN assets
# that aren't in any public database yet.
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/core.sh"
source "${SCRIPT_DIR}/../../lib/config.sh"

# ============================================================
# 1. Favicon Hash Hunting
# ============================================================
# Shodan indexes favicon hashes (mmh3). If we compute the hash of
# the target's favicon, we can find ALL servers using the same
# favicon — including internal tools, staging, forgotten apps.

ghost_favicon_hunt() {
    local target="$1"
    local output_dir="${GHOST_OUTPUT}/discovery/favicon"
    mkdir -p "$output_dir"

    ghost_log phase "Favicon Hash Hunting"

    # Download favicon from main site
    local favicon_url="https://${target}/favicon.ico"
    local favicon_file="${output_dir}/favicon.ico"

    ghost_log info "Fetching favicon from ${favicon_url}..."
    curl -s -H "${H1_HEADER}" -o "$favicon_file" "$favicon_url" 2>/dev/null

    if [[ ! -s "$favicon_file" ]]; then
        # Try alternate locations
        for path in "/assets/favicon.ico" "/static/favicon.ico" "/images/favicon.ico"; do
            curl -s -H "${H1_HEADER}" -o "$favicon_file" "https://${target}${path}" 2>/dev/null
            [[ -s "$favicon_file" ]] && break
        done
    fi

    if [[ -s "$favicon_file" ]]; then
        # Compute mmh3 hash (same algorithm Shodan uses)
        local favicon_hash
        favicon_hash=$(python3 -c "
import mmh3
import codecs
import sys

try:
    with open('${favicon_file}', 'rb') as f:
        data = f.read()
    encoded = codecs.encode(data, 'base64')
    hash_val = mmh3.hash(encoded)
    print(hash_val)
except ImportError:
    # Fallback: compute md5 for manual Shodan search
    import hashlib
    with open('${favicon_file}', 'rb') as f:
        data = f.read()
    print('md5:' + hashlib.md5(data).hexdigest())
except Exception as e:
    print(f'error:{e}', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null)

        if [[ -n "$favicon_hash" && "$favicon_hash" != error:* ]]; then
            ghost_log hit "Favicon hash: ${favicon_hash}"

            # Save Shodan/Censys queries for manual use
            cat > "${output_dir}/search-queries.txt" << EOF
# Favicon Hash Search Queries
# Use these to find ALL servers with the same favicon (related infra)

# Shodan:
http.favicon.hash:${favicon_hash}

# Censys:
services.http.response.favicons.hashes: "${favicon_hash}"

# FOFA:
icon_hash="${favicon_hash}"

# ZoomEye:
iconhash:"${favicon_hash}"
EOF
            ghost_log info "Search queries saved to: ${output_dir}/search-queries.txt"
            ghost_log info "Run these in Shodan/Censys to find related infrastructure"
        else
            ghost_log warn "Could not compute favicon hash (install: pip3 install mmh3)"
            # Still save md5 for manual lookup
            local md5hash=$(md5sum "$favicon_file" | awk '{print $1}')
            echo "Favicon MD5: ${md5hash}" > "${output_dir}/favicon-md5.txt"
        fi
    else
        ghost_log warn "No favicon found at ${target}"
    fi
}

# ============================================================
# 2. CT Log Diffing (find NEW deployments)
# ============================================================
# Instead of just pulling all certs (what everyone does), we:
# - Pull certs from last 24h/48h/7d
# - Compare against known subdomain list
# - NEW entries = freshly deployed = less hardened = more bugs

ghost_ct_diff() {
    local target="$1"
    local known_subs_file="${2:-}"
    local output_dir="${GHOST_OUTPUT}/discovery/ct-diff"
    mkdir -p "$output_dir"

    ghost_log phase "CT Log Diffing (Fresh Deployments)"

    # Get current CT data
    ghost_log info "Fetching current CT log data..."
    curl -s "https://crt.sh/?q=%25.${target}&output=json" \
        --max-time 60 \
        -o "${output_dir}/ct-current.json" 2>/dev/null

    if [[ ! -s "${output_dir}/ct-current.json" ]]; then
        ghost_log warn "crt.sh query failed or empty"
        return
    fi

    # Extract all subdomains with timestamps
    jq -r '.[] | "\(.not_before)|\(.name_value)"' "${output_dir}/ct-current.json" 2>/dev/null | \
        sort -t'|' -k1 -r > "${output_dir}/ct-timeline.txt"

    # Find certs issued in last 7 days
    local week_ago=$(date -d "7 days ago" '+%Y-%m-%d' 2>/dev/null || date -v-7d '+%Y-%m-%d' 2>/dev/null)
    if [[ -n "$week_ago" ]]; then
        grep -E "^${week_ago:0:4}" "${output_dir}/ct-timeline.txt" | \
            awk -F'|' -v cutoff="$week_ago" '$1 >= cutoff {print $2}' | \
            sed 's/\*\.//g' | tr '[:upper:]' '[:lower:]' | sort -u \
            > "${output_dir}/new-last-7days.txt" 2>/dev/null || true
    fi

    # Find certs issued in last 24 hours
    local yesterday=$(date -d "1 day ago" '+%Y-%m-%d' 2>/dev/null || date -v-1d '+%Y-%m-%d' 2>/dev/null)
    if [[ -n "$yesterday" ]]; then
        awk -F'|' -v cutoff="$yesterday" '$1 >= cutoff {print $2}' "${output_dir}/ct-timeline.txt" | \
            sed 's/\*\.//g' | tr '[:upper:]' '[:lower:]' | sort -u \
            > "${output_dir}/new-last-24h.txt" 2>/dev/null || true
    fi

    # If we have a known subdomain list, find the DIFF (truly new ones)
    if [[ -n "$known_subs_file" && -f "$known_subs_file" ]]; then
        jq -r '.[].name_value' "${output_dir}/ct-current.json" 2>/dev/null | \
            sed 's/\*\.//g' | tr '[:upper:]' '[:lower:]' | sort -u \
            > "${output_dir}/ct-all-subs.txt"

        comm -23 "${output_dir}/ct-all-subs.txt" <(sort -u "$known_subs_file") \
            > "${output_dir}/ct-new-unknown.txt" 2>/dev/null || true

        if [[ -s "${output_dir}/ct-new-unknown.txt" ]]; then
            ghost_log hit "NEW subdomains not in your known list: $(wc -l < "${output_dir}/ct-new-unknown.txt")"
            head -20 "${output_dir}/ct-new-unknown.txt" | while read -r sub; do
                ghost_log info "  NEW: ${sub}"
            done
        fi
    fi

    # Report fresh deployments
    if [[ -s "${output_dir}/new-last-7days.txt" ]]; then
        ghost_log hit "Certs issued in last 7 days: $(wc -l < "${output_dir}/new-last-7days.txt")"
        ghost_log info "These are FRESH deployments - likely less hardened!"
        cat "${output_dir}/new-last-7days.txt" | head -20
    fi

    if [[ -s "${output_dir}/new-last-24h.txt" ]]; then
        ghost_log hit "Certs issued in last 24h: $(wc -l < "${output_dir}/new-last-24h.txt")"
        ghost_finding "medium" \
            "Fresh deployment detected (last 24h)" \
            "New certificates issued indicate fresh deployments that may not be fully hardened" \
            "$(cat "${output_dir}/new-last-24h.txt" | head -5 | tr '\n' ',')"
    fi
}

# ============================================================
# 3. TLS Certificate Correlation
# ============================================================
# Connect to hosts, extract cert serial numbers and SANs.
# Hosts sharing the same cert = same infrastructure/deployment.
# Find the WEAKEST host in a cert group to attack.

ghost_tls_correlation() {
    local hosts_file="$1"
    local output_dir="${GHOST_OUTPUT}/discovery/tls-correlation"
    mkdir -p "$output_dir"

    ghost_log phase "TLS Certificate Correlation"

    if [[ ! -s "$hosts_file" ]]; then
        ghost_log warn "No hosts file provided"
        return
    fi

    ghost_log info "Extracting TLS certs from $(wc -l < "$hosts_file") hosts..."

    local cert_data="${output_dir}/cert-data.txt"
    > "$cert_data"

    while IFS= read -r host; do
        ghost_rate_limit 0.2
        local clean_host="${host#https://}"
        clean_host="${clean_host#http://}"
        clean_host="${clean_host%%/*}"
        clean_host="${clean_host%%:*}"

        # Extract cert info
        local cert_info
        cert_info=$(echo | timeout 5 openssl s_client -connect "${clean_host}:443" -servername "$clean_host" 2>/dev/null | \
            openssl x509 -noout -serial -subject -issuer -dates -ext subjectAltName 2>/dev/null)

        if [[ -n "$cert_info" ]]; then
            local serial=$(echo "$cert_info" | grep "serial=" | cut -d= -f2)
            local subject=$(echo "$cert_info" | grep "subject=" | sed 's/subject=//')
            local sans=$(echo "$cert_info" | grep -A1 "Subject Alternative Name" | tail -1 | tr ',' '\n' | grep DNS | sed 's/.*DNS://g' | tr '\n' ',')
            local not_after=$(echo "$cert_info" | grep "notAfter=" | cut -d= -f2)

            echo "${clean_host}|${serial}|${subject}|${sans}|${not_after}" >> "$cert_data"
        fi
    done < <(head -100 "$hosts_file")  # Limit to 100 for speed

    if [[ -s "$cert_data" ]]; then
        # Group by cert serial (same cert = same deployment)
        ghost_log info "Grouping hosts by shared certificates..."

        awk -F'|' '{print $2}' "$cert_data" | sort | uniq -c | sort -rn | \
            while read count serial; do
                if [[ $count -gt 1 && -n "$serial" ]]; then
                    echo "=== Shared cert (${count} hosts): ${serial} ===" >> "${output_dir}/shared-certs.txt"
                    grep "|${serial}|" "$cert_data" | awk -F'|' '{print "  " $1}' >> "${output_dir}/shared-certs.txt"
                    echo "" >> "${output_dir}/shared-certs.txt"
                fi
            done

        if [[ -s "${output_dir}/shared-certs.txt" ]]; then
            ghost_log hit "Found hosts sharing certificates (same infra):"
            cat "${output_dir}/shared-certs.txt" | head -30
        fi

        # Find certs expiring soon (rushed renewal = mistakes)
        ghost_log info "Checking for soon-expiring certs..."
        local thirty_days_out=$(date -d "+30 days" '+%b %d %H:%M:%S %Y' 2>/dev/null || date -v+30d '+%b %d %H:%M:%S %Y' 2>/dev/null)
        # This is informational - expired/expiring certs indicate neglected infra
        while IFS='|' read -r host serial subject sans expiry; do
            if [[ -n "$expiry" ]]; then
                local exp_epoch=$(date -d "$expiry" '+%s' 2>/dev/null || echo 0)
                local now_epoch=$(date '+%s')
                local diff_days=$(( (exp_epoch - now_epoch) / 86400 ))
                if [[ $diff_days -lt 30 && $diff_days -gt -365 ]]; then
                    echo "${host} expires in ${diff_days} days (${expiry})" >> "${output_dir}/expiring-certs.txt"
                fi
            fi
        done < "$cert_data"

        if [[ -s "${output_dir}/expiring-certs.txt" ]]; then
            ghost_log hit "Hosts with expiring/expired certs (neglected infra):"
            cat "${output_dir}/expiring-certs.txt"
        fi

        # Extract NEW subdomains from SANs
        awk -F'|' '{print $4}' "$cert_data" | tr ',' '\n' | \
            sed 's/^ //; s/ $//; s/\*\.//g' | grep -i "wellsfargo" | \
            sort -u > "${output_dir}/sans-subdomains.txt" 2>/dev/null || true

        if [[ -s "${output_dir}/sans-subdomains.txt" ]]; then
            ghost_log hit "Subdomains from TLS SANs: $(wc -l < "${output_dir}/sans-subdomains.txt")"
        fi
    fi
}

# ============================================================
# 4. DNS Wildcard Detection & Bypass
# ============================================================
# Many programs use DNS wildcards (*.target.com → same IP).
# Standard tools report thousands of "live" hosts that are all
# the same default page. We detect this and find the REAL ones.

ghost_wildcard_detect() {
    local target="$1"
    local subs_file="$2"
    local output_dir="${GHOST_OUTPUT}/discovery/wildcard"
    mkdir -p "$output_dir"

    ghost_log phase "DNS Wildcard Detection"

    # Generate random subdomain to test for wildcard
    local random_sub="ghost-$(head /dev/urandom | tr -dc a-z0-9 | head -c 12).${target}"

    ghost_log info "Testing wildcard with: ${random_sub}"
    local wildcard_ip=$(dig +short A "$random_sub" 2>/dev/null | head -1)

    if [[ -n "$wildcard_ip" && "$wildcard_ip" != ";;" ]]; then
        ghost_log warn "WILDCARD DNS DETECTED! Resolves to: ${wildcard_ip}"

        # Also get the wildcard HTTP response fingerprint
        local wildcard_response=$(ghost_request "http://${random_sub}")
        local wc_status=$(echo "$wildcard_response" | cut -d'|' -f1)
        local wc_size=$(echo "$wildcard_response" | cut -d'|' -f3)
        local wc_body=$(echo "$wildcard_response" | cut -d'|' -f5)

        ghost_log info "Wildcard response: status=${wc_status}, size=${wc_size}"

        # Now filter the subdomain list: remove anything that matches wildcard
        if [[ -s "$subs_file" ]]; then
            ghost_log info "Filtering $(wc -l < "$subs_file") subdomains against wildcard..."

            while IFS= read -r sub; do
                ghost_rate_limit 0.05
                local sub_ip=$(dig +short A "$sub" 2>/dev/null | head -1)

                if [[ "$sub_ip" != "$wildcard_ip" && -n "$sub_ip" ]]; then
                    echo "$sub" >> "${output_dir}/non-wildcard-subs.txt"
                fi
            done < <(head -500 "$subs_file")

            if [[ -s "${output_dir}/non-wildcard-subs.txt" ]]; then
                ghost_log hit "REAL subdomains (non-wildcard): $(wc -l < "${output_dir}/non-wildcard-subs.txt")"
                ghost_log info "These resolve to DIFFERENT IPs - actual services!"
            fi
        fi

        # Also check: does the wildcard have different HTTPS response?
        local wildcard_https=$(ghost_request "https://${random_sub}")
        local wc_https_status=$(echo "$wildcard_https" | cut -d'|' -f1)
        ghost_log info "Wildcard HTTPS status: ${wc_https_status}"

        echo "wildcard_ip=${wildcard_ip}" > "${output_dir}/wildcard-info.txt"
        echo "wildcard_http_status=${wc_status}" >> "${output_dir}/wildcard-info.txt"
        echo "wildcard_http_size=${wc_size}" >> "${output_dir}/wildcard-info.txt"
        echo "wildcard_https_status=${wc_https_status}" >> "${output_dir}/wildcard-info.txt"
    else
        ghost_log info "No DNS wildcard detected - all resolved hosts are real"
        if [[ -s "$subs_file" ]]; then
            cp "$subs_file" "${output_dir}/non-wildcard-subs.txt"
        fi
    fi
}

# ============================================================
# 5. HTTP Response Clustering (find outliers)
# ============================================================
# Probe all alive hosts and fingerprint responses by:
# - status code + body size + header count + server header
# Cluster similar responses together.
# The OUTLIERS (unique responses) are the interesting targets.

ghost_response_cluster() {
    local urls_file="$1"
    local output_dir="${GHOST_OUTPUT}/discovery/clusters"
    mkdir -p "$output_dir"

    ghost_log phase "HTTP Response Clustering (Finding Outliers)"

    if [[ ! -s "$urls_file" ]]; then
        ghost_log warn "No URLs file provided"
        return
    fi

    ghost_log info "Fingerprinting $(wc -l < "$urls_file") URLs..."

    local fingerprints="${output_dir}/fingerprints.txt"
    > "$fingerprints"

    while IFS= read -r url; do
        ghost_rate_limit 0.1
        local result=$(ghost_request "$url")
        local status=$(echo "$result" | cut -d'|' -f1)
        local time=$(echo "$result" | cut -d'|' -f2)
        local size=$(echo "$result" | cut -d'|' -f3)
        local body_file=$(echo "$result" | cut -d'|' -f5)
        local header_file=$(echo "$result" | cut -d'|' -f6)

        # Get server header
        local server=$(grep -i '^server:' "$header_file" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '\r\n')

        # Compute content hash (structure, not exact content)
        local content_hash="none"
        if [[ -s "$body_file" ]]; then
            # Hash based on: line count, tag structure, key patterns
            local lines=$(wc -l < "$body_file")
            local title=$(grep -oP '(?<=<title>)[^<]+' "$body_file" 2>/dev/null | head -1)
            content_hash="${lines}:${title:-notitle}"
        fi

        # Size bucketing (group similar sizes)
        local size_bucket
        if [[ $size -lt 100 ]]; then size_bucket="tiny"
        elif [[ $size -lt 1000 ]]; then size_bucket="small"
        elif [[ $size -lt 10000 ]]; then size_bucket="medium"
        elif [[ $size -lt 100000 ]]; then size_bucket="large"
        else size_bucket="huge"
        fi

        echo "${status}|${size_bucket}|${server:-unknown}|${content_hash}|${url}" >> "$fingerprints"

        # Clean up temp files
        rm -f "$body_file" "$header_file" 2>/dev/null
    done < <(head -200 "$urls_file")

    # Cluster by fingerprint (status + size_bucket + server)
    ghost_log info "Clustering responses..."
    awk -F'|' '{key=$1"|"$2"|"$3; clusters[key]++; urls[key]=urls[key] " " $5} END {for (k in clusters) print clusters[k] "|" k "|" urls[k]}' \
        "$fingerprints" | sort -t'|' -k1 -rn > "${output_dir}/clusters.txt"

    # Find outliers (clusters with only 1-2 members)
    awk -F'|' '$1 <= 2 {print}' "${output_dir}/clusters.txt" > "${output_dir}/outliers.txt" 2>/dev/null || true

    # Find the dominant cluster
    local dominant=$(head -1 "${output_dir}/clusters.txt" | cut -d'|' -f1)

    ghost_log info "Response clusters found:"
    head -10 "${output_dir}/clusters.txt" | while IFS='|' read -r count status size_b server hash urls; do
        ghost_log info "  [${count}x] status=${status} size=${size_b} server=${server}"
    done

    if [[ -s "${output_dir}/outliers.txt" ]]; then
        ghost_log hit "OUTLIER responses (unique/interesting targets):"
        awk -F'|' '{print $5}' "${output_dir}/outliers.txt" | tr ' ' '\n' | grep -v '^$' | \
            while read -r url; do
                ghost_log hit "  → ${url}"
            done

        # Save outlier URLs for priority testing
        awk -F'|' '{print $5}' "${output_dir}/outliers.txt" | tr ' ' '\n' | grep -v '^$' | sort -u \
            > "${output_dir}/priority-targets.txt"

        ghost_log info "Priority targets saved: ${output_dir}/priority-targets.txt"
        ghost_log info "These respond DIFFERENTLY from the majority = unique apps = likely bugs"
    fi
}

# ============================================================
# 6. JARM TLS Fingerprinting
# ============================================================
# JARM creates a fingerprint of the TLS implementation.
# Same JARM = same server software/config.
# Find all hosts with matching JARM to the main target,
# then find hosts with DIFFERENT JARM (different server = interesting)

ghost_jarm_fingerprint() {
    local hosts_file="$1"
    local output_dir="${GHOST_OUTPUT}/discovery/jarm"
    mkdir -p "$output_dir"

    ghost_log phase "JARM TLS Fingerprinting"

    # Check if jarm is available (python script)
    if ! command -v python3 &>/dev/null; then
        ghost_log warn "python3 required for JARM fingerprinting"
        return
    fi

    # Create inline JARM-lite (simplified TLS hello fingerprint)
    # Full JARM requires the jarm.py script, this is a lightweight alternative
    ghost_log info "Computing TLS fingerprints..."

    while IFS= read -r host; do
        ghost_rate_limit 0.2
        local clean_host="${host#https://}"
        clean_host="${clean_host#http://}"
        clean_host="${clean_host%%/*}"
        clean_host="${clean_host%%:*}"

        # Get TLS version and cipher as lightweight fingerprint
        local tls_info
        tls_info=$(echo | timeout 5 openssl s_client -connect "${clean_host}:443" \
            -servername "$clean_host" 2>/dev/null | \
            grep -E "(Protocol|Cipher)" | head -2 | tr '\n' '|' | tr -d ' ')

        if [[ -n "$tls_info" ]]; then
            echo "${clean_host}|${tls_info}" >> "${output_dir}/tls-fingerprints.txt"
        fi
    done < <(head -100 "$hosts_file")

    if [[ -s "${output_dir}/tls-fingerprints.txt" ]]; then
        # Group by TLS fingerprint
        awk -F'|' '{fp=$2"|"$3; groups[fp]++; hosts[fp]=hosts[fp]","$1} END {for(g in groups) print groups[g]"|"g"|"hosts[g]}' \
            "${output_dir}/tls-fingerprints.txt" | sort -t'|' -k1 -rn \
            > "${output_dir}/tls-groups.txt"

        # Outliers = different TLS config = different server = interesting
        awk -F'|' '$1 <= 2' "${output_dir}/tls-groups.txt" > "${output_dir}/tls-outliers.txt" 2>/dev/null || true

        if [[ -s "${output_dir}/tls-outliers.txt" ]]; then
            ghost_log hit "TLS outliers (different server config):"
            cat "${output_dir}/tls-outliers.txt" | head -10
        fi

        ghost_log success "TLS fingerprinting complete: $(wc -l < "${output_dir}/tls-fingerprints.txt") hosts analyzed"
    fi
}

# ============================================================
# Main Discovery Runner
# ============================================================
ghost_discovery_run() {
    local target="${1:-$TARGET_DOMAIN}"
    local subs_file="${2:-}"
    local urls_file="${3:-}"

    ghost_setup "$target"
    ghost_log phase "GHOST DISCOVERY MODULE"

    # Step 1: Favicon hunting (always)
    ghost_favicon_hunt "$target"

    # Step 2: CT log diffing
    ghost_ct_diff "$target" "$subs_file"

    # Step 3: TLS correlation (needs host list)
    if [[ -n "$subs_file" && -s "$subs_file" ]]; then
        ghost_tls_correlation "$subs_file"
    fi

    # Step 4: Wildcard detection
    if [[ -n "$subs_file" && -s "$subs_file" ]]; then
        ghost_wildcard_detect "$target" "$subs_file"
    fi

    # Step 5: Response clustering (needs URL list)
    if [[ -n "$urls_file" && -s "$urls_file" ]]; then
        ghost_response_cluster "$urls_file"
    fi

    # Step 6: JARM fingerprinting
    if [[ -n "$subs_file" && -s "$subs_file" ]]; then
        ghost_jarm_fingerprint "$subs_file"
    fi

    ghost_log phase "DISCOVERY COMPLETE"
    ghost_log info "Output: ${GHOST_OUTPUT}/discovery/"
    ghost_log info "Priority targets for next phase:"
    [[ -s "${GHOST_OUTPUT}/discovery/clusters/priority-targets.txt" ]] && \
        cat "${GHOST_OUTPUT}/discovery/clusters/priority-targets.txt" | head -10
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    ghost_discovery_run "$@"
fi
