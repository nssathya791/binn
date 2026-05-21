#!/bin/bash
# ============================================================
# Phase 2: Active Reconnaissance
# ============================================================
# WARNING: This script sends traffic to the target!
# - Run ONLY from YOUR machine with YOUR IP
# - Ensure H1 headers are configured in lib/config.sh
# - Respect rate limits (max 500 req/s per program policy)
#
# Tools needed: httpx, nuclei, gowitness, tlsx, katana, dnsx
#
# Usage: ./active-recon.sh <subdomain-list.txt> [--skip-nuclei] [--skip-screenshots]
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/config.sh"

# Parse arguments
SUBDOMAIN_FILE="${1:-}"
SKIP_NUCLEI=false
SKIP_SCREENSHOTS=false

for arg in "$@"; do
    case "$arg" in
        --skip-nuclei) SKIP_NUCLEI=true ;;
        --skip-screenshots) SKIP_SCREENSHOTS=true ;;
    esac
done

if [[ -z "$SUBDOMAIN_FILE" || ! -f "$SUBDOMAIN_FILE" ]]; then
    log_error "Usage: $0 <subdomain-list.txt> [--skip-nuclei] [--skip-screenshots]"
    log_error "Provide the subdomain list from Phase 1 output."
    exit 1
fi

validate_config
setup_output

RUN_DIR="${PHASE2_OUTPUT}/${TIMESTAMP}"
mkdir -p "${RUN_DIR}"/{httpx,nuclei,screenshots,tech,dns,katana}

log_section "Phase 2: Active Reconnaissance"
log_info "Input: ${SUBDOMAIN_FILE} ($(wc -l < "$SUBDOMAIN_FILE") subdomains)"
log_info "Output: ${RUN_DIR}"
log_info "Rate limit: ${RATE_LIMIT} req/s"
log_info "H1 Header: ${H1_HEADER}"
echo ""
log_warn "=== ACTIVE TRAFFIC WARNING ==="
log_warn "This script sends requests to Wells Fargo infrastructure."
log_warn "Your IP: ${TESTING_IP}"
log_warn "Header: ${H1_HEADER}"
log_warn "Starting in 5 seconds... Ctrl+C to abort."
sleep 5

# ============================================================
# 1. DNS Resolution (filter to alive hosts)
# ============================================================
log_section "1. DNS Resolution"

if check_tool "dnsx"; then
    log_info "Resolving DNS for all subdomains..."
    dnsx -l "$SUBDOMAIN_FILE" -silent -a -resp \
        -rate-limit "$RATE_LIMIT" \
        -o "${RUN_DIR}/dns/resolved.txt" 2>/dev/null || true

    # Extract just the hostnames that resolve
    cat "${RUN_DIR}/dns/resolved.txt" | awk '{print $1}' | sort -u \
        > "${RUN_DIR}/dns/alive-hosts.txt" 2>/dev/null || true

    if [[ -s "${RUN_DIR}/dns/alive-hosts.txt" ]]; then
        WORKING_LIST="${RUN_DIR}/dns/alive-hosts.txt"
        log_success "DNS resolved: $(wc -l < "$WORKING_LIST") alive hosts"
    else
        WORKING_LIST="$SUBDOMAIN_FILE"
        log_warn "dnsx produced no output, using full list"
    fi

    # Check for CNAME records (useful for subdomain takeover)
    log_info "Checking CNAME records..."
    dnsx -l "$SUBDOMAIN_FILE" -silent -cname -resp \
        -rate-limit "$RATE_LIMIT" \
        -o "${RUN_DIR}/dns/cnames.txt" 2>/dev/null || true

    if [[ -s "${RUN_DIR}/dns/cnames.txt" ]]; then
        log_success "CNAME records found: $(wc -l < "${RUN_DIR}/dns/cnames.txt")"
        # Flag potential takeovers (CNAME to external services)
        grep -iE '(amazonaws|azurewebsites|cloudfront|fastly|github\.io|herokuapp|pantheon|shopify|surge\.sh|tumblr|wordpress|zendesk|unbounce|helpjuice|helpscout|ghost\.io|cargocollective|statuspage|bitbucket|squarespace|feedpress|ghost\.io|freshdesk|readme\.io)' \
            "${RUN_DIR}/dns/cnames.txt" > "${RUN_DIR}/dns/potential-takeovers.txt" 2>/dev/null || true
        if [[ -s "${RUN_DIR}/dns/potential-takeovers.txt" ]]; then
            log_success "POTENTIAL SUBDOMAIN TAKEOVERS: $(wc -l < "${RUN_DIR}/dns/potential-takeovers.txt")"
            cat "${RUN_DIR}/dns/potential-takeovers.txt"
        fi
    fi
else
    log_warn "dnsx not installed, using full subdomain list"
    WORKING_LIST="$SUBDOMAIN_FILE"
fi

# ============================================================
# 2. HTTP Probing (httpx)
# ============================================================
log_section "2. HTTP Probing (httpx)"

if check_tool "httpx"; then
    log_info "Probing HTTP/HTTPS services..."

    httpx -l "$WORKING_LIST" \
        -H "${H1_HEADER}" \
        -H "${TOOL_HEADER_PREFIX}: httpx" \
        -silent \
        -threads "$HTTPX_THREADS" \
        -rate-limit "$RATE_LIMIT" \
        -status-code \
        -title \
        -tech-detect \
        -content-length \
        -web-server \
        -cdn \
        -ip \
        -follow-redirects \
        -random-agent \
        -o "${RUN_DIR}/httpx/full-probe.txt" \
        -json -o "${RUN_DIR}/httpx/full-probe.json" \
        2>/dev/null || true

    if [[ -s "${RUN_DIR}/httpx/full-probe.txt" ]]; then
        log_success "HTTP alive: $(wc -l < "${RUN_DIR}/httpx/full-probe.txt") hosts"

        # Extract just URLs for other tools
        cat "${RUN_DIR}/httpx/full-probe.json" 2>/dev/null | \
            jq -r '.url' 2>/dev/null | sort -u \
            > "${RUN_DIR}/httpx/alive-urls.txt" || \
            awk '{print $1}' "${RUN_DIR}/httpx/full-probe.txt" | sort -u \
            > "${RUN_DIR}/httpx/alive-urls.txt"

        # Separate by status code for prioritization
        grep -E '\[200\]' "${RUN_DIR}/httpx/full-probe.txt" \
            > "${RUN_DIR}/httpx/status-200.txt" 2>/dev/null || true
        grep -E '\[30[0-9]\]' "${RUN_DIR}/httpx/full-probe.txt" \
            > "${RUN_DIR}/httpx/status-3xx.txt" 2>/dev/null || true
        grep -E '\[40[0-3]\]' "${RUN_DIR}/httpx/full-probe.txt" \
            > "${RUN_DIR}/httpx/status-4xx.txt" 2>/dev/null || true
        grep -E '\[50[0-9]\]' "${RUN_DIR}/httpx/full-probe.txt" \
            > "${RUN_DIR}/httpx/status-5xx.txt" 2>/dev/null || true

        # Flag interesting responses
        # 401/403 = auth-protected (try bypass later)
        # 500+ = error handling issues
        log_info "Status 200: $(wc -l < "${RUN_DIR}/httpx/status-200.txt" 2>/dev/null || echo 0)"
        log_info "Status 3xx: $(wc -l < "${RUN_DIR}/httpx/status-3xx.txt" 2>/dev/null || echo 0)"
        log_info "Status 4xx: $(wc -l < "${RUN_DIR}/httpx/status-4xx.txt" 2>/dev/null || echo 0)"
        log_info "Status 5xx: $(wc -l < "${RUN_DIR}/httpx/status-5xx.txt" 2>/dev/null || echo 0)"

        # Extract technologies detected
        if [[ -s "${RUN_DIR}/httpx/full-probe.json" ]]; then
            jq -r 'select(.tech != null) | "\(.url) -> \(.tech | join(", "))"' \
                "${RUN_DIR}/httpx/full-probe.json" \
                > "${RUN_DIR}/tech/technologies.txt" 2>/dev/null || true
            log_info "Tech detection saved to tech/technologies.txt"
        fi
    else
        log_error "httpx produced no output. Check network connectivity."
    fi
else
    log_error "httpx is required for Phase 2. Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    exit 1
fi

# ============================================================
# 3. TLS Certificate Analysis
# ============================================================
log_section "3. TLS Certificate Analysis"

if check_tool "tlsx"; then
    log_info "Grabbing TLS certificates..."
    tlsx -l "$WORKING_LIST" \
        -silent \
        -san -cn -so -wc \
        -rate-limit "$RATE_LIMIT" \
        -o "${RUN_DIR}/tech/tls-info.txt" 2>/dev/null || true

    if [[ -s "${RUN_DIR}/tech/tls-info.txt" ]]; then
        log_success "TLS info collected for $(wc -l < "${RUN_DIR}/tech/tls-info.txt") hosts"
        # Extract SANs for additional subdomain discovery
        grep -oP '(?<=\[)[^\]]+' "${RUN_DIR}/tech/tls-info.txt" 2>/dev/null | \
            tr ',' '\n' | sed 's/ //g' | grep -i "wellsfargo" | sort -u \
            > "${RUN_DIR}/tech/tls-sans-new-subs.txt" || true
        if [[ -s "${RUN_DIR}/tech/tls-sans-new-subs.txt" ]]; then
            log_success "New subdomains from TLS SANs: $(wc -l < "${RUN_DIR}/tech/tls-sans-new-subs.txt")"
        fi
    fi
else
    log_warn "tlsx not installed, skipping TLS analysis"
fi

# ============================================================
# 4. Screenshots (gowitness)
# ============================================================
if [[ "$SKIP_SCREENSHOTS" == false ]]; then
    log_section "4. Screenshots (gowitness)"

    if check_tool "gowitness"; then
        if [[ -s "${RUN_DIR}/httpx/alive-urls.txt" ]]; then
            log_info "Taking screenshots of alive hosts..."
            gowitness file \
                -f "${RUN_DIR}/httpx/alive-urls.txt" \
                --screenshot-path "${RUN_DIR}/screenshots" \
                --threads 5 \
                --timeout 15 \
                --header "${H1_HEADER}" \
                --header "${TOOL_HEADER_PREFIX}: gowitness" \
                2>/dev/null || true
            log_success "Screenshots saved to: ${RUN_DIR}/screenshots/"
        fi
    else
        log_warn "gowitness not installed, skipping screenshots"
        log_info "Alternative: use aquatone or eyewitness"
    fi
else
    log_warn "Screenshots skipped (--skip-screenshots)"
fi

# ============================================================
# 5. Web Crawling (katana) - find hidden endpoints
# ============================================================
log_section "5. Web Crawling (katana)"

if check_tool "katana"; then
    if [[ -s "${RUN_DIR}/httpx/alive-urls.txt" ]]; then
        # Only crawl top interesting targets (not the full list)
        # Priority: non-CDN, 200 status, interesting tech
        CRAWL_TARGETS="${RUN_DIR}/katana/crawl-targets.txt"

        # Take top 50 most interesting hosts for crawling
        head -50 "${RUN_DIR}/httpx/alive-urls.txt" > "$CRAWL_TARGETS"

        log_info "Crawling top $(wc -l < "$CRAWL_TARGETS") targets for endpoints..."
        katana -list "$CRAWL_TARGETS" \
            -H "${H1_HEADER}" \
            -H "${TOOL_HEADER_PREFIX}: katana" \
            -silent \
            -depth 3 \
            -js-crawl \
            -known-files all \
            -rate-limit "$RATE_LIMIT" \
            -concurrency 10 \
            -o "${RUN_DIR}/katana/crawl-results.txt" \
            2>/dev/null || true

        if [[ -s "${RUN_DIR}/katana/crawl-results.txt" ]]; then
            log_success "Katana found $(wc -l < "${RUN_DIR}/katana/crawl-results.txt") endpoints"

            # Extract JS files for later analysis
            grep -iE '\.js(\?|$)' "${RUN_DIR}/katana/crawl-results.txt" | sort -u \
                > "${RUN_DIR}/katana/js-files.txt" 2>/dev/null || true

            # Extract API endpoints
            grep -iE '(/api/|/v[0-9]/|/graphql|/rest/|/services/)' \
                "${RUN_DIR}/katana/crawl-results.txt" | sort -u \
                > "${RUN_DIR}/katana/api-endpoints.txt" 2>/dev/null || true

            # Extract potentially sensitive paths
            grep -iE '(admin|dashboard|panel|config|internal|debug|swagger|openapi|graphql|actuator|health|metrics|env|\.git|\.env|backup|upload|download)' \
                "${RUN_DIR}/katana/crawl-results.txt" | sort -u \
                > "${RUN_DIR}/katana/sensitive-paths.txt" 2>/dev/null || true

            [[ -s "${RUN_DIR}/katana/js-files.txt" ]] && \
                log_success "JS files found: $(wc -l < "${RUN_DIR}/katana/js-files.txt")"
            [[ -s "${RUN_DIR}/katana/api-endpoints.txt" ]] && \
                log_success "API endpoints: $(wc -l < "${RUN_DIR}/katana/api-endpoints.txt")"
            [[ -s "${RUN_DIR}/katana/sensitive-paths.txt" ]] && \
                log_success "Sensitive paths: $(wc -l < "${RUN_DIR}/katana/sensitive-paths.txt")"
        fi
    fi
else
    log_warn "katana not installed, skipping crawling"
fi

# ============================================================
# 6. Nuclei Scanning (vulnerability detection)
# ============================================================
if [[ "$SKIP_NUCLEI" == false ]]; then
    log_section "6. Nuclei Vulnerability Scanning"

    if check_tool "nuclei"; then
        if [[ -s "${RUN_DIR}/httpx/alive-urls.txt" ]]; then
            NUCLEI_TARGETS="${RUN_DIR}/httpx/alive-urls.txt"
            CUSTOM_TEMPLATES="${SCRIPT_DIR}/../nuclei-templates"

            log_info "Running nuclei (rate: ${NUCLEI_RATE_LIMIT} req/s)..."
            log_info "This may take a while depending on target count..."

            # Run 1: Custom high-value templates first
            if [[ -d "$CUSTOM_TEMPLATES" && "$(ls -A "$CUSTOM_TEMPLATES" 2>/dev/null)" ]]; then
                log_info "Running custom templates..."
                nuclei -l "$NUCLEI_TARGETS" \
                    -t "$CUSTOM_TEMPLATES" \
                    -H "${H1_HEADER}" \
                    -H "${TOOL_HEADER_PREFIX}: nuclei" \
                    -rl "$NUCLEI_RATE_LIMIT" \
                    -c 25 \
                    -severity medium,high,critical \
                    -o "${RUN_DIR}/nuclei/custom-findings.txt" \
                    -json -o "${RUN_DIR}/nuclei/custom-findings.json" \
                    2>/dev/null || true

                if [[ -s "${RUN_DIR}/nuclei/custom-findings.txt" ]]; then
                    log_success "CUSTOM TEMPLATE FINDINGS: $(wc -l < "${RUN_DIR}/nuclei/custom-findings.txt")"
                fi
            fi

            # Run 2: Subdomain takeover checks
            log_info "Checking for subdomain takeovers..."
            nuclei -l "$NUCLEI_TARGETS" \
                -t takeovers/ \
                -H "${H1_HEADER}" \
                -H "${TOOL_HEADER_PREFIX}: nuclei" \
                -rl "$NUCLEI_RATE_LIMIT" \
                -c 25 \
                -o "${RUN_DIR}/nuclei/takeover-findings.txt" \
                2>/dev/null || true

            if [[ -s "${RUN_DIR}/nuclei/takeover-findings.txt" ]]; then
                log_success "SUBDOMAIN TAKEOVER FINDINGS: $(wc -l < "${RUN_DIR}/nuclei/takeover-findings.txt")"
            fi

            # Run 3: Exposed panels, configs, and misconfigurations
            log_info "Checking for exposed panels and misconfigs..."
            nuclei -l "$NUCLEI_TARGETS" \
                -t exposures/ -t misconfiguration/ -t exposed-panels/ \
                -H "${H1_HEADER}" \
                -H "${TOOL_HEADER_PREFIX}: nuclei" \
                -rl "$NUCLEI_RATE_LIMIT" \
                -c 25 \
                -severity medium,high,critical \
                -o "${RUN_DIR}/nuclei/exposure-findings.txt" \
                -json -o "${RUN_DIR}/nuclei/exposure-findings.json" \
                2>/dev/null || true

            if [[ -s "${RUN_DIR}/nuclei/exposure-findings.txt" ]]; then
                log_success "EXPOSURE FINDINGS: $(wc -l < "${RUN_DIR}/nuclei/exposure-findings.txt")"
            fi

            # Run 4: Known CVEs (high/critical only)
            log_info "Checking for known CVEs (high/critical)..."
            nuclei -l "$NUCLEI_TARGETS" \
                -t cves/ \
                -H "${H1_HEADER}" \
                -H "${TOOL_HEADER_PREFIX}: nuclei" \
                -rl "$NUCLEI_RATE_LIMIT" \
                -c 25 \
                -severity high,critical \
                -o "${RUN_DIR}/nuclei/cve-findings.txt" \
                -json -o "${RUN_DIR}/nuclei/cve-findings.json" \
                2>/dev/null || true

            if [[ -s "${RUN_DIR}/nuclei/cve-findings.txt" ]]; then
                log_success "CVE FINDINGS: $(wc -l < "${RUN_DIR}/nuclei/cve-findings.txt")"
            fi

            # Run 5: Technology-specific checks
            log_info "Running technology-specific checks..."
            nuclei -l "$NUCLEI_TARGETS" \
                -t technologies/ \
                -H "${H1_HEADER}" \
                -H "${TOOL_HEADER_PREFIX}: nuclei" \
                -rl "$NUCLEI_RATE_LIMIT" \
                -c 25 \
                -o "${RUN_DIR}/nuclei/tech-findings.txt" \
                2>/dev/null || true

            # Consolidate all findings
            cat "${RUN_DIR}/nuclei/"*-findings.txt 2>/dev/null | sort -u \
                > "${RUN_DIR}/nuclei/all-findings.txt" || true
            if [[ -s "${RUN_DIR}/nuclei/all-findings.txt" ]]; then
                log_success "TOTAL NUCLEI FINDINGS: $(wc -l < "${RUN_DIR}/nuclei/all-findings.txt")"
            else
                log_info "No nuclei findings (clean scan or all filtered)"
            fi
        fi
    else
        log_error "nuclei not installed. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    fi
else
    log_warn "Nuclei skipped (--skip-nuclei)"
fi

# ============================================================
# 7. Summary & Prioritization
# ============================================================
log_section "PHASE 2 RESULTS SUMMARY"

echo ""
echo "=== Asset Inventory ==="
[[ -s "${RUN_DIR}/dns/alive-hosts.txt" ]] && \
    echo "  DNS resolved hosts:     $(wc -l < "${RUN_DIR}/dns/alive-hosts.txt")"
[[ -s "${RUN_DIR}/httpx/alive-urls.txt" ]] && \
    echo "  HTTP alive URLs:        $(wc -l < "${RUN_DIR}/httpx/alive-urls.txt")"
[[ -s "${RUN_DIR}/httpx/status-200.txt" ]] && \
    echo "  Status 200 (active):    $(wc -l < "${RUN_DIR}/httpx/status-200.txt")"
[[ -s "${RUN_DIR}/httpx/status-4xx.txt" ]] && \
    echo "  Status 4xx (auth-gated):$(wc -l < "${RUN_DIR}/httpx/status-4xx.txt")"

echo ""
echo "=== High-Priority Findings ==="
[[ -s "${RUN_DIR}/dns/potential-takeovers.txt" ]] && \
    echo "  Potential takeovers:    $(wc -l < "${RUN_DIR}/dns/potential-takeovers.txt") *** CHECK THESE ***"
[[ -s "${RUN_DIR}/nuclei/all-findings.txt" ]] && \
    echo "  Nuclei findings:        $(wc -l < "${RUN_DIR}/nuclei/all-findings.txt")"
[[ -s "${RUN_DIR}/katana/api-endpoints.txt" ]] && \
    echo "  API endpoints found:    $(wc -l < "${RUN_DIR}/katana/api-endpoints.txt")"
[[ -s "${RUN_DIR}/katana/sensitive-paths.txt" ]] && \
    echo "  Sensitive paths:        $(wc -l < "${RUN_DIR}/katana/sensitive-paths.txt")"

echo ""
echo "=== Discovery ==="
[[ -s "${RUN_DIR}/tech/tls-sans-new-subs.txt" ]] && \
    echo "  New subs from TLS SANs: $(wc -l < "${RUN_DIR}/tech/tls-sans-new-subs.txt")"
[[ -s "${RUN_DIR}/katana/js-files.txt" ]] && \
    echo "  JS files for analysis:  $(wc -l < "${RUN_DIR}/katana/js-files.txt")"

echo ""
log_info "Full output: ${RUN_DIR}"
log_info "Next: Review findings, then run Phase 3 manual testing on priority targets"
echo ""
log_warn "PRIORITY ORDER FOR PHASE 3:"
log_warn "1. Subdomain takeovers (instant bounty if valid)"
log_warn "2. Nuclei critical/high findings (verify manually)"
log_warn "3. API endpoints with auth bypass potential"
log_warn "4. Sensitive paths (admin panels, configs)"
log_warn "5. 403 endpoints (try bypass techniques)"
log_warn "6. JS files (mine for secrets, hidden endpoints)"
