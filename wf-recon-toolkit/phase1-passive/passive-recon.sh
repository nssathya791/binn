#!/bin/bash
# ============================================================
# Phase 1: Passive Reconnaissance
# ============================================================
# This script collects subdomains and intelligence WITHOUT
# sending any traffic to the target. Safe to run anywhere.
#
# Tools needed: subfinder, amass, jq, curl, gau, waybackurls,
#               github-subdomains (optional), dnsx (optional)
#
# Usage: ./passive-recon.sh [--quick]
#   --quick  Skip slow sources (amass, wayback full)
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/config.sh"

# Parse args
QUICK_MODE=false
[[ "${1:-}" == "--quick" ]] && QUICK_MODE=true

validate_config
setup_output

RUN_DIR="${PHASE1_OUTPUT}/${TIMESTAMP}"
mkdir -p "$RUN_DIR"

log_section "Phase 1: Passive Reconnaissance"
log_info "Target: ${TARGET_DOMAIN}"
log_info "Output: ${RUN_DIR}"
[[ "$QUICK_MODE" == true ]] && log_warn "Quick mode enabled - skipping slow sources"

# Master subdomain file
SUBS_MASTER="${RUN_DIR}/subdomains-all.txt"
touch "$SUBS_MASTER"

# ============================================================
# 1. Certificate Transparency Logs (crt.sh)
# ============================================================
log_section "1. Certificate Transparency (crt.sh)"

crtsh_collect() {
    local domain="$1"
    local output="${RUN_DIR}/crtsh-${domain}.json"

    log_info "Querying crt.sh for %.${domain}..."
    curl -s "https://crt.sh/?q=%25.${domain}&output=json" \
        --max-time 60 \
        -o "$output" 2>/dev/null || true

    if [[ -f "$output" && -s "$output" ]]; then
        # Extract unique subdomains, handle wildcards and newlines in CN
        jq -r '.[].name_value' "$output" 2>/dev/null | \
            sed 's/\*\.//g' | \
            tr '[:upper:]' '[:lower:]' | \
            sort -u >> "$SUBS_MASTER"
        local count=$(jq -r '.[].name_value' "$output" 2>/dev/null | sed 's/\*\.//g' | sort -u | wc -l)
        log_success "crt.sh (${domain}): ${count} subdomains"
    else
        log_warn "crt.sh returned empty/error for ${domain}"
    fi
}

crtsh_collect "$TARGET_DOMAIN"
for domain in "${ADDITIONAL_DOMAINS[@]}"; do
    # Strip wildcard prefix
    clean_domain="${domain#\*.}"
    crtsh_collect "$clean_domain"
done

# ============================================================
# 2. Subfinder (passive sources aggregator)
# ============================================================
log_section "2. Subfinder"

if check_tool "subfinder"; then
    log_info "Running subfinder for ${TARGET_DOMAIN}..."
    subfinder -d "$TARGET_DOMAIN" -silent -all \
        -o "${RUN_DIR}/subfinder.txt" 2>/dev/null || true

    if [[ -f "${RUN_DIR}/subfinder.txt" ]]; then
        cat "${RUN_DIR}/subfinder.txt" >> "$SUBS_MASTER"
        log_success "Subfinder: $(wc -l < "${RUN_DIR}/subfinder.txt") subdomains"
    fi
else
    log_warn "subfinder not installed, skipping"
fi

# ============================================================
# 3. Amass Passive (slow but thorough)
# ============================================================
if [[ "$QUICK_MODE" == false ]]; then
    log_section "3. Amass (passive mode)"

    if check_tool "amass"; then
        log_info "Running amass enum -passive (this may take 5-15 min)..."
        timeout 900 amass enum -passive -d "$TARGET_DOMAIN" \
            -o "${RUN_DIR}/amass.txt" 2>/dev/null || true

        if [[ -f "${RUN_DIR}/amass.txt" ]]; then
            cat "${RUN_DIR}/amass.txt" >> "$SUBS_MASTER"
            log_success "Amass: $(wc -l < "${RUN_DIR}/amass.txt") subdomains"
        fi
    else
        log_warn "amass not installed, skipping"
    fi
else
    log_warn "Skipping amass (quick mode)"
fi

# ============================================================
# 4. Chaos (ProjectDiscovery - pre-aggregated data)
# ============================================================
log_section "4. Chaos ProjectDiscovery"

if [[ -n "$CHAOS_API_KEY" ]]; then
    if check_tool "chaos"; then
        log_info "Querying chaos for ${TARGET_DOMAIN}..."
        chaos -d "$TARGET_DOMAIN" -key "$CHAOS_API_KEY" -silent \
            -o "${RUN_DIR}/chaos.txt" 2>/dev/null || true

        if [[ -f "${RUN_DIR}/chaos.txt" ]]; then
            cat "${RUN_DIR}/chaos.txt" >> "$SUBS_MASTER"
            log_success "Chaos: $(wc -l < "${RUN_DIR}/chaos.txt") subdomains"
        fi
    else
        log_warn "chaos client not installed, skipping"
    fi
else
    log_warn "CHAOS_API_KEY not set, skipping (free at chaos.projectdiscovery.io)"
fi

# ============================================================
# 5. Wayback Machine / CommonCrawl URLs
# ============================================================
log_section "5. Wayback Machine & CommonCrawl"

# Using gau (GetAllURLs) - pulls from Wayback, CommonCrawl, OTX, URLScan
if check_tool "gau"; then
    log_info "Running gau for ${TARGET_DOMAIN}..."
    echo "$TARGET_DOMAIN" | gau --subs --threads 5 \
        --o "${RUN_DIR}/gau-urls.txt" 2>/dev/null || \
    echo "$TARGET_DOMAIN" | gau --subs \
        > "${RUN_DIR}/gau-urls.txt" 2>/dev/null || true

    if [[ -f "${RUN_DIR}/gau-urls.txt" && -s "${RUN_DIR}/gau-urls.txt" ]]; then
        # Extract subdomains from URLs
        cat "${RUN_DIR}/gau-urls.txt" | \
            unfurl -u domains 2>/dev/null >> "$SUBS_MASTER" || \
            grep -oP 'https?://\K[^/]+' "${RUN_DIR}/gau-urls.txt" | \
            sort -u >> "$SUBS_MASTER"

        log_success "GAU: $(wc -l < "${RUN_DIR}/gau-urls.txt") URLs collected"

        # Extract interesting parameters and paths for later
        if check_tool "unfurl"; then
            cat "${RUN_DIR}/gau-urls.txt" | unfurl -u keys 2>/dev/null | \
                sort | uniq -c | sort -rn > "${RUN_DIR}/gau-params.txt" || true
            log_info "Extracted parameter names -> gau-params.txt"
        fi

        # Filter for potentially interesting files
        grep -iE '\.(js|json|xml|config|env|bak|old|sql|zip|tar|gz|log|txt|csv|xlsx)' \
            "${RUN_DIR}/gau-urls.txt" > "${RUN_DIR}/gau-interesting-files.txt" 2>/dev/null || true
        if [[ -s "${RUN_DIR}/gau-interesting-files.txt" ]]; then
            log_success "Found $(wc -l < "${RUN_DIR}/gau-interesting-files.txt") potentially interesting file URLs"
        fi
    fi
elif check_tool "waybackurls"; then
    log_info "Running waybackurls for ${TARGET_DOMAIN}..."
    echo "$TARGET_DOMAIN" | waybackurls > "${RUN_DIR}/wayback-urls.txt" 2>/dev/null || true
    if [[ -f "${RUN_DIR}/wayback-urls.txt" ]]; then
        grep -oP 'https?://\K[^/]+' "${RUN_DIR}/wayback-urls.txt" | \
            sort -u >> "$SUBS_MASTER"
        log_success "Waybackurls: $(wc -l < "${RUN_DIR}/wayback-urls.txt") URLs"
    fi
else
    log_warn "Neither gau nor waybackurls installed, skipping"
fi

# ============================================================
# 6. SecurityTrails API (DNS history)
# ============================================================
log_section "6. SecurityTrails"

if [[ -n "$SECURITYTRAILS_API_KEY" ]]; then
    log_info "Querying SecurityTrails for ${TARGET_DOMAIN}..."
    curl -s "https://api.securitytrails.com/v1/domain/${TARGET_DOMAIN}/subdomains?children_only=false" \
        -H "APIKEY: ${SECURITYTRAILS_API_KEY}" \
        --max-time 30 \
        -o "${RUN_DIR}/securitytrails.json" 2>/dev/null || true

    if [[ -f "${RUN_DIR}/securitytrails.json" && -s "${RUN_DIR}/securitytrails.json" ]]; then
        jq -r '.subdomains[]' "${RUN_DIR}/securitytrails.json" 2>/dev/null | \
            sed "s/$/.${TARGET_DOMAIN}/" >> "$SUBS_MASTER"
        local count=$(jq -r '.subdomains[]' "${RUN_DIR}/securitytrails.json" 2>/dev/null | wc -l)
        log_success "SecurityTrails: ${count} subdomains"
    fi
else
    log_warn "SECURITYTRAILS_API_KEY not set, skipping"
fi

# ============================================================
# 7. VirusTotal Passive DNS
# ============================================================
log_section "7. VirusTotal"

if [[ -n "$VT_API_KEY" ]]; then
    log_info "Querying VirusTotal for ${TARGET_DOMAIN}..."
    curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=${VT_API_KEY}&domain=${TARGET_DOMAIN}" \
        --max-time 30 \
        -o "${RUN_DIR}/virustotal.json" 2>/dev/null || true

    if [[ -f "${RUN_DIR}/virustotal.json" && -s "${RUN_DIR}/virustotal.json" ]]; then
        jq -r '.subdomains[]?' "${RUN_DIR}/virustotal.json" 2>/dev/null >> "$SUBS_MASTER" || true
        log_success "VirusTotal: done"
    fi
else
    log_warn "VT_API_KEY not set, skipping"
fi

# ============================================================
# 8. Shodan (passive - org/ASN lookup)
# ============================================================
log_section "8. Shodan Queries"

if [[ -n "$SHODAN_API_KEY" ]]; then
    log_info "Querying Shodan for Wells Fargo assets..."

    # Search by SSL cert CN
    curl -s "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=ssl.cert.subject.cn:wellsfargo.com&facets=port" \
        --max-time 30 \
        -o "${RUN_DIR}/shodan-ssl.json" 2>/dev/null || true

    # Search by org name
    curl -s "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=org:\"Wells+Fargo\"&facets=port,product" \
        --max-time 30 \
        -o "${RUN_DIR}/shodan-org.json" 2>/dev/null || true

    if [[ -f "${RUN_DIR}/shodan-ssl.json" ]]; then
        jq -r '.matches[]?.hostnames[]?' "${RUN_DIR}/shodan-ssl.json" 2>/dev/null | \
            grep -i "wellsfargo" >> "$SUBS_MASTER" || true
        log_success "Shodan SSL search: done"
    fi

    # Extract IPs for later port scanning context
    jq -r '.matches[]?.ip_str' "${RUN_DIR}/shodan-org.json" 2>/dev/null | \
        sort -u > "${RUN_DIR}/shodan-ips.txt" || true
    log_info "Shodan IPs saved to shodan-ips.txt"
else
    log_warn "SHODAN_API_KEY not set. Manual queries you can run:"
    echo "  - https://www.shodan.io/search?query=ssl.cert.subject.cn%3Awellsfargo.com"
    echo "  - https://www.shodan.io/search?query=org%3A%22Wells+Fargo%22"
    echo "  - https://www.shodan.io/search?query=hostname%3Awellsfargo.com"
fi

# ============================================================
# 9. GitHub Dorking
# ============================================================
log_section "9. GitHub Dorking"

GITHUB_DORKS_FILE="${RUN_DIR}/github-dorks.txt"
cat > "$GITHUB_DORKS_FILE" << 'EOF'
# GitHub search dorks for Wells Fargo assets
# Run these manually at https://github.com/search or use github-subdomains tool
# Each line is a search query - use GitHub code search

"wellsfargo.com" password
"wellsfargo.com" api_key
"wellsfargo.com" apikey
"wellsfargo.com" secret
"wellsfargo.com" token
"wellsfargo.com" AWS_ACCESS_KEY
"wellsfargo.com" authorization
"wellsfargo.com" internal
"connect.secure.wellsfargo.com"
"wellsfargo.com" jdbc
"wellsfargo.com" smtp
"wellsfargo" extension:env
"wellsfargo" extension:yml password
"wellsfargo" extension:json api
"wellsfargo" extension:properties
"wellsfargo.com" filename:.env
"wellsfargo.com" filename:config
"wellsfargo.com" filename:credentials
"wellsfargo" "BEGIN RSA PRIVATE KEY"
"wellsfargo" "BEGIN OPENSSH PRIVATE KEY"
site:wellsfargo.com filetype:pdf
org:wellsfargo
EOF

if [[ -n "$GITHUB_TOKEN" ]]; then
    if check_tool "github-subdomains"; then
        log_info "Running github-subdomains..."
        github-subdomains -d "$TARGET_DOMAIN" -t "$GITHUB_TOKEN" \
            -o "${RUN_DIR}/github-subs.txt" 2>/dev/null || true
        if [[ -f "${RUN_DIR}/github-subs.txt" ]]; then
            cat "${RUN_DIR}/github-subs.txt" >> "$SUBS_MASTER"
            log_success "GitHub subdomains: $(wc -l < "${RUN_DIR}/github-subs.txt")"
        fi
    else
        log_warn "github-subdomains tool not found"
    fi
else
    log_warn "GITHUB_TOKEN not set. Manual dorks saved to: github-dorks.txt"
fi

log_info "GitHub dorks file: ${GITHUB_DORKS_FILE}"

# ============================================================
# 10. Additional passive sources
# ============================================================
log_section "10. Additional Sources"

# AlienVault OTX
log_info "Querying AlienVault OTX..."
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/${TARGET_DOMAIN}/passive_dns" \
    --max-time 30 2>/dev/null | \
    jq -r '.passive_dns[]?.hostname' 2>/dev/null | \
    grep -i "wellsfargo" >> "$SUBS_MASTER" || true

# HackerTarget
log_info "Querying HackerTarget..."
curl -s "https://api.hackertarget.com/hostsearch/?q=${TARGET_DOMAIN}" \
    --max-time 30 2>/dev/null | \
    cut -d',' -f1 >> "$SUBS_MASTER" || true

# ThreatCrowd
log_info "Querying ThreatCrowd..."
curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=${TARGET_DOMAIN}" \
    --max-time 30 2>/dev/null | \
    jq -r '.subdomains[]?' 2>/dev/null >> "$SUBS_MASTER" || true

# Rapiddns
log_info "Querying RapidDNS..."
curl -s "https://rapiddns.io/subdomain/${TARGET_DOMAIN}?full=1" \
    --max-time 30 2>/dev/null | \
    grep -oP '<td>\K[a-zA-Z0-9.-]+\.wellsfargo\.com' >> "$SUBS_MASTER" || true

# ============================================================
# Final Processing
# ============================================================
log_section "Final Processing"

# Deduplicate master list
dedup_file "$SUBS_MASTER"

# Filter only in-scope domains
grep -iE '\.wellsfargo\.com$|\.wf\.com$|\.wellsfargoadvisors\.com$|\.mworld\.com$|\.advisor-connection\.com$' \
    "$SUBS_MASTER" > "${RUN_DIR}/subdomains-inscope.txt" 2>/dev/null || true

# Separate paid vs rep-only targets
grep -iE '\.wellsfargo\.com$' "${RUN_DIR}/subdomains-inscope.txt" \
    > "${RUN_DIR}/subdomains-paid.txt" 2>/dev/null || true

grep -ivE '\.wellsfargo\.com$' "${RUN_DIR}/subdomains-inscope.txt" \
    > "${RUN_DIR}/subdomains-reponly.txt" 2>/dev/null || true

# Look for interesting subdomain patterns
log_info "Flagging interesting subdomains..."
grep -iE '(dev|stage|staging|test|uat|qa|sandbox|internal|admin|portal|api|vpn|remote|citrix|owa|exchange|jenkins|gitlab|jira|confluence|grafana|kibana|elastic|mongo|redis|mysql|postgres|backup|old|legacy|beta|alpha|demo|training|temp|tmp)' \
    "${RUN_DIR}/subdomains-paid.txt" > "${RUN_DIR}/subdomains-interesting.txt" 2>/dev/null || true

# Summary
echo ""
log_section "RESULTS SUMMARY"
echo ""
log_success "Total unique subdomains: $(wc -l < "$SUBS_MASTER")"
[[ -f "${RUN_DIR}/subdomains-paid.txt" ]] && \
    log_success "Paid scope (*.wellsfargo.com): $(wc -l < "${RUN_DIR}/subdomains-paid.txt")"
[[ -f "${RUN_DIR}/subdomains-reponly.txt" ]] && \
    log_info "Rep-only scope: $(wc -l < "${RUN_DIR}/subdomains-reponly.txt")"
[[ -f "${RUN_DIR}/subdomains-interesting.txt" ]] && \
    log_success "Interesting (dev/stage/admin/api): $(wc -l < "${RUN_DIR}/subdomains-interesting.txt")"
[[ -f "${RUN_DIR}/gau-urls.txt" ]] && \
    log_info "Historical URLs collected: $(wc -l < "${RUN_DIR}/gau-urls.txt")"
[[ -f "${RUN_DIR}/gau-interesting-files.txt" ]] && \
    log_success "Interesting file URLs: $(wc -l < "${RUN_DIR}/gau-interesting-files.txt")"

echo ""
log_info "Output directory: ${RUN_DIR}"
log_info "Next step: Run phase2-active/active-recon.sh with the subdomain list"
echo ""
log_warn "REMINDER: Phase 2 sends traffic to the target."
log_warn "Ensure you have your H1 headers configured and run from YOUR machine."
