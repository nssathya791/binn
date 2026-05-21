#!/bin/bash
# ============================================================
# GHOST RECON - Main Orchestrator
# ============================================================
# The unified runner that chains all modules together.
#
# Usage:
#   ./ghost-hunt.sh <target-domain> [options]
#
# Options:
#   --subs <file>       Known subdomain list (from Phase 1)
#   --urls <file>       Alive URLs list (from Phase 2 httpx)
#   --js <file>         JS files list (from Phase 2 katana)
#   --endpoints <file>  API endpoints list
#   --auth <token>      Auth token for authenticated testing
#   --module <name>     Run specific module only (discovery|endpoints|auth|vulns)
#   --quick             Skip slow scans
#
# Example:
#   ./ghost-hunt.sh wellsfargo.com \
#     --subs output/phase1/*/subdomains-paid.txt \
#     --urls output/phase2/*/httpx/alive-urls.txt \
#     --js output/phase2/*/katana/js-files.txt
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST_ROOT="$SCRIPT_DIR"

# Source config
source "${SCRIPT_DIR}/../lib/config.sh"
source "${SCRIPT_DIR}/lib/core.sh"

# Parse arguments
TARGET=""
SUBS_FILE=""
URLS_FILE=""
JS_FILE=""
ENDPOINTS_FILE=""
AUTH_TOKEN=""
MODULE=""
QUICK=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --subs)       SUBS_FILE="$2"; shift 2 ;;
        --urls)       URLS_FILE="$2"; shift 2 ;;
        --js)         JS_FILE="$2"; shift 2 ;;
        --endpoints)  ENDPOINTS_FILE="$2"; shift 2 ;;
        --auth)       AUTH_TOKEN="$2"; shift 2 ;;
        --module)     MODULE="$2"; shift 2 ;;
        --quick)      QUICK=true; shift ;;
        --help|-h)
            head -25 "$0" | tail -20
            exit 0 ;;
        *)
            if [[ -z "$TARGET" ]]; then
                TARGET="$1"
            fi
            shift ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target-domain> [options]"
    echo "Run $0 --help for full usage"
    exit 1
fi

# Validate
validate_config

# Setup output
ghost_setup "$TARGET"

ghost_log phase "GHOST RECON ORCHESTRATOR"
echo -e "  Target:     ${W}${TARGET}${NC}"
echo -e "  Subs file:  ${SUBS_FILE:-none}"
echo -e "  URLs file:  ${URLS_FILE:-none}"
echo -e "  JS file:    ${JS_FILE:-none}"
echo -e "  Auth:       ${AUTH_TOKEN:+[provided]}"
echo -e "  Module:     ${MODULE:-all}"
echo -e "  Quick:      ${QUICK}"
echo ""

# Check dependencies
ghost_check_deps || exit 1

# ============================================================
# Module Execution
# ============================================================

run_discovery() {
    ghost_log phase "═══ MODULE 1: GHOST DISCOVERY ═══"
    source "${SCRIPT_DIR}/modules/01-ghost-discovery.sh"
    ghost_discovery_run "$TARGET" "$SUBS_FILE" "$URLS_FILE"
}

run_endpoints() {
    ghost_log phase "═══ MODULE 2: GHOST ENDPOINTS ═══"
    source "${SCRIPT_DIR}/modules/02-ghost-endpoints.sh"
    ghost_endpoints_run "$JS_FILE" "$URLS_FILE" "$ENDPOINTS_FILE"
}

run_auth() {
    ghost_log phase "═══ MODULE 3: GHOST AUTH & LOGIC ═══"
    source "${SCRIPT_DIR}/modules/03-ghost-auth.sh"
    if [[ -n "$URLS_FILE" && -s "$URLS_FILE" ]]; then
        # Test auth on priority targets
        local priority_urls="${GHOST_OUTPUT}/discovery/clusters/priority-targets.txt"
        local test_file="$URLS_FILE"
        [[ -s "$priority_urls" ]] && test_file="$priority_urls"

        while IFS= read -r url; do
            ghost_auth_manipulation "$url" "$AUTH_TOKEN"
        done < <(head -10 "$test_file")

        # Token entropy on main target
        ghost_token_entropy "https://${TARGET}" "Set-Cookie" 15
    else
        ghost_log warn "No URLs provided. Provide --urls for auth testing."
        ghost_log info "Manual usage: ghost_auth_manipulation <url> [token]"
    fi
}

run_vulns() {
    ghost_log phase "═══ MODULE 4: GHOST VULNERABILITY DETECTION ═══"
    source "${SCRIPT_DIR}/modules/04-ghost-vulns.sh"
    if [[ -n "$URLS_FILE" && -s "$URLS_FILE" ]]; then
        ghost_vulns_run "$URLS_FILE" "$AUTH_TOKEN"
    else
        ghost_log warn "No URLs provided. Provide --urls for vuln testing."
    fi
}

# Execute based on module selection or run all
case "${MODULE}" in
    discovery)  run_discovery ;;
    endpoints)  run_endpoints ;;
    auth)       run_auth ;;
    vulns)      run_vulns ;;
    ""|all)
        run_discovery
        run_endpoints
        run_auth
        run_vulns
        ;;
    *)
        ghost_log error "Unknown module: ${MODULE}"
        ghost_log info "Valid modules: discovery, endpoints, auth, vulns"
        exit 1 ;;
esac

# ============================================================
# Final Report
# ============================================================
ghost_log phase "═══ GHOST RECON COMPLETE ═══"
echo ""

if [[ -f "${GHOST_OUTPUT}/findings.json" ]]; then
    local total=$(jq length "${GHOST_OUTPUT}/findings.json" 2>/dev/null || echo 0)
    local critical=$(jq '[.[] | select(.severity=="critical")] | length' "${GHOST_OUTPUT}/findings.json" 2>/dev/null || echo 0)
    local high=$(jq '[.[] | select(.severity=="high")] | length' "${GHOST_OUTPUT}/findings.json" 2>/dev/null || echo 0)
    local medium=$(jq '[.[] | select(.severity=="medium")] | length' "${GHOST_OUTPUT}/findings.json" 2>/dev/null || echo 0)

    echo -e "  ${W}Findings Summary:${NC}"
    echo -e "  ├── ${R}Critical: ${critical}${NC}"
    echo -e "  ├── ${Y}High:     ${high}${NC}"
    echo -e "  ├── ${B}Medium:   ${medium}${NC}"
    echo -e "  └── ${W}Total:    ${total}${NC}"
    echo ""

    if [[ $critical -gt 0 || $high -gt 0 ]]; then
        echo -e "  ${G}★ HIGH-VALUE FINDINGS:${NC}"
        jq -r '.[] | select(.severity=="critical" or .severity=="high") | "  → [\(.severity)] \(.title)"' \
            "${GHOST_OUTPUT}/findings.json" 2>/dev/null
        echo ""
    fi
else
    echo -e "  No structured findings (check module outputs for raw data)"
fi

echo -e "  ${W}Full output:${NC} ${GHOST_OUTPUT}/"
echo ""
echo -e "  ${C}Next steps:${NC}"
echo -e "  1. Review ${GHOST_OUTPUT}/findings.json"
echo -e "  2. Manually verify each finding in Burp Suite"
echo -e "  3. Write H1 report using templates in report-templates/"
echo -e "  4. Submit to HackerOne (first reporter wins!)"
echo ""
