#!/bin/bash
# ============================================================
#  hunt.sh - Hidden Subdomain Hunter
# ============================================================
# Generic, multi-source subdomain enumeration tool.
#
# Combines 20+ passive sources, DNS brute-force, permutations,
# JS scraping, and DNS resolution to surface HIDDEN subdomains
# that single-tool runs typically miss.
#
# Usage:
#   ./hunt.sh <domain> [options]
#
# See ./hunt.sh --help for full options.
# ============================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/sources.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/active.sh"

# ----------------------- logging -------------------------------------------
RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'; CYAN=$'\033[0;36m'; NC=$'\033[0m'
log_info()    { printf "%s[INFO]%s %s\n"    "$BLUE"   "$NC" "$*"; }
log_success() { printf "%s[+]%s %s\n"       "$GREEN"  "$NC" "$*"; }
log_warn()    { printf "%s[!]%s %s\n"       "$YELLOW" "$NC" "$*"; }
log_error()   { printf "%s[ERROR]%s %s\n"   "$RED"    "$NC" "$*" >&2; }
log_section() {
    printf "\n%s========================================%s\n"   "$CYAN" "$NC"
    printf "%s  %s%s\n"                                          "$CYAN" "$*" "$NC"
    printf "%s========================================%s\n\n"   "$CYAN" "$NC"
}

# ----------------------- defaults ------------------------------------------
DOMAIN=""
QUICK=false
DO_BRUTE=false
DO_PERM=false
DO_RESOLVE=true
DO_HTTPX=false
RECURSIVE=false
RECURSIVE_DEPTH=1
WORDLIST="${SCRIPT_DIR}/wordlists/common-2k.txt"
RESOLVERS=""
THREADS=50
OUTDIR=""
SCOPE_FILTER=""
LOAD_CONFIG=true

usage() {
    cat <<EOF
${CYAN}Hidden Subdomain Hunter${NC}

Combines 20+ passive sources, DNS brute-force, permutations and JS
scraping to surface hidden subdomains.

${CYAN}USAGE${NC}
  ./hunt.sh <domain> [options]

${CYAN}EXAMPLES${NC}
  # Passive only (~3-5 min, no traffic to target zone)
  ./hunt.sh example.com

  # Quick passive (skip slow sources like amass)
  ./hunt.sh example.com --quick

  # Full hunt: passive + brute-force + permutations + resolve + probe
  ./hunt.sh example.com --all

  # Brute force with a custom wordlist and custom resolvers
  ./hunt.sh example.com --brute --wordlist /path/to/big.txt \\
                        --resolvers /path/to/resolvers.txt

  # Recursive hunt (run again on each new subdomain found)
  ./hunt.sh example.com --recursive --depth 2

${CYAN}OPTIONS${NC}
  --quick                Skip slow passive sources (amass, commoncrawl)
  --brute                Enable DNS brute-force using wordlist
  --permutations         Generate permutations from known subs and resolve
  --no-resolve           Skip DNS resolution of the master list
  --probe                Run httpx liveness probe on resolved hosts
  --recursive            Re-run hunt on each newly discovered subdomain
  --depth N              Recursion depth (default: 1, only used with --recursive)
  --all                  Enable: --brute --permutations --probe
  --wordlist FILE        Wordlist for brute-force
                         (default: lib/wordlists/common-2k.txt)
  --resolvers FILE       Trusted resolvers file
                         (default: built-in list of 12 public resolvers)
  --threads N            Concurrency for resolvers/probe (default: 50)
  --output DIR           Output directory (default: ./output/<domain>/<ts>)
  --scope REGEX          Filter final list with extended regex
                         e.g. --scope '\\.(corp|internal)\\.example\\.com$'
  --no-config            Do not source ../lib/config.sh for API keys
  -h | --help            Show this help

${CYAN}REQUIRED${NC}        curl, jq
${CYAN}RECOMMENDED${NC}     subfinder, amass, gau, dnsx, httpx
${CYAN}FOR BRUTE${NC}       puredns OR shuffledns OR dnsx
${CYAN}FOR PERMS${NC}       alterx OR gotator OR dnsgen
${CYAN}OPTIONAL APIs${NC}   CHAOS_API_KEY, SECURITYTRAILS_API_KEY,
                  VT_API_KEY, SHODAN_API_KEY, CENSYS_API_ID/SECRET,
                  BINARYEDGE_API_KEY, GITHUB_TOKEN
                  (set as env vars or in lib/config.sh)
EOF
}

# ----------------------- arg parsing ---------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)        usage; exit 0 ;;
        --quick)          QUICK=true; shift ;;
        --brute)          DO_BRUTE=true; shift ;;
        --permutations)   DO_PERM=true; shift ;;
        --no-resolve)     DO_RESOLVE=false; shift ;;
        --probe)          DO_HTTPX=true; shift ;;
        --recursive)      RECURSIVE=true; shift ;;
        --depth)          RECURSIVE_DEPTH="$2"; shift 2 ;;
        --all)            DO_BRUTE=true; DO_PERM=true; DO_HTTPX=true; shift ;;
        --wordlist)       WORDLIST="$2"; shift 2 ;;
        --resolvers)      RESOLVERS="$2"; shift 2 ;;
        --threads)        THREADS="$2"; shift 2 ;;
        --output)         OUTDIR="$2"; shift 2 ;;
        --scope)          SCOPE_FILTER="$2"; shift 2 ;;
        --no-config)      LOAD_CONFIG=false; shift ;;
        --) shift; break ;;
        -*) log_error "unknown option: $1"; usage; exit 2 ;;
        *)
            if [[ -z "$DOMAIN" ]]; then DOMAIN="$1"
            else log_error "unexpected argument: $1"; exit 2; fi
            shift ;;
    esac
done

if [[ -z "$DOMAIN" ]]; then
    log_error "no domain provided"
    usage; exit 2
fi

# Sanity: domain looks like a domain
if ! [[ "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$ ]]; then
    log_error "invalid domain: '$DOMAIN' (expected e.g. example.com)"
    exit 2
fi
DOMAIN="${DOMAIN,,}"   # lowercase

# ----------------------- optional config (API keys) ------------------------
if [[ "$LOAD_CONFIG" == true && -f "${SCRIPT_DIR}/../lib/config.sh" ]]; then
    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/../lib/config.sh" 2>/dev/null || true
fi

# Required deps check
for bin in curl jq awk sort grep sed; do
    command -v "$bin" >/dev/null 2>&1 || { log_error "missing dep: $bin"; exit 1; }
done

# ----------------------- output layout -------------------------------------
TS=$(date +%Y%m%d-%H%M%S)
[[ -z "$OUTDIR" ]] && OUTDIR="${SCRIPT_DIR}/output/${DOMAIN}/${TS}"
mkdir -p "${OUTDIR}/raw"
log_section "Hidden Subdomain Hunter :: ${DOMAIN}"
log_info "Output: ${OUTDIR}"
log_info "Mode:   $( [[ $QUICK == true ]] && echo quick || echo full )$( [[ $DO_BRUTE == true ]] && echo +brute )$( [[ $DO_PERM == true ]] && echo +perm )$( [[ $RECURSIVE == true ]] && echo " +recursive(${RECURSIVE_DEPTH})" )"

# Default resolvers
if [[ -z "$RESOLVERS" ]]; then
    RESOLVERS="${OUTDIR}/raw/resolvers.txt"
    write_default_resolvers "$RESOLVERS"
fi

# Master list lives at ${OUTDIR}/_master.txt (used by all sources)
: > "${OUTDIR}/_master.txt"

# ----------------------- run one round of hunting on a single domain -------
hunt_one() {
    local d="$1"; local o="$2"
    mkdir -p "${o}/raw"

    log_section "Passive sources :: ${d}"
    src_crtsh         "$d" "$o"
    src_subfinder     "$d" "$o"
    [[ "$QUICK" == false ]] && src_amass "$d" "$o"
    src_chaos         "$d" "$o"
    src_otx           "$d" "$o"
    src_hackertarget  "$d" "$o"
    src_rapiddns      "$d" "$o"
    src_urlscan       "$d" "$o"
    src_certspotter   "$d" "$o"
    src_anubis        "$d" "$o"
    src_threatminer   "$d" "$o"
    src_wayback_cdx   "$d" "$o"
    [[ "$QUICK" == false ]] && src_commoncrawl "$d" "$o"
    src_gau           "$d" "$o"
    src_securitytrails "$d" "$o"
    src_virustotal    "$d" "$o"
    src_shodan        "$d" "$o"
    src_censys        "$d" "$o"
    src_binaryedge    "$d" "$o"
    src_github        "$d" "$o"
    src_jsscrape      "$d" "$o"

    # Dedup running master
    sort -u "${o}/_master.txt" -o "${o}/_master.txt"
    log_info "passive total :: $(wc -l < "${o}/_master.txt") unique"

    if [[ "$DO_BRUTE" == true ]]; then
        log_section "DNS brute-force :: ${d}"
        active_bruteforce "$d" "$o" "$WORDLIST" "$RESOLVERS"
        sort -u "${o}/_master.txt" -o "${o}/_master.txt"
    fi

    if [[ "$DO_PERM" == true ]]; then
        log_section "Permutations :: ${d}"
        active_permutations "$d" "$o" "$RESOLVERS"
        sort -u "${o}/_master.txt" -o "${o}/_master.txt"
    fi
}

# ----------------------- recursive hunting ---------------------------------
declare -A SEEN_DOMAINS=()
SEEN_DOMAINS["$DOMAIN"]=1

hunt_recursive() {
    local current_depth=0
    local frontier=("$DOMAIN")

    while true; do
        local next_frontier=()
        for d in "${frontier[@]}"; do
            local sub_out="${OUTDIR}"
            [[ "$d" != "$DOMAIN" ]] && sub_out="${OUTDIR}/recursive/${d}"
            mkdir -p "$sub_out"
            : > "${sub_out}/_master.txt"
            hunt_one "$d" "$sub_out"
            # Merge into top-level master
            cat "${sub_out}/_master.txt" >> "${OUTDIR}/_master.txt"

            # Pick new "interesting parent" candidates for next round:
            # any sub with extra labels that looks like a delegated zone.
            if [[ "$RECURSIVE" == true && $current_depth -lt $((RECURSIVE_DEPTH - 1)) ]]; then
                while IFS= read -r host; do
                    # take direct children of the original domain (one extra label)
                    local stripped="${host%."$DOMAIN"}"
                    if [[ "$stripped" != "$host" && "$stripped" == *.* ]]; then
                        # candidate parent zone (drop the leftmost label)
                        local parent="${stripped#*.}.${DOMAIN}"
                        if [[ -z "${SEEN_DOMAINS[$parent]:-}" ]]; then
                            SEEN_DOMAINS["$parent"]=1
                            next_frontier+=("$parent")
                        fi
                    fi
                done < "${sub_out}/_master.txt"
            fi
        done

        sort -u "${OUTDIR}/_master.txt" -o "${OUTDIR}/_master.txt"
        current_depth=$((current_depth + 1))
        [[ "$RECURSIVE" == true && $current_depth -lt $RECURSIVE_DEPTH \
             && ${#next_frontier[@]} -gt 0 ]] || break
        log_section "Recursive depth ${current_depth} :: ${#next_frontier[@]} new zones"
        frontier=("${next_frontier[@]}")
    done
}

hunt_recursive

# ----------------------- post-processing -----------------------------------
log_section "Post-processing"

MASTER="${OUTDIR}/_master.txt"
sort -u "$MASTER" -o "$MASTER"
log_info "raw master: $(wc -l < "$MASTER") unique"

# Optional scope filter
if [[ -n "$SCOPE_FILTER" ]]; then
    grep -E "$SCOPE_FILTER" "$MASTER" > "${OUTDIR}/in-scope.txt" || true
    log_success "in-scope filter: $(wc -l < "${OUTDIR}/in-scope.txt") match"
    cp "${OUTDIR}/in-scope.txt" "$MASTER"
fi

# Resolution & wildcard filtering
if [[ "$DO_RESOLVE" == true ]]; then
    log_section "DNS resolution"
    active_resolve "$DOMAIN" "$OUTDIR" "$RESOLVERS"
fi

# Liveness probe
if [[ "$DO_HTTPX" == true ]]; then
    log_section "HTTP liveness"
    active_httpx "$OUTDIR"
fi

# Per-source counts
log_info "Per-source contribution:"
for raw in "${OUTDIR}/raw/"*; do
    [[ -f "$raw" && -s "$raw" ]] || continue
    name=$(basename "$raw")
    # crude line count - good enough for relative comparison
    printf "    %-40s %s lines\n" "$name" "$(wc -l < "$raw")"
done | sort -k2 -nr | head -n 30 | tee "${OUTDIR}/_source-stats.txt"

# Final files
FINAL="${OUTDIR}/subdomains.txt"
cp "$MASTER" "$FINAL"

# Heuristic: surface "interesting" hidden hosts (dev/stage/admin/internal/etc)
INTERESTING="${OUTDIR}/interesting.txt"
grep -iE '(^|[.-])(dev|develop|stg|stage|staging|test|tst|qa|uat|sit|int|internal|intra|admin|root|jenkins|gitlab|jira|confluence|grafana|kibana|elastic|consul|vault|nomad|k8s|kube|rancher|portainer|argocd|tekton|nexus|harbor|artifactory|sonar|sandbox|preprod|pre-prod|hidden|private|secret|legacy|old|backup|tmp|temp|beta|alpha|canary|new|api-internal|api-dev|api-stage|api-uat|admin-api|debug|swagger|metrics|prometheus|alertmanager|monitor)[.-]' \
    "$FINAL" > "$INTERESTING" 2>/dev/null || true

# ----------------------- summary -------------------------------------------
log_section "RESULTS"
log_success "Total unique subdomains:    $(wc -l < "$FINAL")"
[[ -s "${OUTDIR}/resolved.txt" ]]   && log_success "Resolved (live DNS):        $(wc -l < "${OUTDIR}/resolved.txt")"
[[ -s "${OUTDIR}/wildcard-hits.txt" ]] && log_warn "Filtered as wildcard:        $(wc -l < "${OUTDIR}/wildcard-hits.txt")"
[[ -s "${OUTDIR}/httpx.txt" ]]      && log_success "Live HTTP(S) services:      $(wc -l < "${OUTDIR}/httpx.txt")"
[[ -s "$INTERESTING" ]]              && log_success "Interesting (dev/stg/admin): $(wc -l < "$INTERESTING")"
echo
log_info "Final list:    ${FINAL}"
log_info "Interesting:   ${INTERESTING}"
log_info "Stats:         ${OUTDIR}/_source-stats.txt"
log_info "Raw artefacts: ${OUTDIR}/raw/"
echo
