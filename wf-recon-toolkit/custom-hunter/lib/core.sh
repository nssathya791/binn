#!/bin/bash
# ============================================================
# GHOST RECON - Custom Bug Bounty Framework
# ============================================================
# Philosophy: Find what others miss by looking where others don't.
#
# Standard hunters run: subfinder → httpx → nuclei → report
# We run: behavioral analysis, timing attacks, correlation engines,
#         response diffing, cache probing, and state manipulation.
#
# This framework focuses on LOGIC BUGS and BEHAVIORAL ANOMALIES
# that automated scanners completely miss.
# ============================================================

set -euo pipefail

# Framework version
GHOST_VERSION="1.0.0"

# Colors
R='\033[0;31m'
G='\033[0;32m'
Y='\033[1;33m'
B='\033[0;34m'
C='\033[0;36m'
M='\033[0;35m'
W='\033[1;37m'
NC='\033[0m'

# Logging
ghost_banner() {
    echo -e "${M}"
    echo '  ╔═══════════════════════════════════════════╗'
    echo '  ║          G H O S T   R E C O N           ║'
    echo '  ║     "Find what scanners cannot see"      ║'
    echo '  ╚═══════════════════════════════════════════╝'
    echo -e "${NC}"
    echo -e "  ${W}Version: ${GHOST_VERSION}${NC}"
    echo ""
}

ghost_log() {
    local level="$1"
    shift
    local msg="$*"
    local ts=$(date '+%H:%M:%S')
    case "$level" in
        info)   echo -e "${B}[${ts}]${NC} $msg" ;;
        hit)    echo -e "${G}[${ts}][HIT]${NC} $msg" ;;
        warn)   echo -e "${Y}[${ts}][!]${NC} $msg" ;;
        error)  echo -e "${R}[${ts}][ERR]${NC} $msg" ;;
        phase)  echo -e "\n${C}━━━ $msg ━━━${NC}\n" ;;
        find)   echo -e "${G}[${ts}][FINDING]${NC} ${W}$msg${NC}" ;;
    esac
}

# JSON output for structured findings
ghost_finding() {
    local severity="$1"
    local title="$2"
    local detail="$3"
    local evidence="$4"
    local output_file="${GHOST_OUTPUT}/findings.json"

    local ts=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    local entry=$(cat <<EOF
{
  "timestamp": "${ts}",
  "severity": "${severity}",
  "title": "${title}",
  "detail": "${detail}",
  "evidence": "${evidence}",
  "target": "${GHOST_TARGET:-unknown}"
}
EOF
)
    # Append to findings array
    if [[ -f "$output_file" ]]; then
        # Add to existing array
        local tmp=$(mktemp)
        jq ". += [${entry}]" "$output_file" > "$tmp" 2>/dev/null && mv "$tmp" "$output_file"
    else
        echo "[${entry}]" | jq '.' > "$output_file"
    fi

    ghost_log find "${severity^^}: ${title}"
}

# HTTP request wrapper with timing analysis
ghost_request() {
    local url="$1"
    local method="${2:-GET}"
    local data="${3:-}"
    local extra_headers="${4:-}"
    local output_file=$(mktemp)
    local header_file=$(mktemp)

    local curl_opts=(
        -s -S
        -X "$method"
        -o "$output_file"
        -D "$header_file"
        -w '%{http_code}|%{time_total}|%{size_download}|%{redirect_url}|%{ssl_verify_result}'
        -H "${H1_HEADER}"
        -H "${TOOL_HEADER_PREFIX}: ghost-recon"
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        --max-time 15
        -L
    )

    [[ -n "$data" ]] && curl_opts+=(-d "$data")
    [[ -n "$extra_headers" ]] && curl_opts+=(-H "$extra_headers")

    local metrics
    metrics=$(curl "${curl_opts[@]}" "$url" 2>/dev/null) || metrics="000|0|0||1"

    # Parse metrics
    local status=$(echo "$metrics" | cut -d'|' -f1)
    local time=$(echo "$metrics" | cut -d'|' -f2)
    local size=$(echo "$metrics" | cut -d'|' -f3)
    local redirect=$(echo "$metrics" | cut -d'|' -f4)

    # Return structured result
    echo "${status}|${time}|${size}|${redirect}|${output_file}|${header_file}"
}

# Timing analysis - detect blind injection via response time deltas
ghost_timing_baseline() {
    local url="$1"
    local samples="${2:-5}"
    local times=()

    for ((i=0; i<samples; i++)); do
        local result=$(ghost_request "$url")
        local time=$(echo "$result" | cut -d'|' -f2)
        times+=("$time")
        sleep 0.2
    done

    # Calculate average and stddev
    local sum=0
    for t in "${times[@]}"; do
        sum=$(echo "$sum + $t" | bc 2>/dev/null || echo "0")
    done
    local avg=$(echo "scale=4; $sum / $samples" | bc 2>/dev/null || echo "0")

    echo "$avg"
}

# Response fingerprint (hash of structural elements, not content)
ghost_fingerprint() {
    local body_file="$1"
    local header_file="$2"

    # Structure-based fingerprint: count of HTML tags, JSON keys, header count
    local tag_count=$(grep -oP '<[a-z]+' "$body_file" 2>/dev/null | wc -l)
    local json_keys=$(grep -oP '"[^"]+"\s*:' "$body_file" 2>/dev/null | wc -l)
    local header_count=$(wc -l < "$header_file" 2>/dev/null || echo 0)
    local content_type=$(grep -i 'content-type' "$header_file" 2>/dev/null | head -1 | tr -d '\r\n')

    echo "${tag_count}:${json_keys}:${header_count}:${content_type}"
}

# Rate limiter
GHOST_LAST_REQUEST=0
ghost_rate_limit() {
    local min_interval="${1:-0.1}" # seconds between requests
    local now=$(date +%s%N)
    local diff=$(( (now - GHOST_LAST_REQUEST) / 1000000 )) # ms

    local min_ms=$(echo "$min_interval * 1000" | bc | cut -d. -f1)
    if [[ $diff -lt $min_ms ]]; then
        local sleep_time=$(echo "scale=3; ($min_ms - $diff) / 1000" | bc)
        sleep "$sleep_time" 2>/dev/null || sleep 0.1
    fi
    GHOST_LAST_REQUEST=$(date +%s%N)
}

# Dependency checker
ghost_check_deps() {
    local missing=()
    local deps=("curl" "jq" "openssl" "dig" "bc" "python3")

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        ghost_log error "Missing dependencies: ${missing[*]}"
        ghost_log info "Install with: sudo apt install ${missing[*]}"
        return 1
    fi
    return 0
}

# Output setup
ghost_setup() {
    local target="$1"
    GHOST_TARGET="$target"
    GHOST_TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    GHOST_OUTPUT="${GHOST_ROOT}/output/${target}/${GHOST_TIMESTAMP}"
    mkdir -p "${GHOST_OUTPUT}"/{findings,raw,analysis}

    ghost_banner
    ghost_log info "Target: ${target}"
    ghost_log info "Output: ${GHOST_OUTPUT}"
    ghost_log info "Header: ${H1_HEADER}"
    echo ""
}
