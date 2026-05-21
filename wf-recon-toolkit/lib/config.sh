#!/bin/bash
# ============================================================
# WF Recon Toolkit - Shared Configuration
# ============================================================
# INSTRUCTIONS: Fill in YOUR details before running any script.
# ============================================================

# --- REQUIRED: Your HackerOne username ---
H1_USERNAME="YOUR_HACKERONE_USERNAME"

# --- REQUIRED: Your testing IP (for report deconfliction) ---
TESTING_IP="YOUR_IP_ADDRESS"

# --- Target Configuration ---
TARGET_DOMAIN="wellsfargo.com"
TARGET_WILDCARD="*.wellsfargo.com"
PRIORITY_TARGET="connect.secure.wellsfargo.com"

# --- Additional in-scope domains (reputation only, no $) ---
ADDITIONAL_DOMAINS=(
    "*.wf.com"
    "*.wellsfargoadvisors.com"
    "*.mworld.com"
    "*.advisor-connection.com"
)

# --- Rate Limiting (program max: 500 req/s, we stay conservative) ---
RATE_LIMIT=100          # requests per second for active tools
NUCLEI_RATE_LIMIT=50    # nuclei is noisy, keep lower
HTTPX_THREADS=50        # httpx concurrent threads

# --- Required Headers (per program policy) ---
H1_HEADER="X-Bug-Bounty: HackerOne-${H1_USERNAME}"
TOOL_HEADER_PREFIX="X-Bug-Bounty"

# --- API Keys (optional, improves results) ---
SHODAN_API_KEY=""
CENSYS_API_ID=""
CENSYS_API_SECRET=""
SECURITYTRAILS_API_KEY=""
CHAOS_API_KEY=""          # projectdiscovery chaos
GITHUB_TOKEN=""           # for github dorking (read:org scope)
VT_API_KEY=""             # virustotal

# --- Output Directories ---
TOOLKIT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${TOOLKIT_ROOT}/output"
PHASE1_OUTPUT="${OUTPUT_DIR}/phase1"
PHASE2_OUTPUT="${OUTPUT_DIR}/phase2"
PHASE3_OUTPUT="${OUTPUT_DIR}/phase3"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# --- Colors for terminal output ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ============================================================
# Helper Functions
# ============================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_section() {
    echo -e "\n${CYAN}========================================${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}========================================${NC}\n"
}

# Validate config before running
validate_config() {
    local errors=0
    if [[ "$H1_USERNAME" == "YOUR_HACKERONE_USERNAME" ]]; then
        log_error "H1_USERNAME not set in lib/config.sh"
        errors=$((errors + 1))
    fi
    if [[ "$TESTING_IP" == "YOUR_IP_ADDRESS" ]]; then
        log_error "TESTING_IP not set in lib/config.sh"
        errors=$((errors + 1))
    fi
    if [[ $errors -gt 0 ]]; then
        log_error "Fix the above errors in lib/config.sh before running."
        exit 1
    fi
}

# Create output directories
setup_output() {
    mkdir -p "$PHASE1_OUTPUT" "$PHASE2_OUTPUT" "$PHASE3_OUTPUT"
    log_info "Output directory: $OUTPUT_DIR"
}

# Check if a tool is installed
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        log_error "Required tool not found: $1"
        log_error "Install it before running this script."
        return 1
    fi
    return 0
}

# Deduplicate and sort a file in-place
dedup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        sort -u "$file" -o "$file"
        local count=$(wc -l < "$file")
        log_info "Deduped $file -> $count unique entries"
    fi
}
