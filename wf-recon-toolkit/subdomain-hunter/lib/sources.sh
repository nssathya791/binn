#!/bin/bash
# ============================================================
# subdomain-hunter / lib/sources.sh
# ============================================================
# All passive collectors. Each function takes (domain, outdir)
# and appends discovered subdomains to ${outdir}/_master.txt
#
# Each function is fail-soft: missing tools, network errors, or
# empty responses must NEVER abort the parent script.
# ============================================================

# Append helper - sanitize, lowercase, strip wildcard prefix, keep only
# entries that match *.<domain> or == <domain>.
_append_subs() {
    local domain="$1"; local master="$2"; local label="${3:-source}"
    awk -v d="$domain" '
        {
            line=$0
            gsub(/[\r\t ]+/,"",line)
            sub(/^\*\./,"",line)
            line=tolower(line)
            if (line=="") next
            # match host endings on .domain or exact domain
            if (line==d || line ~ ("\\."d"$")) print line
        }' | sort -u | tee -a "$master" | wc -l
}

# ---------- 1. crt.sh -------------------------------------------------------
src_crtsh() {
    local domain="$1"; local out="$2"; local f="${out}/raw/crtsh-${domain}.json"
    log_info "[crt.sh] querying %.${domain}"
    curl -fsSL --max-time 90 \
        "https://crt.sh/?q=%25.${domain}&output=json" -o "$f" 2>/dev/null || {
        log_warn "[crt.sh] no response"; return 0; }
    [[ -s "$f" ]] || { log_warn "[crt.sh] empty"; return 0; }
    local n
    n=$(jq -r '.[].name_value' "$f" 2>/dev/null | tr ',' '\n' | tr -d '"' \
        | _append_subs "$domain" "${out}/_master.txt" crtsh)
    log_success "[crt.sh] +${n}"
}

# ---------- 2. subfinder ----------------------------------------------------
src_subfinder() {
    local domain="$1"; local out="$2"
    command -v subfinder >/dev/null 2>&1 || { log_warn "[subfinder] not installed"; return 0; }
    log_info "[subfinder] -all"
    local f="${out}/raw/subfinder-${domain}.txt"
    subfinder -d "$domain" -silent -all -timeout 30 -o "$f" >/dev/null 2>&1 || true
    [[ -s "$f" ]] || { log_warn "[subfinder] empty"; return 0; }
    local n; n=$(_append_subs "$domain" "${out}/_master.txt" subfinder < "$f")
    log_success "[subfinder] +${n}"
}

# ---------- 3. amass passive ------------------------------------------------
src_amass() {
    local domain="$1"; local out="$2"
    command -v amass >/dev/null 2>&1 || { log_warn "[amass] not installed"; return 0; }
    log_info "[amass] passive (timeout 10m)"
    local f="${out}/raw/amass-${domain}.txt"
    timeout 600 amass enum -passive -d "$domain" -o "$f" >/dev/null 2>&1 || true
    [[ -s "$f" ]] || { log_warn "[amass] empty"; return 0; }
    local n; n=$(_append_subs "$domain" "${out}/_master.txt" amass < "$f")
    log_success "[amass] +${n}"
}

# ---------- 4. ProjectDiscovery Chaos ---------------------------------------
src_chaos() {
    local domain="$1"; local out="$2"
    [[ -n "${CHAOS_API_KEY:-}" ]] || { log_warn "[chaos] CHAOS_API_KEY not set"; return 0; }
    command -v chaos >/dev/null 2>&1 || { log_warn "[chaos] client not installed"; return 0; }
    log_info "[chaos] querying"
    local f="${out}/raw/chaos-${domain}.txt"
    chaos -d "$domain" -key "$CHAOS_API_KEY" -silent -o "$f" >/dev/null 2>&1 || true
    [[ -s "$f" ]] || { log_warn "[chaos] empty"; return 0; }
    local n; n=$(_append_subs "$domain" "${out}/_master.txt" chaos < "$f")
    log_success "[chaos] +${n}"
}

# ---------- 5. AlienVault OTX -----------------------------------------------
src_otx() {
    local domain="$1"; local out="$2"
    log_info "[otx] passive_dns"
    local f="${out}/raw/otx-${domain}.json"
    curl -fsSL --max-time 60 \
        "https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns" \
        -o "$f" 2>/dev/null || { log_warn "[otx] no response"; return 0; }
    [[ -s "$f" ]] || { log_warn "[otx] empty"; return 0; }
    local n
    n=$(jq -r '.passive_dns[]?.hostname' "$f" 2>/dev/null \
        | _append_subs "$domain" "${out}/_master.txt" otx)
    log_success "[otx] +${n}"
}

# ---------- 6. HackerTarget -------------------------------------------------
src_hackertarget() {
    local domain="$1"; local out="$2"
    log_info "[hackertarget] hostsearch"
    local f="${out}/raw/hackertarget-${domain}.txt"
    curl -fsSL --max-time 60 \
        "https://api.hackertarget.com/hostsearch/?q=${domain}" -o "$f" 2>/dev/null \
        || { log_warn "[hackertarget] no response"; return 0; }
    [[ -s "$f" ]] || { log_warn "[hackertarget] empty"; return 0; }
    grep -q "API count exceeded" "$f" && { log_warn "[hackertarget] rate-limited"; return 0; }
    local n; n=$(cut -d',' -f1 "$f" | _append_subs "$domain" "${out}/_master.txt" hackertarget)
    log_success "[hackertarget] +${n}"
}

# ---------- 7. RapidDNS -----------------------------------------------------
src_rapiddns() {
    local domain="$1"; local out="$2"
    log_info "[rapiddns] full=1"
    local f="${out}/raw/rapiddns-${domain}.html"
    curl -fsSL --max-time 60 \
        "https://rapiddns.io/subdomain/${domain}?full=1" -o "$f" 2>/dev/null \
        || { log_warn "[rapiddns] no response"; return 0; }
    [[ -s "$f" ]] || { log_warn "[rapiddns] empty"; return 0; }
    local n
    n=$(grep -oE '[a-zA-Z0-9_.-]+\.'"${domain//./\\.}" "$f" \
        | _append_subs "$domain" "${out}/_master.txt" rapiddns)
    log_success "[rapiddns] +${n}"
}

# ---------- 8. urlscan.io ---------------------------------------------------
src_urlscan() {
    local domain="$1"; local out="$2"
    log_info "[urlscan] search"
    local f="${out}/raw/urlscan-${domain}.json"
    curl -fsSL --max-time 60 \
        "https://urlscan.io/api/v1/search/?q=domain:${domain}&size=10000" \
        -o "$f" 2>/dev/null || { log_warn "[urlscan] no response"; return 0; }
    [[ -s "$f" ]] || { log_warn "[urlscan] empty"; return 0; }
    local n
    n=$(jq -r '.results[]?.page.domain, .results[]?.task.domain' "$f" 2>/dev/null \
        | _append_subs "$domain" "${out}/_master.txt" urlscan)
    log_success "[urlscan] +${n}"
}

# ---------- 9. CertSpotter --------------------------------------------------
src_certspotter() {
    local domain="$1"; local out="$2"
    log_info "[certspotter] issuances"
    local f="${out}/raw/certspotter-${domain}.json"
    curl -fsSL --max-time 60 \
        "https://api.certspotter.com/v1/issuances?domain=${domain}&include_subdomains=true&expand=dns_names" \
        -o "$f" 2>/dev/null || { log_warn "[certspotter] no response"; return 0; }
    [[ -s "$f" ]] || { log_warn "[certspotter] empty"; return 0; }
    local n
    n=$(jq -r '.[]?.dns_names[]?' "$f" 2>/dev/null \
        | _append_subs "$domain" "${out}/_master.txt" certspotter)
    log_success "[certspotter] +${n}"
}

# ---------- 10. AnubisDB (jldc.me) ------------------------------------------
src_anubis() {
    local domain="$1"; local out="$2"
    log_info "[anubis] jldc.me"
    local f="${out}/raw/anubis-${domain}.json"
    curl -fsSL --max-time 60 \
        "https://jldc.me/anubis/subdomains/${domain}" -o "$f" 2>/dev/null \
        || { log_warn "[anubis] no response"; return 0; }
    [[ -s "$f" ]] || { log_warn "[anubis] empty"; return 0; }
    local n
    n=$(jq -r '.[]?' "$f" 2>/dev/null | _append_subs "$domain" "${out}/_master.txt" anubis)
    log_success "[anubis] +${n}"
}

# ---------- 11. ThreatMiner -------------------------------------------------
src_threatminer() {
    local domain="$1"; local out="$2"
    log_info "[threatminer] subdomains"
    local f="${out}/raw/threatminer-${domain}.json"
    curl -fsSL --max-time 60 \
        "https://api.threatminer.org/v2/domain.php?q=${domain}&rt=5" \
        -o "$f" 2>/dev/null || { log_warn "[threatminer] no response"; return 0; }
    [[ -s "$f" ]] || { log_warn "[threatminer] empty"; return 0; }
    local n
    n=$(jq -r '.results[]?' "$f" 2>/dev/null \
        | _append_subs "$domain" "${out}/_master.txt" threatminer)
    log_success "[threatminer] +${n}"
}

# ---------- 12. Wayback CDX -------------------------------------------------
src_wayback_cdx() {
    local domain="$1"; local out="$2"
    log_info "[wayback] CDX index"
    local f="${out}/raw/wayback-${domain}.txt"
    curl -fsSL --max-time 120 \
        "http://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=text&fl=original&collapse=urlkey" \
        -o "$f" 2>/dev/null || { log_warn "[wayback] no response"; return 0; }
    [[ -s "$f" ]] || { log_warn "[wayback] empty"; return 0; }
    local n
    n=$(grep -oE 'https?://[^/ ]+' "$f" | sed -E 's#^https?://##' \
        | _append_subs "$domain" "${out}/_master.txt" wayback)
    log_success "[wayback] +${n}"
}

# ---------- 13. CommonCrawl Index -------------------------------------------
src_commoncrawl() {
    local domain="$1"; local out="$2"
    log_info "[commoncrawl] index"
    local idx_list="${out}/raw/cc-indexes.json"
    curl -fsSL --max-time 30 \
        "https://index.commoncrawl.org/collinfo.json" -o "$idx_list" 2>/dev/null \
        || { log_warn "[commoncrawl] index list unavailable"; return 0; }
    [[ -s "$idx_list" ]] || { log_warn "[commoncrawl] empty index list"; return 0; }
    local latest
    latest=$(jq -r '.[0]."cdx-api"' "$idx_list" 2>/dev/null)
    [[ -n "$latest" && "$latest" != "null" ]] || { log_warn "[commoncrawl] no cdx-api"; return 0; }
    local f="${out}/raw/commoncrawl-${domain}.txt"
    curl -fsSL --max-time 120 \
        "${latest}?url=*.${domain}/*&output=text&fl=url" -o "$f" 2>/dev/null || true
    [[ -s "$f" ]] || { log_warn "[commoncrawl] empty results"; return 0; }
    local n
    n=$(grep -oE 'https?://[^/ ]+' "$f" | sed -E 's#^https?://##' \
        | _append_subs "$domain" "${out}/_master.txt" commoncrawl)
    log_success "[commoncrawl] +${n}"
}

# ---------- 14. gau (URLs -> hosts) -----------------------------------------
src_gau() {
    local domain="$1"; local out="$2"
    command -v gau >/dev/null 2>&1 || { log_warn "[gau] not installed"; return 0; }
    log_info "[gau] subs+wayback+otx+cc"
    local f="${out}/raw/gau-${domain}.txt"
    echo "$domain" | timeout 300 gau --subs --threads 5 > "$f" 2>/dev/null || true
    [[ -s "$f" ]] || { log_warn "[gau] empty"; return 0; }
    local n
    n=$(grep -oE 'https?://[^/ ]+' "$f" | sed -E 's#^https?://##' \
        | _append_subs "$domain" "${out}/_master.txt" gau)
    log_success "[gau] +${n}"
}

# ---------- 15. SecurityTrails ----------------------------------------------
src_securitytrails() {
    local domain="$1"; local out="$2"
    [[ -n "${SECURITYTRAILS_API_KEY:-}" ]] || { log_warn "[securitytrails] SECURITYTRAILS_API_KEY not set"; return 0; }
    log_info "[securitytrails] subdomains"
    local f="${out}/raw/securitytrails-${domain}.json"
    curl -fsSL --max-time 30 \
        "https://api.securitytrails.com/v1/domain/${domain}/subdomains?children_only=false" \
        -H "APIKEY: ${SECURITYTRAILS_API_KEY}" -o "$f" 2>/dev/null \
        || { log_warn "[securitytrails] no response"; return 0; }
    [[ -s "$f" ]] || { log_warn "[securitytrails] empty"; return 0; }
    local n
    n=$(jq -r ".subdomains[]? | . + \".${domain}\"" "$f" 2>/dev/null \
        | _append_subs "$domain" "${out}/_master.txt" securitytrails)
    log_success "[securitytrails] +${n}"
}

# ---------- 16. VirusTotal --------------------------------------------------
src_virustotal() {
    local domain="$1"; local out="$2"
    [[ -n "${VT_API_KEY:-}" ]] || { log_warn "[virustotal] VT_API_KEY not set"; return 0; }
    log_info "[virustotal] subdomains"
    local f="${out}/raw/virustotal-${domain}.json"
    curl -fsSL --max-time 30 \
        -H "x-apikey: ${VT_API_KEY}" \
        "https://www.virustotal.com/api/v3/domains/${domain}/subdomains?limit=1000" \
        -o "$f" 2>/dev/null || { log_warn "[virustotal] no response"; return 0; }
    [[ -s "$f" ]] || { log_warn "[virustotal] empty"; return 0; }
    local n
    n=$(jq -r '.data[]?.id' "$f" 2>/dev/null \
        | _append_subs "$domain" "${out}/_master.txt" virustotal)
    log_success "[virustotal] +${n}"
}

# ---------- 17. Shodan ------------------------------------------------------
src_shodan() {
    local domain="$1"; local out="$2"
    [[ -n "${SHODAN_API_KEY:-}" ]] || { log_warn "[shodan] SHODAN_API_KEY not set"; return 0; }
    log_info "[shodan] dns/domain"
    local f="${out}/raw/shodan-${domain}.json"
    curl -fsSL --max-time 30 \
        "https://api.shodan.io/dns/domain/${domain}?key=${SHODAN_API_KEY}" \
        -o "$f" 2>/dev/null || { log_warn "[shodan] no response"; return 0; }
    [[ -s "$f" ]] || { log_warn "[shodan] empty"; return 0; }
    local n
    n=$(jq -r ".subdomains[]? | . + \".${domain}\"" "$f" 2>/dev/null \
        | _append_subs "$domain" "${out}/_master.txt" shodan)
    log_success "[shodan] +${n}"
}

# ---------- 18. Censys (v2 cert search) -------------------------------------
src_censys() {
    local domain="$1"; local out="$2"
    [[ -n "${CENSYS_API_ID:-}" && -n "${CENSYS_API_SECRET:-}" ]] \
        || { log_warn "[censys] CENSYS_API_ID/SECRET not set"; return 0; }
    log_info "[censys] cert names"
    local f="${out}/raw/censys-${domain}.json"
    curl -fsSL --max-time 60 \
        -u "${CENSYS_API_ID}:${CENSYS_API_SECRET}" \
        "https://search.censys.io/api/v2/certificates/search?q=names:${domain}&per_page=100" \
        -o "$f" 2>/dev/null || { log_warn "[censys] no response"; return 0; }
    [[ -s "$f" ]] || { log_warn "[censys] empty"; return 0; }
    local n
    n=$(jq -r '.result.hits[]?.names[]?' "$f" 2>/dev/null \
        | _append_subs "$domain" "${out}/_master.txt" censys)
    log_success "[censys] +${n}"
}

# ---------- 19. BinaryEdge --------------------------------------------------
src_binaryedge() {
    local domain="$1"; local out="$2"
    [[ -n "${BINARYEDGE_API_KEY:-}" ]] || { log_warn "[binaryedge] BINARYEDGE_API_KEY not set"; return 0; }
    log_info "[binaryedge] subdomains"
    local f="${out}/raw/binaryedge-${domain}.json"
    curl -fsSL --max-time 60 \
        -H "X-Key: ${BINARYEDGE_API_KEY}" \
        "https://api.binaryedge.io/v2/query/domains/subdomain/${domain}" \
        -o "$f" 2>/dev/null || { log_warn "[binaryedge] no response"; return 0; }
    [[ -s "$f" ]] || { log_warn "[binaryedge] empty"; return 0; }
    local n
    n=$(jq -r '.events[]?' "$f" 2>/dev/null \
        | _append_subs "$domain" "${out}/_master.txt" binaryedge)
    log_success "[binaryedge] +${n}"
}

# ---------- 20. GitHub code search (subs in repos) --------------------------
src_github() {
    local domain="$1"; local out="$2"
    [[ -n "${GITHUB_TOKEN:-}" ]] || { log_warn "[github] GITHUB_TOKEN not set"; return 0; }
    if command -v github-subdomains >/dev/null 2>&1; then
        log_info "[github] github-subdomains"
        local f="${out}/raw/github-${domain}.txt"
        github-subdomains -d "$domain" -t "$GITHUB_TOKEN" -o "$f" >/dev/null 2>&1 || true
        [[ -s "$f" ]] || { log_warn "[github] empty"; return 0; }
        local n; n=$(_append_subs "$domain" "${out}/_master.txt" github < "$f")
        log_success "[github] +${n}"
    else
        log_info "[github] code-search via API"
        local f="${out}/raw/github-${domain}.json"
        curl -fsSL --max-time 60 \
            -H "Authorization: token ${GITHUB_TOKEN}" \
            -H "Accept: application/vnd.github.v3+json" \
            "https://api.github.com/search/code?q=%22.${domain}%22&per_page=100" \
            -o "$f" 2>/dev/null || { log_warn "[github] no response"; return 0; }
        [[ -s "$f" ]] || { log_warn "[github] empty"; return 0; }
        local n
        n=$(jq -r '.items[]?.text_matches[]?.fragment // empty' "$f" 2>/dev/null \
            | grep -oE "[a-zA-Z0-9_.-]+\.${domain//./\\.}" \
            | _append_subs "$domain" "${out}/_master.txt" github)
        log_success "[github] +${n}"
    fi
}

# ---------- 21. Wayback / subjs / JS scraping for hidden sub references -----
src_jsscrape() {
    local domain="$1"; local out="$2"
    log_info "[jsscrape] grepping subs from collected URLs"
    local urls="${out}/raw/all-urls.txt"
    : > "$urls"
    for f in "${out}/raw/gau-${domain}.txt" \
             "${out}/raw/wayback-${domain}.txt" \
             "${out}/raw/commoncrawl-${domain}.txt"; do
        [[ -s "$f" ]] && cat "$f" >> "$urls"
    done
    [[ -s "$urls" ]] || { log_warn "[jsscrape] no URLs to mine"; return 0; }

    # Pull the small subset of JS files (cap to 50 to stay polite)
    local js_list="${out}/raw/js-urls.txt"
    grep -iE '\.js(\?|$)' "$urls" | sort -u | head -n 50 > "$js_list" || true

    local found=0
    if [[ -s "$js_list" ]]; then
        local jsdir="${out}/raw/js-bodies"; mkdir -p "$jsdir"
        while IFS= read -r url; do
            [[ -n "$url" ]] || continue
            local safe; safe=$(echo "$url" | tr -c 'A-Za-z0-9.-' '_' | cut -c1-120)
            curl -fsSL --max-time 20 "$url" -o "${jsdir}/${safe}" 2>/dev/null || true
        done < "$js_list"
        found=$(grep -hoEr "[a-zA-Z0-9_.-]+\.${domain//./\\.}" "$jsdir" 2>/dev/null \
            | _append_subs "$domain" "${out}/_master.txt" jsscrape)
    fi
    log_success "[jsscrape] +${found:-0}"
}
