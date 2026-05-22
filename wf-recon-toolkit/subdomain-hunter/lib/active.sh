#!/bin/bash
# ============================================================
# subdomain-hunter / lib/active.sh
# ============================================================
# Active sources & post-processing:
#   - DNS brute-force (dnsx / shuffledns / puredns)
#   - Permutation generation (alterx / dnsgen / gotator)
#   - DNS resolution & wildcard filtering
#   - Liveness probing (httpx)
#
# All functions are fail-soft. They only run when the user
# opts in via flags from hunt.sh.
# ============================================================

# ---------- DNS brute-force ------------------------------------------------
# Tries the wordlist <wordlist>.<domain> against resolvers.
# Prefers: puredns -> shuffledns -> dnsx
active_bruteforce() {
    local domain="$1"; local out="$2"; local wordlist="$3"; local resolvers="$4"
    [[ -s "$wordlist" ]] || { log_warn "[brute] wordlist missing: $wordlist"; return 0; }
    log_info "[brute] $(wc -l < "$wordlist") candidates against $domain"

    local f="${out}/raw/brute-${domain}.txt"
    : > "$f"

    if command -v puredns >/dev/null 2>&1 && [[ -s "$resolvers" ]]; then
        log_info "[brute] using puredns"
        puredns bruteforce "$wordlist" "$domain" \
            -r "$resolvers" --quiet -w "$f" >/dev/null 2>&1 || true
    elif command -v shuffledns >/dev/null 2>&1 && [[ -s "$resolvers" ]]; then
        log_info "[brute] using shuffledns"
        shuffledns -d "$domain" -w "$wordlist" -r "$resolvers" \
            -silent -mode bruteforce -o "$f" >/dev/null 2>&1 || true
    elif command -v dnsx >/dev/null 2>&1; then
        log_info "[brute] using dnsx (slower)"
        # build candidate list, then resolve
        local cand="${out}/raw/brute-candidates.txt"
        awk -v d="$domain" 'NF{print $0"."d}' "$wordlist" | sort -u > "$cand"
        dnsx -l "$cand" -silent -a -resp-only -t 100 \
            -o "${out}/raw/brute-resolved-ips.txt" 2>/dev/null || true
        # Re-run to capture the names that resolved
        dnsx -l "$cand" -silent -t 100 -o "$f" 2>/dev/null || true
    else
        log_warn "[brute] no resolver tool found (puredns/shuffledns/dnsx). Skipping."
        return 0
    fi

    [[ -s "$f" ]] || { log_warn "[brute] zero hits"; return 0; }
    local n; n=$(_append_subs "$domain" "${out}/_master.txt" brute < "$f")
    log_success "[brute] +${n}"
}

# ---------- Permutation generation -----------------------------------------
# Uses already-found subs to generate variants (dev1, dev-1, prod-staging, ...)
active_permutations() {
    local domain="$1"; local out="$2"; local resolvers="$3"
    local seed="${out}/_master.txt"
    [[ -s "$seed" ]] || { log_warn "[perm] no seed subs"; return 0; }

    local perm="${out}/raw/permutations-${domain}.txt"
    : > "$perm"

    if command -v alterx >/dev/null 2>&1; then
        log_info "[perm] alterx (PD)"
        alterx -l "$seed" -silent -o "$perm" >/dev/null 2>&1 || true
    elif command -v gotator >/dev/null 2>&1; then
        log_info "[perm] gotator"
        local words="${out}/raw/perm-words.txt"
        cat > "$words" <<'EOF'
dev
test
stage
staging
qa
uat
prod
prd
preprod
beta
alpha
sandbox
internal
admin
api
v1
v2
v3
new
old
backup
internal
private
EOF
        gotator -sub "$seed" -perm "$words" -depth 1 -numbers 3 \
            -mindup -adv -md > "$perm" 2>/dev/null || true
    elif command -v dnsgen >/dev/null 2>&1; then
        log_info "[perm] dnsgen"
        dnsgen "$seed" > "$perm" 2>/dev/null || true
    else
        log_warn "[perm] no permutation tool (alterx/gotator/dnsgen). Skipping."
        return 0
    fi

    [[ -s "$perm" ]] || { log_warn "[perm] zero candidates"; return 0; }
    log_info "[perm] $(wc -l < "$perm") candidates generated, resolving..."

    # Resolve permutations
    local resolved="${out}/raw/permutations-resolved-${domain}.txt"
    if command -v puredns >/dev/null 2>&1 && [[ -s "$resolvers" ]]; then
        puredns resolve "$perm" -r "$resolvers" --quiet -w "$resolved" >/dev/null 2>&1 || true
    elif command -v shuffledns >/dev/null 2>&1 && [[ -s "$resolvers" ]]; then
        shuffledns -list "$perm" -r "$resolvers" -silent -mode resolve \
            -o "$resolved" >/dev/null 2>&1 || true
    elif command -v dnsx >/dev/null 2>&1; then
        dnsx -l "$perm" -silent -t 100 -o "$resolved" >/dev/null 2>&1 || true
    else
        log_warn "[perm] no resolver, skipping resolution step"
        return 0
    fi

    [[ -s "$resolved" ]] || { log_warn "[perm] zero hits"; return 0; }
    local n; n=$(_append_subs "$domain" "${out}/_master.txt" perm < "$resolved")
    log_success "[perm] +${n}"
}

# ---------- Resolve all & detect wildcards ---------------------------------
# Output:
#   ${out}/resolved.txt          - subs that resolve (after wildcard filter)
#   ${out}/resolved-with-ips.txt - "sub a.b.c.d"
#   ${out}/wildcard-hits.txt     - subs filtered out as wildcard noise
active_resolve() {
    local domain="$1"; local out="$2"; local resolvers="$3"
    local master="${out}/_master.txt"
    [[ -s "$master" ]] || { log_warn "[resolve] master is empty"; return 0; }

    log_info "[resolve] $(wc -l < "$master") candidates"

    local resolved="${out}/resolved.txt"
    local with_ips="${out}/resolved-with-ips.txt"
    local wild="${out}/wildcard-hits.txt"
    : > "$resolved"; : > "$with_ips"; : > "$wild"

    if command -v puredns >/dev/null 2>&1 && [[ -s "$resolvers" ]]; then
        log_info "[resolve] puredns (handles wildcards)"
        puredns resolve "$master" -r "$resolvers" --quiet \
            -w "$resolved" --write-wildcards "$wild" >/dev/null 2>&1 || true
    elif command -v shuffledns >/dev/null 2>&1 && [[ -s "$resolvers" ]]; then
        log_info "[resolve] shuffledns"
        shuffledns -list "$master" -r "$resolvers" -silent -mode resolve \
            -o "$resolved" >/dev/null 2>&1 || true
    elif command -v dnsx >/dev/null 2>&1; then
        log_info "[resolve] dnsx (no wildcard filter)"
        dnsx -l "$master" -silent -t 100 -o "$resolved" >/dev/null 2>&1 || true
    else
        log_warn "[resolve] no resolver tool installed (puredns/shuffledns/dnsx)"
        cp "$master" "$resolved"
    fi

    # Add IPs to a separate file when dnsx is available
    if command -v dnsx >/dev/null 2>&1 && [[ -s "$resolved" ]]; then
        dnsx -l "$resolved" -silent -a -resp -t 100 \
            -o "$with_ips" >/dev/null 2>&1 || true
    fi

    log_success "[resolve] $(wc -l < "$resolved" 2>/dev/null || echo 0) live"
}

# ---------- Liveness probe (httpx) -----------------------------------------
active_httpx() {
    local out="$1"
    local resolved="${out}/resolved.txt"
    [[ -s "$resolved" ]] || { log_warn "[httpx] nothing to probe"; return 0; }
    command -v httpx >/dev/null 2>&1 || { log_warn "[httpx] not installed"; return 0; }

    log_info "[httpx] probing $(wc -l < "$resolved") hosts"
    httpx -l "$resolved" -silent -threads 50 -timeout 10 \
        -title -tech-detect -status-code -content-length \
        -o "${out}/httpx.txt" >/dev/null 2>&1 || true

    [[ -s "${out}/httpx.txt" ]] && \
        log_success "[httpx] $(wc -l < "${out}/httpx.txt") live HTTP(S) services" \
        || log_warn "[httpx] no live services"
}

# ---------- Default trusted-resolvers list ---------------------------------
write_default_resolvers() {
    local f="$1"
    cat > "$f" <<'EOF'
1.1.1.1
1.0.0.1
8.8.8.8
8.8.4.4
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
64.6.64.6
64.6.65.6
77.88.8.8
77.88.8.1
EOF
}
