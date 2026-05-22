# Hidden Subdomain Hunter

A generic, multi-source subdomain enumeration tool that combines **20+ passive
sources**, **DNS brute-force**, **permutation generation**, **JS scraping**,
**recursive enumeration**, and **DNS/HTTP liveness validation** to surface
hidden subdomains that single-tool runs typically miss.

Standalone (`hunt.sh <domain>`) but also drops in cleanly next to the rest of
the `wf-recon-toolkit` and reuses its `lib/config.sh` for API keys.

---

## Why "hidden"?

Most public subdomain tools query 3-5 sources and call it a day. Truly hidden
subdomains live in places like:

- **Recently-issued certificates** that haven't been indexed yet (CertSpotter)
- **JS bundles** that hardcode internal API URLs
- **Wayback / CommonCrawl** archived URLs from years ago
- **Permutations** of known names (`api-dev` -> `api-uat`, `api-staging`, ...)
- **Brute-forced labels** that never appear in any public dataset
- **Delegated child zones** that need recursive enumeration

This tool hits all of them.

---

## Sources used

### Passive (run by default, zero traffic to target)

| # | Source            | Auth     | Notes                                    |
|---|-------------------|----------|------------------------------------------|
| 1 | crt.sh            | none     | Certificate Transparency logs            |
| 2 | subfinder `-all`  | none     | Aggregates ~20 sources internally        |
| 3 | amass passive     | none     | Slow but thorough (skipped in `--quick`) |
| 4 | PD Chaos          | optional | Pre-aggregated dataset                   |
| 5 | AlienVault OTX    | none     | Passive DNS                              |
| 6 | HackerTarget      | none     | hostsearch (rate-limited)                |
| 7 | RapidDNS          | none     | Scraped index                            |
| 8 | urlscan.io        | none     | Public scan index                        |
| 9 | CertSpotter       | none     | Real-time CT issuances                   |
|10 | AnubisDB (jldc.me)| none     | Pre-aggregated                           |
|11 | ThreatMiner       | none     | Passive DNS                              |
|12 | Wayback CDX       | none     | Archive.org index                        |
|13 | CommonCrawl       | none     | Latest CC index                          |
|14 | gau               | none     | Wayback + CC + OTX + URLScan combined    |
|15 | SecurityTrails    | API key  | DNS history                              |
|16 | VirusTotal v3     | API key  | Subdomain relationships                  |
|17 | Shodan            | API key  | DNS domain endpoint                      |
|18 | Censys v2         | API id+s | Cert search                              |
|19 | BinaryEdge        | API key  | Subdomain endpoint                       |
|20 | GitHub code search| token    | finds subs hardcoded in public repos     |
|21 | JS scrape         | none     | Mines JS bundles from collected URLs     |

### Active (opt-in)

| Stage          | Tool preference (first available wins)         |
|----------------|------------------------------------------------|
| Brute-force    | `puredns` -> `shuffledns` -> `dnsx`            |
| Permutations   | `alterx` -> `gotator` -> `dnsgen`              |
| Resolution     | `puredns` -> `shuffledns` -> `dnsx`            |
| HTTP probe     | `httpx`                                        |

A built-in 2k-entry wordlist ships at `wordlists/common-2k.txt`. Override with
`--wordlist /path/to/big.txt` (e.g. SecLists `subdomains-top1million-110000`).

---

## Quick start

```bash
cd wf-recon-toolkit/subdomain-hunter
chmod +x hunt.sh

# Passive only - 3-5 minutes, no traffic to target
./hunt.sh example.com

# Quick passive (skip amass and CommonCrawl)
./hunt.sh example.com --quick

# Full hunt: passive + brute + permutations + resolve + HTTP probe
./hunt.sh example.com --all

# Use a big SecLists wordlist
./hunt.sh example.com --brute \
    --wordlist ~/SecLists/Discovery/DNS/subdomains-top1million-110000.txt

# Recursive: re-run on each child zone discovered (depth 2)
./hunt.sh example.com --recursive --depth 2 --all

# Constrain to in-scope only
./hunt.sh example.com --all --scope '\.(corp|api|prod)\.example\.com$'
```

---

## Output

```
output/<domain>/<timestamp>/
├── subdomains.txt           # FINAL deduplicated list (all sources combined)
├── interesting.txt          # heuristic-flagged hidden hosts (dev/stage/admin/internal/...)
├── resolved.txt             # subset that resolves via DNS (after wildcard filtering)
├── resolved-with-ips.txt    # "host  ip" lines from dnsx
├── wildcard-hits.txt        # filtered out as wildcard noise
├── httpx.txt                # live HTTP(S) services + tech detection
├── in-scope.txt             # if --scope was supplied
├── _source-stats.txt        # per-source contribution counts
├── _master.txt              # internal accumulator (= subdomains.txt pre-filter)
└── raw/
    ├── crtsh-<domain>.json
    ├── subfinder-<domain>.txt
    ├── amass-<domain>.txt
    ├── chaos-<domain>.txt
    ├── otx-<domain>.json
    ├── ...                  # one file per source
    ├── js-bodies/           # downloaded JS files mined for hidden subs
    ├── brute-<domain>.txt
    ├── permutations-<domain>.txt
    └── permutations-resolved-<domain>.txt
```

---

## CLI reference

```
./hunt.sh <domain> [options]

  --quick                Skip slow sources (amass, commoncrawl)
  --brute                Enable DNS brute-force using --wordlist
  --permutations         Generate permutations from found subs and resolve
  --no-resolve           Skip the final DNS resolution step
  --probe                Run httpx on resolved hosts
  --recursive            Re-run hunt on each child zone discovered
  --depth N              Recursion depth (default 1, requires --recursive)
  --all                  Shortcut for --brute --permutations --probe
  --wordlist FILE        Wordlist for brute-force
  --resolvers FILE       Trusted resolvers file
  --threads N            Concurrency (default 50)
  --output DIR           Output directory
  --scope REGEX          Filter final list with extended regex
  --no-config            Don't source ../lib/config.sh
  -h | --help            Show help
```

### Required deps

`curl`, `jq`, standard POSIX tools (`awk`, `sort`, `grep`, `sed`).

### Recommended deps (significantly improve recall)

```bash
# Go-based (run after installing Go 1.21+)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/d3mondev/puredns/v2@latest
go install github.com/gwen001/github-subdomains@latest
go install github.com/Josue87/gotator@latest

export PATH="$PATH:$(go env GOPATH)/bin"
```

### API keys (optional, but each one unlocks more sources)

Set as environment variables OR fill them into `../lib/config.sh`:

```bash
export CHAOS_API_KEY="..."          # free at chaos.projectdiscovery.io
export SECURITYTRAILS_API_KEY="..." # free tier available
export VT_API_KEY="..."             # virustotal.com
export SHODAN_API_KEY="..."
export CENSYS_API_ID="..."
export CENSYS_API_SECRET="..."
export BINARYEDGE_API_KEY="..."
export GITHUB_TOKEN="..."           # PAT, repo:public scope is enough
```

---

## Tips

- **Run twice, a week apart.** New certs and Wayback entries appear constantly.
  Diff the two `subdomains.txt` files to catch newly-deployed assets first.
- **Big wordlists matter** for brute-force. SecLists 110k easily uncovers
  hosts that no public dataset has.
- **Combine with `--scope`** to drop your scan straight into a Burp scope file.
- **Permutations on a real seed list** are extremely productive against banks
  / large enterprises that follow naming conventions
  (`api-prod-east1`, `api-prod-east2`, ...).
- **Recursive on big targets** (`--recursive --depth 2`) finds delegated
  child zones such as `*.eu.corp.example.com` that don't show up at the apex.

---

## Authorized use only

This tool only sends traffic during the optional `--brute`, `--permutations`,
`--no-resolve` (off), and `--probe` stages. The DNS lookups go to public
recursive resolvers, and HTTP probes hit the target directly with `httpx`.

Only run this against domains you own or are explicitly authorized to test
(e.g. an in-scope HackerOne / Bugcrowd program). The authors assume no
liability for misuse.
