# WF Recon Toolkit

A structured bug bounty reconnaissance and testing toolkit for the Wells Fargo HackerOne program. Designed for authorized security researchers participating in the public bug bounty program.

## Disclaimer

This toolkit is for **authorized security research only** under the Wells Fargo HackerOne Bug Bounty Program. You must:
- Have an active HackerOne account
- Follow all program rules and scope restrictions
- Only test accounts you own
- Include required identification headers on all traffic
- Respect rate limits (max 500 req/s)
- Stop immediately if you suspect service impact

Unauthorized use against any target is illegal. The authors assume no liability.

## Program Quick Reference

| Target | Bounty Range | Priority |
|--------|-------------|----------|
| `*.wellsfargo.com` | $100 - $7,500 | Primary |
| `connect.secure.wellsfargo.com` | $150 - $15,000 | High-value |
| `*.wf.com` | Rep only | Low |
| `*.wellsfargoadvisors.com` | Rep only | Low |
| `*.mworld.com` | Rep only | Low |
| `*.advisor-connection.com` | Rep only | Low |

## Directory Structure

```
wf-recon-toolkit/
├── README.md                    # This file
├── lib/
│   └── config.sh               # Shared configuration (EDIT THIS FIRST)
├── phase1-passive/
│   └── passive-recon.sh        # Subdomain enumeration (zero target traffic)
├── phase2-active/
│   └── active-recon.sh         # HTTP probing, scanning, crawling
├── phase3-manual/
│   └── manual-testing.sh       # JS analysis, IDOR prep, 403 bypass, wordlists
├── nuclei-templates/
│   ├── auth-bypass-403.yaml    # 403 forbidden bypass techniques
│   ├── exposed-actuator.yaml   # Spring Boot actuator endpoints
│   ├── exposed-env-file.yaml   # .env file exposure
│   ├── exposed-git-directory.yaml # .git directory exposure
│   ├── exposed-swagger-openapi.yaml # API documentation exposure
│   ├── idor-api-patterns.yaml  # IDOR/BOLA pattern detection
│   ├── js-secrets-exposure.yaml # Hardcoded secrets in JS
│   ├── open-redirect.yaml      # Open redirect parameters
│   ├── sensitive-info-disclosure.yaml # Stack traces, internal IPs
│   ├── ssrf-detection.yaml     # SSRF via common parameters (OOB)
│   └── subdomain-takeover-enhanced.yaml # Dangling CNAME detection
├── burp-config/
│   ├── burp-project-options.json # Burp project configuration
│   ├── match-replace-rules.json  # H1 headers + scope rules
│   └── setup-guide.md           # Step-by-step Burp setup
└── output/                      # Generated at runtime
    ├── phase1/
    ├── phase2/
    └── phase3/
```

## Quick Start

### Step 1: Configure

```bash
# Clone/copy this toolkit to your testing machine
cd wf-recon-toolkit

# Edit the config file - fill in YOUR details
nano lib/config.sh
```

**Required fields in `lib/config.sh`:**
- `H1_USERNAME` - Your HackerOne username
- `TESTING_IP` - Your public IP address

**Optional (improves results):**
- `SHODAN_API_KEY` - Shodan API key
- `CHAOS_API_KEY` - ProjectDiscovery Chaos (free)
- `SECURITYTRAILS_API_KEY` - SecurityTrails
- `GITHUB_TOKEN` - GitHub personal access token (read:org scope)
- `VT_API_KEY` - VirusTotal

### Step 2: Phase 1 - Passive Recon

```bash
# Full passive recon (10-20 min)
./phase1-passive/passive-recon.sh

# Quick mode (skip amass, ~3 min)
./phase1-passive/passive-recon.sh --quick
```

**What it does (zero traffic to target):**
- Certificate Transparency logs (crt.sh)
- Subfinder (passive source aggregator)
- Amass passive enumeration
- ProjectDiscovery Chaos
- Wayback Machine / CommonCrawl (gau)
- SecurityTrails DNS history
- VirusTotal passive DNS
- Shodan cert/org search
- GitHub dorking
- AlienVault OTX, HackerTarget, ThreatCrowd, RapidDNS

**Output:** `output/phase1/<timestamp>/subdomains-paid.txt`

### Step 3: Phase 2 - Active Recon

```bash
# Full active scan
./phase2-active/active-recon.sh output/phase1/<timestamp>/subdomains-paid.txt

# Skip nuclei (faster, just probe + crawl)
./phase2-active/active-recon.sh output/phase1/<timestamp>/subdomains-paid.txt --skip-nuclei

# Skip screenshots
./phase2-active/active-recon.sh output/phase1/<timestamp>/subdomains-paid.txt --skip-screenshots
```

**What it does (sends traffic to target with H1 headers):**
- DNS resolution + CNAME takeover detection (dnsx)
- HTTP/HTTPS probing with tech detection (httpx)
- TLS certificate analysis (tlsx)
- Visual screenshots (gowitness)
- Web crawling for endpoints/JS/APIs (katana)
- Nuclei vulnerability scanning (5 passes: custom, takeovers, exposures, CVEs, tech)

**Output:** `output/phase2/<timestamp>/` with subdirectories for each tool

### Step 4: Phase 3 - Manual Testing

```bash
./phase3-manual/manual-testing.sh output/phase2/<timestamp>
```

**What it does:**
- Downloads and analyzes JS files for secrets and hidden endpoints
- Generates IDOR test cases from discovered API endpoints
- Prepares 403 bypass request templates for Burp Repeater
- Creates banking-specific fuzzing wordlists
- Generates HackerOne report templates

**Output:** `output/phase3/<timestamp>/` with analysis results, wordlists, and templates

### Step 5: Burp Suite Manual Testing

```bash
# Read the setup guide
cat burp-config/setup-guide.md
```

1. Configure Match & Replace rules (see `burp-config/match-replace-rules.json`)
2. Set target scope
3. Install recommended extensions (Autorize, Logger++, JS Link Finder, Param Miner)
4. Follow the priority checklist in `output/phase3/<timestamp>/priority-checklist.md`

## Tool Dependencies

### Required (core functionality)

| Tool | Purpose | Install |
|------|---------|---------|
| `curl` | HTTP requests | Usually pre-installed |
| `jq` | JSON parsing | `apt install jq` / `brew install jq` |
| `httpx` | HTTP probing | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `nuclei` | Vulnerability scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |

### Recommended (significantly improves results)

| Tool | Purpose | Install |
|------|---------|---------|
| `subfinder` | Passive subdomain enum | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `dnsx` | DNS resolution/CNAME | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| `katana` | Web crawling | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| `tlsx` | TLS analysis | `go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest` |
| `gau` | Wayback/CC URLs | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| `gowitness` | Screenshots | `go install github.com/sensepost/gowitness@latest` |
| `unfurl` | URL parsing | `go install github.com/tomnomnom/unfurl@latest` |

### Optional (advanced features)

| Tool | Purpose | Install |
|------|---------|---------|
| `amass` | Deep passive enum | `go install github.com/owasp-amass/amass/v4/...@master` |
| `chaos` | PD Chaos client | `go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest` |
| `github-subdomains` | GitHub scraping | `go install github.com/gwen001/github-subdomains@latest` |
| `linkfinder` | JS endpoint extraction | `pip3 install linkfinder` |
| `waybackurls` | Wayback URLs | `go install github.com/tomnomnom/waybackurls@latest` |
| `Burp Suite Pro` | Manual testing | https://portswigger.net/burp/pro |

### One-liner Install (Go tools)

```bash
# Ensure Go 1.21+ is installed, then:
go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
go install github.com/projectdiscovery/katana/cmd/katana@latest && \
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest && \
go install github.com/lc/gau/v2/cmd/gau@latest && \
go install github.com/sensepost/gowitness@latest && \
go install github.com/tomnomnom/unfurl@latest

# Add Go bin to PATH if not already
export PATH=$PATH:$(go env GOPATH)/bin
```

## High-Value Bug Classes (What Pays)

Based on program bounty distribution (66% medium, 14% high, 10% critical):

### Critical ($4,000 - $15,000)
- Authentication bypass / account takeover
- SSRF with internal network access
- RCE (remote code execution)
- SQL injection with data extraction
- Business logic flaws in financial operations

### High ($2,000 - $7,500)
- IDOR/BOLA on sensitive data (balances, transactions, PII)
- Subdomain takeover (verified, claimable)
- Exposed credentials/secrets (valid, usable)
- Stored XSS in authenticated contexts
- Authorization bypass (privilege escalation)

### Medium ($300 - $4,000)
- Open redirect (especially on OAuth flows)
- CORS misconfiguration with impact
- Information disclosure (internal IPs, stack traces)
- Exposed admin panels / API documentation
- Reflected XSS (non-trivial exploitation)

### Won't Pay (don't bother reporting)
- Missing security headers (CSP, HSTS, X-XSS-Protection)
- SPF/DKIM/DMARC issues
- Self-XSS
- CSRF on non-sensitive forms
- Clickjacking on non-sensitive pages
- Missing cookie flags
- Version/banner disclosure
- Rate limiting issues
- SSL/TLS configuration

## Program Rules Reminder

1. **Headers required**: `X-Bug-Bounty: HackerOne-<username>` on every request
2. **Rate limit**: Max 500 req/s (toolkit defaults to 100 for safety)
3. **Account testing**: Only YOUR accounts, never real customer data
4. **Registration**: Use `<username>+x@wearehackerone.com` format
5. **IP reporting**: Include your testing IP in high/critical reports
6. **No DoS**: Stop if you suspect service impact
7. **No disclosure**: Program does not allow public disclosure
8. **One vuln per report**: Unless chaining for impact
9. **Duplicates**: First reporter wins, verified by timestamp
10. **Third-party**: Assets owned by third parties are not eligible for bounty

## Workflow Summary

```
Phase 1 (Passive)          Phase 2 (Active)           Phase 3 (Manual)
─────────────────          ─────────────────          ─────────────────
crt.sh                     DNS resolution             JS secret mining
subfinder        ──►       httpx probing     ──►      IDOR test cases
amass                      nuclei scanning            403 bypass attempts
gau/wayback                katana crawling            Custom fuzzing
shodan/censys              gowitness screenshots      Burp manual testing
github dorks               TLS analysis               Report writing

     Zero traffic              With H1 headers            Targeted exploitation
     to target                 rate-limited               on YOUR accounts
```

## Tips for Success

1. **Speed matters**: First valid report wins. Run Phase 1 immediately, Phase 2 within hours.
2. **Focus on connect.secure.wellsfargo.com**: 2x bounty multiplier vs wildcard.
3. **Subdomain takeovers are easy wins**: Check CNAME records to abandoned services.
4. **JS files are goldmines**: Banks ship large bundles with hidden endpoints/keys.
5. **IDOR is the #1 bug class for banking**: Test every ID parameter with a second account.
6. **Write clear reports**: Include request/response, impact statement, and remediation. Better reports get higher bounties.
7. **Don't spray and pray**: Targeted manual testing beats automated scanners.
8. **Check the interesting subdomains list**: dev/stage/qa hosts have weaker security.
9. **Monitor for new subdomains**: Run Phase 1 weekly to catch newly deployed assets.
10. **Read previous disclosures**: Check HackerOne Hacktivity for WF-adjacent programs to understand what gets paid.

## License

This toolkit is provided as-is for authorized security research. Use responsibly.
