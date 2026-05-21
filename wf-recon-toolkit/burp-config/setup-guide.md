# Burp Suite Configuration Guide for Wells Fargo Bug Bounty

## Quick Setup (5 minutes)

### 1. Match & Replace Rules (CRITICAL - do this first)

Go to: **Settings > Network > Connections > Match and Replace Rules**
(In older Burp: **Proxy > Options > Match and Replace**)

Add these rules:

| Type | Match | Replace | Regex |
|------|-------|---------|-------|
| Request header | *(empty)* | `X-Bug-Bounty: HackerOne-YOUR_USERNAME` | No |
| Request header | *(empty)* | `X-Bug-Bounty: BurpSuite` | No |

> **Why:** Program policy REQUIRES these headers on all testing traffic for deconfliction.
> Without them, your testing may be flagged as malicious and reports may be rejected.

### 2. Target Scope

Go to: **Target > Scope > Use advanced scope control**

**Include in scope:**
```
Protocol: HTTPS
Host: ^.*\.wellsfargo\.com$
Port: (any)
File: (any)
```

Add additional entries for:
- `^connect\.secure\.wellsfargo\.com$` (priority target)
- `^.*\.wf\.com$` (rep only)
- `^.*\.wellsfargoadvisors\.com$` (rep only)
- `^.*\.mworld\.com$` (rep only)
- `^.*\.advisor-connection\.com$` (rep only)

**Exclude from scope:**
- `^.*\.google\.com$`
- `^.*\.gstatic\.com$`
- `^.*\.googleapis\.com$`
- `^.*\.facebook\.com$`
- `^.*\.doubleclick\.net$`
- `^.*\.akamai\.net$`
- `^.*\.cloudfront\.net$`

### 3. Intruder/Scanner Rate Limiting

Go to: **Settings > Network > Connections > Throttle**

Set:
- **Fixed delay:** 20ms between requests (= ~50 req/s)
- Or use **Resource Pool** with max concurrent requests: 10

> Program policy max is 500 req/s. Stay well under to avoid detection/blocking.

### 4. Collaborator/Interactsh for OOB Testing

For SSRF and blind injection testing:
- **Burp Collaborator** (built-in, Professional only): Settings > Collaborator
- **Interactsh** (free alternative): Run `interactsh-client` separately

### 5. Extensions to Install (BApp Store)

Essential:
- **Autorize** - IDOR/BOLA testing (test same request with different auth)
- **Logger++** - Enhanced request/response logging
- **JS Link Finder** - Extract endpoints from JS responses
- **Param Miner** - Discover hidden parameters
- **Active Scan++** - Enhanced active scanning

Recommended:
- **Turbo Intruder** - Fast, scriptable fuzzing
- **Auth Analyzer** - Multi-role authorization testing
- **JSON Web Tokens** - JWT manipulation
- **GraphQL Raider** - If GraphQL endpoints found
- **Hackvertor** - Encoding/decoding transformations
- **HTTP Request Smuggler** - Request smuggling detection

### 6. Autorize Setup (for IDOR hunting)

1. Install Autorize from BApp Store
2. Login as Account A (attacker) - copy the full Cookie/Authorization header
3. Paste into Autorize's "Authorization Header" field
4. Login as Account B (victim) in the browser proxied through Burp
5. Browse as Account B - Autorize will replay each request with Account A's token
6. Look for green (bypassed) results = potential IDOR

### 7. Proxy Listener

Default: `127.0.0.1:8080`

If using with browser:
- Install Burp's CA certificate
- Use FoxyProxy to route only `*.wellsfargo.com` through Burp
- This keeps your other browsing clean

## Testing Workflow in Burp

### Phase 1: Passive Crawl
1. Set Proxy intercept to OFF
2. Browse the target naturally (login, navigate features)
3. Let Burp build the sitemap passively
4. Review Target > Site map for interesting endpoints

### Phase 2: Active Discovery
1. Right-click interesting endpoints > "Scan" or "Send to Intruder"
2. Use Intruder with banking-params.txt wordlist for parameter discovery
3. Check Scanner results for medium/high issues

### Phase 3: Manual Exploitation
1. Send interesting requests to Repeater
2. Test IDOR: change user/account IDs
3. Test auth bypass: remove/modify Authorization header
4. Test injection: add payloads to parameters
5. Document everything with screenshots for your report

## Keyboard Shortcuts
- `Ctrl+R` - Send to Repeater
- `Ctrl+I` - Send to Intruder
- `Ctrl+Shift+R` - Repeater: Go (send request)
- `Ctrl+U` - URL-encode selected text
- `Ctrl+Shift+U` - URL-decode selected text
