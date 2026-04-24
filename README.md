# cwrap
cwrap is an intelligent HTTP client with built-in active security analysis.
It translates intent into HTTP requests and automatically performs identity-aware probing, session tracking, and object-level authorization reasoning.

Basic Usage
```bash
cwrap <command> <url> [words] [flags]
```

### Example:
```bash
cwrap fetch https://site.com page=2
cwrap send https://api.site/login json user=admin pass=123
cwrap upload https://site.com/uploads file=@file
cwrap scan https://site.com wordlist.txt
cwrap recon https://site.com http
cwrap exploit reports/site-com_2026-04-24_17-14-51.report
```

## Philosophy
curl exposes HTTP mechanics.  
cwrap expresses HTTP meaning.

| You think | curl requires | cwrap |
|--------|--------|--------|
| read page | GET | `fetch` |
| send data | POST + headers | `send` |
| JSON | content-type header | `json` |
| auth | Authorization header | `bearer=` |
| cookies | cookie jar flags | `cookie:` |
| find hidden paths | custom scripts | `scan` |
| probe a target | custom scripts | `recon` |
| confirm vulnerabilities | custom scripts | `exploit` |

The goal is predictable, readable commands.

## Installation
```bash
git clone https://github.com/Des1red/cwrap
cd cwrap
go build
```

Run:
```bash
./cwrap
```

---

## Commands

### Fetch — read resources
```
cwrap fetch <url> [words]
```
Never sends a body.
```bash
cwrap fetch https://httpbin.org/get
cwrap fetch https://api.site/users page=2
cwrap fetch https://site.com browser
cwrap fetch https://api.site/me bearer=TOKEN
```

---

### Send — submit data
```
cwrap send <url> [words]
```
Always sends a POST request.
```bash
cwrap send https://httpbin.org/post name=your_name
cwrap send https://httpbin.org/post json name=your_name age=30
cwrap send https://api.site json user.name=your_name user.age=30
```

---

### Scan — subdirectory scanner
```
cwrap scan <url> <wordlist> [words]
```

Parallel subdirectory scanner with automatic soft 404 detection and baseline fingerprinting.

#### What scan does

- Takes two baseline probes against random paths to fingerprint the server's 404 behavior
- Detects soft 404 servers (those that return 200 for everything) and filters them by exact content hash
- For servers that randomize responses, falls back to size-band filtering (within 5%)
- Runs 20 parallel workers against the wordlist
- Prints found paths color-coded by status code
- Saves all 200 results to `<host>_scan.txt` — one URL per line, ready to feed into `recon --tfile`

#### Output colors

| Color | Status |
|-------|--------|
| Green | 200 OK |
| Yellow | 301/302/303 redirect |
| Red | 401/403 denied |

#### Examples

```bash
# Basic scan
cwrap scan https://site.com wordlist.txt

# Authenticated scan
cwrap scan https://site.com wordlist.txt bearer=TOKEN

# Chain into recon
cwrap scan https://site.com wordlist.txt
cwrap recon --tfile site-com_scan.txt http
```

#### Soft 404 detection

Some servers return HTTP 200 for all paths including non-existent ones. cwrap detects this automatically:

```
⚠  Soft 404 detected — filtering by exact content match (baseline: 8753 bytes)
```

When detected, responses that match the baseline hash are silently skipped. Only paths with genuinely different content surface as findings.

---

### Recon — active security analysis
```
cwrap recon <url> [profile] [flags]
```

Performs identity-aware active reconnaissance against a web application or API.
cwrap automatically probes endpoints, tracks sessions, and reasons about authorization boundaries.

#### Profiles

| Profile | Best for |
|---------|----------|
| `http` | Web applications (HTML, forms, JS) |
| `api` | JSON APIs |

#### What recon does

- Fetches the target and extracts links, forms, and JS endpoints
- Derives multiple probe identities: session (your credentials), anonymous (no auth), fake-admin (role confusion headers)
- Discovers live identities dynamically — when a new role/uid combination is observed in JWT cookies, cwrap registers it as a named identity and re-probes all known endpoints with it
- Probes discovered endpoints with each identity and compares responses
- Detects path-level ID segments (`/users/123`) and generates mutation probes
- Tracks session cookies across the run and reuses them on subsequent runs
- Runs analyzers to detect auth boundaries, role boundaries, IDOR surfaces, ownership patterns, and credentialless token issuance
- Saves a full report to `reports/`

#### Signals detected

| Signal | Meaning |
|--------|---------|
| `AuthBoundary` | Endpoint allows some identities and denies others |
| `RoleBoundary` | Authenticated identity denied — role/permission wall |
| `ObjectOwnership` | Different identities access different objects at the same endpoint |
| `PossibleIDOR` | Structural response diff across ID values with no-cred denial |
| `CredentiallessTokenIssuance` | Server issues tokens without credentials |
| `AdminSurface` | Endpoint path contains admin/internal/debug patterns |
| `PublicAccess` | Endpoint accessible without any credentials |
| `StateChanging` | Endpoint accepts POST/PUT/PATCH/DELETE |
| `SensitiveKeyword` | JS contains secrets, keys, or hardcoded credentials |

#### Examples

```bash
# Web application recon
cwrap recon https://site.com http

# API recon
cwrap recon https://api.site/users api

# Authenticated recon (session reused from previous run)
cwrap recon https://site.com http bearer=TOKEN

# Recon from a list of URLs
cwrap recon --tfile urls.txt http

# Debug mode (shows probe execution)
cwrap recon https://site.com http --debug
```

#### Session persistence

cwrap captures cookies issued during probing and saves them to `~/.config/cwrap/sessions/<host>.json`.
On the next run against the same host, those cookies are automatically injected into the session identity — giving the engine an authenticated starting point without re-supplying credentials.

#### Reports

Every recon run produces a full report at `reports/<host>_<timestamp>.report` containing:
- Discovery tree (how entities were found)
- Per-entity signals, methods, statuses
- Identity behavior (what each probe identity received, with role/uid from JWT claims)
- Parameter intelligence (IDLike, enumerable, auth/ownership boundary, access and denial maps)
- JS intelligence (secrets, endpoints, role gates, env vars)
- Identity vault (frozen cookie snapshots for each discovered live identity)
- Findings and actionable next steps

---

### Exploit — vulnerability confirmation and chain expansion
```
cwrap exploit <report> [flags]
```

Loads a recon report and runs a two-stage exploit engine against the target.

#### Stage 1 — Vulnerability Confirmation

Probes confirmed findings from the report to prove vulnerabilities exist:

| Probe | What it tests |
|-------|--------------|
| Ownership probe | Cross-identity object access — can identity B read identity A's objects? |
| IDOR probe | Parameter-level access control — can a denied identity reach a protected value? |
| Credentialless probe | Token reuse — does a credentialless token grant authenticated access? |

Each probe replays real tokens from the identity vault using frozen cookie snapshots captured during recon.

#### Stage 2 — Chain Expansion

Takes confirmed stage 1 findings and expands them to measure true impact:

| Expander | Seeds from | Action |
|----------|-----------|--------|
| Credentialless Token Reuse | Confirmed credentialless access | Tests all credless identities against role/admin boundary endpoints not yet tested |
| IDOR Object Enumeration | Confirmed ownership bypass | Enumerates neighboring object IDs with the denied identity — stops at 3 consecutive 404/403 responses |
| Ownership Bypass Pivot | Confirmed ownership bypass | Tests the bypassing identity against neighboring objects — skips own objects |

#### Examples

```bash
# Run exploit against a report
cwrap exploit reports/site-com_2026-04-24.report

# Debug mode
cwrap exploit reports/site-com_2026-04-24.report --debug
```

#### Output

```
═══ Vulnerability Confirmation ═══

[1/4] Ownership probe — https://site.com/api/notes/1 (param: note_id)
  testing: member-uid-2 (role=member uid=2)
  token:   auth_token=eyJ...
  [CONFIRMED] member-uid-2 accessed https://site.com/api/notes/1 → 200
  response:   {"id":1,"title":"Alice's note","owner_id":1}
  ✓ Ownership bypass confirmed

═══ Chain Expansion ═══

  Credentialless Token Reuse
    anonymous => member-uid-1 (role=member uid=1) — 6 tested, 5 confirmed
    token:    auth_token=eyJ...
      [CONFIRMED] https://site.com/api/notes/1 → 200
      [blocked]   https://site.com/api/notes/2 → 403
      ...

  IDOR Object Enumeration
    member-uid-2 (role=member uid=2) — 3 tested, 0 confirmed
      [blocked]   https://site.com/api/notes/3 → 403
      ...

✓ Chain expansion confirmed — 5 additional access(es) confirmed
```

---

## Semantic Words
Order does not matter.

### Encoding
- `json` → application/json
- `form` → application/x-www-form-urlencoded

### Profiles
- `browser` → Firefox headers (default)
- `chrome` → Chrome headers
- `api` → JSON API headers
- `curl` → Curl headers

### Recon profiles
- `http` → Web application recon (HTML, forms, JS)
- `web` → alias for http
- `api` → API recon (JSON structure, auth)

### Data
- `key=value` — meaning depends on command:

| Command | Result |
|------|------|
| fetch | query string |
| send | request body |

---

## JSON Builder

### Automatically infers types:
```bash
send api json active=true count=5 price=3.14 name=your_name nullval=null
```
```json
{
  "active": true,
  "count": 5,
  "price": 3.14,
  "name": "your_name",
  "nullval": null
}
```

#### Nested objects
```bash
send api json user.name=your_name user.age=30
```
```json
{
  "user": {
    "name": "your_name",
    "age": 30
  }
}
```

#### Arrays
```bash
send api json tag=a tag=b tag=c
```
```json
{
  "tag": ["a", "b", "c"]
}
```

---

## Authentication & Cookies

```
bearer=TOKEN
cookie:name=value
```

#### Examples:
```bash
cwrap fetch https://api.site/me bearer=abc123
cwrap fetch https://site.com cookie:session=xyz
```

---

## Escape Hatch (curl compatible)

Raw flags still work:
```bash
-h "Header: value"
-d '{"raw":true}'
-f file=@image.png
--proxy http://127.0.0.1:8080
--run
```

cwrap interprets words first, flags second.

---

## Typical Workflow

```bash
# 1. Scan — discover hidden paths
cwrap scan https://site.com wordlist.txt

# 2. Recon — map the surface and detect vulnerabilities
cwrap recon --tfile site-com_scan.txt http

# 3. Exploit — confirm findings and measure impact
cwrap exploit reports/site-com_2026-04-24_17-14-51.report
```

Scan, recon, and exploit are designed to chain. Scan output feeds directly into recon via `--tfile`, and the report produced by recon is the exact input exploit expects.

---

## Examples

#### Read paginated API
```bash
cwrap fetch https://api.site/users api page=2 limit=20
```

#### Login request
```bash
cwrap send https://api.site/login json username=admin password=123
```

#### Authenticated request
```bash
cwrap fetch https://api.site/me bearer=TOKEN
```

#### Complex JSON
```bash
cwrap send https://api.site json filter.name=your_name filter.age=30 tag=a tag=b
```

#### Discover and recon hidden paths
```bash
cwrap scan https://site.com /usr/share/wordlists/dirb/common.txt
cwrap recon --tfile site-com_scan.txt http
```

#### Full security assessment workflow
```bash
# Discover surface
cwrap scan https://site.com wordlist.txt

# Deep recon each discovered path
cwrap recon --tfile site-com_scan.txt http

# Confirm and expand vulnerabilities
cwrap exploit reports/site-com_2026-04-24_17-14-51.report
```