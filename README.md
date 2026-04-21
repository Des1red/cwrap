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
cwrap recon https://site.com http
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
| probe a target | custom scripts | `recon` |

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
| `ObjectOwnership` | Different identities access different objects |
| `PossibleIDOR` | Structural response diff across ID values with no-cred denial |
| `CredentiallessTokenIssuance` | Server issues tokens without credentials |
| `AdminSurface` | Path contains admin/internal/debug patterns |
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
- Per-entity signals, methods, headers, statuses
- Identity behavior (what each probe identity received)
- Parameter intelligence (IDLike, enumerable, auth/ownership boundary)
- JS intelligence (secrets, endpoints, role gates, env vars)
- Findings and actionable next steps

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

#### Recon a login page
```bash
cwrap recon https://site.com/login http
```

#### Recon an authenticated API endpoint
```bash
cwrap recon https://api.site/users api bearer=TOKEN
```

#### Recon with session from previous run
```bash
# First run captures cookies from login
cwrap recon https://site.com/login http

# Subsequent runs reuse them automatically
cwrap recon https://site.com/dashboard http
```