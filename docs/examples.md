# cwrap Examples

## Directory scan
```bash
./cwrap scan http://localhost:9001 --dir wordlists/small-directory-list-20k.txt
```

<p align="center"> <img src="assets/scan9001.png" alt="cwrap directory discovery scan output" width="900"> </p>

## Fetch preview

```bash
./cwrap fetch http://localhost:9001/?wsdl firefox
```

<p align="center"> <img src="assets/fetch9001.png" alt="cwrap fetch preview with Firefox headers" width="900"> </p>

## Recon summary
```bash
./cwrap recon http://localhost:9001 && ./cwrap recon http://localhost:9001 firefox
```

<p align="center"> <img src="assets/recon9001.png" alt="cwrap recon summary showing discovered security boundaries" width="900"> </p> 

### Recon full report
The full recon report is saved as a `.report` file and contains the discovery tree, entity intelligence, detected boundaries, suggested next steps, and the identity vault used later by the exploit engine.
```md
========== CWRAP FULL RECON REPORT ==========
Target:    http://localhost:9001
Generated: 2026-04-28 18:31:54

------------------------------------------------
GLOBAL STATS
------------------------------------------------
Entities:          15
Edges:             14
Global parameters: 9

Signals (count of entities tagged):
  - AdminSurface: 1
  - AuthBoundary: 1
  - CredentiallessTokenIssuance: 1
  - HasForm: 1
  - HasJSONBody: 5
  - IDLikeParam: 14
  - ObjectOwnership: 2
  - PossibleIDOR: 1
  - RoleBoundary: 10
  - StateChanging: 15

------------------------------------------------
DISCOVERY TREE
------------------------------------------------
http://localhost:9001
├── http://localhost:9001/login/alice  [html]
│   └── http://localhost:9001/home  [html]
│       ├── http://localhost:9001/api/notes  [html]
│       ├── http://localhost:9001/api/notes/1  [html]
│       ├── http://localhost:9001/api/notes/2  [html]
│       ├── http://localhost:9001/api/messages/1  [html]
│       ├── http://localhost:9001/api/messages/2  [html]
│       ├── http://localhost:9001/login/bob  [html]
│       │   └── http://localhost:9001/home  [html]  (seen)
│       ├── http://localhost:9001/login/admin  [html]
│       │   └── http://localhost:9001/home  [html]  (seen)
│       └── http://localhost:9001/logout  [form]
├── http://localhost:9001/login/bob  [html]  (seen)
└── http://localhost:9001/login/admin  [html]  (seen)

------------------------------------------------
ENTITY INTELLIGENCE
------------------------------------------------

[ENTITY] http://localhost:9001/api/notes/1
  Probes: 18
  Methods: [DELETE GET HEAD OPTIONS PATCH POST PUT]
  AuthLikely: true
  Content: JSON
  Statuses: 200×53 401×1 403×18
  Signals: [HasJSONBody IDLikeParam ObjectOwnership PossibleIDOR RoleBoundary StateChanging]
  Identities:
    member-uid-1: [IdentityUser creds effective role=member uid=1 exp=2026-04-29 03:31]
    member-uid-2: [IdentityUser creds effective role=member uid=2 exp=2026-04-29 03:31]
    owner-uid-3: [IdentityElevated creds effective role=owner uid=3 exp=2026-04-29 03:31]
    session: [IdentityElevated creds effective role=owner uid=3 exp=2026-04-29 03:31]
  Parameters:
    content: [json]
    id: [json IDLike AuthBoundary OwnershipBoundary interest=1]
      changes: [input-affects-response role-wall-403-authenticated]
      access: map[member-uid-1:1 owner-uid-3:1]
      denied: map[member-uid-2:1]
    note_id: [path IDLike Reflection AuthBoundary OwnershipBoundary PossibleIDOR SuspectIDOR interest=5]
      changes: [idor-raw-diff interest+object role-wall-403-authenticated stable-structure structure-changes]
      access: map[member-uid-1:1 member-uid-2:1 owner-uid-3:2]
      denied: map[member-uid-1:1 member-uid-2:1]
    owner_id: [json IDLike]
    title: [json]
  Findings:
    ! Horizontal privilege escalation possible via param: note_id
    ! Object ownership enforcement observed
    ! Role/permission boundary observed — authenticated identity denied access
    ! Suspect IDOR surface via param: note_id
  Next Steps:
    > Attempt cross-identity object access via note_id
    > Attempt cross-user object access (IDOR) across identities
    > Check if role is encoded in JWT claims and attempt tampering
    > Probe role confusion via header injection (X-User-Role, X-Forwarded-User)
    > Test horizontal privilege escalation using id
    > Test horizontal privilege escalation using note_id
    > Test vertical privilege escalation — attempt access with lower-privilege token

[ENTITY] http://localhost:9001/api/notes/2
  Probes: 13
  Methods: [DELETE GET HEAD OPTIONS PATCH POST PUT]
  AuthLikely: true
  Content: JSON
  Statuses: 200×32 401×1 403×19
  Signals: [HasJSONBody IDLikeParam ObjectOwnership RoleBoundary StateChanging]
  Identities:
    member-uid-1: [IdentityUser creds effective role=member uid=1 exp=2026-04-29 03:31]
    member-uid-2: [IdentityUser creds effective role=member uid=2 exp=2026-04-29 03:31]
    owner-uid-3: [IdentityElevated creds effective role=owner uid=3 exp=2026-04-29 03:31]
    session: [IdentityElevated creds effective role=owner uid=3 exp=2026-04-29 03:31]
  Parameters:
    content: [json]
    id: [json IDLike]
    note_id: [path IDLike AuthBoundary OwnershipBoundary]
      changes: [role-wall-403-authenticated]
      access: map[member-uid-2:1 owner-uid-3:1]
      denied: map[member-uid-1:1]
    owner_id: [json IDLike]
    title: [json]
  Findings:
    ! Object ownership enforcement observed
    ! Role/permission boundary observed — authenticated identity denied access
  Next Steps:
    > Attempt cross-user object access (IDOR) across identities
    > Check if role is encoded in JWT claims and attempt tampering
    > Probe role confusion via header injection (X-User-Role, X-Forwarded-User)
    > Test horizontal privilege escalation using note_id
    > Test vertical privilege escalation — attempt access with lower-privilege token

... output truncated ...

------------------------------------------------
IDENTITY VAULT
------------------------------------------------
  member-uid-1:
    auth_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsInJvbGUiOiJtZW1iZXIiLCJ1c2VyX2lkIjoxLCJqdGkiOiIxLTE3NzczOTAzMTI2NjkyODU3NjAiLCJleHAiOjE3Nzc0MzM1MTJ9.gw6zaXLS9XThNqwrm8KXYR7xrUeFCdtOP20O8DoZGqc
  member-uid-2:
    auth_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjIsInJvbGUiOiJtZW1iZXIiLCJ1c2VyX2lkIjoyLCJqdGkiOiIyLTE3NzczOTAzMTMwNzU0OTA1NjAiLCJleHAiOjE3Nzc0MzM1MTN9.OjSmFLvGQpynZ5FAvU29X2AKtJh8a3h4cO4KKb6KhZU
  owner-uid-3:
    auth_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjMsInJvbGUiOiJvd25lciIsInVzZXJfaWQiOjMsImp0aSI6IjMtMTc3NzM5MDMxMzE1MjI0NTQ3MSIsImV4cCI6MTc3NzQzMzUxM30.2T996HL5LLHwtiizVauffRkXoc3jvZI1oy4VmyLv1QU


=============== END OF REPORT ===============

```
## Exploit Engine preview
```bash
./cwrap exploit reports/localhost-9001_2026-04-28_18-31-54.report
```

<p align="center">
  <img src="assets/exploit9001-1.png" alt="cwrap exploit vulnerability confirmation output" width="900">
</p>

<p align="center">
  <img src="assets/exploit9001-2.png" alt="cwrap exploit ownership and credentialless token probes" width="900">
</p>

<p align="center">
  <img src="assets/exploit9001-3.png" alt="cwrap exploit chain expansion confirmed output" width="900">
</p>

## Recon — JavaScript leaks and admin surfaces

```bash
./cwrap recon http://localhost:9004
```
<p align="center"> <img src="assets/recon9004js.png" alt="cwrap recon summary showing public admin surfaces and JavaScript leaks" width="900"> </p>

The full report also extracts JavaScript references, leaked keywords, internal hosts, feature flags, and API endpoints discovered from served scripts. Example from Full report:
```md
[ENTITY] http://localhost:9004/js/admin.js
  Probes: 1
  Methods: [GET]
  Statuses: 200×3
  Signals: [SensitiveKeyword]
  Identities:
    anonymous: [IdentityNone]
    fake-admin: [IdentityNone]
    session: [IdentityUser creds role=member uid=1 exp=2026-04-28 22:26]
  JS Intelligence:
    aws_key: 1
    endpoint: 5
    host_private_ip: 2
    keyword: 1
    priv_gate: 1
    role_check: 1
    [aws_key] access_key_id: AKIAIOSFODNN7EXAMPLE
    [keyword] password: changeme123
    [role_check] role: admin
    [priv_gate] if_gate: Privilege gate conditional detected
    [host_private_ip] ip: 192.168.1.100:5432
    [host_private_ip] ip: 10.0.1.20:6379
  Findings:
    ! JS leaks present: 6
    ! Sensitive keywords detected in content/JS
  Next Steps:
    > Review JS findings for secrets, endpoints, role gates, and client-side auth assumptions
```
<p align="center"> <img src="assets/9004js-leaks.png" alt="cwrap recon full report showing JavaScript leaks and discovered API endpoints" width="900"> </p>

## Exploit — JWT role tampering

```bash
./cwrap recon http://localhost:9006/login
./cwrap exploit reports/localhost-9006-login_2026-04-28_18-58-31.report
```

<p align="center"> <img src="assets/recon9006login.png" alt="cwrap recon summary showing credentialless issuance and role boundary signals" width="900"> </p> <p align="center"> <img src="assets/exploit9006.png" alt="cwrap exploit output confirming JWT role tampering against admin endpoints" width="900"> </p>

## Recon — IDOR surfaces in API parameters

```bash
./cwrap recon http://localhost:9003
```
<p align="center"> <img src="assets/recon9003.png" alt="cwrap recon summary showing IDOR surfaces across user_id and id parameters" width="900"> </p>