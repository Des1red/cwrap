# cwrap

Most authorization bugs aren't found because they're well hidden — they're found
because most tools never ask the right questions. A scanner that hits every
endpoint once, authenticated as one identity, will miss the entire class of
vulnerabilities that only appear when you compare what different identities can
see and do. cwrap is built around that comparison loop.

## What problem it solves

Authorization testing is fundamentally a relational problem. A 200 on
`/api/orders/123` tells you nothing on its own. What matters is whether the
session that owns order 123 and the session that doesn't both return 200 —
and whether the responses are identical. Doing that manually across dozens of
endpoints, multiple identity types, and varying token states is the part of a
pentest that usually gets cut for time.

cwrap automates the comparison. It doesn't just replay requests; it builds a
map of what each identity is permitted to do, then probes the gaps.

## How identities work

Rather than requiring you to enumerate identities upfront, cwrap derives them
from the material you already have. Feed it a JWT and it extracts the claims —
`sub`, `role`, `scope`, custom fields — and uses those as the basis for probe
identity construction. A fake-admin probe is built from the real token's
structure with role claims promoted. An anonymous probe drops credentials
entirely. A session probe replays the exact cookie jar captured during recon.

This matters because real applications often have more identity states than
you'd think to enumerate manually: authenticated, anonymous, expired token,
token issued to a different resource, token with elevated claims that were
never validated server-side. cwrap probes all of them without you having to
construct each one by hand.

## The pipeline

Three stages run in sequence, each feeding the next.

**Scan** discovers surface. It runs a soft-404-aware directory probe across
one or more wordlists, expands any 200-returning directories into a second
pass, and runs subdomain enumeration against the apex domain with wildcard
DNS detection. The baseline for soft-404 and wildcard filtering is always
taken with a plain, unauthenticated client — separate from the auth-carrying
scan client — so credential state doesn't corrupt the fingerprint.

**Recon** runs the identity comparison loop. For each endpoint discovered or
provided, it probes as the session identity, as anonymous, and as a
constructed fake-admin, then records the divergence. An API engine sets
`Accept: application/json` globally and parses structured responses. An HTTP
engine follows redirects and tracks cookie issuance. The engine selection and
the header profile (Firefox, curl, bare) are independent axes — you can run
API recon with Firefox headers if that's what the application expects.

**Exploit** replays findings from a recon report and expands chains. If recon
found that anonymous can read `/api/messages/42`, exploit will iterate the
ID space, attempt writes, and test cross-identity ownership: does the session
that owns resource A have any access path to resource B that recon didn't
probe. Token reuse is tested by replaying captured tokens against endpoints
that should require fresh issuance.

## What it catches

The three vulnerability classes it finds automatically:

**IDOR** — resource identifiers that are guessable or sequential, where
access control is enforced by obscurity rather than ownership checks. cwrap
detects these when two identities receive identical responses for the same
resource ID.

**Ownership bypass** — endpoints where the authenticated user can read or
modify resources they don't own, typically because the server trusts a
client-supplied identifier over the session's actual owner claim.

**Credentialless token issuance** — endpoints that return a session token,
API key, or signed object without validating that the requesting identity is
entitled to receive one. Usually found at registration flows, OAuth callbacks,
and password reset endpoints.

## Design decisions worth knowing

The header stack is unified. Every command — scan probes, recon requests,
exploit replays — runs through the same `httpcore.BuildHeaders` path. Profile
selection, bearer injection, and custom header merging happen in one place.
This means the requests cwrap sends during exploit look exactly like the
requests it sends during recon, which is the only way cross-stage
comparisons are meaningful.

Controlled handoffs are intentional. Scan doesn't automatically feed recon.
Recon doesn't automatically trigger exploit. You decide when to proceed,
which means you can inspect findings between stages and adjust scope. The
tool is aggressive within a stage but doesn't escalate autonomously.

The report format is machine-readable. Exploit reads recon output directly.
You can also pipe recon output into other tools without post-processing.
