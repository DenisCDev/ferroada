<h1 align="center">Ferroada</h1>

<p align="center">
  <b>English</b> · <a href="README.pt-BR.md">Português</a>
</p>

<p align="center">
  <b>In front of your app. On your server.</b><br>
  It blocks the attack and holds back what should never leak. You don't touch your code and you don't send your traffic to anyone else's cloud.<br>
  <sub><i>"I will give you a name, and I shall call you Sting."</i></sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/rust-pingora%200.8.1-D4A24E?labelColor=171310" alt="Rust with Pingora 0.8.1">
  <img src="https://img.shields.io/badge/single%20binary-distroless%20~20MB-43A48E?labelColor=171310" alt="single binary, ~20MB distroless container">
  <img src="https://img.shields.io/badge/external%20deps-zero-43A48E?labelColor=171310" alt="zero external dependencies">
  <img src="https://img.shields.io/badge/cargo%20audit-in%20build-D4A24E?labelColor=171310" alt="cargo audit runs in the build">
</p>

<p align="center">
  <img src="assets/mtg-sting.jpg" width="640" alt="Sting, the Glinting Dagger — art by Nino Is, Tales of Middle-earth (2023)">
</p>

> *"Sting, the Glinting Dagger"*, which the Brazilian edition of **Magic: The Gathering** printed as
> **"Ferroada, o Punhal Reluzente"**. Art by Nino Is, Tales of Middle-earth (2023).
> The blade glows when the enemy draws near. That is exactly the job.

**Every attack comes in through the same door as legitimate traffic.** SQL injection, XSS,
path traversal, a scanner running the usual list — it all arrives as an ordinary HTTP
request, and most systems only notice once the damage is already in the log. Fixing
the backend is the right path, and also the slowest: every framework, every version,
every legacy system is a new front.

Ferroada tackles the problem at the infrastructure level: it sits **in front of your app,
on your server**, without changing a single line of it. It blocks known attacks
on the way in, masks sensitive data on the way out, and keeps a score per site and client network
— anyone acting like a scanner is slowed down before finding anything. DDoS stays with the CDN.
The one looking at your API's requests is Ferroada, on your server. Built with
[Pingora 0.8.1](https://github.com/cloudflare/pingora/releases/tag/0.8.1), Cloudflare's proxy engine,
compiled into a single binary and shipped as a ~20MB distroless container.
This version limits decoded HTTP/2 headers to 64 KiB by default and each
HTTP/2 connection to 100 concurrent streams, rejecting oversized headers with 431
before they reach the application. Ferroada pins the exact version in the manifest and in the lockfile
so that the local build, the container and CI all use the same base.

Ferroada is **not** production-grade: it lacks an external security audit
and there is no LTS line. Reporting vulnerabilities and what this covers: [SECURITY.md](SECURITY.md).

```
Internet → [Ferroada :3000] → Your System :8080
                ↓
         Dashboard 127.0.0.1:9000
```

**Multi-site:** a single deployment protects several backends at once:

```
Internet
  │
  ├── meusite.com       ──→ backend-a:8080
  ├── api.meusite.com   ──→ backend-b:3000
  └── outrosite.com     ──→ backend-c:4000
         │
    [Ferroada :3000]
         │
    Dashboard 127.0.0.1:9000
```

---

## What Ferroada protects

### Inbound layer (WAF)

| Attack | Where it inspects | Blocked example |
|--------|----------------|-------------------|
| **SQL Injection** | URI, headers and any HTTP body | `?id=1 UNION SELECT * FROM users` |
| **XSS (Cross-Site Scripting)** | URI, headers and any HTTP body | `<script>alert(1)</script>`, `onerror=`, `javascript:` |
| **Path Traversal** | URI, headers | `../../etc/passwd`, `%2e%2e%2f` |
| **CRLF Injection** | URI, headers, body | `%0d%0aSet-Cookie:` (multipart is skipped in the body) |
| **JNDI / Log4Shell** | URI, headers, body | `${jndi:ldap://...}`, including obfuscated forms |
| **Request Smuggling** | Headers | Duplicate `Content-Length`, `CL`+`TE`, invalid `TE` → 400 |
| **Sensitive Path Access** | URI path + profile | `/.env`, `/.git/`, `/phpmyadmin`, `/.aws/credentials` |
| **Bad Bots** | User-Agent | 18 signatures: sqlmap, nikto, nuclei, etc. (weak signal; the abuse quota does not depend on it) |
| **Brute Force / basic DDoS** | Site + IPv4 or IPv6 /64 prefix | Sliding-window rate limit (configured via env) |
| **Stuffing / enumeration / signup** | Composite identity (opt-in `abuse`) | The same fingerprint across different IPs shares the cap; a site without an `abuse` block is unchanged |

Application abuse protection is opt-in in the TOML (`abuse = { stuffing_max = 10, challenge = "pow" }`).
The identity combines site, /64 network, TLS fingerprint (hash of the ClientHello — version,
offered ciphers and compression; it is **not** the public JA4 string), HTTP fingerprint
(header names, without values), session, API key and `jwt.sub`. Without an MMDB file
the ASN stays empty and the process still starts. The `pow` challenge is only for browsers
(`Accept: text/html`) after the score; an API with JWT or JSON never receives HTML.
There is no ML in the hot path.

SQLi detection covers five categories — classic (`UNION SELECT`, `OR 1=1`),
stacked queries (`;DROP`), blind/time-based (`SLEEP`, `BENCHMARK`, `WAITFOR`),
function abuse (`EXTRACTVALUE`, `LOAD_FILE`) and comment evasion
(`/*!UNION*/`). XSS detection recognizes ~40 event handlers (`ontoggle`,
`onpointerover`, `onbegin`, ...) plus `confirm()`, `prompt()`, `Function()`,
`<math>`, `<base>` and `url(javascript:)`.

#### Paths blocked by default

Files and directories that should never be publicly exposed:

```
/.env  /.git/  /.svn/  /.hg/  /.DS_Store  /.htaccess  /.htpasswd
/wp-config.php
/phpmyadmin/  /phpinfo.php  /server-status  /server-info
/actuator/  /console  /debug
/config.php  /config.yml  /config.json  /database.yml
/docker-compose.yml  /Dockerfile  /.dockerenv
/.ssh/  /id_rsa  /id_ed25519  /.aws/credentials
/.bash_history  /.npmrc  /.vscode  /.idea  /web.config
```

The `generic` profile does not assume that `/wp-admin`, `/wp-login.php` and `xmlrpc.php`
are attacks. `wordpress` monitors those requests without blocking; `strict`
blocks them. Truly sensitive files, such as `wp-config.php`, remain
blocked in every profile.

L0 (regex) is always on. L1 is a Coraza sidecar with CRS 4.25 LTS over a
Unix socket, opt-in (`WAF_ENGINE=coraza`). The Ferroada binary does not link
Coraza: a crash in the ruleset does not take down the proxy. Default timeout 500 ms;
the process only marks the engine as `coraza` after the ready probe. A missing
sidecar on a `require_complete` route responds 403 and counts
`waf_engine_unavailable` — it does not silently turn the WAF off.

CRS paranoia separates `blocking` from `executing`: rules at the executing level
run without necessarily blocking. Shadow mode evaluates L1, records the rule ID and
anomaly score in the event, and does not return 403. Exclusions per site, route,
parameter and content-type live in the TOML (`[waf.l1]`, `[[sites.l1.exclusions]]`).
See `deploy/coraza/`.

OpenAPI 3.0/3.1 is opt-in per site: a path in the TOML (`openapi = "./openapi.yaml"`
or `openapi = { spec = "./openapi.yaml", unknown_endpoint = "observe" }`).
The spec is compiled at startup. Without a spec the proxy behaves exactly as
it does today. With a spec, Ferroada validates method, route, path/query/header, content-type
and the JSON body (types, required, enum, extra fields). An unknown endpoint
is observe or deny (in the pack the default is observe; on a `require_complete` route
without the key, deny). A method or content-type outside the contract: deny. The event
reports the path and the field; the body never goes into the log.

JWT/JWKS is opt-in per site (`jwt = { jwks = "...", issuer = "...", audience = "..." }`).
Without the block the site stays the same, including without `Authorization`. With the block,
the token is the identity key: alg allowlist (default only RS256/ES256;
`none` rejected; HS* only with explicit `algorithms` and `hmac_secret_env`),
`iss` and `aud` required, `exp`/`nbf`/`iat`/`jti` validated, JWKS cached
with a fetch timeout and last-known-good if the IdP goes down. Bindings in the TOML
(`jwt.sub == path.account_id`, `jwt.tenant_id == body.tenant_id`). Rate and
behavior then use the hash of `sub`/tenant, not just the IP. The token and the
payload never go into the log.

Authorization is an opt-in callback per route (`authorization = { socket =
"unix:///run/authz.sock", action = "transfer:create", resource =
"path.account_id", fail_mode = "closed" }`). Without the block the route stays
as it is today: JWT bindings if they exist, otherwise the proxy does not decide ownership.
With the block, Ferroada asks the application's service — Unix socket only,
50 ms timeout (200 ms cap) — whether that `jwt.sub` may perform the action on that
resource. The response is `{ "allow": true|false }`. Socket down or timeout:
`fail_mode = closed` returns 403; `open` lets the request through and increments the metric.
Ferroada does not embed OPA/Cedar and does not guess whether the object belongs to the
user — the contract is with the app's service. The event carries neither token nor body.

GraphQL is opt-in per site/route (`graphql = { max_depth = 8, max_operations = 5, introspection = false }`).
Without the block, `POST /graphql` only gets HTTP/WAF/OpenAPI. With the block, the
proxy parses the AST (JSON `{"query":...}`, array batch, or
`application/graphql`) and enforces caps on depth, complexity, aliases,
fragments and number of operations. Introspection (`__schema` / `__type`)
starts disabled in production. Persisted queries are a local allowlist of
SHA-256 hashes; `persisted_only = true` rejects ad-hoc queries outside the list. The cost
quota uses `jwt.sub` if the site has JWT, otherwise the IP. A failed parse becomes
`ParseError` and follows the route's policy (403 on `require_complete`). The event
reports which limit was exceeded (`depth`, `aliases`, …), never the query.

gRPC is opt-in per site (`grpc = { descriptor = "./api.pb", allow = ["pkg.Service/Method"], max_message_bytes = "64KiB", reflection = false }`).
Without the block, `application/grpc` (and `+proto`) follows the protocol matrix — currently
`deny`, or `bypass-explicit` if the operator changes it; the proxy does **not** start
inspecting on its own. With the block, the FileDescriptorSet is compiled at startup.
A method outside the allowlist returns 403 and zero bytes reach the origin. A per-message
size (read from the frame's 5-byte prefix) above `max_message_bytes`
also returns 403. The cap counts the payload; the frame on the wire is 5 bytes larger, so
a 64KiB message does not fit in the 64KiB HTTP replay without `max_decoded_body`. Reflection (`grpc.reflection.v1` / `ServerReflectionInfo`) starts
disabled; it only passes with `reflection = true`. If the client does not send
`grpc-timeout`, the proxy injects the cap (default 10s) or denies if
`require_deadline = true`. Protobuf that does not match the descriptor becomes
`ParseError` and follows the route's policy. The event carries service/method, never
the payload. DLP on protobuf fields does not exist in this scope.

#### Body inspection

The body of any allowed method is inspected before it reaches the backend.
The proxy reads **all** chunks, applies the `MAX_BODY_SIZE` cap to
`Transfer-Encoding: chunked` as well, limits the sum of concurrent buffers with
`WAF_MAX_IN_FLIGHT_BYTES` and, before reading the body, conservatively reserves
the limit for both concurrent copies (local inspection + Pingora replay). If the
client sent `Content-Encoding: gzip`
or `deflate`, the WAF inflates a copy only for inspection — the original bytes
go to the upstream only after the decision. In Pingora 0.8.1, the safe replay
before the upstream is limited to 64KB; that is why `MAX_BODY_SIZE` is also
limited to 65536 bytes, **except** on `require_complete` routes with
`max_decoded_body` — there the three caps (bytes on the wire, WAF text, inflate)
rise together to that number, the body goes to a spool and the origin only receives it
after the outcome. Without `max_decoded_body` the process does not create
`/var/lib/ferroada/spool`. The inspection records `complete`, `truncated`,
`unsupported_encoding`, `unsupported_content_type`, `parse_error`,
`budget_exceeded` or `timed_out`. A giant gzip is
cut off at the route's inflate cap (256KB by default), so a zip bomb does not
exhaust memory. Sensitive routes can require complete inspection and reject
any other state.
JSON is parsed to expose escapes such as `<`; form-urlencoded handles `+` and
percent-encoding; textual GraphQL goes through the same text canonicalization.
gRPC/binary, unknown encodings and non-textual multipart are explicitly marked
as incomplete inspection, so fail-closed routes do not forward them by
mistake.

### Behavioral analysis (behavioral scoring)

Signature rules catch the known attack; the behavior score catches whoever
is **looking** for one. Each IP accumulates points per suspicious action and loses 5
points per second of good behavior:

| Signal | Points |
|-------|--------|
| WAF block | +20 |
| 401 response | +5 |
| 404 response | +3 |
| Request without User-Agent | +8 |
| Path scan (>30 unique paths/min) | detected |
| User-Agent rotation (>3 UAs) | detected |

Past 50 points, the client is slowed down; past 80, it is banned for 10 minutes. The
identity includes site and network address; IPv6 is grouped by /64 to prevent
cheap rotation within the same prefix. The
thresholds are configurable, tracking is capped at 50 thousand IPs with LRU
cleanup, and the decay, scoring and ban logic has unit tests
(`src/behavioral.rs`).

### Infrastructure hardening

| Protection | What it does | Response |
|----------|-----------|----------|
| **Security Headers** | Injects X-Content-Type-Options, X-Frame-Options, Referrer-Policy, X-Permitted-Cross-Domain-Policies into every response | Automatic headers |
| **Server Header Stripping** | Removes `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Debug-Token`, `X-Runtime` | Infrastructure details hidden |
| **HTTP Method Restriction** | Blocks TRACE, CONNECT and unconfigured methods | 405 Method Not Allowed |
| **Request Size Limiting** | Limits the body to 64KB before the upstream and the URI to 8KB | 413 / 414 |
| **Host Validation** | Validates the Host header against the `ALLOWED_HOSTS` allowlist (prevents DNS rebinding) | 421 Misdirected Request |
| **HTTPS Enforcement** | Redirects HTTP → HTTPS when TLS is configured + injects HSTS | 301 Moved Permanently |
| **Secure dashboard** | Listens on loopback by default; an external bind requires a token, OIDC or mTLS | 401 Unauthorized |
| **Multi-encoding Protection** | Decodes URL and headers recursively (max. 8x), including `%uXXXX` and `+` as a space in the query | Prevents `%2525252e` bypass, percent-encoded XSS in headers |
| **Upstream timeouts** | `HttpPeer` with connect/read/write; the client body has its own deadline | A dead upstream does not hold the worker |
| **Rate limit with eviction** | Sliding window per site/network; expired keys leave the map; configurable cap | A flood of identities does not grow memory forever |
| **Trusted proxies** | Only accepts XFF/X-Forwarded-Proto from networks in `TRUSTED_PROXIES` | Prevents spoofing and a rate limit shared through the load balancer |
| **Limits and backpressure** | Limits headers, in-flight requests, keep-alive and writes to the client | Rejects exhaustion early with 431/503 |
| **Supply chain in CI** | `cargo audit` in the Docker build; fuzz (waf/protocol/dlp) and CycloneDX SBOM on every pull request | The job goes red if the audit finds a CVE or the fuzzer crashes |

#### Security headers — the "don't break things" philosophy

**Conservative defaults** (still need to be validated against the application):
```
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin
X-XSS-Protection: 0
X-Permitted-Cross-Domain-Policies: none
```

`X-Frame-Options` can be changed with `FRAME_OPTIONS` or preserved from the
upstream with `FRAME_OPTIONS=off`; `SAMEORIGIN` can break legitimate embeds from
another origin.

**Conditional** (only enabled when you explicitly configure them):
```
Strict-Transport-Security    → only when FORCE_HTTPS=true
Content-Security-Policy      → only when CSP_POLICY is set
Permissions-Policy           → only when PERMISSIONS_POLICY is set
```

**Removed** from the response (always):
```
Server, X-Powered-By, X-AspNet-Version, X-Debug-Token, X-Runtime
```

### Outbound layer (DLP)

| Sensitive data | Detected pattern | Masked result |
|---------------|------------------|---------------------|
| **CPF** | `390.533.447-05` (check digit) | `***.***.***-**` |
| **CNPJ** | `04.252.011/0001-10` (check digit) | `**.***.***/****-**` |
| **Card** | 13–19 digits with Luhn | digits become `*` |
| **Bearer Token** | `Bearer eyJhbGciOi...` | `Bearer [REDACTED]` |

CPF (Brazilian individual taxpayer ID) and CNPJ (Brazilian company ID) values with a wrong check digit are not masked. JSON paths (`$.user.cpf`) are
opt-in in the TOML per site or route; without them blob DLP still applies. `DLP_ACTION=block`
does not release a single byte to the client before inspection finishes.

If the backend leaks a CPF or token in a textual identity, gzip,
deflate or brotli response, Ferroada decompresses it within a limit, masks it and recompresses it.
Brotli without an inflate budget is an observable skip, not "clean". When it may
transform a response, it removes `Content-Length`, `ETag`, `Content-MD5`,
`Digest`, `Content-Digest` and `Repr-Digest`, since they would no longer represent the
bytes sent. SSE, gRPC, NDJSON, WebSocket and signed responses pass through without
transformation so the protocol is not corrupted; each skip becomes an observable event.
Range requests are removed before the upstream and unexpected partial textual
responses are rejected, preventing a `206` from bypassing the masking. The buffer is limited to
1MB per response and 64MB per process by default.

### Monitoring

<p align="center">
  <img src="assets/dashboard.png" width="880" alt="Ferroada dashboard: overview with requests, blocks, clean traffic and an event list">
</p>

The binary serves the API at `http://localhost:9000`: `/healthz`, `/readyz`,
`/api/metrics` and `/metrics`. GET `/` is not a dashboard — just a plain-text index.
With `DASHBOARD_TOKEN`, login is POST `/api/login` (token in the body, never in the
query) and opens a short session in an HttpOnly cookie. Outside loopback, a token
alone is not enough: enable OIDC (authorization code + PKCE) or mTLS (client
certificate). `viewer` reads metrics; `operator` can POST `/api/reload` with the session's CSRF
or Bearer. Without `DASHBOARD_OIDC_*` and without a client CA, the current behavior
(token) remains. This is not production-grade.

The Next dashboard (`web/`) is the interface: Overview and Events, refreshed every 5 s. If the proxy is not running, the dashboard shows zeros and `unavailable` — it does not make up traffic. Demo data only with `FERROADA_ALLOW_DEMO=true`.

```bash
cd web
npm install
cp .env.example .env.local
npm run dev    # http://localhost:3100
```

`FERROADA_URL` (default `http://127.0.0.1:9000`) and `FERROADA_TOKEN` (if
`DASHBOARD_TOKEN` is set) stay on the Next server, not in the browser. The
dashboard only delivers metrics after the visitor enters `FERROADA_WEB_TOKEN`;
that separate credential stays in the tab's `sessionStorage` and is sent as a Bearer
only to the same Next server.

---

## What Ferroada does NOT protect

These vulnerabilities are **application logic** issues and must be fixed
in the backend code — a proxy that promised to solve them would be lying:

| Vulnerability | Why a proxy does not solve it |
|----------------|--------------------------|
| **IDOR** (Insecure Direct Object Reference) | JWT bindings check claim == path/body. Ownership (may this principal access this object?) can only be answered by the app's authorization service, via the opt-in Unix socket. Without the block, the proxy does not invent that decision. |
| **Mass Assignment** | Only the backend knows which fields are allowed in each request |
| **Race Condition** | Concurrency control is the responsibility of the database/backend |
| **Weak JWT / secret** | Backend authentication configuration |
| **Plain-text passwords / unsalted hashes** | A storage decision in the database |
| **Role manipulation** | Authorization is backend business logic |
| **Social engineering** | Human factor — no software solves it |
| **Game hacking / WebSocket** | Ferroada does not inspect WebSocket traffic |

**Ferroada is the first line of defense (infrastructure), not the only one.** For
complete security, the backend needs its own validation.

---

## Quick start

A lab on your machine. For production: copy a pack from [`deploy/topologies/`](deploy/topologies/) — the dashboard stays on loopback and is **not** published to the internet.

### 1. Build

```bash
docker build -t ferroada .
```

### 2. Run

```bash
docker run -d \
  -e TARGET_URL=http://host.docker.internal:8080 \
  -e RUST_LOG=info \
  -e DASHBOARD_BIND=127.0.0.1 \
  -e DASHBOARD_TOKEN='troque-por-um-token-longo' \
  -e RATE_LIMIT_MAX=100 \
  -e RATE_LIMIT_WINDOW=60 \
  -p 3000:3000 \
  --name ferroada \
  ferroada
```

The dashboard listens on `127.0.0.1:9000` **inside** the container. In the lab, get in with `docker exec` or publish it only on the host's loopback. In production use the tunnel `ssh -L 9000:127.0.0.1:9000`.

### 3. Test

```bash
# Normal request (passthrough)
curl -i http://localhost:3000/

# SQL Injection → 403
curl -i "http://localhost:3000/?id=1 UNION SELECT * FROM users"

# XSS → 403
curl -i "http://localhost:3000/?q=<script>alert(1)</script>"

# Path Traversal → 403
curl -i "http://localhost:3000/../../etc/passwd"

# Sensitive path → 403
curl -i http://localhost:3000/.env
curl -i http://localhost:3000/.git/config

# Body injection (POST) → 403
curl -i -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","pass":"x\" OR 1=1--"}'

# Rate limit → 429 (after 100 requests)
for i in $(seq 1 105); do
  curl -s -o /dev/null -w "%{http_code} " http://localhost:3000/
done

# Dashboard (only if you published the host's loopback)
curl -H 'Authorization: Bearer troque-por-um-token-longo' \
  http://127.0.0.1:9000/api/metrics
```

---

## Installation modes

The binary is a Pingora process. It does not run on Hostinger or as a function on Vercel. Each folder in `deploy/topologies/` is a fail-closed pack: toml, env, Compose, systemd unit, origin-lock and an honest `VISIBILIDADE.md`.

| Mode | When to use |
|------|-------------|
| [`vps-site`](deploy/topologies/vps-site/) | VPS with the site (frontend + backend) |
| [`vps-api`](deploy/topologies/vps-api/) | VPS with the API only |
| [`vps-supabase-selfhost`](deploy/topologies/vps-supabase-selfhost/) | API + self-hosted Supabase (Kong) |
| [`vps-supabase-cloud`](deploy/topologies/vps-supabase-cloud/) | API on the VPS, Supabase Cloud |
| [`vps-full`](deploy/topologies/vps-full/) | Everything on the VPS |
| [`hostinger-origin`](deploy/topologies/hostinger-origin/) | Static site on Hostinger; Ferroada on a VPS in front |
| [`vercel-origin`](deploy/topologies/vercel-origin/) | App on Vercel; Ferroada on a VPS in front |
| [`cdn-edge`](deploy/topologies/cdn-edge/) | Internet → CDN → Ferroada → backend (recommended) |
| [`Helm`](deploy/helm/ferroada/) | Kubernetes (rootless pod; the dashboard is not a Service) |

Start with the mode's `CHECKLIST.md`. TLS: Ferroada terminates it if there is a `fullchain.pem`; otherwise Caddy sits in front. The two never publish 443 at the same time. Edge CIDRs: `deploy/cidrs/` (dated snapshot, no fetch inside the process).

```bash
ferroada init --topology vps-api --origin http://127.0.0.1:8080 --public-host api.exemplo.com --non-interactive
ferroada init --topology cdn-edge --origin http://127.0.0.1:8080 --public-host api.exemplo.com --trusted-proxies auto --non-interactive
ferroada healthcheck   # GET 127.0.0.1:9000/healthz; exit 0/1. Distroless has no curl.
ferroada reload        # SIGHUP: tries the new TOML; if it fails, last-known-good
ferroada policy compile --config ferroada.toml -o ferroada.policy.json
ferroada policy sign --key priv.pem --in ferroada.policy.json -o ferroada.policy.sig
```

`--trusted-proxies auto` copies the snapshot in `deploy/cidrs/` (embedded in the binary). Zero HTTP. To update the list: `ferroada cidrs update` (HTTP only in this command; `--cidrs-from-network` does not exist in `init`). `--listen-mode privileged` emits :80/:443 **and** `CAP_NET_BIND_SERVICE`; `proxied` keeps the process on 127.0.0.1:3000 with Caddy in front.

---

## Configuration

All configuration is done through environment variables:

| Variable | Default | Description |
|----------|---------|-----------|
| `TARGET_URL` | *(required\*)* | URL of the upstream system — single-site mode (e.g. `http://meu-sistema:8080`) |
| `RUST_LOG` | `info` | Log level (`debug`, `info`, `warn`, `error`) |
| `RATE_LIMIT_MAX` | `100` | Maximum requests per site/network within the window |
| `RATE_LIMIT_WINDOW` | `60` | Time window in seconds |
| `RATE_LIMIT_MAX_IPS` | `50000` | Cap on risk identities in the map (eviction above it) |
| `REPLICA_COUNT` | `1` | Conservatively splits the rate/behavior budgets across replicas |
| `RISK_SESSION_COOKIE` | `session` | Session cookie included (hashed) in the risk identity |
| `RISK_API_KEY_HEADER` | `X-API-Key` | API key header included (hashed) in the risk identity |
| `UPSTREAM_CONNECT_TIMEOUT` | `5` | Seconds for `connect()` to the backend |
| `UPSTREAM_READ_TIMEOUT` | `30` | Maximum seconds reading the backend's response |
| `UPSTREAM_WRITE_TIMEOUT` | `30` | Maximum seconds writing to the backend |
| `BODY_READ_TIMEOUT` | `10` | Maximum seconds reading the client's body |
| `DOWNSTREAM_WRITE_TIMEOUT` | `30` | Maximum seconds writing the response to the client |
| `DOWNSTREAM_KEEPALIVE_SECS` | `30` | Idle timeout of the HTTP/1 connection with the client |
| `DOWNSTREAM_KEEPALIVE_REQUESTS` | `100` | Maximum requests reusing the same HTTP/1 connection |
| `MAX_IN_FLIGHT_REQUESTS` | `1024` | Cap on concurrent requests; the excess receives 503 |
| `CONNECTION_RATE_MAX` | `60` | New connections accepted per IP within the window, before TLS/HTTP |
| `CONNECTION_RATE_WINDOW` | `1` | Window of the connection limit, in seconds |
| `CONNECTION_RATE_MAX_IPS` | `50000` | Cap on IPs tracked by the connection filter |
| `GLOBAL_CONNECTION_RATE_MAX` | `10000` | New global connections accepted per window, before TLS/HTTP |
| `MAX_ACTIVE_CONNECTIONS` | `10000` | Cap on active downstream sessions, including those waiting for HTTP/1 headers |
| `MAX_HEADER_COUNT` | `100` | Maximum headers per request |
| `MAX_HEADER_BYTES` | `65536` | Maximum sum of header names and values |
| `MAX_UPSTREAM_RETRIES` | `0` | Retries after the first attempt; capped at 3. With several origins, GET/HEAD/OPTIONS get at least 1 retry if the origin resets before responding. POST/PATCH are not retried. |
| `PROXY_THREADS` | Available CPUs (max. 64) | Threads per service |
| `GRACE_PERIOD_SECS` | `5` | Wait before the final phase of graceful shutdown |
| `GRACEFUL_SHUTDOWN_TIMEOUT_SECS` | `30` | Limit of the final phase of graceful shutdown |
| `TLS_CERT_PATH` | *(optional)* | Path to the TLS certificate (fullchain.pem) |
| `TLS_KEY_PATH` | *(optional)* | Path to the TLS private key |
| `PROXY_LISTEN` | `0.0.0.0:3000` | HTTP listener address |
| `TLS_LISTEN` | `0.0.0.0:3443` | HTTPS listener address (only with `TLS_CERT_PATH`/`TLS_KEY_PATH`) |
| `DASHBOARD_PORT` | `9000` | Monitoring dashboard port |
| `DASHBOARD_BIND` | `127.0.0.1` | Dashboard IP; a non-loopback bind requires a token (or OIDC/mTLS) |
| `DASHBOARD_TOKEN` | *(empty on loopback)* | Bearer token. `FERROADA_PRODUCTION=true` requires it even on loopback, even with OIDC/mTLS. Without production, a bind outside loopback accepts a token **or** OIDC/mTLS. On loopback the token alone remains valid. |
| `DASHBOARD_OIDC_ISSUER` / `DASHBOARD_OIDC_CLIENT_ID` / `DASHBOARD_OIDC_REDIRECT_URI` | *(unset = off)* | Opt-in OIDC (authorization code + PKCE). Without these and without `DASHBOARD_MTLS_CA` the dashboard remains token-only. |
| `DASHBOARD_OIDC_CLIENT_SECRET` | *(optional)* | Confidential secret; never goes in the URL. PKCE runs anyway. |
| `DASHBOARD_OIDC_ROLE_CLAIM` | `ferroada_role` | ID token claim mapped to `viewer` or `operator`. |
| `DASHBOARD_OIDC_OPERATORS` / `DASHBOARD_OIDC_VIEWERS` | `operator` / `viewer` | Claim values that grant each role. Without operator, POST `/api/reload` is 403. |
| `DASHBOARD_MTLS_CA` | *(unset)* | CA for client certificates. Requires `DASHBOARD_TLS_CERT_PATH`/`DASHBOARD_TLS_KEY_PATH`. The handshake verifies the cert if the client sends one. Outside loopback the API requires the cert (or an OIDC session). |
| `DASHBOARD_MTLS_OPERATORS` / `DASHBOARD_MTLS_VIEWERS` | *(empty = viewer)* | CNs with the operator/viewer role. |
| `DASHBOARD_SESSION_TTL_SECS` | `900` | `HttpOnly`, `SameSite=Strict` cookie, `Secure` if the dashboard speaks TLS. Min. 60, max. 8h. |
| `DASHBOARD_AUDIT_LOG` | *(unset)* | Append-only JSONL file (login, reload, auth failure). Does not record the token or the OIDC code. |
| `DASHBOARD_API_RATE_MAX` / `DASHBOARD_API_RATE_WINDOW` | `60` / `60` | Cap on requests to `/api` per IP and window in seconds. |
| `FERROADA_PRODUCTION` | *(unset)* | If `true`, the token is required even on 127.0.0.1. GET `/` on `:9000` is only the plain-text index; `/api/metrics` and `/metrics` require a session, Bearer (loopback) or mTLS. |
| `FERROADA_POLICY_PUBKEY` | *(unset)* | Ed25519 public key (PEM, hex or base64). Opt-in: without it a bare TOML starts. With it, the snapshot needs a valid `ferroada.policy.sig` |
| `FERROADA_POLICY_SIG` | `ferroada.policy.sig` | Ed25519 signature of the snapshot (`ferroada policy compile`) |
| `FERROADA_PID_FILE` | `ferroada.pid` | Written at boot; `ferroada reload --pid-file` reads from here |
| `OTEL_EXPORTER_OTLP_ENDPOINT` / `FERROADA_OTLP_ENDPOINT` | *(unset = off)* | HTTP base of the OTLP Collector (`http://127.0.0.1:4318`). Without it the process opens no extra socket. HTTPS and userinfo in the URL are rejected; the export never sends `Authorization`. |
| `OTEL_EXPORTER_OTLP_TIMEOUT` | `1000` | OTLP POST timeout in milliseconds (5s cap). A dead Collector increments `ferroada_otel_export_failed_total` and the proxy keeps going. |
| `TRUSTED_PROXIES` | *(empty)* | CIDRs allowed to send XFF/X-Forwarded-Proto |
| `PROXY_PROTOCOL` | `false` | PROXY v2 parser (not a Pingora flag). `true` only behind HAProxy/nginx/Caddy/TCP NLB. An invalid prefix rejects the connection. Cloudflare does **not** turn this on |
| `CLIENT_IP_ORDER` | `proxy_protocol,x-forwarded-for` | Order of IP sources. `Forwarded` (RFC 7239) is only used if listed; the default still strips hop-by-hop |
| `CLIENT_IP_HEADER` | *(unset)* | Extra header (e.g. `cf-connecting-ip`) only if `CLIENT_IP_ORDER` includes `header` |
| `FERROADA_ALLOW_DEMO` | *(unset)* | If `true`, the Next dashboard makes up metrics while the proxy is down. Production: do not enable |
| `SECURITY_HEADERS` | `true` | Inject secure headers into responses (nosniff, X-Frame, Referrer) |
| `FRAME_OPTIONS` | `SAMEORIGIN` | X-Frame-Options value; `off` preserves the upstream's |
| `CSP_POLICY` | *(disabled)* | Content-Security-Policy — only enable it if you know what you are doing |
| `PERMISSIONS_POLICY` | *(disabled)* | Permissions-Policy — only enable it if you don't use camera/mic/geolocation |
| `ALLOWED_METHODS` | `GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS` | Allowed HTTP methods |
| `MAX_BODY_SIZE` | `65536` | Maximum body size; larger values are capped at 64KB by Pingora 0.8.1's safe replay. Routes with `max_decoded_body` use that cap instead. |
| `SPOOL_DIR` | *(unset = off)* | Spool directory; only validated/cleaned if some route has `max_decoded_body`. Default in that mode: `/var/lib/ferroada/spool` |
| `SPOOL_MAX_BYTES` | `536870912` | Aggregate cap on spool bytes (512 MiB) |
| `SPOOL_MAX_FILES` | `256` | Cap on concurrent `spool-*` files |
| `WAF_MAX_IN_FLIGHT_BYTES` | `67108864` | Global reservation for the local copy, the Pingora replay and the decompressed inspection buffer (256 KiB + sentinel byte) |
| `MAX_URI_LENGTH` | `8192` | Maximum URI size in bytes (8KB) |
| `ALLOWED_HOSTS` | *(disabled)* | Allowlist of domains in the Host header (e.g. `meusite.com,www.meusite.com`) |
| `FORCE_HTTPS` | `false` | Redirect HTTP → HTTPS (requires TLS to be configured) |
| `HTTPS_REDIRECT_HOST` | *(empty)* | Trusted public host for redirects in single-site/default mode |
| `DLP_ENABLED` | `true` | Enables DLP inspection of CPF/CNPJ/card numbers and tokens in responses |
| `DLP_ACTION` | `redact` if unset and `DLP_ENABLED=true` | `monitor` (counts, does not mask), `redact` (masks), `block` (502 if PII is found or the buffer overflows). Production packs emit `monitor` |
| `ORIGIN_SECRET_HEADER` | `X-Ferroada-Origin` if only `ORIGIN_SECRET` exists | Name of the header injected upstream. Unset with an empty secret = not injected |
| `ORIGIN_SECRET` | *(unset)* | Value of the origin header. Never logged. Empty = not injected |
| `DLP_MAX_RESPONSE_BYTES` | `1048576` | Maximum buffer per textual response inspected by DLP |
| `DLP_MAX_IN_FLIGHT_BYTES` | `67108864` | Global memory budget for concurrent DLP buffers |
| `BAD_BOT_ENABLED` | `true` | Blocking by User-Agent signature (sqlmap, nikto, ...) |
| `WAF_PROFILE` | `generic` | `generic`, `wordpress` (monitor) or `strict` for WordPress operational paths |
| `WAF_REQUIRE_COMPLETE_PATHS` | *(empty)* | Fail-closed prefixes in single-site mode, comma-separated |
| `WAF_ENGINE` | `native` | `native` (L0 only) or `coraza` (L1 sidecar; requires Unix socket and ready probe) |
| `WAF_SIDECAR_SOCKET` | `/run/coraza/waf.sock` | Socket of the L1 sidecar |
| `WAF_SIDECAR_TIMEOUT_MS` | `500` | Cap on the L1 call. 20 ms would return 403 on clean traffic during the CRS cold start |
| `BEHAVIORAL_ENABLED` | `true` | Behavior score per site/network |
| `BEHAVIORAL_SLOW_THRESHOLD` | `50` | Points before the IP starts being slowed down |
| `BEHAVIORAL_BLOCK_THRESHOLD` | `80` | Points to ban the IP |
| `BEHAVIORAL_BAN_SECS` | `600` | Ban duration in seconds |
| `BEHAVIORAL_MAX_IPS` | `50000` | Cap on tracked IPs (LRU cleanup above it) |

*\* `TARGET_URL` is required only in single-site mode. In multi-site mode, use `ferroada.toml`.*

### Multi-site

To protect several backends with a single deployment, create a `ferroada.toml` file:

```toml
# Complete and commented: ferroada.toml.example

[[sites]]
hosts = ["meusite.com", "www.meusite.com"]
backend = "http://backend-a:8080"
# backend = ["http://a:8080", "http://b:8080"]  # round-robin + health GET /health/ready
waf_profile = "wordpress"
require_complete_waf_inspection = ["/api/payment", "/api/admin/"]

[[sites]]
hosts = ["api.meusite.com"]
backend = "http://backend-b:3000"
# Opt-in. Without the block, the site stays HTTP/WAF/DLP only.
# openapi = { spec = "./openapi.yaml", unknown_endpoint = "observe" }
# jwt = { jwks = "https://auth.exemplo.com/.well-known/jwks.json", issuer = "https://auth.exemplo.com", audience = "api.meusite.com", bindings = ["jwt.sub == path.account_id"] }
# abuse = { stuffing_max = 10, challenge = "pow" }
# [[sites.routes]]
# prefix = "/accounts/"
# authorization = { socket = "unix:///run/authz.sock", action = "account:read", resource = "path.account_id", fail_mode = "closed" }
```

Routing is done automatically by each request's Host header. Unconfigured
hosts receive `421 Misdirected Request`.

**Rules:**
- If `ferroada.toml` exists → multi-site mode (ignores `TARGET_URL`)
- If it does not exist → uses `TARGET_URL` as before (backward compatible)
- Rate limit and behavioral scoring are isolated per site; IPv6 is aggregated by /64
- WAF/DLP do not keep decisions across sites; metrics remain global to the process
- The `ALLOWED_HOSTS` env var still works as an additional restriction

```bash
# Multi-site with Docker (lab). Production: deploy/topologies/
docker run -d \
  -v ./ferroada.toml:/ferroada.toml:ro \
  -e DASHBOARD_BIND=127.0.0.1 \
  -e DASHBOARD_TOKEN='troque-por-um-token-longo' \
  -p 3000:3000 \
  ferroada
```

### HTTPS (TLS termination)

For production, configure TLS to accept HTTPS on port 3443:

```bash
docker run -d \
  -e TARGET_URL=http://backend:8080 \
  -e TLS_CERT_PATH=/certs/fullchain.pem \
  -e TLS_KEY_PATH=/certs/privkey.pem \
  -e DASHBOARD_BIND=127.0.0.1 \
  -e DASHBOARD_TOKEN='troque-por-um-token-longo' \
  -v /etc/letsencrypt/live/meudominio:/certs:ro \
  -p 443:3443 \
  -p 80:3000 \
  ferroada
```

---

## Integration with existing systems

### Docker Compose (single-site)

```yaml
services:
  ferroada:
    build: ./ferroada
    ports:
      - "80:3000"
    environment:
      - TARGET_URL=http://app:8080
      - RATE_LIMIT_MAX=100
      - DASHBOARD_BIND=127.0.0.1
      - DASHBOARD_TOKEN=${FERROADA_DASHBOARD_TOKEN}
    depends_on:
      - app

  app:
    image: seu-sistema:latest
    expose:
      - "8080"
```

The dashboard is not published to the internet. Tunnel: `ssh -L 9000:127.0.0.1:9000`. In the Docker packs the mapping is only `127.0.0.1:9000` on the host. Complete packs: `deploy/topologies/`.

### Docker Compose (multi-site)

```yaml
services:
  ferroada:
    build: ./ferroada
    ports:
      - "80:3000"
    environment:
      - DASHBOARD_BIND=127.0.0.1
      - DASHBOARD_TOKEN=${FERROADA_DASHBOARD_TOKEN}
    volumes:
      - ./ferroada.toml:/ferroada.toml:ro
    depends_on:
      - site-a
      - site-b

  site-a:
    image: meusite:latest
    expose:
      - "8080"

  site-b:
    image: outrosite:latest
    expose:
      - "3000"
```

### Nginx (pointing to Ferroada)

```nginx
location / {
    proxy_pass http://localhost:3000;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

Set `TRUSTED_PROXIES` to the actual CIDR of the Nginx network. Without it,
Ferroada ignores XFF and uses the remote socket. A peer outside that allowlist
cannot change its identity by sending its own headers.

### AWS / Cloud

Point the ALB/Target Group at port 3000 of the Ferroada container instead of
directly at the backend.

### Production behind an edge

The recommended design is `Internet → Cloudflare/CDN/LB → Ferroada → backend`.
DDoS stays with the CDN. The one looking at your API's requests is Ferroada, on your server.
Restrict the origin to accept only the edge (firewall, private tunnel or
mTLS) and register its CIDRs in `TRUSTED_PROXIES`. Ferroada does not replace
Anycast or L3/L4 DDoS mitigation: if the machine's link saturates, the process
has no way to respond with 429.

State remains local to each replica. With multiple replicas, configure
`REPLICA_COUNT`: Ferroada splits the rate budgets and the behavior
thresholds to keep the aggregate limit conservative even without a store. Bans and
history are not replicated; keep client affinity or apply the distributed
layer at the edge. Logs go to stdout for the platform's collector.
`GET /healthz` confirms the process; `GET /readyz` checks the backends with a deadline
and returns 503 if any of them is unavailable. These routes do not require a token;
`/api/metrics` and `/metrics` use the dashboard's authentication.

---

## Architecture

```
src/
├── proxy.rs         # Pipeline: Host → route → method/size → rate → behavioral → abuse → WAF L0/L1 → OpenAPI/JWT/GraphQL/gRPC/authz → origin → DLP
├── protocol.rs      # inspect/deny/monitor/bypass matrix (and quarantine = 403 + tag)
├── waf.rs / waf_engine.rs / waf_l1.rs  # L0 regex; L1 Coraza sidecar
├── spool.rs         # Body > 64 KiB only on a fail-closed route with max_decoded_body
├── openapi.rs / jwt.rs / graphql.rs / grpc.rs / authz.rs
├── abuse.rs         # Per-fingerprint quota (opt-in)
├── dlp.rs           # Blob + JSON path; monitor/redact/block
├── policy.rs        # Signed snapshot and last-known-good
├── origin.rs        # Multiple backends, health, circuit
├── otel.rs          # Opt-in OTLP
├── proxy_protocol.rs / client_ip.rs
└── dashboard.rs / dashboard_oidc.rs / dashboard_auth.rs
deploy/topologies/   # VPS / Hostinger / Vercel / CDN packs
deploy/helm/ferroada/
web/                 # Next dashboard (zeros if the proxy goes down, no demo)
fuzz/                # waf, protocol, dlp — runs in PR CI
```

### Request pipeline

```
Client
  │
  ▼
[HTTPS Redirect] ──301──→ Client (if FORCE_HTTPS and HTTP request)
  │ ok
  ▼
[Host Check] ──421──→ Client (Host not allowed, DNS rebinding)
  │ ok
  ▼
[Route Backend] ──421──→ Client (Host without a configured site, multi-site)
  │ ok
  ▼
[Method Check] ──405──→ Client (TRACE, CONNECT, etc.)
  │ ok
  ▼
[Size Check] ──413/414──→ Client (body/URI too large)
  │ ok
  ▼
[Rate Limiter] ──429──→ Client (Too Many Requests)
  │ ok
  ▼
[Behavioral Score] ──403──→ Client (IP above the ban threshold)
  │ ok
  ▼
[Abuse quotas] ──403──→ stuffing/enumeration (opt-in; same fingerprint, different IPs)
  │ ok
  ▼
[WAF L0 + L1] ──403──→ regex and, if enabled, the Coraza sidecar
  │ ok
  ▼
[OpenAPI / JWT / GraphQL / gRPC / authz] ──403/401──→ only if the site has the block in the TOML
  │ ok
  ▼
[Upstream Backend]
  │
  ▼
[Strip Server Headers] → Removes Server, X-Powered-By, etc.
  │
  ▼
[Inject Security Headers] → HSTS, CSP, X-Frame-Options, etc.
  │
  ▼
[DLP: Response Masking] → CPF/CNPJ/card numbers and tokens masked
  │
  ▼
Client (clean, hardened response)
```

---

## Stack

- **Pingora 0.8** (Cloudflare) — high-performance HTTP proxy
- **Rust** — single binary, no runtime, no garbage collector
- **Distroless** — Docker image with no shell and no package manager (~20MB)
- **Zero external dependencies** — no need for Redis, a database or any auxiliary service
- **Not production-grade yet** — lacks an external audit and LTS. See [SECURITY.md](SECURITY.md).
