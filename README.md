# CIMI — Cyber Incident Monitor in India

A real-time, **STIX 2.1-compliant threat-intelligence aggregation platform** purpose-built
around Indian cyberspace.

CIMI ingests CERT-In advisories alongside live queries to VirusTotal, AbuseIPDB and
AlienVault OTX, cross-references vulnerabilities against the CISA Known Exploited
Vulnerabilities catalog, normalises everything to the STIX 2.1 object model, and blends the
results into a single composite verdict per Indicator of Compromise.

> **Major Project · Session 2026–27**
> Department of Computer Science and Engineering (Cyber Security)
> G H Raisoni College of Engineering & Management, Nagpur
> **Team:** Lobh Dhomne (H19), Riya Adhe (H30), Vaishnavi Rokade (H54)
> **Guide:** Saurabh Vyas, Assistant Professor

---

## 1. Quick start

```bash
# 1. install dependencies (5 packages, no build step)
npm install

# 2. create your config
cp .env.example .env

# 3. run
npm start
```

Open **http://localhost:3000** and sign in with:

| | |
|---|---|
| Username | `analyst` |
| Password | `Cimi@2026` |

Both are configurable in `.env` (`DEFAULT_ADMIN_USER` / `DEFAULT_ADMIN_PASSWORD`).
The account is created automatically on first boot.

Run the test suite at any time:

```bash
npm test     # 37 checks: unit + full API + static assets
```

### Requirements

* **Node.js 18 or newer** (uses the built-in `fetch`). Node 20/22 recommended.
* No database server, no build tooling, no bundler. Tailwind is vendored at
  `public/vendor/tailwind.js`, so the interface works fully offline.

---

## 2. API keys (optional)

CIMI runs **with or without** provider credentials.

| Provider | Env variable | Free tier | Without a key |
|---|---|---|---|
| VirusTotal | `VIRUSTOTAL_API_KEY` | 4 req/min, 500/day | falls back to the simulator |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | 1,000 checks/day | falls back to the simulator |
| AlienVault OTX | `OTX_API_KEY` | generous | falls back to the simulator |
| CISA KEV | — (public feed) | unlimited | offline sample catalog |
| CERT-In | — (scraped) | — | offline advisory sample |

**The simulator** is a deterministic offline intelligence generator: the verdict for an
indicator is derived from a SHA-256 of the indicator itself, so the same value always
produces the same result — reproducible for demonstrations and viva. Everything it
produces is tagged `simulated: true` and the UI shows a **SIMULATED** badge, so it can
never be mistaken for live data.

Add a key to `.env` and restart — that source switches to live automatically, and the
sidebar status changes from `sim` to `live`.

Set `FORCE_DEMO_MODE=true` to force the simulator even when keys are present.

---

## 2b. Deployment — set up once, then forget it

CIMI is fully self-contained: one container, one persistent volume, no database.
Nothing needs to be re-done after the first setup — the admin account, the JWT signing
secret and all history live in the volume and survive restarts, reboots and image updates.

### Option A — Docker Compose (recommended, any VPS)

```bash
git clone <this repo> cimi && cd cimi
cp .env.example .env          # add your API keys; change DEFAULT_ADMIN_PASSWORD
docker compose up -d          # → http://<server-ip>:3000
```

For a public hostname with **automatic HTTPS** (Let's Encrypt), point your domain's A
record at the server, set `DOMAIN=cimi.example.com` in `.env`, and start the TLS profile
instead:

```bash
docker compose --profile tls up -d     # → https://cimi.example.com
```

Certificates are obtained and renewed automatically by Caddy. The container restarts on
crash and on reboot (`restart: unless-stopped`).

Updating later is two commands: `git pull && docker compose up -d --build`.

Already running nginx/Apache on the same host? Skip the `tls` profile and add a
`proxy_pass http://127.0.0.1:3000;` location to your existing site — the app already
sets `trust proxy`.

### Option B — Render / Railway / Fly.io

These platforms detect the `Dockerfile` automatically. Set the environment variables
from `.env.example` in the platform's dashboard and attach a persistent disk mounted at
`/app/data`. Without a persistent disk the store resets on every deploy.

### Option C — bare Node.js with a process manager

```bash
npm ci --omit=dev
npm i -g pm2
pm2 start server.js --name cimi && pm2 save && pm2 startup
```

### What persists where

| Item | Location (in the volume / `data/`) |
|---|---|
| Analyst accounts, MFA secrets | `users.json` |
| Lookup history, log reports | `ioc_history.json`, `log_reports.json` |
| JWT signing secret (auto-generated once) | `jwt.secret` |

Back up the volume (`docker run --rm -v cimi-data:/d -v $PWD:/b alpine tar czf /b/cimi-backup.tgz /d`)
and you have everything.

---

## 3. Architecture

Three tiers. The frontend never talks to an external API: every request is proxied,
cached and rate-limited through the backend, which is the only component holding
provider keys.

```
┌──────────────────────────────────────────────────────────────────┐
│  PRESENTATION — Tailwind CSS single-page app (public/)           │
│  Login (JWT + MFA) · Dashboard · IoC Lookup · Threat Correlation │
│  Log Analysis · Threat Intelligence Feeds · Settings             │
└───────────────────────────────┬──────────────────────────────────┘
                                │ REST + Bearer JWT
┌───────────────────────────────▼──────────────────────────────────┐
│  APPLICATION — Node.js / Express (src/)                          │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ Routes: auth · ioc · correlation · logs · feeds · dashboard │  │
│  │ Middleware: JWT auth · rate limiting · Helmet · CORS        │  │
│  ├────────────────────────────────────────────────────────────┤  │
│  │ Aggregation service — parallel fan-out + composite scoring  │  │
│  │ STIX 2.1 normaliser · MITRE ATT&CK mapper                   │  │
│  │ Correlation engine · Log analyser · CERT-In scraper         │  │
│  │ In-memory TTL cache (15 min default, 6 h for CISA KEV)      │  │
│  └────────────────────────────────────────────────────────────┘  │
└───────────────┬──────────────────────────────┬───────────────────┘
                │                              │
┌───────────────▼──────────────┐  ┌────────────▼───────────────────┐
│ DATA — flat-file JSON store  │  │ EXTERNAL SOURCES               │
│ users.json · ioc_history.json│  │ VirusTotal · AbuseIPDB · OTX   │
│ log_reports.json             │  │ CISA KEV · CERT-In             │
│ scrypt-hashed credentials    │  │                                │
└──────────────────────────────┘  └────────────────────────────────┘
```

### Request flow for a single IoC lookup

1. Analyst submits an indicator on the **IoC Lookup** page.
2. The API auto-detects the type — IP / domain / URL / MD5 / SHA-1 / SHA-256 / CVE.
3. The aggregation service queries every applicable source **in parallel**, falling back to
   cache (including stale cache) when a source is rate-limited.
4. Results are normalised into STIX 2.1 observables, blended into a weighted composite
   verdict, and mapped to MITRE ATT&CK techniques.
5. The result is persisted to `ioc_history.json` and returned with its STIX bundle.

### Composite scoring

Sources are blended by weight — VirusTotal 0.45, AbuseIPDB 0.30, OTX 0.25 — normalised
over the sources that actually answered, so a rate-limited provider reduces *confidence*
rather than dragging the *score* to zero. Two independent malicious votes add a +12
corroboration bonus, three add a further +8, and a CISA KEV hit (exploited in the wild)
floors the score at 85.

Verdict bands: **≥65 malicious · 30–64 suspicious · <30 clean.**

---

## 4. Modules

### Security Dashboard
KPI tiles, a 14-day stacked verdict-trend chart, verdict donut, geographic distribution,
top ATT&CK techniques and indicator-type split — all computed from the analyst's own
lookup history, with no additional data entry. Charts are hand-built SVG: no chart
library, no CDN.

### IoC Lookup
Single and bulk (up to 25) indicator screening. Shows a source-wise breakdown with each
provider's raw statistics, the blended verdict, the ATT&CK mapping with the evidence that
matched, a 14-day reputation timeline, and a live preview of the STIX 2.1 bundle —
downloadable for SOAR/SIEM ingestion.

### Threat Correlation
Groups indicators that share OTX pulses, tags, malware families, geography or ATT&CK
techniques. Edge weight is Jaccard similarity over the combined signal sets; an edge
requires either a *strong* signal (a shared pulse or malware family) or at least two
shared signals, so a common country alone never invents a campaign. Connected components
of the resulting graph are reported as campaign clusters and drawn as a radial network.

### Log Analysis
Upload or paste a raw log (≤2 MB). Regex extraction pulls out public IPs (private ranges
are excluded), domains, URLs and MD5/SHA-1/SHA-256 hashes plus CVE IDs, ranks them by
frequency, and auto-screens the **15 most frequent unique indicators** against live
intelligence. The log format is auto-detected (Apache/Nginx, Linux auth, firewall, JSON
lines, CSV, timestamped application logs).

### Threat Intelligence Feeds
CERT-In advisories, the CISA KEV catalog, OTX pulses, and a **feed-health view** scoring
each source on availability, volume and freshness. Advisories can be exported as a STIX
2.1 bundle of `vulnerability` SDOs.

### Security
* **JWT** sessions — HS256, implemented directly on `node:crypto` (no `jsonwebtoken`
  dependency), with timing-safe signature comparison.
* **scrypt** password hashing (N=16384, r=8, p=1) with per-user salts; the login path does
  equivalent work for unknown users to prevent account enumeration.
* **TOTP MFA** (RFC 6238) with ±1 step drift tolerance, also dependency-free.
* **Helmet** security headers with a strict Content-Security-Policy.
* **Rate limiting** — 300 requests / 15 min globally, 20 / 15 min on auth endpoints.

---

## 5. STIX 2.1 compliance

Every lookup emits a spec-shaped bundle. Object IDs are deterministic UUIDv5-style
identifiers derived from the indicator, so the same indicator always produces the same
STIX ID across runs and installations.

| STIX object | Emitted for |
|---|---|
| `indicator` (SDO) | every lookup, with a STIX patterning expression |
| `ipv4-addr` / `domain-name` / `url` / `file` (SCO) | the observable itself |
| `observed-data` (SDO) | wraps the SCO |
| `attack-pattern` (SDO) | each mapped MITRE ATT&CK technique |
| `relationship` (SRO) | `indicator --indicates--> attack-pattern` |
| `vulnerability` (SDO) | CERT-In advisories and KEV entries |
| `bundle` | the container |

Example pattern for an IP indicator:

```
[ipv4-addr:value = '185.220.101.44']
```

---

## 6. API reference

All endpoints except `/api/health` and `/api/auth/*` require
`Authorization: Bearer <token>`.

### Auth
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/auth/login` | `{username, password, mfaToken?}` → `{token, user}` or `{mfaRequired:true}` |
| POST | `/api/auth/register` | create an analyst account |
| GET | `/api/auth/me` | current session user |
| POST | `/api/auth/mfa/setup` | returns a TOTP secret + `otpauth://` URL |
| POST | `/api/auth/mfa/confirm` | `{token}` — enables MFA |
| POST | `/api/auth/mfa/disable` | `{password}` |

### Indicators
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/ioc/lookup` | `{indicator, type?}` — single lookup |
| POST | `/api/ioc/bulk` | `{indicators: []}` — up to 25 |
| GET | `/api/ioc/detect?value=` | type-detection helper |
| GET | `/api/ioc/history?limit=&verdict=` | lookup history |
| DELETE | `/api/ioc/history` | clear history |
| POST | `/api/ioc/stix` | STIX 2.1 bundle for one or more indicators |

### Analysis
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/correlation` | `{indicators: []}` — nodes, edges, clusters |
| GET | `/api/correlation/history?limit=` | correlate recent lookups |
| POST | `/api/logs/analyse` | `{content, fileName?}` — extract + screen |
| GET | `/api/logs/reports` | past log reports |
| GET | `/api/logs/reports/:id` | one report |
| GET | `/api/dashboard?days=14` | full dashboard payload |

### Feeds
| Method | Path | Purpose |
|---|---|---|
| GET | `/api/feeds/certin?limit=&severity=&q=&refresh=` | CERT-In advisories |
| GET | `/api/feeds/kev?limit=&q=` | CISA KEV catalog |
| GET | `/api/feeds/otx?limit=` | OTX pulses |
| GET | `/api/feeds/health` | feed health + data-quality scores |
| GET | `/api/feeds/certin/stix` | advisories as a STIX bundle |
| GET | `/api/health` | service status (public) |

**Example**

```bash
TOKEN=$(curl -s localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"analyst","password":"Cimi@2026"}' | jq -r .token)

curl -s localhost:3000/api/ioc/lookup \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"indicator":"185.220.101.44"}' | jq '.verdict, .score'
```

---

## 7. The CERT-In scraper

CERT-In publishes vulnerability notes from a Java servlet endpoint protected by
request-pattern and rate-limiting controls, which surface as intermittent
`RemoteDisconnected` errors — the principal engineering risk identified in the synopsis.

`src/services/providers/certin.js` addresses this with:

* a complete set of browser-like request headers (`Sec-Fetch-*`, `Accept-Language`,
  `Referer`, `Upgrade-Insecure-Requests`, realistic `User-Agent`);
* **exponential back-off retry** (3 attempts, 900 ms → 1.8 s → 3.6 s), skipping retries
  on 4xx responses other than 429;
* a tolerant HTML table parser that pulls advisory IDs (`CIVN-`/`CIAD-`), titles,
  severities, dates and CVE references;
* **graceful degradation** — if the endpoint is blocked or the markup changes, the module
  serves the last good cached result, or a representative offline advisory set flagged
  `simulated: true` with the reason shown in the UI. Downstream modules never break.

---

## 8. Project layout

```
cimi/
├── server.js                    # boot, scheduler, graceful shutdown
├── package.json
├── .env.example
├── Dockerfile · docker-compose.yml · Caddyfile   # one-command deployment
├── src/
│   ├── app.js                   # Express wiring, Helmet CSP, rate limits
│   ├── config/index.js          # typed config from .env
│   ├── middleware/
│   │   ├── auth.js              # JWT bearer auth, role guard
│   │   └── errors.js            # async wrapper, 404, error handler
│   ├── routes/                  # auth, ioc, correlation, logs, feeds, dashboard
│   ├── services/
│   │   ├── aggregator.js        # parallel fan-out + composite scoring
│   │   ├── attack.js            # MITRE ATT&CK technique mapping
│   │   ├── auth.js              # scrypt hashing, MFA lifecycle
│   │   ├── cache.js             # TTL cache with stale-if-error
│   │   ├── correlation.js       # similarity graph + clustering
│   │   ├── dashboard.js         # KPI / trend / geo aggregation
│   │   ├── loganalysis.js       # extraction + auto-screening
│   │   ├── simulator.js         # deterministic offline intelligence
│   │   ├── stix.js              # STIX 2.1 normalisation
│   │   ├── store.js             # atomic flat-file JSON persistence
│   │   └── providers/           # virustotal, abuseipdb, otx, cisakev, certin
│   └── utils/                   # http, indicators, jwt, totp
├── public/
│   ├── index.html               # SPA shell
│   ├── css/app.css
│   ├── js/{api,charts,app}.js
│   └── vendor/tailwind.js       # vendored — works offline
├── data/                        # JSON store (created at runtime)
└── tests/smoke.test.js          # 37 checks
```

---

## 9. Implementation notes

* **Atomic writes.** The flat-file store writes to a temp file and renames, and serialises
  read-modify-write cycles per file, so concurrent requests cannot corrupt or clobber
  `ioc_history.json`. A corrupt file is preserved for forensics and rebuilt.
* **Stale-if-error caching.** When a provider is rate-limited, CIMI serves the expired
  cache entry marked `stale: true` rather than returning nothing.
* **Bounded concurrency.** Bulk lookups use a 4-worker pool so a 25-indicator batch does
  not burst past VirusTotal's 4 req/min free-tier ceiling all at once.
* **ATT&CK is gated on the verdict.** Techniques describe adversary behaviour, so an
  indicator no source flagged gets no technique mapping — an incidental keyword in a pulse
  title must never tell an analyst that a benign IP is running ransomware.
* **History is bounded.** `ioc_history.json` keeps the newest 5,000 entries and
  `log_reports.json` the newest 200, so the flat files stay a sensible size.

---

## 10. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `EADDRINUSE` | Port 3000 is taken — set `PORT=3001` in `.env`. |
| All sources show `sim` | No API keys in `.env`. Expected; add keys to go live. |
| CERT-In shows "degraded" | The endpoint is rate-limiting or blocking. The offline set is shown; try `?refresh=true` later. |
| Signed out after restart | The `data/` directory (which holds the auto-generated `jwt.secret`) was wiped or is not on a persistent volume. |
| VirusTotal returns "rate limit exceeded" | Free tier is 4 req/min. Caching mitigates it; wait a minute. |

---

## 11. References

1. Barnum, S. (2012). *Standardizing Cyber Threat Intelligence Information with STIX.* MITRE.
2. Wagner, C. et al. (2016). *MISP: The Design and Implementation of a Collaborative Threat Intelligence Sharing Platform.* WISCS '16, 49–56.
3. Strom, B.E. et al. (2018). *MITRE ATT&CK: Design and Philosophy.* MITRE Technical Report.
4. OASIS CTI TC (2021). *STIX Version 2.1 and TAXII Version 2.1 Specifications.*
5. CISA (2026). *Known Exploited Vulnerabilities Catalog.* https://www.cisa.gov/known-exploited-vulnerabilities-catalog
6. CERT-In (2026). *Vulnerability Notes and Security Advisories.* https://www.cert-in.org.in
7. VirusTotal API v3 — https://docs.virustotal.com/reference/overview
8. AbuseIPDB API — https://docs.abuseipdb.com/
9. AlienVault OTX API — https://otx.alienvault.com/api
10. Chismon, D. and Ruks, M. (2015). *Threat Intelligence: Collecting, Analysing, Evaluating.* MWR InfoSecurity / CERT-UK.

---

## License

MIT — academic project, G H Raisoni College of Engineering & Management, Nagpur.
