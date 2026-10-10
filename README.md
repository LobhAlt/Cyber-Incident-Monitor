# CIMI: Cyber Incident Monitor in India

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
npm start
```

The launcher does all the setup on first run. It creates `.env` from `.env.example`,
installs dependencies, picks a free port if 3000 is taken, and opens the dashboard in your
browser. Set `OPEN_BROWSER=false` in `.env` to stop it opening a browser tab.

Sign in at **http://localhost:3000** with:

| | |
|---|---|
| Username | `analyst` |
| Password | `Cimi@2026` |

On first sign-in CIMI makes you replace this password, because it is published here.

Both are configurable in `.env` (`DEFAULT_ADMIN_USER` / `DEFAULT_ADMIN_PASSWORD`).
The account is created automatically on first boot.

Run the test suite at any time:

```bash
npm test     # 85 checks: unit, full API, static assets, MongoDB storage and email
```

### Requirements

* **Node.js 20 or newer** (uses the built-in `fetch`). Node 22 recommended.
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
| CISA KEV | none (public feed) | unlimited | offline sample catalog |
| CERT-In | none (scraped) | n/a | offline advisory sample |

**The simulator** is a deterministic offline intelligence generator: the verdict for an
indicator is derived from a SHA-256 of the indicator itself, so the same value always
produces the same result, so it is reproducible for demonstrations and viva. Everything it
produces is tagged `simulated: true` and the UI shows a **SIMULATED** badge, so it can
never be mistaken for live data.

Add a key to `.env` and restart, and that source switches to live automatically, and the
sidebar status changes from `sim` to `live`.

Set `FORCE_DEMO_MODE=true` to force the simulator even when keys are present.

---

## 2b. Deployment: one-time setup

CIMI stores its data either as JSON files under `data/` (the default) or in MongoDB when
`MONGODB_URI` is set. Use MongoDB Atlas on hosts whose disk is wiped on restart, such as
Render's free plan (Option A). Files are fine on a server with a permanent disk (Option B).

### Option A: Render (free) + MongoDB Atlas (free)

Render's free plan sleeps after about 15 idle minutes and wipes its disk on restart, so
the data goes to a free MongoDB Atlas cluster instead. The repo includes a `render.yaml`.

**1. Create the database (MongoDB Atlas, about 5 minutes)**
1. Sign up at <https://www.mongodb.com/cloud/atlas/register> and create a free **M0** cluster.
   Pick a region close to your Render region (for example Mumbai or Singapore).
2. **Database Access → Add New Database User**: password authentication, a username such as
   `cimi`, and a generated password. Role: *Read and write to any database*.
3. **Network Access → Add IP Address → Allow access from anywhere** (`0.0.0.0/0`). Render's
   free plan has no fixed outgoing IP, so this is required; the strong password protects it.
4. **Database → Connect → Drivers**, copy the connection string, and put your password in it:
   `mongodb+srv://cimi:<password>@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority`
   If the password contains `@ : / ? # [ ]` or `%`, URL-encode those characters.

**2. Deploy on Render**
1. Push this repo to GitHub, then on <https://dashboard.render.com> choose
   **New → Blueprint** and select the repo. Render reads `render.yaml`.
2. Fill in the values it asks for:
   * `MONGODB_URI`: the Atlas connection string from step 1.
   * `PUBLIC_URL`: `https://<service-name>.onrender.com` (you can edit it after the first
     deploy, once you know the address).
   * `DEFAULT_ADMIN_PASSWORD`: anything; you must change it on first sign-in anyway.
   * `BREVO_API_KEY` and `MAIL_FROM`: needed for confirmation and reset emails. Render's
     free plan blocks SMTP ports, so Gmail SMTP will not work there; use
     [Brevo](https://www.brevo.com) (free, 300 emails a day) instead. Sign up, add and verify
     your sender address under **Senders, Domains & Dedicated IPs → Senders**, then create a
     key under **SMTP & API → API Keys**. Set `MAIL_FROM` to `CIMI <the verified address>`
     and leave the `SMTP_*` values blank. Without any of these, links appear in Render's
     **Logs** tab.
   * API keys: optional.
3. Click **Apply**. The first build takes a few minutes. The log line
   `Storage  MongoDB (cimi)` confirms the database is in use.
4. Open the site and sign in as `analyst` with the admin password you set, then choose a
   new password.

**Things to know about the free plan**
* The first visit after the server has slept takes 30–60 seconds to load.
* The hourly feed refresh and watchlist checks only run while the server is awake.
* Run a single instance. The server caches database contents in memory, which is only
  correct when one process owns the data.

### Option B: your own server with Node.js and a process manager

```bash
npm ci --omit=dev
npm i -g pm2
pm2 start server.js --name cimi && pm2 save && pm2 startup
```

### Public-site features

| Feature | Where |
|---|---|
| Privacy policy / Terms | `public/privacy.html`, `public/terms.html` (linked from sign-in page and app footer) |
| Custom 404 | `public/404.html`, served with a real 404 status for unknown paths |
| Favicon / touch icon / social preview | `public/favicon.svg`, `apple-touch-icon.png`, `og-image.png` |
| `robots.txt`, `sitemap.xml` | generated by the server from `PUBLIC_URL` (or the request host) |
| Storage notice | shown once; becomes an analytics consent prompt when `PLAUSIBLE_DOMAIN` is set |
| Analytics | optional, cookie-less Plausible; script loads only after the visitor allows it |
| Spam protection | auth rate limit (20 / 15 min), honeypot field on sign-up, `ALLOW_REGISTRATION=false` to close sign-up |
| Force HTTPS | `FORCE_HTTPS=true` (301 redirect + HSTS via Helmet) |
| Compression | gzip/brotli via `compression` middleware for all responses |
| Light and dark mode | follows the device setting until the toggle (top right) is used; the choice is remembered |
| 3D globe | `public/js/globe.js`, a dependency-free canvas globe. On the dashboard it plots real source countries from your lookups, with arcs to India; drag to spin |
| Motion | cards ease in on scroll, KPI numbers count up, header progress bar; all off when the device asks for reduced motion |

### What persists where

With `MONGODB_URI` set, everything below lives in the `cimi_store` collection of the
database (one document per item, plus the session secret) instead of `data/`.

| Item | Location in `data/` |
|---|---|
| Analyst accounts, MFA secrets | `users.json` |
| Lookup history, log reports | `ioc_history.json`, `log_reports.json` |
| Watchlist, activity log | `watchlist.json`, `audit_log.json` |
| Admin settings, signed-out sessions | `settings.json`, `revoked_sessions.json` |
| JWT signing secret (auto-generated once) | `jwt.secret` |

Back up `data/` (or, with MongoDB, use Atlas's backup tools) and you have everything.

---

## 3. Architecture

Three tiers. The frontend never talks to an external API: every request is proxied,
cached and rate-limited through the backend, which is the only component holding
provider keys.

```
┌──────────────────────────────────────────────────────────────────┐
│  PRESENTATION · Tailwind CSS single-page app (public/)           │
│  Login (JWT + MFA) · Dashboard · IoC Lookup · Threat Correlation │
│  Log Analysis · Threat Intelligence Feeds · Settings             │
└───────────────────────────────┬──────────────────────────────────┘
                                │ REST + Bearer JWT
┌───────────────────────────────▼──────────────────────────────────┐
│  APPLICATION · Node.js / Express (src/)                          │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ Routes: auth · ioc · correlation · logs · feeds · dashboard │  │
│  │ Middleware: JWT auth · rate limiting · Helmet · CORS        │  │
│  ├────────────────────────────────────────────────────────────┤  │
│  │ Aggregation service · parallel fan-out + composite scoring  │  │
│  │ STIX 2.1 normaliser · MITRE ATT&CK mapper                   │  │
│  │ Correlation engine · Log analyser · CERT-In scraper         │  │
│  │ In-memory TTL cache (15 min default, 6 h for CISA KEV)      │  │
│  └────────────────────────────────────────────────────────────┘  │
└───────────────┬──────────────────────────────┬───────────────────┘
                │                              │
┌───────────────▼──────────────┐  ┌────────────▼───────────────────┐
│ DATA · flat-file JSON store  │  │ EXTERNAL SOURCES               │
│ users.json · ioc_history.json│  │ VirusTotal · AbuseIPDB · OTX   │
│ log_reports.json             │  │ CISA KEV · CERT-In             │
│ scrypt-hashed credentials    │  │                                │
└──────────────────────────────┘  └────────────────────────────────┘
```

### Request flow for a single IoC lookup

1. Analyst submits an indicator on the **IoC Lookup** page.
2. The API auto-detects the type: IP / domain / URL / MD5 / SHA-1 / SHA-256 / CVE.
3. The aggregation service queries every applicable source **in parallel**, falling back to
   cache (including stale cache) when a source is rate-limited.
4. Results are normalised into STIX 2.1 observables, blended into a weighted composite
   verdict, and mapped to MITRE ATT&CK techniques.
5. The result is persisted to `ioc_history.json` and returned with its STIX bundle.

### Composite scoring

Sources are blended by weight (VirusTotal 0.45, AbuseIPDB 0.30, OTX 0.25), normalised
over the sources that actually answered, so a rate-limited provider reduces *confidence*
rather than dragging the *score* to zero. Two independent malicious votes add a +12
corroboration bonus, three add a further +8, and a CISA KEV hit (exploited in the wild)
floors the score at 85.

Verdict bands: **≥65 malicious · 30–64 suspicious · <30 clean.**

---

## 4. Modules

### Security Dashboard
KPI tiles, a 14-day stacked verdict-trend chart, verdict donut, geographic distribution,
top ATT&CK techniques and indicator-type split, all computed from the analyst's own
lookup history, with no additional data entry. Charts are hand-built SVG: no chart
library, no CDN.

### IoC Lookup
Single and bulk (up to 25) indicator screening. Shows a source-wise breakdown with each
provider's raw statistics, the blended verdict, the ATT&CK mapping with the evidence that
matched, a 14-day reputation timeline, and a live preview of the STIX 2.1 bundle.
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

### Watchlist
Save indicators to watch. They are re-screened every scheduler interval (hourly by
default) and the last 20 scores are kept as a trend line. If a verdict gets worse (clean →
suspicious → malicious) the owner gets an email; alerts can be switched off per indicator.
Each analyst sees only their own watchlist (up to 50 entries).

### Reports
Lookup, correlation and log-analysis results, plus the activity log, have a **Download PDF
report** button. It opens the browser's print dialog with a print stylesheet that turns the
result into a white, paper-friendly page with a header naming the analyst and the time.

### Admin
Visible only to the `admin` role:
* **Accounts**: list users with status (active, unconfirmed, disabled), MFA and last
  sign-in; disable (which also ends their sessions), re-enable, resend the confirmation
  link or delete. Admins cannot disable or delete themselves, and the last admin is kept.
* **Sign-up switch**: open or close self-service registration without a restart.
* **Activity log**: sign-ins (including failures and lockouts), sign-ups, password changes
  and resets, sign-outs, lookups, watchlist alerts and admin actions, with IP addresses.
  Never contains passwords, tokens or codes.
* **Clear all lookup history** (analysts can clear only their own).

### Security
* **JWT** sessions: HS256, implemented directly on `node:crypto` (no `jsonwebtoken`
  dependency), with timing-safe signature comparison.
* **Session cookie, not browser storage.** The token is sent only as an `HttpOnly`,
  `SameSite=Strict` cookie (`Secure` over HTTPS). Page scripts cannot read it, other sites
  cannot send it, and nothing about the account is kept in `localStorage`. API responses
  are `Cache-Control: no-store`.
* **Email confirmation.** Sign-up asks for an email address and sends a one-time link that
  expires in 24 hours. Only a SHA-256 hash of the link's code is stored. Accounts cannot
  sign in until confirmed. The code travels in the URL fragment (`#token=`), so it never
  reaches server logs or `Referer` headers.
* Email goes through Brevo's HTTPS API when `BREVO_API_KEY` is set, otherwise SMTP when
  `SMTP_HOST` is set. With neither, links are printed in the server terminal so local
  installs still work. Sending gives up after 15 seconds instead of hanging.
* **scrypt** password hashing (N=16384, r=8, p=1) with per-user salts; the login path does
  equivalent work for unknown users to prevent account enumeration.
* **TOTP MFA** (RFC 6238) with ±1 step drift tolerance, also dependency-free.
* **Default password must be changed.** Signing in with the README's default admin
  password gives a session that can only reach the change-password endpoint.
* **Password policy**: at least 8 characters, three of lowercase / uppercase / digits /
  symbols (or 16+ characters), not a common password, not containing the username or
  email. A live strength meter shows the same rules while typing.
* **Forgot password**: emails a one-time reset link valid for 30 minutes, hashed at rest.
  Resetting or changing a password signs out every other session.
* **Server-side session control**: every request re-checks the account. Sign-out revokes
  that token, "Sign out everywhere" and password changes end all sessions, and disabled
  accounts are cut off immediately.
* **Lockout**: 5 wrong passwords for the same login name pause sign-in for 15 minutes.
  Unknown names are tracked the same way, so a lockout never confirms an account exists.
* **Helmet** security headers with a strict Content-Security-Policy.
* **Rate limiting**: 300 requests / 15 min globally, 20 / 15 min on auth endpoints.

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

All endpoints except `/api/health` and `/api/auth/*` require a session. The browser app
uses the `cimi_session` cookie set by `/api/auth/login`. Scripted clients can keep that
cookie (`curl -c jar -b jar …`) or send it as `Authorization: Bearer <token>`.

### Auth
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/auth/login` | `{username, password, mfaToken?}` (username or email) → sets the session cookie, returns `{user}`; or `{mfaRequired:true}`; `403 EMAIL_UNVERIFIED` until confirmed |
| POST | `/api/auth/register` | `{username, email, password}` → creates an unconfirmed account and emails a link |
| POST | `/api/auth/verify-email` | `{token}` from the emailed link → confirms the account |
| POST | `/api/auth/resend-verification` | `{login}` → sends a fresh link (same reply whether or not the account exists) |
| POST | `/api/auth/forgot-password` | `{login}` → emails a reset link (same reply whether or not the account exists) |
| POST | `/api/auth/reset-password` | `{token, password}` → sets the password and ends all sessions |
| POST | `/api/auth/change-password` | `{currentPassword, newPassword}` → ends other sessions, issues a fresh cookie |
| POST | `/api/auth/logout` | revokes this session and clears the cookie |
| POST | `/api/auth/logout-all` | ends every session for the account |
| GET | `/api/auth/me` | current session user |
| POST | `/api/auth/mfa/setup` | returns a TOTP secret + `otpauth://` URL |
| POST | `/api/auth/mfa/confirm` | `{token}`, enables MFA |
| POST | `/api/auth/mfa/disable` | `{password}` |

### Indicators
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/ioc/lookup` | `{indicator, type?}`, single lookup |
| POST | `/api/ioc/bulk` | `{indicators: []}`, up to 25 |
| GET | `/api/ioc/detect?value=` | type-detection helper |
| GET | `/api/ioc/history?limit=&verdict=` | lookup history |
| DELETE | `/api/ioc/history?scope=all` | clear your own history (`scope=all`: everyone's, admin only) |
| POST | `/api/ioc/stix` | STIX 2.1 bundle for one or more indicators |

### Analysis
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/correlation` | `{indicators: []}`, nodes, edges, clusters |
| GET | `/api/correlation/history?limit=` | correlate recent lookups |
| POST | `/api/logs/analyse` | `{content, fileName?}`, extract + screen |
| GET | `/api/logs/reports` | past log reports |
| GET | `/api/logs/reports/:id` | one report |
| GET | `/api/dashboard?days=14` | full dashboard payload |

### Watchlist
| Method | Path | Purpose |
|---|---|---|
| GET | `/api/watchlist` | your watched indicators |
| POST | `/api/watchlist` | `{indicator, note?}`, add and screen once |
| POST | `/api/watchlist/:id/check` | re-screen now |
| PATCH | `/api/watchlist/:id` | `{alerts: true/false}` |
| DELETE | `/api/watchlist/:id` | stop watching |

### Admin (admin role only)
| Method | Path | Purpose |
|---|---|---|
| GET | `/api/admin/users` | all accounts (no secrets) |
| POST | `/api/admin/users/:id/disable` · `/enable` · `/resend-verification` | account actions |
| DELETE | `/api/admin/users/:id` | delete an account |
| GET | `/api/admin/audit?limit=&event=&actor=` | activity log |
| GET / PUT | `/api/admin/settings` | `{registrationEnabled}` |

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
`RemoteDisconnected` errors. This was the principal engineering risk identified in the synopsis.

`src/services/providers/certin.js` addresses this with:

* a complete set of browser-like request headers (`Sec-Fetch-*`, `Accept-Language`,
  `Referer`, `Upgrade-Insecure-Requests`, realistic `User-Agent`);
* **exponential back-off retry** (3 attempts, 900 ms → 1.8 s → 3.6 s), skipping retries
  on 4xx responses other than 429;
* a tolerant HTML table parser that pulls advisory IDs (`CIVN-`/`CIAD-`), titles,
  severities, dates and CVE references;
* **graceful degradation**: if the endpoint is blocked or the markup changes, the module
  serves the last good cached result, or a representative offline advisory set flagged
  `simulated: true` with the reason shown in the UI. Downstream modules never break.

---

## 8. Project layout

```
cimi/
├── server.js                    # boot, scheduler, graceful shutdown
├── package.json
├── .env.example
├── render.yaml                  # Render deployment blueprint
├── scripts/launch.js            # npm start: one-step local setup and launch
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
│   └── vendor/tailwind.js       # vendored, works offline
├── data/                        # JSON store (created at runtime)
└── tests/smoke.test.js          # 43 checks
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
  indicator no source flagged gets no technique mapping. An incidental keyword in a pulse
  title must never tell an analyst that a benign IP is running ransomware.
* **History is bounded.** `ioc_history.json` keeps the newest 5,000 entries and
  `log_reports.json` the newest 200, so the flat files stay a sensible size.

---

## 10. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `EADDRINUSE` | Port 3000 is taken Set `PORT=3001` in `.env`. |
| All sources show `sim` | No API keys in `.env`. Expected; add keys to go live. |
| CERT-In shows "degraded" | The endpoint is rate-limiting or blocking. The offline set is shown; try `?refresh=true` later. |
| Signed out after restart | The `data/` directory (which holds the auto-generated `jwt.secret`) was wiped. On hosts without a permanent disk, set `MONGODB_URI` or `JWT_SECRET`. |
| VirusTotal returns "rate limit exceeded" | Free tier is 4 req/min. Caching mitigates it; wait a minute. |

---

## 11. References

1. Barnum, S. (2012). *Standardizing Cyber Threat Intelligence Information with STIX.* MITRE.
2. Wagner, C. et al. (2016). *MISP: The Design and Implementation of a Collaborative Threat Intelligence Sharing Platform.* WISCS '16, 49–56.
3. Strom, B.E. et al. (2018). *MITRE ATT&CK: Design and Philosophy.* MITRE Technical Report.
4. OASIS CTI TC (2021). *STIX Version 2.1 and TAXII Version 2.1 Specifications.*
5. CISA (2026). *Known Exploited Vulnerabilities Catalog.* https://www.cisa.gov/known-exploited-vulnerabilities-catalog
6. CERT-In (2026). *Vulnerability Notes and Security Advisories.* https://www.cert-in.org.in
7. VirusTotal API v3: https://docs.virustotal.com/reference/overview
8. AbuseIPDB API: https://docs.abuseipdb.com/
9. AlienVault OTX API: https://otx.alienvault.com/api
10. Chismon, D. and Ruks, M. (2015). *Threat Intelligence: Collecting, Analysing, Evaluating.* MWR InfoSecurity / CERT-UK.

---

## License

MIT. Academic project, G H Raisoni College of Engineering & Management, Nagpur.
