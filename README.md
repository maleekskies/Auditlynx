# SecOps Toolkit

Two defensive security tools in one app:

1. **Security Headers & Config Checker** — fetches a URL server-side and grades it (A–F) on HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cookie flags (Secure/HttpOnly/SameSite), and info-disclosure headers.
2. **Phishing Email Analyzer** — paste raw `.eml`-style email source (headers + body) and get a categorized breakdown: SPF/DKIM/DMARC results, sender/domain mismatches, deceptive or malicious-looking links, urgency/social-engineering language, header anomalies, and risky attachment extensions.

This is heuristic triage tooling for a human analyst — it surfaces signals, it doesn't hand down verdicts. Always confirm findings manually before acting on them.

## Project structure

```
secops-toolkit/
├── backend/          FastAPI app (Python)
│   └── app/
│       ├── main.py           # app entrypoint, CORS, routes
│       ├── routers/          # /api/check-headers, /api/analyze-email
│       └── services/         # the actual analysis logic
└── frontend/          React + Vite + Tailwind
    └── src/
        ├── App.jsx
        └── components/
```

## Running locally

**Backend** (requires Python 3.10+):

```bash
cd backend
python3 -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

**Frontend** (requires Node 18+):

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. The Vite dev server proxies `/api/*` requests to `http://127.0.0.1:8000` (see `vite.config.js`), so the frontend and backend talk to each other automatically in dev — no env vars needed locally.

## Deploying

**Backend**: any host that runs a Python ASGI app works — Render, Railway, Fly.io, a plain VPS behind nginx, etc. Start command:
```bash
uvicorn app.main:app --host 0.0.0.0 --port $PORT
```
Before deploying somewhere public, lock down CORS in `app/main.py` (`allow_origins=["*"]` → your actual frontend domain).

**Frontend**: build a static bundle and host it anywhere static (Vercel, Netlify, S3+CloudFront, nginx):
```bash
cd frontend
npm run build   # outputs to dist/
```
Since the proxy in `vite.config.js` only applies in dev, once deployed you need the frontend to know where the backend lives. Simplest fix: set the frontend's host so `/api/*` reverse-proxies to the backend (e.g. an nginx rule or a Vercel rewrite), which keeps the code unchanged. Alternatively, replace the relative `fetch('/api/...')` calls in `HeadersChecker.jsx` and `PhishingAnalyzer.jsx` with a full backend URL read from `import.meta.env.VITE_API_URL`.

## Notes on the heuristics

- The headers checker only evaluates what's observable from a single unauthenticated GET request — it won't catch logic-level issues (e.g. authenticated-endpoint CSP gaps).
- The phishing analyzer's typosquat and urgency-language checks are pattern/distance-based, not ML — expect some false positives/negatives, especially on brands outside the built-in list (`COMMON_BRANDS` in `email_analyzer.py`) or on non-English content.
- Neither tool stores anything — every request is stateless, nothing is persisted or logged beyond normal server access logs.

## Extending

- Add more header checks or brand names by editing `backend/app/services/header_checker.py` / `email_analyzer.py` — each check returns a `Finding`, so new checks slot in the same way.
- To add a third module, add a router + service on the backend, a component on the frontend, and a new entry in `Sidebar.jsx`'s `MODULES` array.
