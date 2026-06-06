# Smap AI Recon Center v2 — Enterprise SOC Edition

A polished, fully-featured analyst dashboard for the Smap recon database (`smap.db`).

## Quick start

```bash
mkdir -p data
cp /path/to/smap.db data/smap.db
docker compose up --build
```

- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API docs: http://localhost:8000/docs

## Pages

- **/** — Threat intelligence overview (15 stat tiles, 9 charts, critical highlights, SSL hygiene)
- **/hosts** — Host inventory (filters, sorting, pagination)
- **/hosts/[ip]** — Host detail with AI assessment, ports, vulns, techs, tags, certificates
- **/vulnerabilities** — CVE list with filters
- **/vulnerabilities/[cve]** — CVE detail with affected host list
- **/scans** — Scan history
- **/scans/[id]** — Scan detail with AI brief and severity breakdown
- **/ai** — AI Insights center (overall posture, top-risk hosts, historical briefs)
- **/technologies** — Technology fingerprint inventory
- **/geo** — Geographic & ASN distribution
- **/diff** — Latest vs previous scan diff (new hosts, gone hosts, new CVEs, resolved CVEs)

## Architecture

- **Backend**: FastAPI (read-only over SQLite) — pluggable read-only schema
- **Frontend**: Next.js 14 (App Router), TypeScript, Tailwind, Recharts, lucide-react
- **Design**: Dark, glassmorphism, SOC-style. Severity-aware coloring, country flags, sparklines.
- **Safety**: Backend mounts the DB read-only. No write endpoints.

## Schema expectations

The backend expects the standard Smap schema with tables:
`scans`, `hosts`, `ports`, `vulnerabilities`, `technologies`, `host_tags`,
`ai_host_analysis`, `ai_scan_analysis`.
