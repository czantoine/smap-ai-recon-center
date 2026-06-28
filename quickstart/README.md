# Quickstart — Smap → SQLite → Grafana → Ollama

This guide helps you deploy the full **passive recon + AI-assisted threat intelligence** stack locally with Docker Compose.

For the overall project overview, architecture, and feature set, see the [main README](../README.md).

---

## Stack Overview

| Service | Role | Default Port |
|---|---|---|
| `smap-importer` | Imports passive scan results into SQLite | — |
| `grafana` | Dashboards and operational visibility | `3009` |
| `ollama` | Local LLM runtime | `11434` |
| `ollama-init` | Pulls the AI model on first startup | — |
| `ai-analyzer` | Reads recon data and stores AI analysis back into SQLite | — |

---

## Requirements

- **Docker** 20.x+
- **Docker Compose** v2
- No Shodan API key required

### Recommended memory for AI models

| Model | Approx. RAM | Notes |
|---|---|---|
| `phi3:mini` | ~4 GB | lightweight |
| `mistral:7b` | ~8 GB | balanced |
| `llama3.1:8b` | ~10 GB | heavier, better quality |

---

## Launch

```bash
git clone https://github.com/czantoine/smap-ai-recon-center
cd smap-ai-recon-center/quickstart
# vi targets.txt          # optional: edit targets
docker compose up -d --build
```

Monitor startup:

```bash
docker compose logs -f ollama_init
docker compose logs -f ai_analyzer
```

Open Grafana after ~30–60s:

- **URL:** `http://localhost:3009`
- **Login:** `admin` / `admin`

The dashboard and datasource are **auto-provisioned** — nothing to configure manually.

The dashboard JSON is downloaded from grafana.com when the Grafana container starts.

---

## Targets

> `targets.txt` is copied into the image at **build time**.

### Option A — Rebuild (simple)

```bash
vi targets.txt
docker compose build smap-importer
docker compose up -d smap-importer
```

### Option B — Volume mount (no rebuild)

Add to `docker-compose.yml`:

```yaml
services:
  smap-importer:
    volumes:
      - ./targets.txt:/app/targets.txt:ro
```

Then edit and restart:

```bash
vi targets.txt
docker compose restart smap-importer
```

### Option C — Automated scheduling

- Cron inside the container for periodic re-scans
- External scheduler (e.g., `crazymax/swarm-cronjob`)
- Fetch from API / CMDB at runtime

### Supported formats

```
1.1.1.1          # IPv4
example.com      # Hostname
178.23.56.0/24   # CIDR
```

---

## Entrypoint Flow

`entrypoint.sh` runs this sequence on each container start:

```
PRE-FLIGHT
├── HTTPS connectivity test → internetdb.shodan.io
├── DNS resolution check
└── TLS error reporting

SCAN
├── smap -iL targets.txt -oJ smap-output.json
├── JSON validation (size > 5 bytes)
└── Fallback to XML (-oX) if JSON fails

IMPORT (import_smap.py)
├── Auto-detect format (JSON / JSONL / XML / nmap-json)
├── Extract hosts, ports, CVEs, CPEs, SSL, geo
├── Compute CVSS severity + per-host risk level
├── Generate host tags (shodan / os / service / status)
└── Write 7 tables + 14 indexes → smap.db

VERIFY
└── Print DB summary (tables, row counts, samples)
```

---

## Validate the Deployment

### Check services

```bash
docker compose ps
```

### Check AI table population

```bash
docker compose exec grafana sh -c "sqlite3 /var/lib/sqlite/smap.db 'SELECT COUNT(*) FROM ai_scan_analysis;'"
docker compose exec grafana sh -c "sqlite3 /var/lib/sqlite/smap.db 'SELECT COUNT(*) FROM ai_host_analysis;'"
```

### Follow logs

```bash
docker compose logs -f ai_analyzer
docker compose logs -f ollama
docker compose logs -f grafana
```
---

## Choosing a Model

If the default model is too heavy, edit `docker-compose.yml` and change the model in both places:

1. `ai-analyzer.environment.OLLAMA_MODEL`
2. `ollama-init` model pull command

Example alternatives:

- `phi3:mini`
- `mistral:7b`
- `llama3.1:8b`

---

## Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `GF_SECURITY_ADMIN_USER` | `admin` | Grafana admin username |
| `GF_SECURITY_ADMIN_PASSWORD` | `admin` | Grafana admin password |
| `GF_INSTALL_PLUGINS` | `frser-sqlite-datasource` | Plugins installed at startup |
| `GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS` | `frser-sqlite-datasource` | Allow unsigned SQLite plugin |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ollama-init` takes time | Model is still downloading | Wait for the pull to complete |
| `ai-analyzer` cannot find DB | Importer has not created `smap.db` yet | Wait for importer completion |
| `ai-analyzer` cannot find model | Ollama model not yet pulled | Check `docker compose logs ollama_init` |
| High memory usage | Model too large for host RAM | Switch to a smaller model |
| No AI panels populated | AI tables still empty | Check analyzer logs and row counts |
| Grafana works but no AI data | Analyzer has not run yet | Wait or restart `ai-analyzer` |
| `internetdb.shodan.io ... FAILED` | No HTTPS outbound to Shodan | Disable VPN/proxy, open firewall to `internetdb.shodan.io:443` |
| `0 hosts imported` | Shodan blocked | Same as above |
| `Illegal number` in entrypoint | Old `entrypoint.sh` bug | Pull latest version (fixed `ERRS` sanitization) |
| `No file found at smap-output.json` | Normal post-import cleanup | Not an error — import succeeded, file was deleted |
| Dashboard says "No data" | DB not mounted or wrong path | Verify `sqlite.yml` path matches volume mount |
| SQLite plugin not loading | Plugin not installed | Ensure `GF_INSTALL_PLUGINS=frser-sqlite-datasource` |

---

## Cleanup

```bash
# Stop (keep data)
docker compose down

# Full reset (removes DB + Grafana data)
docker compose down -v

# Also remove built images
docker compose down -v --rmi all
```
