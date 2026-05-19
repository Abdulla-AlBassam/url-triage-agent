# URL Triage Agent — Plan

A SOC-style triage tool that takes a URL and returns a verdict (BENIGN / SUSPICIOUS / MALICIOUS) with evidence. A Claude tool-use loop drives a kit of classical analysis scripts: DNS, WHOIS, TLS, IOC extraction, threat-intel lookups, and a sandboxed headless render. The agent picks its own path through the toolkit and writes a structured report.

## Why this design

The job spec calls for two things:

1. AI agents that autonomously identify and analyse cyber threats.
2. Scripts that extract, filter, and classify malicious content and indicators.

Those are the two layers of this build. The agent is the brain; the tools are the muscle. Each tool is a small, testable script that does one job well, so the agent layer is a thin orchestrator over real, demonstrable security engineering.

## Architecture

```
        ┌──────────────────────────────────────────────────────┐
        │                  Web UI (FastAPI + HTMX + SSE)        │
        │  Paste URL  →  Live tool-call stream  →  Final report │
        └────────────────────────┬─────────────────────────────┘
                                 │
                  ┌──────────────▼──────────────┐
                  │      Agent loop (Claude)     │  system prompt + tool defs (cached)
                  │   tool_use → tool_result …   │
                  └──┬───────────┬───────────┬──┘
                     │           │           │
        ┌────────────▼──┐  ┌─────▼─────┐  ┌──▼────────────┐
        │ Network tools │  │ Intel API │  │  Sandboxed    │
        │  DNS / WHOIS  │  │  URLhaus  │  │  Playwright   │
        │  TLS cert     │  │  VirusTo. │  │  fetch        │
        │  Favicon hash │  │  urlscan  │  │  (Docker)     │
        └───────────────┘  └───────────┘  └───────────────┘
                                 │
                       ┌─────────▼─────────┐
                       │  Reports (SQLite, │
                       │  JSON + Markdown) │
                       └───────────────────┘
```

## Tool inventory

Each tool is a Python function exposed to Claude via a JSON schema. The agent decides which to call and in what order.

| Tool | Purpose |
| --- | --- |
| `dns_lookup` | A, AAAA, MX, NS, TXT records. Flags newly-resolved, single-A, or short-TTL. |
| `whois_lookup` | Registrar, creation date, expiry. Domain-age signal. |
| `tls_certificate` | Issuer, validity, SAN list, age. Flags self-signed and LE-on-fresh-domain. |
| `urlhaus_lookup` | abuse.ch URLhaus query. No key needed. |
| `virustotal_lookup` | VT v3 URL/domain/file scan results. API key required. |
| `urlscan_lookup` | Recent urlscan.io scans on this host. API key required. |
| `sandbox_fetch` | Playwright in a hardened Docker container. Returns status, final URL, redirect chain, title, DOM text excerpt, screenshot, network requests, console logs. |
| `extract_iocs` | Regex extractor for URLs, IPs, hashes, emails, BTC. |
| `favicon_hash` | mmh3 hash of favicon. Useful for known-bad clusters. |
| `brand_impersonation_check` | Heuristics on rendered page: cross-domain form posts, brand strings in body but not in domain, login UI on a fresh domain. |
| `write_report` | Terminal tool. Persists verdict + evidence, ends the loop. |

The agent is told in the system prompt that no single signal is conclusive, that it must corroborate, and that `write_report` ends the run.

## Sandbox

Playwright runs in a Docker container with:

- No bind mounts.
- `--network` set to a dedicated bridge with egress only to the target host (resolved at fetch time, enforced by iptables in the container).
- Screenshot and HAR-style network log written to a host-mounted output dir over a unix socket, not via the network namespace.
- Container is destroyed after each fetch.

This is the realistic-SOC story. For development we can fall back to a less locked-down container, but the production shape is the iptables-restricted one.

## Repo layout

```
url-triage-agent/
├── README.md
├── PLAN.md                       ← this file
├── pyproject.toml                 (uv-managed)
├── .env.example
├── docker/
│   ├── sandbox.Dockerfile
│   └── entrypoint.sh
├── src/agent/
│   ├── main.py                    CLI entry: `agent run <url>`
│   ├── loop.py                    tool-use loop, streaming
│   ├── prompts/system.md
│   ├── models.py                  Pydantic types
│   ├── tools/
│   │   ├── registry.py            schema + dispatcher
│   │   ├── dns.py / whois.py / tls.py
│   │   ├── urlhaus.py / virustotal.py / urlscan.py
│   │   ├── sandbox_fetch.py
│   │   ├── ioc_extract.py / favicon.py / brand.py
│   │   └── report.py
│   ├── store.py                   SQLite
│   └── web/
│       ├── server.py              FastAPI + SSE
│       └── templates/             HTMX
├── tests/
│   ├── test_tools.py
│   └── fixtures/
└── reports/                       JSON + MD outputs
```

## Tech choices

- **Python 3.12**, **uv** for dependency management.
- **Anthropic SDK** with prompt caching on the system prompt and tool schemas.
- **claude-sonnet-4-6** as default model (fast, cheap, good at tool use); switch to opus for tough cases via a flag.
- **FastAPI** + **HTMX** + **Server-Sent Events** for the dashboard. No React, no build step.
- **SQLite** for run history. One row per run + one row per tool call.
- **Pydantic v2** for tool input/output schemas.
- **Docker** for the Playwright sandbox.

## Two-day timeline

### Day 1 — plumbing and core loop

- Repo scaffold, `pyproject.toml`, `.env.example`, README skeleton.
- Sandbox Dockerfile with Playwright + chromium.
- Agent loop in `loop.py` with streaming, prompt caching, tool dispatch.
- First six tools wired: `dns_lookup`, `whois_lookup`, `tls_certificate`, `urlhaus_lookup`, `sandbox_fetch`, `extract_iocs`, `write_report`.
- CLI: `uv run agent run <url>` writes a JSON + markdown report and prints a summary.
- Smoke test on three URLs: one benign, one known-phish from URLhaus, one parked domain.

**Exit criterion:** end-to-end run from CLI produces a report file. No web UI yet.

### Day 2 — intel, UI, write-up

- Add `virustotal_lookup`, `urlscan_lookup`, `favicon_hash`, `brand_impersonation_check`.
- SQLite store with run history table.
- FastAPI server with one page: input box, live tool-call stream over SSE, final report card.
- Triage five real URLs end-to-end. Screenshot the agent stream for the report.
- Write the report (`docs/report.md`, ~2k words): problem framing, architecture, agent loop, sandbox design, sample triages, limitations, future work.
- Record a 60–90 second demo video.

**Exit criterion:** open `localhost:8000`, paste a URL, watch the agent work, see the verdict. Report and demo video committed.

## External services and keys needed

- `ANTHROPIC_API_KEY` — required.
- `VIRUSTOTAL_API_KEY` — free tier, 4 req/min, 500/day. Sign up at virustotal.com.
- `URLSCAN_API_KEY` — free tier. Sign up at urlscan.io.
- URLhaus needs no key.

The agent degrades gracefully: if a key is missing, that tool returns `{"available": false}` and the agent works around it.

## Risk register

| Risk | Mitigation |
| --- | --- |
| Live malicious sites attack the sandbox | Docker container, no host mounts, egress restricted to target only, destroyed per fetch. |
| Agent loops forever on a hard URL | Hard cap of 12 tool calls per run; force `write_report` on cap. |
| API rate limits during demo | Cache responses per (tool, input) for the session. |
| Sample URLs go down mid-build | Pull a fresh batch from URLhaus at the start of day 2. |
| Day 2 runs over | Web UI is the cut line. Ship CLI + report if dashboard is rough. |

## What "done" looks like for the application

A public-ish GitHub repo with:

1. Working CLI and web UI.
2. Clean README with architecture diagram and three documented sample runs.
3. A ~2k-word technical report in `docs/`.
4. A short demo video link.
5. A clear "this maps to the JD" framing in the README's opening paragraph.
