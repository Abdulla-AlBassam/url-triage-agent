# URL Triage Agent

An autonomous AI agent that investigates whether a web link is safe, suspicious, or malicious, and explains its reasoning step by step.

```
$ uv run triage https://carbon-dating-calibration.garden/.../google.ct

→ whois_lookup ... age: 1 day, registrar: PDR
→ dns_lookup ... Cloudflare A records, 300s TTL
→ virustotal_lookup ... submitted (not previously seen)
→ urlhaus_lookup ... found, threat: malware_download, tag: ClearFake

╭─────────────────────────── Verdict ────────────────────────────╮
│ MALICIOUS                                                      │
│ Confidence: 10/10                                              │
│                                                                │
│ URLhaus positively identifies this URL as an active ClearFake  │
│ malware-download site...                                       │
╰────────────────────────────────────────────────────────────────╯
```

Hand it any URL. It picks the right investigative tools, reads the evidence, and returns a verdict (`BENIGN`, `SUSPICIOUS`, or `MALICIOUS`) with a confidence score and a corroborated evidence list.

For the design rationale, threat model, and detailed component breakdown, see [`TECHNICAL.md`](TECHNICAL.md).

## What it does, in plain English

You get sent a link. You don't trust it. Is it a phishing page? A malware download? A real business you haven't heard of?

A human security analyst would investigate by hand. They'd check who registered the domain. They'd see if it's been reported to public threat databases. They'd open the page in an isolated browser to see what it actually shows. Then they'd write a short note: "Yes, it's bad, and here's why." That takes minutes per link, and the queue grows faster than they can clear it.

This tool does that work in seconds, automatically, for any URL you give it.

## How it works

Two characters in this story.

**The brain.** Claude (Anthropic's AI model) reads the URL and decides which checks to run. It can't run them itself, so it asks the program to do them on its behalf.

**The hands.** Ten small Python scripts that each perform one specific investigation: "look up this domain", "ask VirusTotal about this URL", "open this page in a sandboxed browser". The agent calls them "tools".

The brain picks a tool, the hands run it, the brain reads the result, the brain picks the next tool. Eventually the brain calls a special tool, `write_report`, and says: "I'm done. Here's my verdict and the evidence." That back-and-forth is the *agent loop*, and it lives in [`agent_loop.py`](src/triage_agent/agent_loop.py).

## The tools

| Tool | What it does |
| --- | --- |
| `dns_lookup` | Asks DNS who answers for the domain. A/AAAA/MX/NS/TXT + TTL. |
| `whois_lookup` | Looks up when the domain was registered and by whom. Fresh domains are suspicious. |
| `tls_certificate` | Pulls the site's TLS cert. Self-signed, brand-new, or short-SAN-list certs are suspicious. |
| `urlhaus_lookup` | Checks abuse.ch's community feed of malicious URLs. A hit here is strong evidence. |
| `virustotal_lookup` | Asks 70+ antivirus engines what they think of the URL. |
| `urlscan_lookup` | Checks urlscan.io's archive of previous sandbox renders for this domain. |
| `sandbox_fetch` | Renders the page in a hardened Docker container. See "Sandbox" below. |
| `ioc_extractor` | Pulls IOCs (URLs, IPs, hashes, emails, Bitcoin addresses) out of arbitrary text. |
| `favicon_hasher` | Computes a Shodan-compatible MurmurHash3 of the site's favicon. A fingerprint of the phishing kit it came from. |
| `brand_impersonation` | Scores 0–10 for "is this page pretending to be a known brand?" using the rendered DOM. |
| `write_report` | The agent's "I'm done" signal. Ends the investigation with a structured verdict. |

## Sandbox

The `sandbox_fetch` tool is the heaviest piece of engineering in the project. The agent reaches for it when the cheaper signals haven't settled the question and the page itself needs to be rendered. The container is hardened along multiple axes:

- **No host mounts.** The container cannot see the host filesystem.
- **`--cap-drop=ALL`** plus `NET_ADMIN`, `SETUID`, `SETGID` only. Everything else is denied.
- **`--security-opt=no-new-privileges`**. No setuid escalation paths.
- **`--read-only`** root filesystem with a small `/tmp` tmpfs for scratch.
- **Memory and CPU caps** (768 MB, 1 CPU). A runaway page cannot eat the laptop.
- **iptables egress lockdown.** Outbound TCP is allowed only to the resolved target IPs on ports 80 and 443. The page cannot quietly contact a C2 server, a tracking pixel, or anything else.
- **Non-root runtime.** The entrypoint sets iptables as root, then drops to a non-root user via `gosu` before launching Chromium.
- **Per-fetch throwaway.** A fresh container per request, removed on exit. No state survives.

The full threat model is in [`TECHNICAL.md`](TECHNICAL.md#the-sandbox-threat-model).

## Quickstart

You need three things:

1. **Python 3.12+**. Check with `python3 --version`.
2. **uv**, a fast Python package manager: `curl -LsSf https://astral.sh/uv/install.sh | sh`
3. **Docker Desktop**, running. Required only for the sandbox tool.

Then:

```bash
# Copy the env template and paste your real keys.
cp .env.example .env
# Open .env in your editor and add at least ANTHROPIC_API_KEY.

# Install dependencies.
uv sync

# Triage a URL.
uv run triage https://example.com
```

The first sandbox call builds the Docker image (~1.5 GB pull, one-time). Subsequent calls reuse it.

## API keys

| Key | Required? | Get one |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | **Yes** | [console.anthropic.com](https://console.anthropic.com/) |
| `URLHAUS_AUTH_KEY` | For URLhaus | [auth.abuse.ch](https://auth.abuse.ch/) (free) |
| `VIRUSTOTAL_API_KEY` | Optional, recommended | [virustotal.com](https://www.virustotal.com/gui/join-us) (free) |
| `URLSCAN_API_KEY` | Optional, recommended | [urlscan.io](https://urlscan.io/user/signup) (free) |

Tools whose key is missing report themselves as unavailable and the agent works around them. Only the Anthropic key is strictly required to run.

## Sample runs

Two transcripts of real runs live in [`docs/sample_runs/`](docs/sample_runs/):

- [`01_benign_github.txt`](docs/sample_runs/01_benign_github.txt). `https://github.com`. Settled cleanly from cheap signals.
- [`02_malicious_tiktok_phish.txt`](docs/sample_runs/02_malicious_tiktok_phish.txt). A live TikTok-Shop credential phish. Exercises the full pipeline: DNS, WHOIS, TLS, VirusTotal, URLhaus, sandbox render, and brand-impersonation analysis.

## Repo layout

```
url-triage-agent/
├── README.md                        ← you are here
├── TECHNICAL.md                     ← design rationale and threat model
├── PLAN.md                          ← the original design notes
├── pyproject.toml                   ← dependencies and entry point
├── .env.example                     ← template for API keys
├── sandbox/                         ← the Docker sandbox
│   ├── Dockerfile                   ← Playwright + iptables + non-root
│   ├── entrypoint.sh                ← egress lockdown, then drop privs
│   └── runner.py                    ← Playwright capture, JSON to stdout
├── src/triage_agent/
│   ├── agent_loop.py                ← the brain-talks-to-hands loop
│   ├── cli.py                       ← the command-line interface
│   ├── tool_registry.py             ← decorator-based tool registration
│   ├── prompts/system_prompt.md     ← the SOC-analyst system prompt
│   └── tools/                       ← one file per tool, all real
├── tests/
│   └── test_smoke.py                ← scaffolding integrity tests
├── docs/sample_runs/                ← saved transcripts of real runs
└── reports/                         ← saved verdicts (JSON)
```

## What this isn't

- Not a replacement for a SIEM, a full threat-intel platform, or a SOC. It triages a single URL at a time.
- Not a sandbox in the malware-analysis sense. Chromium runs there, but we don't detonate binaries; we render web pages.
- Not deterministic. The agent's exact path through the tools varies. The verdict is reliable on clear-cut cases and well-corroborated on ambiguous ones, but you should read the evidence rather than trusting the label alone.
- Not benchmarked. The handful of real-world runs in this repo are anecdotes, not statistics. A measured precision/recall study against a labelled corpus is a natural next step.

## Tests

```bash
uv run pytest
```

Smoke tests cover the scaffolding: every tool registers, every schema is JSON-serialisable, dispatch handles unknowns, the system prompt loads.

## Licence

MIT. See `LICENSE`.
