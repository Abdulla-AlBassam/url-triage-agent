# URL Triage Agent

An AI assistant that investigates whether a web link is safe, suspicious, or malicious, and explains its reasoning. Built to mimic how a junior SOC analyst would triage an unknown URL: pull on a thread, check a database, render the page in a sandbox, write up a verdict.

## The problem in plain English

You get sent a link. You don't trust it. Is it a phishing page? A malware download? A real business you haven't heard of?

A human security analyst would investigate by hand. They'd check who registered the domain. They'd see if it's been reported to public threat databases. They'd open the page in an isolated browser to see what it actually shows. Then they'd write a short note: "Yes, it's bad, and here's why." That takes minutes per link.

This tool does that work in seconds, automatically, for any URL you give it.

## How it works (the short version)

There are two characters in this story.

**The brain.** An AI model (Claude, made by Anthropic) reads the URL and decides which checks to run. It can't run the checks itself, so it asks the program to do them on its behalf.

**The hands.** A set of small Python scripts that each perform one specific investigation: "look up this domain", "ask VirusTotal about this URL", "open this page in a sandboxed browser". These are called "tools" in the AI-agent world.

The brain picks a tool, the hands run it, the brain reads the result, the brain picks the next tool. Eventually the brain calls a special tool called `write_report` and says: "I'm done. Here's my verdict and the evidence."

That back-and-forth is called an *agent loop*. It's the heart of this project.

## The tools

The agent has eleven tools at its disposal:

| Tool | What it does |
| --- | --- |
| `dns_lookup` | Asks the internet's address book "who answers for this domain?" |
| `whois_lookup` | Looks up when the domain was registered and by whom. Fresh domains are suspicious. |
| `tls_certificate` | Examines the site's security certificate. Self-signed or brand-new certs are suspicious. |
| `urlhaus_lookup` | Checks abuse.ch's free community database of malicious URLs. |
| `virustotal_lookup` | Asks 70+ antivirus engines what they think of this URL. |
| `urlscan_lookup` | Checks urlscan.io to see if anyone has already screenshotted this page. |
| `sandbox_fetch` | Opens the page in a locked-down browser inside a Docker container, so we can see what it actually shows without risking our laptop. |
| `ioc_extractor` | Pulls out suspicious patterns (other URLs, IP addresses, hashes, Bitcoin wallets) from the page's text. |
| `favicon_hasher` | Fingerprints the site's tiny tab icon. Phishing kits reuse the same icon across hundreds of fake sites. |
| `brand_impersonation` | Checks if the page is pretending to be a known brand (Microsoft, your bank, etc.). |
| `write_report` | The agent's "I'm done" button. Ends the investigation with a verdict. |

## Repo tour

```
url-triage-agent/
├── README.md                        ← you are here
├── PLAN.md                          ← the design notes
├── pyproject.toml                   ← the project's package list
├── .env.example                     ← template for your secret keys
├── sandbox/                         ← Docker setup for the safe browser
│   └── Dockerfile
├── src/triage_agent/
│   ├── agent_loop.py                ← the heart: the brain-talks-to-hands loop
│   ├── cli.py                       ← the command-line interface
│   ├── tool_registry.py             ← keeps track of which tools exist
│   ├── prompts/
│   │   └── system_prompt.md         ← the instructions we give the AI
│   └── tools/                       ← one file per tool, named after what it does
│       ├── dns_lookup.py
│       ├── whois_lookup.py
│       ├── tls_certificate.py
│       ├── urlhaus_lookup.py
│       ├── virustotal_lookup.py
│       ├── urlscan_lookup.py
│       ├── sandbox_fetch.py
│       ├── ioc_extractor.py
│       ├── favicon_hasher.py
│       ├── brand_impersonation.py
│       └── write_report.py
├── tests/
│   └── test_smoke.py                ← a quick "does the scaffolding hold up" test
└── reports/                         ← saved verdicts land here
```

## Running it

You need three things first:

1. **Python 3.12 or newer.** Check with `python3 --version`.
2. **uv**, a fast Python package manager. Install: `curl -LsSf https://astral.sh/uv/install.sh | sh`
3. **Docker Desktop**, running. Only needed for the sandboxed browser tool.

Then:

```bash
# 1. Copy the env template and paste your real keys in.
cp .env.example .env
# Open .env in your editor, paste in your Anthropic key (and optionally the others).

# 2. Install the project's dependencies.
uv sync

# 3. Run a triage.
uv run triage https://example.com
```

You'll see the agent's thought process scroll past, then a final verdict panel.

## The stack, explained for non-techies

- **Python** is the programming language. It's a general-purpose language with great libraries for both AI work and security tooling.
- **Claude** is the AI model that acts as the brain. It's made by Anthropic. We pick it because it's reliable at the "tool use" pattern this project depends on.
- **The Anthropic SDK** is the library we use to send requests to Claude.
- **uv** is a tool that downloads the project's other libraries and keeps them in a private folder so they don't pollute the rest of your machine.
- **Docker** is a way to run a program inside a sealed-off box. We use it to render suspicious web pages in a browser that has no access to our laptop's files or network.
- **Playwright** is a library that drives a real browser (Chromium) from a Python script. It's how we open pages in our sandbox.
- **FastAPI + HTMX** make the small web dashboard. FastAPI is the server, HTMX is a library that lets the page update itself without us writing JavaScript.
- **SQLite** is a tiny database that lives in a single file. We use it to remember past triages.

## Status

This is the day-1 scaffold. The agent loop is real and works end-to-end against the Anthropic API. The tools are stubs that return fixed placeholder data so the loop can be tested without external dependencies. The real tool implementations land next.
