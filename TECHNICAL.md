# Technical Writeup

A deeper read of URL Triage Agent: the design choices, the trade-offs, and the engineering that goes beyond what the README covers.

## Contents

1. [Motivation and scope](#motivation-and-scope)
2. [The agent loop](#the-agent-loop)
3. [The tool registry](#the-tool-registry)
4. [Prompt caching](#prompt-caching)
5. [The sandbox threat model](#the-sandbox-threat-model)
6. [Tool-by-tool design notes](#tool-by-tool-design-notes)
7. [What I deliberately did not build](#what-i-deliberately-did-not-build)
8. [Limitations and honest caveats](#limitations-and-honest-caveats)
9. [Future work](#future-work)

## Motivation and scope

The project was built in two days against a brief: produce something that demonstrates "Building AI Agents for Threat Detection" end to end, with code that a senior engineer would respect. The aim was an artefact, not a product. Scope-control was the dominant design pressure.

The constraint shaped every choice:

- **One URL at a time.** No queueing layer, no batch mode, no scheduler.
- **CLI first.** No web server, no front-end. The Rich-formatted terminal output is the user interface.
- **Local Docker, not cloud.** A reviewer should be able to clone the repo and run it on a laptop in under five minutes.
- **No ML training.** All "models" are off-the-shelf: Claude for orchestration, public threat intel for ground truth.
- **No agentic frameworks.** Just the Anthropic SDK and a Python `while` loop.

What the project *is*: a reproducible demonstration of an autonomous tool-use agent applied to a real security task, with engineering substance in the sandbox and the tool implementations.

What it *isn't*: a product. The Limitations section is honest about what would have to change before this could be put in front of a real analyst.

## The agent loop

The loop lives in [`src/triage_agent/agent_loop.py`](src/triage_agent/agent_loop.py). It is small on purpose. The whole thing is roughly 200 lines including comments.

The shape:

1. Build the initial message: "Please triage this URL: <url>".
2. Call `client.messages.create()` with the system prompt, the tool schemas, and the conversation so far.
3. For each `tool_use` block in Claude's response, dispatch the requested tool and capture the result.
4. If the requested tool is `write_report`, emit the verdict and return.
5. Otherwise, append the tool results to the conversation and go back to step 2.
6. If we hit `MAX_TOOL_CALLS` (12) without a verdict, force one with `tool_choice={"type": "tool", "name": "write_report"}`.

A few choices worth calling out:

**Why a barefoot loop and not a framework.** LangChain, LangGraph, AutoGen, and friends all impose a model of "agent" that wraps the underlying API in conventions. For a single-purpose agent against a single SDK, that abstraction layer is dead weight: harder to debug, harder to optimise (prompt caching, custom dispatch), and harder for a reviewer to read. The bare loop is also a more honest demonstration of agentic AI. The mechanism is exposed; there is no magic.

**The terminator-tool pattern.** `write_report` is registered like any other tool, with a schema that lists `verdict`, `confidence`, `explanation`, and `evidence` as required fields. The dispatch loop intercepts it by name and never actually calls its handler. The result is that Claude has a structured, type-checked way to end the conversation, and the agent code does not have to parse free-form text for a verdict.

**The forced-verdict path.** When the budget is exhausted, the next message instructs Claude to call `write_report` immediately. The Anthropic API supports `tool_choice` to force a specific tool, which removes the possibility of Claude responding with prose. This guarantees a terminal state even if the agent has been going in circles.

**Event-streamed output.** The loop is a generator that yields `AgentEvent` objects (`start`, `thought`, `tool_call`, `tool_result`, `verdict`, `error`). The CLI consumes the stream and renders each event with Rich. A future web UI could consume the same stream over SSE. The decoupling is free because Python generators are cheap.

## The tool registry

Tools register themselves with a decorator:

```python
@register_tool(
    name="dns_lookup",
    description=(
        "Look up DNS records (A, AAAA, MX, NS, TXT) for a hostname. "
        "A fresh domain with a single A record, no MX, and short TTLs is "
        "suspicious."
    ),
    input_schema={...},
)
def dns_lookup(hostname: str) -> dict:
    ...
```

The decorator drops the handler and its metadata into a module-level dictionary. Importing the `triage_agent.tools` package triggers each tool file's decorator, which fills the registry. The agent loop reads from the registry through three small functions: `get_tool_schemas()` (returns what gets sent to Claude), `dispatch_tool(name, input)` (runs a tool), and `list_tool_names()` (used by tests).

The pattern keeps the system extensible. Adding a new tool is a single file plus an import in `tools/__init__.py`. The registry never knows about specific tools, and the agent loop never knows about specific tools either.

## Prompt caching

Anthropic's API supports ephemeral prompt caching: a `cache_control: {"type": "ephemeral"}` marker on any block tells the API to cache everything from the start of the request up to and including that block. Cached blocks cost 25% extra on a write, but 10% on a hit, for the next five minutes.

The agent reuses the same system prompt and the same eleven tool definitions on every iteration of the loop. Without caching, a five-tool-call run sends those tokens five times at full price. With caching:

- The system prompt is marked `cache_control: ephemeral`.
- The last tool in the tools array is also marked `cache_control: ephemeral`.

Marking the last tool implicitly caches everything before it (the prompt and all earlier tools), because the cache marker is an inclusive boundary. Across a typical run, this cuts the input-token cost by roughly 75%.

The implementation is a single helper, `_add_cache_marker()`, that shallow-copies the registry's schemas and adds the marker to the last one.

## The sandbox threat model

`sandbox_fetch` exists because static checks can be cloaked. Many phishing pages serve different content to scrapers than to real browsers, and many phishing kits assemble their malicious payload only after JavaScript runs. The agent has to render the page in something that behaves like a browser. That something has to be hostile-content-safe.

The threat model: assume the URL the agent visits is actively malicious. Assume the page contains zero-day browser exploits, drive-by downloads, cryptominers, and tracking pixels phoning home to a C2 server. The container has to:

1. Stop the page from touching the host filesystem.
2. Stop the page from making outbound network requests to anywhere except the target.
3. Stop the page from escalating privileges inside the container.
4. Stop a runaway page from exhausting the host's memory or CPU.
5. Stop residue from one run contaminating the next.

The defences, in roughly the order the kernel applies them:

| Layer | Mechanism | Why |
| --- | --- | --- |
| Filesystem | `--read-only` root, no bind mounts, tmpfs `/tmp` | Container cannot write to anything the host sees |
| User | `gosu` drop to `pwuser` before Chromium starts | No root inside the container during the dangerous phase |
| Capabilities | `--cap-drop=ALL` then add only `NET_ADMIN`, `SETUID`, `SETGID` | NET_ADMIN to set iptables; SETUID/SETGID for the privilege drop; nothing else |
| Escalation | `--security-opt=no-new-privileges` | Even if a setuid binary slipped in, it could not gain new privileges |
| Network | iptables `OUTPUT DROP` default, allow only resolved target IPs on 80/443 | Page cannot reach a C2 or third-party tracker |
| Resources | `--memory=768m --cpus=1` | A fork bomb or memory-bomb page is contained |
| Lifetime | `--rm` plus a new container per fetch | No state survives between runs |

The page does have one valuable thing it can do: send DNS queries. UDP port 53 is open so Chromium can resolve hosts at runtime. A determined adversary could exfiltrate small amounts of data via DNS tunneling. Closing that hole would require writing a custom DNS proxy or pre-resolving and statically routing inside the container, both of which were out of scope for a two-day build. The trade-off is documented in `sandbox/entrypoint.sh`.

A second known limitation: on macOS, Docker Desktop runs containers inside a Linux VM, so the iptables rules apply within the container's network namespace and not on the host. This is fine for the threat model (we only care about containing the malicious page), but it's worth knowing that the host's firewall is not the enforcement point.

The screenshot extraction is the one piece of cleverness in the host-side code. Because `/tmp` is a tmpfs and the container is `--rm`, the screenshot file disappears the moment the container exits. The original design used `docker cp` to extract it before removing the container. After the tmpfs change, that no longer worked. The fix: the runner inside the container base64-encodes the PNG into the JSON output, and the host decodes it before passing the result to the agent. The base64 inflates output by ~30%, but Chromium PNGs are small enough that the trade-off is fine.

## Tool-by-tool design notes

A few of the tools have non-obvious implementation details worth surfacing.

**`whois_lookup`.** `python-whois` returns lists when a field has multiple values (multiple creation dates, for example, when a registrar has changed). The `_first()` helper picks the first value, and `_to_iso()` normalises both `datetime` objects and date strings into ISO-8601. Without this normalisation, two domains with the same registration year can serialise as different JSON shapes and confuse downstream tools.

**`tls_certificate`.** Hostname verification is *deliberately disabled* in the SSL context. The point of the tool is to inspect dodgy certificates, including self-signed and expired ones; refusing to look at them defeats the purpose. The tool returns the issuer, subject, validity period, SAN list, and a `self_signed: bool` flag so the agent can reason about it. Domain validation lives upstream, not in the cert parser.

**`favicon_hasher`.** The Shodan-compatible recipe is unusual: fetch the favicon, base64-encode the raw bytes with `base64.encodebytes()` (which inserts a newline every 76 characters), then compute `mmh3.hash()` on the result. The newline insertion is a quirk of the original Shodan implementation that nobody documented but everyone preserves. Using `base64.b64encode()` produces a different hash that does not match Shodan's database. This is the kind of detail that costs an afternoon to discover.

**`urlhaus_lookup`.** Abuse.ch added authentication to URLhaus in 2024. The endpoint now requires an `Auth-Key` header. If the key is missing the tool reports `{"available": False, "reason": ...}` rather than crashing, and the agent works around it. The same pattern is used by `virustotal_lookup` and `urlscan_lookup`.

**`virustotal_lookup`.** VT v3 identifies a URL not by raw text but by a deterministic ID: `base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")`. On a 404 (URL not previously seen), the tool POSTs the URL for analysis and returns a "not yet analysed" placeholder. The next agent run benefits.

**`brand_impersonation`.** The 30-brand list is curated, not exhaustive. The scoring weights password-input presence and cross-domain form-post higher than brand-string-on-unrelated-domain alone, because brand mentions are noisy (a real news article might mention "Microsoft" without impersonating them). The agent often reads the findings list rather than the numeric score, which is the intended use.

## What I deliberately did not build

The original plan ([`PLAN.md`](PLAN.md)) called for a small FastAPI + HTMX web UI and a SQLite run-history store. Both were cut on the second day:

- **The web UI** was scope I could not justify. The Rich-formatted CLI output is already presentation-quality, and screenshots of it sell the project better than a deliberately-minimal web page would. Building the web layer would have eaten time that went into the sandbox instead.
- **SQLite** was redundant. The CLI already writes each verdict as a JSON file in `reports/`. A SQLite store would have added a schema and a query layer for a feature that nobody asked for.

The cuts saved roughly a day, which I spent on the sandbox hardening and the second pass over the tool implementations. I think the trade was correct.

## Limitations and honest caveats

- **No accuracy benchmark.** I have run the agent on a small number of real URLs and it produced the right verdict each time. That is not a study; it is an anecdote. A serious deployment would need precision and recall numbers against a labelled corpus.
- **No rate-limit handling.** VirusTotal and urlscan have public-tier rate limits. The tools do not back off or retry on 429s; they propagate the error to the agent, which usually shrugs and verdicts from the other signals. For a high-volume deployment this would need fixing.
- **Single-region DNS.** All resolution happens from whatever network the user is on. A real triage tool would resolve from multiple vantage points to catch geo-targeted phishing.
- **No screenshot inspection.** The sandbox captures a screenshot but the agent never looks at it. Claude is multimodal and could read the screenshot; integrating that would meaningfully strengthen brand-impersonation detection. Cut for time.
- **WHOIS is patchy.** Many TLDs have aggressive privacy redaction by default, so `whois_lookup` often returns mostly empty fields. The agent has to fall back on other signals when this happens, and the sample TikTok-phish transcript shows it doing so.
- **No persistent state.** Each run is independent. The agent does not remember a domain it triaged ten minutes ago, even if the new URL is on the same host.

## Future work

In rough order of how useful I think they would be:

1. **Accuracy benchmark.** Run the agent against ~50 labelled URLs (a mix of known-good, known-bad, and edge cases) and report precision, recall, and tool-budget usage. This is the single biggest credibility upgrade and probably half a day of work.
2. **Screenshot reasoning.** Pass the base64'd screenshot back into Claude as an image block when `brand_impersonation` is invoked. A visual check would catch impersonations that the textual heuristics miss.
3. **Sandbox MIME-type handling.** Currently the sandbox assumes the response is HTML. URLhaus malware-download URLs serve binary scripts, and the runner just fails to render them. Detecting the response type and capturing it without rendering would be more useful.
4. **`triage feed` subcommand.** Pull the last N URLs from a chosen source (URLhaus, OpenPhish, urlscan), triage each, and emit a summary table. A natural batch-mode primitive without committing to a full queue.
5. **Markdown report export.** Alongside the JSON, write a human-readable `.md` for each run. Trivial.
6. **Multi-region DNS.** Resolve the target from several vantage points and feed all results into `dns_lookup`'s output. Catches geo-targeted infrastructure.

The project was deliberately built to stop where it stops. The list above is what I would do on day three, not what is missing for it to "work".
