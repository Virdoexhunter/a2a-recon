# a2a-recon

**Black-box recon for multi-agent / Agent-to-Agent (A2A) LLM systems.**

`a2a-recon` fingerprints a multi-agent LLM application from the outside: it works out
whether a target is multi-agent, maps the agents and their handoffs, leaks the
inter-agent message format, tests whether agent/role messages are authenticated, and
locates the tool-executor — then writes a JSON report with evidence per finding.

It is the companion tool for **Chapter 22 — Agent-to-Agent (A2A) Injection** of the
[AI Red Teaming notes](https://nebulous-gem-db8.notion.site/AI-RED-TEAMING-by-Virdoex_hunter-3e7d108d10ab80d49818eed4e636892c).

> ⚠️ **Recon only.** It sends benign probes and canary tokens — no exploits, no
> jailbreaks, no destructive payloads. Use it **only** on systems you own or have
> explicit written permission to test.

---

## What it checks (7 probes)

| Probe | What it tells you |
| --- | --- |
| Multi-agent detection | Baselines latency, forces a delegation, flags staged latency + handoff keywords ("delegating", "planner", "routing to"…) |
| Architecture disclosure | Asks the system to describe its own agents and rebuilds the roster |
| Message-format leak | Tries to echo an inter-agent message, regex-detects role schemas like `[from: supervisor]` |
| Message authentication | Sends a **forged** `[from: supervisor]` asking only for a harmless canary token; if obeyed, role messages are likely unauthenticated |
| Executor / tools | Finds which hop can actually call tools (the real target) |
| Untrusted-input echo | Plants a benign canary in "content to summarize" and checks if it survives to output |
| A2A agent card | Fetches `/.well-known/agent-card.json` (and the legacy `agent.json`) to grab declared skills/endpoints |

Every finding is marked **"confirm manually"** — the tool is a lead generator, not a verdict.

---

## Install

No dependencies beyond Python 3.8+ (standard library only).

```bash
git clone https://github.com/Virdoexhunter/a2a-recon.git
cd a2a-recon
```

## Usage

The transport is pluggable, so it works against any HTTP chat endpoint:

```bash
python3 a2a_recon.py --authorized \
  --url https://your-lab.example/api/chat \
  --header "Content-Type: application/json" \
  --body-template '{"message": "{PROMPT}"}' \
  --response-path message \
  --out report.json
```

| Flag | Meaning |
| --- | --- |
| `--url` | The chat endpoint to test |
| `--method` | HTTP method (default `POST`) |
| `--header` | Repeatable, `"Key: Value"` |
| `--body-template` | JSON string containing the literal token `{PROMPT}` |
| `--response-path` | Dot-path to the reply text (e.g. `choices.0.message.content`), or `raw` |
| `--delay` | Seconds between requests (respect rate limits) |
| `--out` | Report file (default `a2a_recon_report.json`) |
| `--authorized` | **Required** — you confirm you are authorised to test this target |

It refuses to run without `--authorized`.

## Example output

```json
{
  "target": "https://your-lab.example/api/chat",
  "summary": [
    "multi-agent likelihood: high",
    "role/message schema LEAKED (spoofing surface)",
    "forged supervisor label OBEYED (likely unauthenticated)",
    "tool/executor capability present"
  ],
  "findings": [ ... per-probe detail with evidence ... ]
}
```

---

## Ethics & scope

This tool is for **authorised security testing and education only**. It intentionally
carries no weaponized payloads — only benign canaries. Testing systems you do not own
or have written permission to assess is illegal. You are responsible for staying in scope.

## License

MIT

---

*Built by [Virdoex_hunter](https://x.com/Virdoex_hunter) · part of the AI Red Teaming series.*
