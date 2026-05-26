# RLS Shield

RLS Shield is a dependency-free DeFi security triage agent for the Swarms Marketplace. It converts scanner findings, Supabase RLS warnings, webhook risks, and database linter output into a prioritized remediation plan with owners, patch checklists, and verification steps.

The agent is designed for builders who need a practical release-readiness review before launching paid DeFi products, tokenized agents, or marketplace workflows.

## What It Does

- Ranks security findings by severity.
- Maps known DeFi/Supabase risks to concrete remediation playbooks.
- Produces patch checklists for engineers.
- Produces verification checks for QA, CI, or release review.
- Runs without external AI APIs, model keys, databases, or paid services.
- Works as direct Python code, a local CLI-style script, or a small HTTP service.

## Current Playbooks

- Circle webhook signature fail-closed behavior.
- Paid content exposure through free or zero-price RLS bypasses.
- Explicit `user_roles` write policies as defense in depth.
- Anonymous execution of `SECURITY DEFINER` functions.
- Authenticated execution of privileged `SECURITY DEFINER` functions.

## Repository Layout

```text
.
├── rls_shield_agent.py      # Paste-ready Swarms Marketplace agent code
├── server.py                # Dependency-free HTTP server wrapper
├── REGISTER.md             # Exact Swarms registration fields
├── src/                    # Node CLI version used during local development
├── test/                   # Node tests
└── test_python_agent.py    # Python smoke test for pytest-compatible runners
```

## Requirements

- Python 3.10 or newer.
- No Python package dependencies.
- Optional: Node.js 18 or newer if you want to run the development CLI/tests in `src/`.

## Run Locally

Run the paste-ready Python agent:

```bash
python3 rls_shield_agent.py
```

Use it from Python:

```python
from rls_shield_agent import triage_security_findings

scanner_output = """
Circle Webhook Accepts Unauthenticated Requests When Secret Is Unset.
The earnings_calls_select_full_content policy allows rows where price_usdc <= 0.
"""

report = triage_security_findings(scanner_output)
print(report["summary"])
```

Run the HTTP service:

```bash
python3 server.py
```

Default service URL:

```text
http://0.0.0.0:8091
```

Health check:

```bash
curl http://127.0.0.1:8091/health
```

Demo report:

```bash
curl http://127.0.0.1:8091/demo
```

Analyze findings:

```bash
curl -X POST http://127.0.0.1:8091/triage \
  -H "Content-Type: application/json" \
  -d '{"scanner_output":"Public Can Execute SECURITY DEFINER Function without signing in."}'
```

Change host/port:

```bash
RLS_SHIELD_HOST=0.0.0.0 RLS_SHIELD_PORT=8091 python3 server.py
```

## Swarms Marketplace

Use `rls_shield_agent.py` as the direct agent code in the Swarms launch form.

- Product type: Agent
- Language: Python
- Package requirements: none
- Monetization: Tokenization
- Ticker: RLSX
- Frenzy Mode: enabled

See [REGISTER.md](REGISTER.md) for the full registration copy.

## Why It Does Not Require An API Key

RLS Shield is deterministic security triage code. It does not call Swarms API, OpenAI, Anthropic, Supabase, Circle, or any external service at runtime.

The Swarms API key shown in Swarms documentation is for developers who want to run Swarms Cloud API calls. The marketplace registration flow for this submission uses the Swarms web launch form and your connected wallet for tokenization.

## Development Checks

Python execution smoke test:

```bash
python3 rls_shield_agent.py
```

Optional Node development tests:

```bash
npm test
```

## Security Notes

- Do not commit wallet private keys, seed phrases, API keys, or `.env` files.
- Tokenization requires wallet approval in the Swarms web UI.
- This agent gives remediation guidance; final production changes should still be reviewed and tested by the project team.

## License

MIT
