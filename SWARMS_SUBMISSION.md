# Swarms Marketplace Submission

## Selected name

RLS Shield

## Marketplace category

DeFi / Security / Automation

## Short description

Turns DeFi scanner findings into prioritized remediation plans, database migration guidance, webhook hardening steps, and verification commands.

## Long description

RLS Shield is a security triage agent for DeFi builders shipping under time pressure. Paste scanner output, Supabase RLS warnings, webhook findings, or database linter output and the agent produces a ranked remediation report with owners, patch checklists, and validation steps.

The first release is tuned for high-risk DeFi application failures: unauthenticated payment webhooks, public paid-content reads, role escalation through weak RLS write policies, and exposed SECURITY DEFINER functions. It is designed to help teams move from noisy scanner text to actionable engineering work without hiding the verification burden.

## What buyers get

- Prioritized security finding triage.
- Patch checklist for each finding.
- Verification commands and test cases to prove the fix.
- Database and API hardening guidance for Supabase-backed DeFi apps.
- JSON output for CI or agent-to-agent workflows.

## Suggested launch settings

- Product type: Agent or Prompt
- Model: Tokenized
- Frenzy Mode: Enabled
- Price: 5 to 15 USDC for the initial listing
- Token ticker: RLSX
- Programming language: Python
- Package requirements: none
- Agent code: paste `rls_shield_agent.py`

## Basic information

- Name: RLS Shield
- Description: RLS Shield turns DeFi scanner findings into prioritized remediation plans, Supabase RLS fixes, webhook hardening steps, and verification checks.
- Categories: DeFi, Security, Developer Tools
- Tags: DeFi, security, Supabase, RLS, audit, webhooks, Postgres, automation

## Use cases

### Scanner finding triage

Paste vulnerability scanner output and receive a severity-ranked remediation plan with patch steps, owners, and validation checks.

### Supabase RLS hardening

Convert RLS warnings into concrete policy changes for anon, authenticated, purchaser, owner, and admin access paths.

### Payment webhook review

Identify fail-open payment webhook risks and generate verification checks for signature validation, replay protection, and idempotency.

### Release readiness

Turn stale or noisy security findings into a current release checklist that engineers can run before marketplace or production launch.

## Links

- GitHub: add the public repository URL after you create it.

## Launch checklist

1. Sign in at https://swarms.world/signin.
2. Open https://swarms.world/launch?type=prompt&model=tokenized&frenzy=true.
3. Use one of the recommended names and paste the marketplace copy above.
4. Upload or link this package as the agent implementation artifact.
5. Enable Frenzy Mode and tokenize the listing.
6. List it for sale before the hackathon deadline.

## Demo command

```bash
npm run demo
```

## Structured output command

```bash
npm run demo -- --json
```
