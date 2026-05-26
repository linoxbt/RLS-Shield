# RLS Shield Swarms Registration Guide

Use this file to register RLS Shield on the Swarms Marketplace.

## Hackathon Eligibility Checklist

According to the Swarms ACM Hackathon documentation, eligible submissions must:

- Be an agent or prompt with clear real-world utility.
- Use Frenzy Mode during launch.
- Be tokenized.
- Be published on the Swarms Marketplace.
- Be listed for sale before May 27, 2026.

RLS Shield is positioned as a DeFi/security developer tool, which fits the documented hackathon examples for finance, developer tools, operations, and productivity.

## Important API Answer

RLS Shield does not require any external API key to run.

- No Swarms API key is required by the agent code.
- No OpenAI, Anthropic, Groq, Supabase, Circle, or database key is required.
- No package dependencies are required.
- Swarms wallet connection is still required in the web UI to tokenize and list the product.
- The optional web UI is deployable on Vercel and also does not require environment variables.

The Swarms API is only relevant if you are building with Swarms Cloud API separately. For this marketplace launch, use the Swarms web launch form.

## Launch URL

Use:

```text
https://swarms.world/launch?type=prompt&model=tokenized&frenzy=true
```

If the page lets you choose the product type manually, choose `Agent`.

## Product Type

```text
Agent
```

Reason: RLS Shield includes executable Python code. Swarms documentation describes agents as product submissions with executable code.

## Basic Information

Name:

```text
RLS Shield
```

Description:

```text
RLS Shield turns DeFi scanner findings into prioritized remediation plans, Supabase RLS fixes, webhook hardening steps, and verification checks. It helps teams convert noisy security warnings into concrete patch checklists before launch.
```

Categories:

```text
DeFi, Security, Developer Tools
```

Tags:

```text
DeFi, security, Supabase, RLS, audit, webhooks, Postgres, automation
```

## Agent Media

Recommended action:

```text
Use Auto Generate
```

Prompt idea for generated media:

```text
A professional cybersecurity dashboard for a DeFi database security agent, showing shield-like protection over database rows, access policies, and payment webhook signals. Clean, modern, high-trust, dark interface with green and white accents.
```

## Agent Implementation

Implementation mode:

```text
Code
```

Programming language:

```text
python
```

Package requirements:

```text
None
```

If the form already contains `requests`, remove it. RLS Shield uses only Python standard library modules.

Agent code:

```text
Paste the full contents of rls_shield_agent.py.
```

GitHub import:

```text
https://github.com/linoxbt/RLS-Shield
```

If GitHub import succeeds, still inspect the imported code and confirm it uses `rls_shield_agent.py`.

## Use Cases

Use case 1 title:

```text
Scanner finding triage
```

Use case 1 description:

```text
Paste vulnerability scanner output and receive a severity-ranked remediation plan with patch steps, owners, and validation checks.
```

Use case 2 title:

```text
Supabase RLS hardening
```

Use case 2 description:

```text
Convert RLS warnings into concrete policy changes for anon, authenticated, purchaser, owner, and admin access paths.
```

Use case 3 title:

```text
Payment webhook review
```

Use case 3 description:

```text
Identify fail-open payment webhook risks and generate verification checks for signature validation, replay protection, and idempotency.
```

Use case 4 title:

```text
Release readiness
```

Use case 4 description:

```text
Turn stale or noisy security findings into a current release checklist that engineers can run before marketplace or production launch.
```

## Links

Link name:

```text
GitHub
```

URL:

```text
https://github.com/linoxbt/RLS-Shield
```

Optional second link name:

```text
Live Demo
```

URL:

```text
http://144.91.76.243:8091/demo
```

The live health endpoint is:

```text
http://144.91.76.243:8091/health
```

Optional third link name after Vercel deployment:

```text
Web UI
```

URL:

```text
https://YOUR-VERCEL-DOMAIN.vercel.app
```

## Pricing And Tokenization

Choose:

```text
Tokenization
```

Ticker:

```text
RLSX
```

Suggested initial sale price:

```text
5 USDC
```

You can choose a higher initial price, such as `10 USDC` or `15 USDC`, if you want stronger premium positioning.

Expected tokenization requirement:

```text
0.04 SOL minting fee
```

Wallet:

```text
Use the connected linoxbt wallet.
```

## Quality Validation Notes

The submission should pass automated quality review because it includes:

- Executable Python code.
- Type hints and docstrings.
- No external dependencies.
- A clear README.
- Concrete use cases.
- A public GitHub repository.
- A deterministic demo path.

## Pre-Submit Checklist

- Confirm wallet is connected.
- Confirm product type is `Agent`.
- Confirm name is `RLS Shield`.
- Confirm ticker is `RLSX`.
- Confirm tokenization/Frenzy Mode is enabled.
- Confirm package requirements are empty.
- Confirm the GitHub URL is `https://github.com/linoxbt/RLS-Shield`.
- Confirm at least three use cases are filled in.
- Confirm generated image has uploaded successfully.
- Submit the product for quality validation.
- After approval, confirm it is publicly listed for sale before May 27, 2026.

## Reference Links

- Hackathon docs: https://docs.swarms.ai/docs/marketplace/acm-hackathon
- Marketplace launch: https://swarms.world/launch?type=prompt&model=tokenized&frenzy=true
- Monetization/tokenization docs: https://docs.swarms.ai/docs/marketplace/tokenization
