# RLS Shield

A Swarms ACM Hackathon agent package that converts scanner findings into a ranked remediation report for DeFi applications.

## Run

```bash
npm run demo
```

Analyze your own scanner output:

```bash
node src/index.js --input findings.txt
```

Or pipe findings:

```bash
cat findings.txt | node src/index.js
```

Use JSON for automation:

```bash
npm run demo -- --json
```

## Current playbooks

- Circle webhook signature fail-closed behavior.
- Paid content exposure through free or zero-price RLS bypasses.
- Explicit `user_roles` write policies as defense in depth.
- Anonymous execution of `SECURITY DEFINER` functions.
- Authenticated execution of privileged `SECURITY DEFINER` functions.
- Outdated scanner result handling.

## Swarms submission

See `SWARMS_SUBMISSION.md` for marketplace copy, naming options, and the launch checklist.
