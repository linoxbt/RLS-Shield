const severityRank = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3
};

const playbooks = [
  {
    id: 'circle-webhook-secret-unset',
    severity: 'critical',
    match: ['circle webhook', 'unauthenticated', 'secret is unset'],
    title: 'Circle webhook accepts unauthenticated requests when secret is unset',
    impact: 'Attackers can spoof payment events and unlock paid access without paying.',
    owner: 'Backend payments',
    patches: [
      'Fail closed when CIRCLE_WEBHOOK_SECRET is missing outside local development.',
      'Verify Circle signatures against the raw request body before parsing JSON.',
      'Reject unknown event types and enforce idempotency on provider event IDs.',
      'Log failed webhook verification attempts for alerting and incident review.'
    ],
    verification: [
      'Unset CIRCLE_WEBHOOK_SECRET and assert POST /api/circle-webhook fails before state changes.',
      'Send an invalid signature and assert the endpoint returns 401 or 403.',
      'Replay a valid event ID and assert no second unlock or confirmation is created.'
    ]
  },
  {
    id: 'paid-content-free-bypass',
    severity: 'high',
    match: ['price_usdc <= 0', 'earnings_calls_select_full_content'],
    title: 'Paid content can be exposed through free or zero-price RLS bypasses',
    impact: 'Paid transcripts, audio URLs, and trade notes can become public through bad price or preview flags.',
    owner: 'Database/RLS',
    patches: [
      'Require auth.uid() IS NOT NULL for full-content reads.',
      'Expose public previews through a safe view that excludes paid-only columns.',
      'Add CHECK constraints that prevent sensitive fields on free preview rows.',
      'Test anon, authenticated-unpaid, and authenticated-paid read paths.'
    ],
    verification: [
      'As anon, assert sensitive columns are not selectable on zero-price or preview rows.',
      'As an unpaid authenticated user, assert transcript and media fields are blocked.',
      'As a purchaser or owner, assert the paid content path still returns expected fields.'
    ]
  },
  {
    id: 'user-roles-mutation-policy',
    severity: 'high',
    match: ['user_roles', 'prevent_role_escalation'],
    title: 'Role mutation depends on trigger logic instead of explicit RLS write policies',
    impact: 'A future migration that weakens the trigger could allow users to grant themselves admin roles.',
    owner: 'Database/RLS',
    patches: [
      'Add explicit INSERT and UPDATE policies that allow only admins to assign roles.',
      'Add a DELETE policy only for admins, or disallow deletes if role history is required.',
      'Keep the trigger as a second guard and add migration tests for both controls.',
      'Revoke direct table writes from exposed roles if role changes should only happen through RPC.'
    ],
    verification: [
      'As a normal authenticated user, assert INSERT into user_roles fails.',
      'As a normal authenticated user, assert UPDATE role = admin fails.',
      'As an admin, assert intended role-management operations still succeed.'
    ]
  },
  {
    id: 'anon-security-definer-execute',
    severity: 'high',
    match: ['public can execute security definer', 'without signing in'],
    title: 'Anonymous users can execute SECURITY DEFINER functions',
    impact: 'Unauthenticated callers may be able to run database logic with elevated privileges.',
    owner: 'Database/RPC',
    patches: [
      'REVOKE EXECUTE on affected functions from anon and public.',
      'Grant EXECUTE only to roles that require the function.',
      'Move internal SECURITY DEFINER functions outside exposed schemas when possible.',
      'Set a fixed search_path inside every SECURITY DEFINER function.'
    ],
    verification: [
      'As anon, assert affected RPC calls return permission denied.',
      'As an authorized role, assert required RPC behavior still works.',
      'Run the Supabase database linter and confirm the anon SECURITY DEFINER lint is cleared.'
    ]
  },
  {
    id: 'authenticated-security-definer-execute',
    severity: 'medium',
    match: ['signed-in users can execute security definer'],
    title: 'Signed-in users can execute SECURITY DEFINER functions',
    impact: 'Any authenticated account may trigger privileged logic outside the intended workflow.',
    owner: 'Database/RPC',
    patches: [
      'Revoke EXECUTE from authenticated on functions that are not public API.',
      'Add role checks inside functions that must remain callable from the API.',
      'Prefer SECURITY INVOKER for functions that do not need elevated privileges.',
      'Document intended callers for every exposed RPC.'
    ],
    verification: [
      'As a basic authenticated user, assert restricted RPCs return permission denied.',
      'As an authorized user, assert the function succeeds only for permitted operations.',
      'Run the database linter and inspect remaining SECURITY DEFINER warnings.'
    ]
  },
  {
    id: 'outdated-scanner-results',
    severity: 'low',
    match: ['outdated'],
    title: 'Security scanner findings are outdated',
    impact: 'Teams may be making decisions from stale vulnerability state.',
    owner: 'Security operations',
    patches: [
      'Refresh scanner findings after applying fixes.',
      'Attach scanner run timestamps to release checks.',
      'Block production release only on current high-confidence findings.'
    ],
    verification: [
      'Rerun the scanner and compare current finding IDs against the remediation checklist.',
      'Archive stale findings with dates so they cannot be mistaken for active risk.'
    ]
  }
];

export const sampleFindings = `Circle Webhook Accepts Unauthenticated Requests When Secret Is Unset.
The earnings_calls_select_full_content policy allows rows where price_usdc <= 0.
The user_roles table relies on the prevent_role_escalation trigger.
Public Can Execute SECURITY DEFINER Function without signing in.
Signed-In Users Can Execute SECURITY DEFINER Function.`;

function normalize(input) {
  return String(input || '').toLowerCase().replace(/\s+/g, ' ').trim();
}

function getContext(input, playbook) {
  const lines = String(input || '').split(/\r?\n/).filter(Boolean);
  const index = lines.findIndex((line) => playbook.match.some((needle) => normalize(line).includes(needle)));
  if (index === -1) return '';
  return lines.slice(Math.max(0, index - 1), index + 4).join(' ').replace(/\s+/g, ' ').trim();
}

function buildActions(findings) {
  if (findings.length === 0) {
    return [
      'Refresh scanner results and paste the complete finding text.',
      'Map every current finding to source files, migrations, and regression tests.',
      'Do not accept launch risk until a fresh scanner run is attached to the release checklist.'
    ];
  }

  const first = findings.some((finding) => finding.severity === 'critical')
    ? 'Fix payment-spoofing and access-unlock risks before launch.'
    : 'Patch high-severity data exposure and privilege risks before launch.';

  return [
    first,
    'Apply RLS/function EXECUTE changes in migrations with role-based regression tests.',
    'Rerun scanners and attach fresh scan timestamps to the release checklist.'
  ];
}

export function triageSecurityFindings(scannerOutput) {
  const normalized = normalize(scannerOutput);
  const findings = playbooks
    .filter((playbook) => playbook.match.every((needle) => normalized.includes(needle)))
    .map((playbook) => ({
      id: playbook.id,
      severity: playbook.severity,
      title: playbook.title,
      impact: playbook.impact,
      owner: playbook.owner,
      context: getContext(scannerOutput, playbook),
      patch_checklist: playbook.patches,
      verification: playbook.verification
    }))
    .sort((a, b) => severityRank[a.severity] - severityRank[b.severity] || a.title.localeCompare(b.title));

  const summary = {
    total: findings.length,
    critical: findings.filter((finding) => finding.severity === 'critical').length,
    high: findings.filter((finding) => finding.severity === 'high').length,
    medium: findings.filter((finding) => finding.severity === 'medium').length,
    low: findings.filter((finding) => finding.severity === 'low').length
  };

  return {
    agent: 'RLS Shield',
    version: '1.0.0',
    summary,
    findings,
    next_actions: buildActions(findings)
  };
}
