const severityRank = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3
};

const issuePlaybooks = [
  {
    id: 'circle-webhook-secret-unset',
    severity: 'critical',
    match: [/circle webhook/i, /unauthenticated/i, /secret is unset/i],
    title: 'Circle webhook accepts unauthenticated requests when secret is unset',
    impact: 'An attacker can spoof payment events and mark paid transactions as confirmed.',
    patches: [
      'Fail closed when CIRCLE_WEBHOOK_SECRET is missing in every non-local environment.',
      'Verify the Circle signature against the raw request body before parsing or mutating payment state.',
      'Reject unknown event types and require idempotency on provider event IDs.',
      'Store webhook verification failures with request metadata for alerting.'
    ],
    verification: [
      'Unset CIRCLE_WEBHOOK_SECRET and assert POST /api/circle-webhook returns 503 or 500 before touching state.',
      'Send a request with an invalid signature and assert a 401 or 403 response.',
      'Replay a valid event ID and assert no second unlock or confirmation is created.'
    ],
    suggestedOwner: 'Backend payments'
  },
  {
    id: 'paid-content-free-bypass',
    severity: 'high',
    match: [/price_usdc\s*<=\s*0/i, /earnings_calls_select_full_content/i, /free\/zero-price/i],
    title: 'Paid earnings call content can be exposed by free or zero-price policy bypass',
    impact: 'Sensitive paid content can become public if pricing or preview flags are set incorrectly.',
    patches: [
      'Require auth.uid() IS NOT NULL for full-content reads.',
      'Separate preview fields from paid fields with a public-safe view instead of full-row SELECT.',
      'Add CHECK constraints that prevent sensitive fields on rows marked free preview.',
      'Add tests for anon, authenticated-unpaid, and authenticated-paid read paths.'
    ],
    verification: [
      'As anon, SELECT a free or zero-price row and assert sensitive columns are unavailable.',
      'As authenticated unpaid user, assert full transcript and media URLs are blocked.',
      'As purchaser or owner, assert the full row or secure view returns expected paid fields.'
    ],
    suggestedOwner: 'Database/RLS'
  },
  {
    id: 'user-roles-mutation-policy',
    severity: 'high',
    match: [/user_roles/i, /prevent_role_escalation/i],
    title: 'Role mutation depends on trigger instead of explicit RLS write policies',
    impact: 'A future migration that disables or bypasses the trigger could allow privilege escalation.',
    patches: [
      'Add explicit INSERT and UPDATE RLS policies that allow only admins to assign or change roles.',
      'Add DELETE policy only for admins or disallow deletes entirely if role history is required.',
      'Keep the trigger as a second guard and add a migration test that verifies both layers.',
      'Revoke direct table writes from exposed roles if mutations should only happen through RPC.'
    ],
    verification: [
      'As a normal authenticated user, assert INSERT into user_roles fails.',
      'As a normal authenticated user, assert UPDATE role = admin fails.',
      'As an admin, assert intended role-management operations still work.'
    ],
    suggestedOwner: 'Database/RLS'
  },
  {
    id: 'anon-security-definer-execute',
    severity: 'high',
    match: [/public can execute security definer/i, /without signing in/i],
    title: 'Anonymous users can execute SECURITY DEFINER functions',
    impact: 'Unauthenticated callers may be able to run functions with elevated database privileges.',
    patches: [
      'REVOKE EXECUTE on affected functions from anon and public.',
      'Grant EXECUTE only to roles that require the function.',
      'Move internal SECURITY DEFINER functions outside exposed schemas when possible.',
      'Set a fixed search_path inside every SECURITY DEFINER function.'
    ],
    verification: [
      'As anon, assert RPC calls to affected functions return permission denied.',
      'As an authorized role, assert required RPC behavior still works.',
      'Run the Supabase database linter and confirm lint 0028 is cleared.'
    ],
    suggestedOwner: 'Database/RPC'
  },
  {
    id: 'authenticated-security-definer-execute',
    severity: 'medium',
    match: [/signed-in users can execute security definer/i, /security definer.*signed-in users/i],
    title: 'Signed-in users can execute SECURITY DEFINER functions',
    impact: 'Any authenticated account may be able to trigger privileged logic outside its intended workflow.',
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
    ],
    suggestedOwner: 'Database/RPC'
  },
  {
    id: 'outdated-scanner-results',
    severity: 'low',
    match: [/outdated scanner results/i, /\(outdated\)/i, /click update/i],
    title: 'Security scanner findings are outdated',
    impact: 'Teams may be making decisions from stale vulnerability state.',
    patches: [
      'Refresh scanner findings after applying fixes.',
      'Attach scanner run timestamps to release checks.',
      'Block production release only on current high-confidence findings.'
    ],
    verification: [
      'Rerun the scanner and compare current finding IDs against the remediation checklist.',
      'Archive stale findings with dates so they cannot be mistaken for active risk.'
    ],
    suggestedOwner: 'Security operations'
  }
];

export const demoFindings = `Error
Circle Webhook Accepts Unauthenticated Requests When Secret Is Unset
(outdated)
If CIRCLE_WEBHOOK_SECRET is not configured, /api/circle-webhook accepts any POST request. Attackers can spoof Circle payment events.

Warning
Paid earnings call content readable without authentication via free/zero-price bypass
The earnings_calls_select_full_content policy allows rows where price_usdc <= 0 to be read by anyone.

Warning
The user_roles table has only a SELECT policy. Role mutation protection relies entirely on the prevent_role_escalation trigger.

Warning
Public Can Execute SECURITY DEFINER Function
Detects SECURITY DEFINER functions that are callable without signing in.

Warning
Signed-In Users Can Execute SECURITY DEFINER Function
Detects SECURITY DEFINER functions that are callable by signed-in users.`;

function hasAllMatches(text, patterns) {
  return patterns.every((pattern) => pattern.test(text));
}

function extractContext(input, playbook) {
  const lines = input.split(/\r?\n/);
  const foundIndex = lines.findIndex((line) => playbook.match.some((pattern) => pattern.test(line)));
  if (foundIndex === -1) return '';
  const start = Math.max(0, foundIndex - 1);
  const end = Math.min(lines.length, foundIndex + 4);
  return lines.slice(start, end).join(' ').replace(/\s+/g, ' ').trim();
}

export function analyzeFindings(input) {
  const normalized = input.replace(/\s+/g, ' ').trim();
  const findings = issuePlaybooks
    .filter((playbook) => hasAllMatches(normalized, playbook.match))
    .map((playbook) => ({
      id: playbook.id,
      severity: playbook.severity,
      title: playbook.title,
      impact: playbook.impact,
      suggestedOwner: playbook.suggestedOwner,
      context: extractContext(input, playbook),
      patches: playbook.patches,
      verification: playbook.verification
    }))
    .sort((a, b) => severityRank[a.severity] - severityRank[b.severity] || a.title.localeCompare(b.title));

  const unknownSignals = [];
  if (/rls/i.test(input) && !findings.some((finding) => finding.suggestedOwner.includes('Database'))) {
    unknownSignals.push('RLS language was detected, but no specific RLS playbook matched.');
  }
  if (/webhook/i.test(input) && !findings.some((finding) => finding.id.includes('webhook'))) {
    unknownSignals.push('Webhook language was detected, but no specific webhook playbook matched.');
  }

  return {
    agent: {
      name: 'RLS Shield',
      version: '1.0.0'
    },
    summary: {
      totalFindings: findings.length,
      critical: findings.filter((finding) => finding.severity === 'critical').length,
      high: findings.filter((finding) => finding.severity === 'high').length,
      medium: findings.filter((finding) => finding.severity === 'medium').length,
      low: findings.filter((finding) => finding.severity === 'low').length
    },
    findings,
    unknownSignals,
    nextActions: buildNextActions(findings)
  };
}

function buildNextActions(findings) {
  if (findings.length === 0) {
    return [
      'Re-run the scanner with fresh results and provide the full finding text.',
      'Map each finding to source files, migrations, and tests before accepting risk.'
    ];
  }

  const actions = [
    'Fix critical payment spoofing paths before marketplace or production release.',
    'Apply database RLS and function EXECUTE changes in a single migration with role-based tests.',
    'Rerun the scanner after fixes and attach the current scan timestamp to the release checklist.'
  ];

  if (!findings.some((finding) => finding.severity === 'critical')) {
    actions[0] = 'Patch high-severity data exposure and privilege paths before release.';
  }

  return actions;
}

export function renderMarkdownReport(result) {
  const lines = [];
  lines.push(`# ${result.agent.name}`);
  lines.push('');
  lines.push(`Findings triaged: ${result.summary.totalFindings}`);
  lines.push(`Severity mix: ${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.medium} medium, ${result.summary.low} low`);
  lines.push('');
  lines.push('## Recommended execution order');
  result.nextActions.forEach((action, index) => {
    lines.push(`${index + 1}. ${action}`);
  });

  for (const finding of result.findings) {
    lines.push('');
    lines.push(`## ${finding.severity.toUpperCase()}: ${finding.title}`);
    lines.push('');
    lines.push(`Impact: ${finding.impact}`);
    lines.push(`Owner: ${finding.suggestedOwner}`);
    if (finding.context) {
      lines.push(`Scanner context: ${finding.context}`);
    }
    lines.push('');
    lines.push('Patch checklist:');
    finding.patches.forEach((patch) => {
      lines.push(`- ${patch}`);
    });
    lines.push('');
    lines.push('Verification:');
    finding.verification.forEach((step) => {
      lines.push(`- ${step}`);
    });
  }

  if (result.unknownSignals.length) {
    lines.push('');
    lines.push('## Unmatched signals');
    result.unknownSignals.forEach((signal) => {
      lines.push(`- ${signal}`);
    });
  }

  return lines.join('\n');
}
