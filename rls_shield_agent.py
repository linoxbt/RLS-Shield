"""RLS Shield: DeFi security triage agent for Swarms Marketplace.

Paste scanner output, Supabase RLS warnings, webhook findings, or database
linter output into `triage_security_findings` to receive a prioritized
remediation plan with owners, patch steps, and verification checks.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
import json
import re
from typing import Any, Iterable, Literal

Severity = Literal["critical", "high", "medium", "low"]


@dataclass(frozen=True)
class FindingPlaybook:
    """A deterministic remediation playbook matched against scanner text."""

    id: str
    severity: Severity
    title: str
    patterns: tuple[str, ...]
    impact: str
    owner: str
    patches: tuple[str, ...]
    verification: tuple[str, ...]


PLAYBOOKS: tuple[FindingPlaybook, ...] = (
    FindingPlaybook(
        id="circle-webhook-secret-unset",
        severity="critical",
        title="Circle webhook accepts unauthenticated requests when secret is unset",
        patterns=("circle webhook", "unauthenticated", "secret is unset"),
        impact="Attackers can spoof payment events and unlock paid access without paying.",
        owner="Backend payments",
        patches=(
            "Fail closed when CIRCLE_WEBHOOK_SECRET is missing outside local development.",
            "Verify Circle signatures against the raw request body before parsing JSON.",
            "Reject unknown event types and enforce idempotency on provider event IDs.",
            "Log failed webhook verification attempts for alerting and incident review.",
        ),
        verification=(
            "Unset CIRCLE_WEBHOOK_SECRET and assert POST /api/circle-webhook fails before state changes.",
            "Send an invalid signature and assert the endpoint returns 401 or 403.",
            "Replay a valid event ID and assert no second unlock or confirmation is created.",
        ),
    ),
    FindingPlaybook(
        id="paid-content-free-bypass",
        severity="high",
        title="Paid content can be exposed through free or zero-price RLS bypasses",
        patterns=("price_usdc <= 0", "earnings_calls_select_full_content"),
        impact="Paid transcripts, audio URLs, and trade notes can become public through bad price or preview flags.",
        owner="Database/RLS",
        patches=(
            "Require auth.uid() IS NOT NULL for full-content reads.",
            "Expose public previews through a safe view that excludes paid-only columns.",
            "Add CHECK constraints that prevent sensitive fields on free preview rows.",
            "Test anon, authenticated-unpaid, and authenticated-paid read paths.",
        ),
        verification=(
            "As anon, assert sensitive columns are not selectable on zero-price or preview rows.",
            "As an unpaid authenticated user, assert transcript and media fields are blocked.",
            "As a purchaser or owner, assert the paid content path still returns expected fields.",
        ),
    ),
    FindingPlaybook(
        id="user-roles-mutation-policy",
        severity="high",
        title="Role mutation depends on trigger logic instead of explicit RLS write policies",
        patterns=("user_roles", "prevent_role_escalation"),
        impact="A future migration that weakens the trigger could allow users to grant themselves admin roles.",
        owner="Database/RLS",
        patches=(
            "Add explicit INSERT and UPDATE policies that allow only admins to assign roles.",
            "Add a DELETE policy only for admins, or disallow deletes if role history is required.",
            "Keep the trigger as a second guard and add migration tests for both controls.",
            "Revoke direct table writes from exposed roles if role changes should only happen through RPC.",
        ),
        verification=(
            "As a normal authenticated user, assert INSERT into user_roles fails.",
            "As a normal authenticated user, assert UPDATE role = admin fails.",
            "As an admin, assert intended role-management operations still succeed.",
        ),
    ),
    FindingPlaybook(
        id="anon-security-definer-execute",
        severity="high",
        title="Anonymous users can execute SECURITY DEFINER functions",
        patterns=("public can execute security definer", "without signing in"),
        impact="Unauthenticated callers may be able to run database logic with elevated privileges.",
        owner="Database/RPC",
        patches=(
            "REVOKE EXECUTE on affected functions from anon and public.",
            "Grant EXECUTE only to roles that require the function.",
            "Move internal SECURITY DEFINER functions outside exposed schemas when possible.",
            "Set a fixed search_path inside every SECURITY DEFINER function.",
        ),
        verification=(
            "As anon, assert affected RPC calls return permission denied.",
            "As an authorized role, assert required RPC behavior still works.",
            "Run the Supabase database linter and confirm the anon SECURITY DEFINER lint is cleared.",
        ),
    ),
    FindingPlaybook(
        id="authenticated-security-definer-execute",
        severity="medium",
        title="Signed-in users can execute SECURITY DEFINER functions",
        patterns=("signed-in users can execute security definer",),
        impact="Any authenticated account may trigger privileged logic outside the intended workflow.",
        owner="Database/RPC",
        patches=(
            "Revoke EXECUTE from authenticated on functions that are not public API.",
            "Add role checks inside functions that must remain callable from the API.",
            "Prefer SECURITY INVOKER for functions that do not need elevated privileges.",
            "Document intended callers for every exposed RPC.",
        ),
        verification=(
            "As a basic authenticated user, assert restricted RPCs return permission denied.",
            "As an authorized user, assert the function succeeds only for permitted operations.",
            "Run the database linter and inspect remaining SECURITY DEFINER warnings.",
        ),
    ),
)

SEVERITY_ORDER: dict[Severity, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


def _matches(text: str, patterns: Iterable[str]) -> bool:
    return all(pattern.lower() in text for pattern in patterns)


def triage_security_findings(scanner_output: str) -> dict[str, Any]:
    """Return prioritized remediation guidance for DeFi security scanner output.

    Args:
        scanner_output: Raw scanner text, database linter warnings, or issue summaries.

    Returns:
        A dictionary containing severity counts, matched findings, patch checklists,
        verification checks, and next actions.
    """

    normalized = _normalize(scanner_output)
    findings = []

    for playbook in PLAYBOOKS:
        if _matches(normalized, playbook.patterns):
            findings.append(
                {
                    "id": playbook.id,
                    "severity": playbook.severity,
                    "title": playbook.title,
                    "impact": playbook.impact,
                    "owner": playbook.owner,
                    "patch_checklist": list(playbook.patches),
                    "verification": list(playbook.verification),
                }
            )

    findings.sort(key=lambda item: (SEVERITY_ORDER[item["severity"]], item["title"]))
    counts = {
        "total": len(findings),
        "critical": sum(1 for item in findings if item["severity"] == "critical"),
        "high": sum(1 for item in findings if item["severity"] == "high"),
        "medium": sum(1 for item in findings if item["severity"] == "medium"),
        "low": sum(1 for item in findings if item["severity"] == "low"),
    }

    if counts["critical"]:
        first_action = "Fix payment-spoofing and access-unlock risks before launch."
    elif counts["high"]:
        first_action = "Patch high-severity data exposure and privilege risks before launch."
    else:
        first_action = "Refresh scanner results and map each current finding to source files and tests."

    return {
        "agent": "RLS Shield",
        "version": "1.0.0",
        "summary": counts,
        "findings": findings,
        "next_actions": [
            first_action,
            "Apply RLS/function EXECUTE changes in migrations with role-based regression tests.",
            "Rerun scanners and attach fresh scan timestamps to the release checklist.",
        ],
    }


def run_agent(scanner_output: str) -> str:
    """Run RLS Shield and return a formatted JSON report."""

    return json.dumps(triage_security_findings(scanner_output), indent=2)


if __name__ == "__main__":
    sample = """
    Circle Webhook Accepts Unauthenticated Requests When Secret Is Unset.
    The earnings_calls_select_full_content policy allows rows where price_usdc <= 0.
    The user_roles table relies on the prevent_role_escalation trigger.
    Public Can Execute SECURITY DEFINER Function without signing in.
    Signed-In Users Can Execute SECURITY DEFINER Function.
    """
    print(run_agent(sample))
