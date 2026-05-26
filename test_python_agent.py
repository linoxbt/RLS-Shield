"""Smoke tests for the paste-ready RLS Shield Python implementation."""

from rls_shield_agent import triage_security_findings


def test_triage_security_findings_detects_core_playbooks() -> None:
    sample = """
    Circle Webhook Accepts Unauthenticated Requests When Secret Is Unset.
    The earnings_calls_select_full_content policy allows rows where price_usdc <= 0.
    The user_roles table relies on the prevent_role_escalation trigger.
    Public Can Execute SECURITY DEFINER Function without signing in.
    Signed-In Users Can Execute SECURITY DEFINER Function.
    """

    result = triage_security_findings(sample)

    assert result["agent"] == "RLS Shield"
    assert result["summary"]["total"] == 5
    assert result["summary"]["critical"] == 1
    assert result["summary"]["high"] == 3
    assert result["summary"]["medium"] == 1
