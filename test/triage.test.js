import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeFindings, demoFindings, renderMarkdownReport } from '../src/triage.js';

test('detects and ranks bundled scanner findings', () => {
  const result = analyzeFindings(demoFindings);

  assert.equal(result.summary.totalFindings, 5);
  assert.equal(result.summary.critical, 1);
  assert.equal(result.summary.high, 3);
  assert.equal(result.summary.medium, 1);
  assert.equal(result.findings[0].id, 'circle-webhook-secret-unset');
});

test('renders a usable markdown remediation report', () => {
  const report = renderMarkdownReport(analyzeFindings(demoFindings));

  assert.match(report, /RLS Shield/);
  assert.match(report, /Circle webhook accepts unauthenticated requests/);
  assert.match(report, /Patch checklist:/);
  assert.match(report, /Verification:/);
});

test('returns guidance when no playbook matches', () => {
  const result = analyzeFindings('Unrecognized scanner output');

  assert.equal(result.summary.totalFindings, 0);
  assert.ok(result.nextActions.length > 0);
});
