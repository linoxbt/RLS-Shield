const input = document.querySelector('#scanner-input');
const runButton = document.querySelector('#run-triage');
const loadSampleButton = document.querySelector('#load-sample');
const clearButton = document.querySelector('#clear-input');
const copyButton = document.querySelector('#copy-json');
const inputCount = document.querySelector('#input-count');
const runState = document.querySelector('#run-state');
const healthState = document.querySelector('#health-state');
const reportSubtitle = document.querySelector('#report-subtitle');
const emptyState = document.querySelector('#empty-state');
const findingList = document.querySelector('#finding-list');
const nextActions = document.querySelector('#next-actions');
const nextActionsList = document.querySelector('#next-actions-list');
const template = document.querySelector('#finding-template');

const sample = `Circle Webhook Accepts Unauthenticated Requests When Secret Is Unset.
The earnings_calls_select_full_content policy allows rows where price_usdc <= 0.
The user_roles table relies on the prevent_role_escalation trigger.
Public Can Execute SECURITY DEFINER Function without signing in.
Signed-In Users Can Execute SECURITY DEFINER Function.`;

let lastReport = null;

function setMetric(id, value) {
  document.querySelector(id).textContent = String(value ?? 0);
}

function updateInputCount() {
  inputCount.textContent = `${input.value.length.toLocaleString()} chars`;
}

function setBusy(isBusy) {
  runButton.disabled = isBusy;
  runState.textContent = isBusy ? 'Running' : 'Ready';
}

function renderList(listElement, items) {
  listElement.innerHTML = '';
  for (const item of items) {
    const li = document.createElement('li');
    li.textContent = item;
    listElement.appendChild(li);
  }
}

function renderReport(report) {
  lastReport = report;
  const summary = report.summary || {};
  setMetric('#metric-total', summary.total);
  setMetric('#metric-critical', summary.critical);
  setMetric('#metric-high', summary.high);
  setMetric('#metric-medium', summary.medium);
  findingList.innerHTML = '';

  const findings = report.findings || [];
  reportSubtitle.textContent = findings.length
    ? `${findings.length} finding${findings.length === 1 ? '' : 's'} mapped to remediation playbooks.`
    : 'No playbook matched. Refresh scanner output or paste a complete finding.';

  emptyState.hidden = findings.length > 0;
  copyButton.disabled = false;

  const actions = report.next_actions || [];
  nextActions.hidden = actions.length === 0;
  renderList(nextActionsList, actions);

  for (const finding of findings) {
    const node = template.content.cloneNode(true);
    const card = node.querySelector('.finding-card');
    const pill = node.querySelector('.severity-pill');
    const owner = node.querySelector('.owner');
    const title = node.querySelector('h3');
    const impact = node.querySelector('.impact');
    const context = node.querySelector('.context');

    pill.textContent = finding.severity;
    pill.classList.add(finding.severity);
    owner.textContent = finding.owner || finding.suggestedOwner || 'Security';
    title.textContent = finding.title;
    impact.textContent = finding.impact;

    if (finding.context) {
      context.textContent = `Scanner context: ${finding.context}`;
    } else {
      context.remove();
    }

    renderList(node.querySelector('.patches'), finding.patch_checklist || finding.patches || []);
    renderList(node.querySelector('.verification'), finding.verification || []);
    findingList.appendChild(card);
  }
}

async function runTriage() {
  const scannerOutput = input.value.trim();
  if (!scannerOutput) {
    input.focus();
    runState.textContent = 'Paste findings first';
    return;
  }

  setBusy(true);
  try {
    const response = await fetch('/api/triage', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scanner_output: scannerOutput })
    });

    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || 'Triage request failed');
    }

    renderReport(payload);
    runState.textContent = 'Complete';
  } catch (error) {
    runState.textContent = 'Error';
    reportSubtitle.textContent = error.message;
  } finally {
    runButton.disabled = false;
  }
}

async function checkHealth() {
  try {
    const response = await fetch('/api/health');
    const payload = await response.json();
    healthState.textContent = payload.status === 'ok' ? 'Online' : 'Unknown';
  } catch {
    healthState.textContent = 'Unavailable';
  }
}

loadSampleButton.addEventListener('click', () => {
  input.value = sample;
  updateInputCount();
  runTriage();
});

clearButton.addEventListener('click', () => {
  input.value = '';
  updateInputCount();
  input.focus();
});

runButton.addEventListener('click', runTriage);

copyButton.addEventListener('click', async () => {
  if (!lastReport) return;
  await navigator.clipboard.writeText(JSON.stringify(lastReport, null, 2));
  copyButton.textContent = 'Copied JSON';
  setTimeout(() => {
    copyButton.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 8h10v12H8zM6 16H4V4h12v2" /></svg>Copy JSON`;
  }, 1400);
});

input.addEventListener('input', updateInputCount);

updateInputCount();
checkHealth();
