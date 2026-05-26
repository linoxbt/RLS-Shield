import { triageSecurityFindings } from './_triage-core.js';

function readBody(request) {
  if (request.body && typeof request.body === 'object') {
    return Promise.resolve(JSON.stringify(request.body));
  }

  if (typeof request.body === 'string') {
    return Promise.resolve(request.body);
  }

  return new Promise((resolve, reject) => {
    let body = '';
    request.on('data', (chunk) => {
      body += chunk;
    });
    request.on('end', () => resolve(body));
    request.on('error', reject);
  });
}

export default async function handler(request, response) {
  if (request.method === 'OPTIONS') {
    response.status(200).json({ ok: true });
    return;
  }

  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    response.status(405).json({ error: 'Use POST with scanner_output text.' });
    return;
  }

  const rawBody = await readBody(request);
  let scannerOutput = rawBody;

  if (String(request.headers['content-type'] || '').includes('application/json')) {
    try {
      const parsed = JSON.parse(rawBody || '{}');
      scannerOutput = parsed.scanner_output || parsed.text || '';
    } catch (error) {
      response.status(400).json({ error: `Invalid JSON: ${error.message}` });
      return;
    }
  }

  if (!String(scannerOutput || '').trim()) {
    response.status(400).json({ error: 'Provide scanner_output text or a raw text request body.' });
    return;
  }

  response.status(200).json(triageSecurityFindings(scannerOutput));
}
