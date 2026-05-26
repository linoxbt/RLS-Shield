import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import demoHandler from '../api/demo.js';
import healthHandler from '../api/health.js';
import triageHandler from '../api/triage.js';

function createResponse() {
  return {
    statusCode: 200,
    headers: {},
    payload: undefined,
    status(code) {
      this.statusCode = code;
      return this;
    },
    setHeader(key, value) {
      this.headers[key] = value;
    },
    json(payload) {
      this.payload = payload;
      return this;
    }
  };
}

function createRequest({ method = 'GET', headers = {}, body = '' } = {}) {
  const request = new EventEmitter();
  request.method = method;
  request.headers = headers;
  request.emitBody = () => {
    if (body) request.emit('data', Buffer.from(body));
    request.emit('end');
  };
  return request;
}

test('health endpoint reports the serverless agent as online', () => {
  const response = createResponse();
  healthHandler(createRequest(), response);

  assert.equal(response.statusCode, 200);
  assert.equal(response.payload.status, 'ok');
  assert.equal(response.payload.requires_external_api, false);
});

test('demo endpoint returns sample triage output', () => {
  const response = createResponse();
  demoHandler(createRequest(), response);

  assert.equal(response.statusCode, 200);
  assert.equal(response.payload.summary.total, 5);
});

test('triage endpoint accepts JSON scanner output', async () => {
  const request = createRequest({
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      scanner_output: 'Public Can Execute SECURITY DEFINER Function without signing in.'
    })
  });
  const response = createResponse();
  const done = triageHandler(request, response);
  request.emitBody();
  await done;

  assert.equal(response.statusCode, 200);
  assert.equal(response.payload.summary.high, 1);
  assert.equal(response.payload.findings[0].id, 'anon-security-definer-execute');
});
