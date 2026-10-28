// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { canonicalize } from './index.js';
import { verifyResolutionReceipt } from './resolution.js';
import { computeBme04Digest, verifyBme04ResolutionReceipt } from './resolution-bme04.js';

const suite = JSON.parse(readFileSync(new URL('../../conformance/vectors/resolution.bme04.v1.json', import.meta.url), 'utf8'));
const oldSuite = JSON.parse(readFileSync(new URL('../../conformance/vectors/resolution.v1.json', import.meta.url), 'utf8'));
for (const c of suite.canonicalization) test(`BME04 independent upstream digest: ${c.id}`, () => {
  assert.equal(computeBme04Digest(c.json), c.digest);
  if (c.canonical_bytes) assert.equal(Buffer.byteLength(canonicalize(JSON.parse(c.json))), c.canonical_bytes);
});
for (const v of suite.vectors) test(`BME04: ${v.id}`, () => {
  const before = JSON.stringify(v);
  const result = verifyBme04ResolutionReceipt(v.receipt_json, v.options);
  for (const [key, expected] of Object.entries(v.expected)) assert.equal(result[key], expected, JSON.stringify(result));
  assert.equal(JSON.stringify(v), before, 'verifier must not mutate caller inputs');
});
for (const c of suite.digest_boundaries) test(`BME04 resource boundary: ${c.id}`, () => {
  const raw = c.kind === 'depth' ? '{"a":' + '['.repeat(c.count) + ']'.repeat(c.count) + '}'
    : c.kind === 'nodes' ? '{"a":[' + Array(c.count).fill('0').join(',') + ']}'
      : '{"a":"' + 'x'.repeat(c.count - 8) + '"}';
  assert.equal(computeBme04Digest(raw), c.digest);
});
test('BME04 cannot replace v1 through the legacy API or a relabel', () => {
  const v = suite.vectors[0];
  const receipt = JSON.parse(v.receipt_json);
  assert.equal(verifyResolutionReceipt(receipt, v.options).valid, false);
  receipt.profile = 'EP-RESOLUTION-v1';
  assert.equal(verifyResolutionReceipt(receipt, v.options).valid, false);
  const legacy = structuredClone(oldSuite.vectors.find(v => v.id === 'accept_approved').resolution_receipt);
  assert.equal(verifyBme04ResolutionReceipt(JSON.stringify(legacy), v.options).valid, false);
  legacy.profile = suite.profile;
  assert.equal(verifyBme04ResolutionReceipt(JSON.stringify(legacy), v.options).valid, false);
});
test('BME04 requires raw object JSON and refuses absent caller policy', () => {
  const v = suite.vectors[0];
  for (const raw of [null, {}, [], '', '{} trailing', '[]', 'null', '{"x":NaN}']) {
    assert.equal(verifyBme04ResolutionReceipt(raw as string, v.options).valid, false);
  }
  assert.equal(verifyBme04ResolutionReceipt(v.receipt_json).valid, false);
});
