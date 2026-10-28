// SPDX-License-Identifier: Apache-2.0
// Offline, bounded verification of one preserved upstream fixture and four mutations.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../..');
const source = JSON.parse(readFileSync(join(here, 'source.json'), 'utf8'));
const bytes = readFileSync(join(here, source.fixture_local_path));
const sha256 = createHash('sha256').update(bytes).digest('hex');
assert.equal(sha256, source.fixture_sha256, 'upstream fixture bytes changed');
const original = JSON.parse(bytes.toString('utf8'));
assert.equal(original.vectors.length, 1, 'expected exactly one upstream vector');
assert.equal(original.vectors[0].expect.valid, true);
const receipt = original.vectors[0].trust_receipt;
assert.equal(receipt.signoffs[0].key_class, 'B');
assert.equal(receipt.contexts[0].required_approvals, 1);

const flipHex = (hex) => {
  assert.match(hex, /^[0-9a-f]{64}$/);
  return (hex[0] === '0' ? '1' : '0') + hex.slice(1);
};
const definitions = [
  ['mutated_initiator', 'action.initiator', (r) => {
    r.action.initiator = 'other-requester@pilot.example';
  }],
  ['mutated_args_hash', 'action.parameters.args_sha256', (r) => {
    r.action.parameters.args_sha256 = flipHex(r.action.parameters.args_sha256);
  }],
  ['mutated_checkpoint_root', 'log_proof.checkpoint.root_hash', (r) => {
    const hash = r.log_proof.checkpoint.root_hash;
    assert.match(hash, /^sha256:[0-9a-f]{64}$/);
    r.log_proof.checkpoint.root_hash = 'sha256:' + flipHex(hash.slice(7));
  }],
  ['mutated_signoff_signature', 'signoffs[0].signature', (r) => {
    const sig = r.signoffs[0].signature;
    assert.match(sig, /^[A-Za-z0-9_-]+$/);
    r.signoffs[0].signature = (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1);
  }],
];
const corpus = structuredClone(original);
for (const [id, , mutate] of definitions) {
  const vector = structuredClone(original.vectors[0]);
  vector.id = id;
  vector.expect = { valid: false };
  mutate(vector.trust_receipt);
  corpus.vectors.push(vector);
}
const expected = corpus.vectors.map(({ id, expect }) => ({ id, valid: expect.valid }));
const options = {
  cwd: root, encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 * 1024,
  env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
};
const python = process.env.PYTHON || 'python3';
const temp = mkdtempSync(join(tmpdir(), 'emilia-gargoyle-'));
try {
  const path = join(temp, 'mutations.json');
  writeFileSync(path, JSON.stringify(corpus));
  const js = JSON.parse(execFileSync(process.execPath, ['conformance/runners/run-js.mjs', path], options));
  const py = JSON.parse(execFileSync(python, ['conformance/runners/run_py.py', path], options));
  assert.deepEqual(js, expected, 'JavaScript verdicts differ from the expected IDs and booleans');
  assert.deepEqual(py, expected, 'Python verdicts differ from the expected IDs and booleans');
  // Identify the checkout used without treating a working tree as a pinned release.
  const commit = execFileSync('git', ['rev-parse', 'HEAD'], options).trim();
  const status = execFileSync('git', ['status', '--porcelain', '--untracked-files=all', '--',
    'conformance/runners', 'packages/verify', 'packages/python-verify', 'lib',
    'package.json', 'package-lock.json'], options).trim();
  assert.equal(status, '', 'verification source tree must be clean');
  console.log(JSON.stringify({
    format: 'emilia-gargoyle-interop-result-v1',
    upstream_commit: source.upstream_commit,
    fixture_sha256: sha256,
    verifier_checkout_commit: commit,
    verifier_source_tree_clean: true,
    node: process.version,
    python: execFileSync(python, ['--version'], options).trim(),
    mutations: definitions.map(([id, field]) => ({ id, field })),
    js, python_results: py,
    scope: source.scope,
  }, null, 2));
} finally {
  rmSync(temp, { recursive: true, force: true });
}
