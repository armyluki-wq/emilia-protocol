// SPDX-License-Identifier: Apache-2.0
/** Experimental, opt-in native BME-04 resolution evidence. v1 is unchanged. */
import crypto from 'node:crypto';
import { canonicalize, isCanonicalizable, verifyWebAuthnSignoff } from './index.js';
import { strictJsonGate } from './strict-json.js';

type Obj = Record<string, any>;
export const BME04_RESOLUTION_VERSION = 'EP-RESOLUTION-BME04-v1';
export const BME04_CONTEXT_TYPE = 'ep.resolution.bme04.v1';
export const BME04_SOURCE_REVISION = 'draft-morrison-binding-moment-envelope-04';
export const BME04_ACTION_MAPPING = 'BME04-JCS-ACTION-v1';
export interface Bme04ResolutionOptions {
  acceptedProfile?: string;
  sourceRevision?: string;
  actionMapping?: string;
  bindingMomentJson?: string;
  actionJson?: string;
  principalKeys?: Record<string, Obj>;
  rpId?: string;
  allowedOrigins?: string[];
  expectedNonce?: string;
  expectedInitiator?: string;
  evaluationTime?: string;
}
const HASH = /^sha256:[0-9a-f]{64}$/;
const RFC3339_OFFSET = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,3})?(?:Z|([+-])(\d{2}):(\d{2}))$/;
const CONTEXT_KEYS = new Set([
  'ep_version', 'context_type', 'source_revision', 'action_mapping',
  'principal', 'principal_key_id', 'initiator', 'nonce', 'issued_at', 'expires_at', 'resolution',
]);
function isRecord(value: unknown): value is Obj {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value: unknown, allowed: Set<string>, required: Set<string> = allowed): value is Obj {
  if (!isRecord(value)) return false;
  const keys = Object.keys(value);
  return keys.every((key) => allowed.has(key))
    && [...required].every((key) => Object.hasOwn(value, key));
}

function isHash(value: unknown): value is string {
  return typeof value === 'string' && value.length === 71 && HASH.test(value);
}

function parseInstant(value: unknown): number {
  if (typeof value !== 'string' || value.startsWith('0000-') || value.endsWith('-00:00')) return NaN;
  const match = value.match(RFC3339_OFFSET);
  if (!match || match[0].length !== value.length) return NaN;
  const [, year, month, day, hour, minute, second, , offsetHour, offsetMinute] = match;
  const calendar = new Date(0);
  calendar.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
  calendar.setUTCHours(Number(hour), Number(minute), Number(second), 0);
  if (calendar.toISOString().slice(0, 19) !== `${year}-${month}-${day}T${hour}:${minute}:${second}`) return NaN;
  if (offsetHour !== undefined && (Number(offsetHour) > 23 || Number(offsetMinute) > 59)) return NaN;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : NaN;
}

function sha256Canonical(value: unknown): string | null {
  try {
    if (!isCanonicalizable(value)) return null;
    return `sha256:${crypto.createHash('sha256').update(canonicalize(value), 'utf8').digest('hex')}`;
  } catch {
    return null;
  }
}


/** Refuse rounded fractional/out-of-range JSON literals before JSON.parse. */
function exactIntegerLiteral(token: string): boolean {
  const value = Number(token);
  if (!Number.isSafeInteger(value)) return false;
  const match = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(token);
  if (!match) return false;
  const digits = BigInt(match[2] + (match[3] ?? ''));
  if (digits === 0n) return true;
  const shift = Number(match[4] ?? '0') - (match[3]?.length ?? 0);
  if (!Number.isSafeInteger(shift) || shift > 16 || shift < -token.length) return false;
  const divisor = 10n ** BigInt(Math.abs(shift));
  if (shift < 0 && digits % divisor !== 0n) return false;
  const exact = shift < 0 ? digits / divisor : digits * divisor;
  return exact <= 9007199254740991n && Number(exact) === Math.abs(value);
}
// Replaces every JSON string literal with "" in one linear pass. Input has
// already passed strictJsonGate, so escapes are well formed.
function stripJsonStrings(raw: string): string {
  let out = '';
  let i = 0;
  while (i < raw.length) {
    if (raw[i] !== '"') {
      out += raw[i++];
      continue;
    }
    i++;
    while (i < raw.length && raw[i] !== '"') i += raw[i] === '\\' ? 2 : 1;
    i++;
    out += '""';
  }
  return out;
}

function parseRaw(raw: unknown): Obj {
  if (typeof raw !== 'string' || Buffer.byteLength(raw, 'utf8') > 1024 * 1024 || !strictJsonGate(raw).ok) {
    throw new Error('invalid raw JSON');
  }
  const withoutStrings = stripJsonStrings(raw);
  for (const match of withoutStrings.matchAll(/-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g)) {
    if (!exactIntegerLiteral(match[0])) throw new Error('outside integer profile');
  }
  const value = JSON.parse(raw);
  if (!isRecord(value) || !isCanonicalizable(value)) throw new Error('outside canonical profile');
  return value;
}
function canonicalBase64url(value: unknown): Buffer {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('invalid base64url');
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.toString('base64url') !== value) throw new Error('noncanonical base64url');
  return decoded;
}
export function computeBme04Digest(rawJson: string): string | null {
  try { return sha256Canonical(parseRaw(rawJson)); } catch { return null; }
}
function nativeResolutionValid(resolution: unknown, envelope: Obj): resolution is Obj {
  if (!isRecord(resolution) || !isHash(resolution.envelope_digest)) return false;
  const common = ['envelope_digest', 'resolution'];
  if (resolution.resolution === 'option') {
    return hasExactKeys(resolution, new Set([...common, 'option_idx']))
      && Number.isSafeInteger(resolution.option_idx) && resolution.option_idx >= 0
      && resolution.option_idx < envelope.question.options.length;
  }
  if (resolution.resolution === 'answer') {
    return hasExactKeys(resolution, new Set([...common, 'answer']))
      && typeof resolution.answer === 'string' && envelope.question.hatches.free_text === true;
  }
  return (resolution.resolution === 'declined'
      || (resolution.resolution === 'question' && envelope.question.hatches.dialogue === true))
    && hasExactKeys(resolution, new Set(common));
}
function structureValid(receipt: Obj): boolean {
  if (!hasExactKeys(receipt, new Set(['profile', 'signoff'])) || receipt.profile !== BME04_RESOLUTION_VERSION) return false;
  const signoff = receipt.signoff;
  if (!hasExactKeys(signoff, new Set(['@type', 'context', 'webauthn'])) || signoff['@type'] !== 'ep.signoff') return false;
  if (!hasExactKeys(signoff.context, CONTEXT_KEYS)
    || !hasExactKeys(signoff.webauthn, new Set(['authenticator_data', 'client_data_json', 'signature']))) return false;
  const context = signoff.context;
  return context.ep_version === '1.0' && context.context_type === BME04_CONTEXT_TYPE
    && context.source_revision === BME04_SOURCE_REVISION && context.action_mapping === BME04_ACTION_MAPPING
    && ['principal', 'principal_key_id', 'initiator', 'nonce'].every((key) => typeof context[key] === 'string' && context[key].length > 0);
}

/** Raw JSON only: callers must not erase duplicate-member evidence before verification. */
export function verifyBme04ResolutionReceipt(receiptJson: string, opts: Bme04ResolutionOptions = {}) {
  const checks: Record<string, boolean> = {};
  let outcome: string | null = null;
  const refuse = (reason: string) => ({ valid: false, authorizes_action: false, outcome,
    requires_successor: false, checks, reason });
  try {
    checks.profile_policy = opts.acceptedProfile === BME04_RESOLUTION_VERSION
      && opts.sourceRevision === BME04_SOURCE_REVISION && opts.actionMapping === BME04_ACTION_MAPPING;
    if (!checks.profile_policy) return refuse('bme04_profile_not_admitted');
    let receipt: Obj, envelope: Obj, action: Obj | null = null;
    try {
      receipt = parseRaw(receiptJson);
      envelope = parseRaw(opts.bindingMomentJson);
      if (opts.actionJson !== undefined) action = parseRaw(opts.actionJson);
    } catch { return refuse('invalid_raw_json'); }
    checks.structure = structureValid(receipt);
    if (!checks.structure) return refuse('malformed_resolution_receipt');
    const signoff = receipt.signoff, context = signoff.context;
    checks.binding_moment_shape = bindingMomentShapeValid(envelope);
    if (!checks.binding_moment_shape) return refuse('malformed_binding_moment');
    checks.outcome_shape = nativeResolutionValid(context.resolution, envelope);
    if (!checks.outcome_shape) return refuse('invalid_outcome_shape');
    const resolution = context.resolution;
    outcome = resolution.resolution;
    checks.envelope_binding = resolution.envelope_digest === sha256Canonical(envelope);
    if (!checks.envelope_binding) return refuse('envelope_binding_mismatch');
    checks.selected_option_binding = outcome === 'option' && action !== null
      && envelope.question.options[resolution.option_idx].action_digest === sha256Canonical(action);
    const pin = isRecord(opts.principalKeys) && Object.hasOwn(opts.principalKeys, context.principal_key_id)
      ? opts.principalKeys[context.principal_key_id] : null;
    checks.principal_pin = isRecord(pin) && pin.principal === context.principal
      && typeof pin.public_key === 'string' && pin.public_key.length > 0;
    if (!checks.principal_pin) return refuse('principal_key_not_pinned_for_role');
    try {
      const key = crypto.createPublicKey({ key: canonicalBase64url(pin!.public_key), format: 'der', type: 'spki' });
      checks.signature_algorithm = key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1';
    } catch { checks.signature_algorithm = false; }
    if (!checks.signature_algorithm) return refuse('unsupported_signature_algorithm');
    const initiatorPinned = typeof opts.expectedInitiator === 'string' && opts.expectedInitiator.length > 0;
    checks.initiator_binding = opts.expectedInitiator === undefined || (initiatorPinned && opts.expectedInitiator === context.initiator);
    if (!checks.initiator_binding) return refuse('initiator_binding_mismatch');
    const noncePinned = typeof opts.expectedNonce === 'string' && opts.expectedNonce.length > 0;
    checks.nonce_binding = opts.expectedNonce === undefined || (noncePinned && opts.expectedNonce === context.nonce);
    if (!checks.nonce_binding) return refuse('nonce_binding_mismatch');
    const issued = parseInstant(context.issued_at), expires = parseInstant(context.expires_at);
    checks.time_window = Number.isFinite(issued) && Number.isFinite(expires) && issued < expires;
    checks.evaluation_time = false;
    if (!checks.time_window) return refuse('resolution_outside_validity_window');
    if (opts.evaluationTime !== undefined) {
      const at = parseInstant(opts.evaluationTime);
      checks.evaluation_time = Number.isFinite(at) && at >= issued && at <= expires;
      if (!checks.evaluation_time) return refuse('resolution_outside_validity_window');
    }
    checks.rp_id = typeof opts.rpId === 'string' && opts.rpId.length > 0;
    if (!checks.rp_id) return refuse('rp_id_required');
    checks.origin = Array.isArray(opts.allowedOrigins) && opts.allowedOrigins.length > 0
      && opts.allowedOrigins.every((x) => typeof x === 'string' && x.length > 0);
    if (!checks.origin) return refuse('webauthn_origin_not_allowed');
    try {
      for (const value of Object.values(signoff.webauthn)) canonicalBase64url(value);
      parseRaw(new TextDecoder('utf-8', { fatal: true }).decode(canonicalBase64url(signoff.webauthn.client_data_json)));
      checks.webauthn_encoding = true;
    } catch { checks.webauthn_encoding = false; }
    if (!checks.webauthn_encoding) return refuse('malformed_webauthn_encoding');
    checks.webauthn = verifyWebAuthnSignoff(signoff, pin!.public_key, {
      mode: 'relying-party', rpId: opts.rpId, allowedOrigins: opts.allowedOrigins,
    }).valid === true;
    if (!checks.webauthn) return refuse('webauthn_verification_failed');
    checks.authorization_context = checks.selected_option_binding && initiatorPinned && noncePinned && checks.evaluation_time;
    return { valid: true, authorizes_action: outcome === 'option' && checks.authorization_context,
      outcome, requires_successor: outcome === 'answer' || outcome === 'question', checks };
  } catch { return refuse('malformed_resolution_receipt'); }
}
function bindingMomentShapeValid(bindingMoment: Obj | undefined): boolean {
  const outerAllowed = new Set(['synopsis', 'findings', 'recommendations', 'offer', 'question', 'meta']);
  const outerRequired = new Set(['synopsis', 'findings', 'recommendations', 'offer', 'question']);
  if (!hasExactKeys(bindingMoment, outerAllowed, outerRequired)) return false;
  if (typeof bindingMoment.synopsis !== 'string'
    || !Array.isArray(bindingMoment.findings) || !bindingMoment.findings.every((x) => typeof x === 'string')
    || !Array.isArray(bindingMoment.recommendations) || !bindingMoment.recommendations.every((x) => typeof x === 'string')
    || typeof bindingMoment.offer !== 'string') return false;

  const question = bindingMoment.question;
  const questionKeys = new Set(['stem', 'options', 'recommended_idx', 'hatches']);
  if (!hasExactKeys(question, questionKeys) || typeof question.stem !== 'string') return false;
  if (!Array.isArray(question.options) || question.options.length < 2 || question.options.length > 4) return false;
  const optionKeys = new Set(['label', 'reasoning', 'action_digest']);
  if (!question.options.every((option) => hasExactKeys(option, optionKeys)
    && typeof option.label === 'string' && typeof option.reasoning === 'string' && isHash(option.action_digest))) return false;
  if (!Number.isSafeInteger(question.recommended_idx)
    || question.recommended_idx < 0 || question.recommended_idx >= question.options.length) return false;
  const hatchKeys = new Set(['free_text', 'dialogue']);
  if (!hasExactKeys(question.hatches, hatchKeys)
    || typeof question.hatches.free_text !== 'boolean'
    || typeof question.hatches.dialogue !== 'boolean') return false;

  if (Object.hasOwn(bindingMoment, 'meta')) {
    const metaKeys = new Set(['decision_class', 'calibration_note']);
    if (!hasExactKeys(bindingMoment.meta, metaKeys, new Set())) return false;
    if (Object.values(bindingMoment.meta).some((value) => typeof value !== 'string')) return false;
  }
  return true;
}
