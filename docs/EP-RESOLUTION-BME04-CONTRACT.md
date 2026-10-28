<!-- SPDX-License-Identifier: Apache-2.0 -->
# Experimental BME-04 resolution profile

Status: opt-in implementation profile, not released or a claim of general BME interoperability. Source pin: [draft-morrison-binding-moment-envelope-04](https://www.ietf.org/archive/id/draft-morrison-binding-moment-envelope-04.txt), 13 October 2026 (SHA-256 `94ffe86a54ac0d869fd4e97cece67b12d2a1d556f00fd6b20b307ef1ee03a5ef`). Existing `EP-RESOLUTION-v1` remains unchanged.

## Closed contract

Profile: `EP-RESOLUTION-BME04-v1`; signed context type: `ep.resolution.bme04.v1`.
Source revision: `draft-morrison-binding-moment-envelope-04`.
Action mapping: `BME04-JCS-ACTION-v1`. It hashes the exact caller-supplied JSON material action using the source's integer-only JCS profile. It does **not** assume equality with an EP receipt action hash or project a different action format. Applications requiring another projection need a separately specified and admitted mapping.

The closed outer object is `{profile, signoff}`. Signoff is exactly `{@type: "ep.signoff", context, webauthn}`; webauthn retains the existing three fields. Context has exactly:

- `ep_version: "1.0"`
- `context_type: "ep.resolution.bme04.v1"`
- `source_revision: "draft-morrison-binding-moment-envelope-04"`
- `action_mapping: "BME04-JCS-ACTION-v1"`
- `principal`, `principal_key_id`, `initiator`, `nonce` (nonempty strings)
- `issued_at`, `expires_at` (valid increasing RFC3339 instants)
- `resolution`: the exact **inner native** BME resolution object, with `envelope_digest`, `resolution`, and only `option_idx` for `option` or `answer` for `answer`. `question` and `declined` carry no third member.

This profile admits only P-256/ES256 WebAuthn signatures and base64url-encoded SPKI DER public keys. Other EC curves, Ed25519 and ML-DSA are refused even if another verifier entry point supports them. Every WebAuthn binary field and the pinned key must use canonical, unpadded base64url. Decoded client-data JSON must be valid UTF-8 and pass the same raw JSON domain checks described below. The WebAuthn challenge signs SHA256(JCS(context)), as in the existing primitive. Profile, revision and mapping are therefore tied to the signature through the checked context type and signed fields. A relabel cannot migrate signatures between profiles.

## Entry points and trust inputs

JS `verifyBme04ResolutionReceipt(receiptJson, opts)` and Python `verify_bme04_resolution_receipt(receipt_json, opts)` accept raw JSON strings. Go `VerifyBME04ResolutionReceipt(receiptJSON string, opts BME04ResolutionOptions)` follows the same contract.

Options use the following names in the shared JSON vectors:

- `acceptedProfile`, `sourceRevision`, `actionMapping`: all three mandatory and exactly equal to the constants above, independently configured by the relying party. Unknown, missing, mismatched pins refuse.
- `bindingMomentJson`: raw JSON of the native `binding_moment` **value**.
- `actionJson`: optional raw JSON of the actual material action; required for `authorizes_action: true`. A missing action allows historical evidence verification without authority. A malformed supplied action refuses.
- `principalKeys`, `rpId`, `allowedOrigins`: same independently supplied role/key and WebAuthn pins as v1.
- `expectedNonce`, `expectedInitiator`, `evaluationTime`: optional for historical evidence; required for authority. Wrong supplied values refuse.

Receipt, envelope, supplied action and WebAuthn client data are each limited to 1 MiB of UTF-8 JSON. Parsing rejects duplicate decoded names and non-scalar Unicode. There may be at most 64 nested containers (the root counts as one) and 100,000 values (objects, arrays and primitives each count once; member names do not). Numbers must be exact safe integers. JSON numeric spellings are evaluated exactly before conversion so rounding cannot turn a fractional or out-of-range literal into an accepted integer. Strings are not Unicode-normalized. Hash functions operate on parsed data only after these gates. The digest helper accepts raw JSON objects, not scalar or array roots.

This local profile restricts RFC3339 instants to years 0001 through 9999, uppercase `T`/`Z`, and at most three fractional-second digits. Year 0000, unknown offset `-00:00`, leap seconds, impossible dates, and offset hours above 23 or minutes above 59 refuse. There is no truncation of finer precision. Authorization accepts the inclusive interval `[issued_at, expires_at]`, requires `issued_at < expires_at`, and uses the caller's independently supplied evaluation time.

Native envelope options have exactly `{label, reasoning, action_digest}`. Other envelope members follow -04's closed grammar. Every option digest is required and well formed, even if unselected. Native resolution shape and exact envelope digest must match. Disabled hatches cannot supply an `answer` or `question` resolution under this profile.

`valid` records authenticated resolution evidence; `authorizes_action` additionally requires native `option`, a recomputed actual-action digest equal to the selected option digest, and all local acceptance/freshness inputs. A different actual action leaves authentic selection evidence valid but cannot authorize that action. A decline never requires or carries an action digest and never authorizes anything. `requires_successor` is true only for `answer` or `question`.

The result uses `outcome` with the **native** vocabulary (`option`, `answer`, `question`, `declined`), plus `valid`, `authorizes_action`, `requires_successor`, checks and optional reason. It does not silently translate these into v1 outcomes.

## Replay and implementation boundary

This is a stateless verifier. A changed expected nonce refuses an older resolution; an authentic historic resolution remains evidence. The caller must atomically consume its outstanding envelope/nonce before execution and refuse an already-resolved envelope. A passing verifier result does not perform that consumption, make a provider call, establish faithful display or prove physical effect.

## Shared vectors

`conformance/vectors/resolution.bme04.v1.json` is a separately versioned fixture set. Every case has `id`, `receipt_json`, `options`, and `expected` (`valid`, `authorizes_action`, optional `outcome`). It includes the upstream Section 6.4 actions and envelope digest as independent canonicalization assertions, native resolution cases, cryptographic tampering, malformed raw JSON, trust-policy refusals, and v1 isolation. It is not added to headline conformance counts until the normal evidence writers and review gates run.

## Use and validation

The JS entry point is `@emilia-protocol/verify/resolution-bme04`. Python callers
import from `emilia_verify.resolution_bme04`; Go callers use
`VerifyBME04ResolutionReceipt`. None is auto-selected by the existing Gate or
v1 resolution entry point. These source entry points are experimental and not
yet published in a package release.

```js
import { verifyBme04ResolutionReceipt } from '@emilia-protocol/verify/resolution-bme04';
const result = verifyBme04ResolutionReceipt(rawReceipt, {
  acceptedProfile: 'EP-RESOLUTION-BME04-v1',
  sourceRevision: 'draft-morrison-binding-moment-envelope-04',
  actionMapping: 'BME04-JCS-ACTION-v1',
  bindingMomentJson: rawBindingMoment,
  actionJson: rawActualAction,
  principalKeys: enrolledRoleKeys,
  rpId: expectedRpId, allowedOrigins: expectedOrigins,
  expectedNonce: outstandingNonce, expectedInitiator: expectedInitiator,
  evaluationTime: currentTrustedTime,
});
// Check authorizes_action, then the separate atomic consumption/enforcement
// contract. A valid historical record alone cannot release an action.
```

Focused source validation, from the repository root:

```sh
npm run build --prefix packages/verify
node --test packages/verify/resolution-bme04.test.js packages/verify/resolution.test.js packages/verify/resolution-source-version-gate.test.js
PYTHONPATH=packages/python-verify python3 packages/python-verify/tests/test_resolution_bme04.py
(cd packages/go-verify && GOTOOLCHAIN=local GOPROXY=off go test -run 'BME04|Resolution' ./...)
```

The fixture generator is `conformance/vectors/generate-resolution-bme04.mjs`.
It creates only public synthetic test keys and requires Node with ML-DSA-65
support to regenerate the correctly signed algorithm-refusal fixture. Running
the verifier tests does not require ML-DSA support. The six compact
`digest_boundaries` recipes exercise actual parser limits without storing
multi-megabyte fixtures. Signed fixtures are checked in; ECDSA signatures need
not reproduce byte-for-byte on regeneration.
