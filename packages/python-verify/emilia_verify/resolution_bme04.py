# SPDX-License-Identifier: Apache-2.0
"""Experimental opt-in native BME-04 profile. No v1 behavior is changed."""
import base64
import datetime
import decimal
import json
import re

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key

from . import (
    _reject_duplicate_members, _resolution_binding_moment_shape_valid,
    _resolution_exact_keys, _resolution_hash, _resolution_is_hash,
    is_canonicalizable, verify_webauthn_signoff,
)

BME04_RESOLUTION_VERSION = "EP-RESOLUTION-BME04-v1"
BME04_CONTEXT_TYPE = "ep.resolution.bme04.v1"
BME04_SOURCE_REVISION = "draft-morrison-binding-moment-envelope-04"
BME04_ACTION_MAPPING = "BME04-JCS-ACTION-v1"
_CONTEXT_KEYS = {"ep_version", "context_type", "source_revision", "action_mapping",
                 "principal", "principal_key_id", "initiator", "nonce", "issued_at", "expires_at", "resolution"}


def _number(token):
    value = decimal.Decimal(token)
    if not value.is_finite() or value != value.to_integral_value() or abs(value) > 9007199254740991:
        raise ValueError("outside integer profile")
    return int(value)


def _scalars(value, depth=0, count=None):
    count = [0] if count is None else count
    count[0] += 1
    # Match the raw parser's 64 containers (root counts as one) and the
    # canonicalizer's 100000 values (keys are not separate value nodes).
    if depth > 64 or (isinstance(value, (dict, list)) and depth >= 64) or count[0] > 100000:
        raise ValueError("excessive JSON resources")
    if isinstance(value, str):
        value.encode("utf-8", "strict")
    elif isinstance(value, dict):
        for key, child in value.items():
            key.encode("utf-8", "strict")
            _scalars(child, depth + 1, count)
    elif isinstance(value, list):
        for child in value:
            _scalars(child, depth + 1, count)


def _parse(raw):
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > 1024 * 1024:
        raise ValueError("raw JSON required")
    value = json.loads(raw, object_pairs_hook=_reject_duplicate_members,
                       parse_int=_number, parse_float=_number, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))
    _scalars(value)
    if not isinstance(value, dict) or not is_canonicalizable(value):
        raise ValueError("outside canonical profile")
    return value


def _base64url(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("invalid base64url")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value:
        raise ValueError("noncanonical base64url")
    return decoded


def compute_bme04_digest(raw_json):
    try:
        return _resolution_hash(_parse(raw_json))
    except Exception:
        return None


def _envelope_valid(envelope):
    # Validate every new option member, then reuse the unchanged v1 grammar on a
    # detached view. Never remove fields from the supplied or signed object.
    options = envelope.get("question", {}).get("options") if isinstance(envelope.get("question"), dict) else None
    if not isinstance(options, list):
        return False
    for option in options:
        if (not _resolution_exact_keys(option, {"label", "reasoning", "action_digest"})
                or not _resolution_is_hash(option.get("action_digest"))):
            return False
    view = dict(envelope)
    view["question"] = dict(envelope["question"])
    view["question"]["options"] = [{"label": option["label"], "reasoning": option["reasoning"]} for option in options]
    return _resolution_binding_moment_shape_valid(view)


def _native_resolution_valid(resolution, envelope):
    if not isinstance(resolution, dict) or not _resolution_is_hash(resolution.get("envelope_digest")):
        return False
    common = {"envelope_digest", "resolution"}
    kind = resolution.get("resolution")
    if kind == "option":
        index = resolution.get("option_idx")
        return (_resolution_exact_keys(resolution, common | {"option_idx"})
                and isinstance(index, int) and not isinstance(index, bool)
                and 0 <= index < len(envelope["question"]["options"]))
    if kind == "answer":
        return (_resolution_exact_keys(resolution, common | {"answer"})
                and isinstance(resolution.get("answer"), str)
                and envelope["question"]["hatches"]["free_text"] is True)
    return ((kind == "declined" or (kind == "question" and envelope["question"]["hatches"]["dialogue"] is True))
            and _resolution_exact_keys(resolution, common))


def _structure_valid(receipt):
    if not _resolution_exact_keys(receipt, {"profile", "signoff"}) or receipt["profile"] != BME04_RESOLUTION_VERSION:
        return False
    signoff = receipt["signoff"]
    if not _resolution_exact_keys(signoff, {"@type", "context", "webauthn"}) or signoff["@type"] != "ep.signoff":
        return False
    context = signoff["context"]
    if (not _resolution_exact_keys(context, _CONTEXT_KEYS)
            or not _resolution_exact_keys(signoff["webauthn"], {"authenticator_data", "client_data_json", "signature"})):
        return False
    return (context["ep_version"] == "1.0" and context["context_type"] == BME04_CONTEXT_TYPE
            and context["source_revision"] == BME04_SOURCE_REVISION and context["action_mapping"] == BME04_ACTION_MAPPING
            and all(isinstance(context[k], str) and bool(context[k]) for k in ("principal", "principal_key_id", "initiator", "nonce")))


def _instant(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?(Z|[+-]\d{2}:\d{2})", value):
        return None
    if value.startswith("0000-") or value.endswith("-00:00"):
        return None
    if not value.endswith("Z") and (int(value[-5:-3]) > 23 or int(value[-2:]) > 59):
        return None
    try:
        return datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def verify_bme04_resolution_receipt(receipt_json, opts=None):
    """Raw JSON only. A valid result is evidence; stateless verification never consumes a nonce."""
    opts = {} if opts is None else opts
    checks = {}
    outcome = None

    def refuse(reason):
        return {"valid": False, "authorizes_action": False, "outcome": outcome,
                "requires_successor": False, "checks": checks, "reason": reason}

    try:
        checks["profile_policy"] = (opts.get("acceptedProfile") == BME04_RESOLUTION_VERSION
                                     and opts.get("sourceRevision") == BME04_SOURCE_REVISION
                                     and opts.get("actionMapping") == BME04_ACTION_MAPPING)
        if not checks["profile_policy"]:
            return refuse("bme04_profile_not_admitted")
        try:
            receipt = _parse(receipt_json)
            envelope = _parse(opts.get("bindingMomentJson"))
            action = _parse(opts["actionJson"]) if "actionJson" in opts else None
        except Exception:
            return refuse("invalid_raw_json")
        checks["structure"] = _structure_valid(receipt)
        if not checks["structure"]:
            return refuse("malformed_resolution_receipt")
        signoff = receipt["signoff"]
        context = signoff["context"]
        checks["binding_moment_shape"] = _envelope_valid(envelope)
        if not checks["binding_moment_shape"]:
            return refuse("malformed_binding_moment")
        checks["outcome_shape"] = _native_resolution_valid(context["resolution"], envelope)
        if not checks["outcome_shape"]:
            return refuse("invalid_outcome_shape")
        resolution = context["resolution"]
        outcome = resolution["resolution"]
        checks["envelope_binding"] = resolution["envelope_digest"] == _resolution_hash(envelope)
        if not checks["envelope_binding"]:
            return refuse("envelope_binding_mismatch")
        checks["selected_option_binding"] = (outcome == "option" and action is not None
            and envelope["question"]["options"][resolution["option_idx"]]["action_digest"] == _resolution_hash(action))
        pins = opts.get("principalKeys")
        pin = pins.get(context["principal_key_id"]) if isinstance(pins, dict) else None
        checks["principal_pin"] = (isinstance(pin, dict) and pin.get("principal") == context["principal"]
                                   and isinstance(pin.get("public_key"), str) and bool(pin["public_key"]))
        if not checks["principal_pin"]:
            return refuse("principal_key_not_pinned_for_role")
        try:
            encoded = pin["public_key"]
            key = load_der_public_key(_base64url(encoded))
            checks["signature_algorithm"] = isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1)
        except Exception:
            checks["signature_algorithm"] = False
        if not checks["signature_algorithm"]:
            return refuse("unsupported_signature_algorithm")
        initiator = opts.get("expectedInitiator")
        initiator_pinned = isinstance(initiator, str) and bool(initiator)
        checks["initiator_binding"] = "expectedInitiator" not in opts or (initiator_pinned and initiator == context["initiator"])
        if not checks["initiator_binding"]:
            return refuse("initiator_binding_mismatch")
        nonce = opts.get("expectedNonce")
        nonce_pinned = isinstance(nonce, str) and bool(nonce)
        checks["nonce_binding"] = "expectedNonce" not in opts or (nonce_pinned and nonce == context["nonce"])
        if not checks["nonce_binding"]:
            return refuse("nonce_binding_mismatch")
        issued, expires = _instant(context["issued_at"]), _instant(context["expires_at"])
        checks["time_window"] = issued is not None and expires is not None and issued < expires
        checks["evaluation_time"] = False
        if not checks["time_window"]:
            return refuse("resolution_outside_validity_window")
        if "evaluationTime" in opts:
            at = _instant(opts["evaluationTime"])
            checks["evaluation_time"] = at is not None and issued <= at <= expires
            if not checks["evaluation_time"]:
                return refuse("resolution_outside_validity_window")
        rp = opts.get("rpId")
        checks["rp_id"] = isinstance(rp, str) and bool(rp)
        if not checks["rp_id"]:
            return refuse("rp_id_required")
        origins = opts.get("allowedOrigins")
        checks["origin"] = isinstance(origins, list) and bool(origins) and all(isinstance(x, str) and bool(x) for x in origins)
        if not checks["origin"]:
            return refuse("webauthn_origin_not_allowed")
        try:
            for value in signoff["webauthn"].values():
                _base64url(value)
            _parse(_base64url(signoff["webauthn"]["client_data_json"]).decode("utf-8", "strict"))
            checks["webauthn_encoding"] = True
        except Exception:
            checks["webauthn_encoding"] = False
        if not checks["webauthn_encoding"]:
            return refuse("malformed_webauthn_encoding")
        checks["webauthn"] = verify_webauthn_signoff(signoff, pin["public_key"], {"rpId": rp, "allowedOrigins": origins}).get("valid") is True
        if not checks["webauthn"]:
            return refuse("webauthn_verification_failed")
        checks["authorization_context"] = checks["selected_option_binding"] and initiator_pinned and nonce_pinned and checks["evaluation_time"]
        return {"valid": True, "authorizes_action": outcome == "option" and checks["authorization_context"],
                "outcome": outcome, "requires_successor": outcome in ("answer", "question"), "checks": checks}
    except Exception:
        return refuse("malformed_resolution_receipt")
