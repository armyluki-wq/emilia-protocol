// SPDX-License-Identifier: Apache-2.0
// Experimental, explicitly admitted BME-04 resolution evidence. v1 is unchanged.
package emiliaverify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const BME04ResolutionVersion = "EP-RESOLUTION-BME04-v1"
const BME04ContextType = "ep.resolution.bme04.v1"
const BME04SourceRevision = "draft-morrison-binding-moment-envelope-04"
const BME04ActionMapping = "BME04-JCS-ACTION-v1"

// BME04ResolutionOptions are independent relying-party policy and transaction
// inputs, never authority supplied by the receipt itself. Optional strings use
// pointers: an omitted value permits historical evidence, an empty supplied
// value refuses. Action, nonce, initiator and evaluation time are all needed
// before authentic selection evidence can authorize the actual action.
type BME04ResolutionOptions struct {
	AcceptedProfile   string                       `json:"acceptedProfile"`
	SourceRevision    string                       `json:"sourceRevision"`
	ActionMapping     string                       `json:"actionMapping"`
	BindingMomentJSON string                       `json:"bindingMomentJson"`
	ActionJSON        *string                      `json:"actionJson,omitempty"`
	PrincipalKeys     map[string]map[string]string `json:"principalKeys"`
	RPID              string                       `json:"rpId"`
	AllowedOrigins    []string                     `json:"allowedOrigins"`
	ExpectedNonce     *string                      `json:"expectedNonce,omitempty"`
	ExpectedInitiator *string                      `json:"expectedInitiator,omitempty"`
	EvaluationTime    *string                      `json:"evaluationTime,omitempty"`
}

var bme04InstantPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$`)

func bme04Instant(value any) (time.Time, bool) {
	s, ok := value.(string)
	if !ok || !bme04InstantPattern.MatchString(s) || strings.HasPrefix(s, "0000-") || strings.HasSuffix(s, "-00:00") {
		return time.Time{}, false
	}
	// Go accepts offset minute 60 and hour 24, unlike this closed profile.
	if !strings.HasSuffix(s, "Z") {
		hour, _ := strconv.Atoi(s[len(s)-5 : len(s)-3])
		minute, _ := strconv.Atoi(s[len(s)-2:])
		if hour > 23 || minute > 59 {
			return time.Time{}, false
		}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}

// encoding/json replaces malformed escaped surrogates with U+FFFD. Inspect
// original bytes first, and count containers independently of decoded values.
func bme04RawScalarGate(raw string) bool {
	if len(raw) > 1024*1024 || !utf8.ValidString(raw) || !json.Valid([]byte(raw)) {
		return false
	}
	quoted, depth := false, 0
	for i := 0; i < len(raw); i++ {
		if !quoted {
			switch raw[i] {
			case '"':
				quoted = true
			case '{', '[':
				depth++
				if depth > 64 {
					return false
				}
			case '}', ']':
				depth--
			}
			continue
		}
		if raw[i] == '"' {
			quoted = false
			continue
		}
		if raw[i] != '\\' {
			continue
		}
		i++
		if raw[i] != 'u' {
			continue
		}
		unit, _ := strconv.ParseUint(raw[i+1:i+5], 16, 16)
		i += 4
		if unit >= 0xdc00 && unit <= 0xdfff {
			return false
		}
		if unit >= 0xd800 && unit <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1:i+3] != `\u` {
				return false
			}
			low, err := strconv.ParseUint(raw[i+3:i+7], 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

// Evaluate an already JSON-validated number token in decimal arithmetic.
// No float conversion or enormous power allocation can round a fraction into
// an integer, turn underflow into zero, or admit an out-of-range value.
func bme04ExactInteger(token string) (json.Number, bool) {
	negative := strings.HasPrefix(token, "-")
	mantissa := strings.TrimPrefix(token, "-")
	exponent := "0"
	if i := strings.IndexAny(mantissa, "eE"); i >= 0 {
		exponent, mantissa = mantissa[i+1:], mantissa[:i]
	}
	fraction := 0
	if i := strings.IndexByte(mantissa, '.'); i >= 0 {
		fraction = len(mantissa) - i - 1
		mantissa = mantissa[:i] + mantissa[i+1:]
	}
	digits := strings.TrimLeft(mantissa, "0")
	if digits == "" {
		return json.Number("0"), true
	}
	exp, err := strconv.ParseInt(exponent, 10, 64)
	if err != nil || exp > int64(fraction)+16 || exp < int64(fraction)-int64(len(digits)) {
		return "", false
	}
	shift := exp - int64(fraction)
	if shift < 0 {
		cut := len(digits) + int(shift)
		if strings.Trim(digits[cut:], "0") != "" {
			return "", false
		}
		digits = digits[:cut]
	} else {
		digits += strings.Repeat("0", int(shift))
	}
	if len(digits) > 16 || (len(digits) == 16 && digits > "9007199254740991") {
		return "", false
	}
	if negative {
		digits = "-" + digits
	}
	return json.Number(digits), true
}

func bme04NormalizeIntegers(value any, remaining *int) (any, bool) {
	*remaining--
	if *remaining < 0 {
		return nil, false
	}
	switch v := value.(type) {
	case json.Number:
		return bme04ExactInteger(v.String())
	case map[string]any:
		for key, child := range v {
			normalized, ok := bme04NormalizeIntegers(child, remaining)
			if !ok {
				return nil, false
			}
			v[key] = normalized
		}
	case []any:
		for i, child := range v {
			normalized, ok := bme04NormalizeIntegers(child, remaining)
			if !ok {
				return nil, false
			}
			v[i] = normalized
		}
	}
	return value, true
}

func bme04ParseRaw(raw string) (map[string]any, error) {
	if !bme04RawScalarGate(raw) {
		return nil, fmt.Errorf("invalid raw JSON")
	}
	value, err := decodeStrictJSONObject([]byte(raw))
	if err != nil {
		return nil, err
	}
	remaining := 100000
	if _, ok := bme04NormalizeIntegers(value, &remaining); !ok || !IsCanonicalizable(value) {
		return nil, fmt.Errorf("outside integer canonical profile")
	}
	return value, nil
}

func bme04Digest(value map[string]any) string {
	sum := sha256.Sum256([]byte(Canonicalize(value)))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ComputeBME04Digest hashes a raw material-action or envelope object after the
// closed JSON profile checks. An empty result means the input was refused.
func ComputeBME04Digest(rawJSON string) string {
	value, err := bme04ParseRaw(rawJSON)
	if err != nil {
		return ""
	}
	return bme04Digest(value)
}

func bme04StructureValid(receipt map[string]any) bool {
	if !resolutionExactKeys(receipt, []string{"profile", "signoff"}, []string{"profile", "signoff"}) || getStr(receipt, "profile") != BME04ResolutionVersion {
		return false
	}
	signoff := getMap(receipt["signoff"])
	keys := []string{"@type", "context", "webauthn"}
	if !resolutionExactKeys(signoff, keys, keys) || getStr(signoff, "@type") != "ep.signoff" {
		return false
	}
	ctx := getMap(signoff["context"])
	keys = []string{"ep_version", "context_type", "source_revision", "action_mapping", "principal", "principal_key_id", "initiator", "nonce", "issued_at", "expires_at", "resolution"}
	waKeys := []string{"authenticator_data", "client_data_json", "signature"}
	if !resolutionExactKeys(ctx, keys, keys) || !resolutionExactKeys(getMap(signoff["webauthn"]), waKeys, waKeys) {
		return false
	}
	if getStr(ctx, "ep_version") != "1.0" || getStr(ctx, "context_type") != BME04ContextType || getStr(ctx, "source_revision") != BME04SourceRevision || getStr(ctx, "action_mapping") != BME04ActionMapping {
		return false
	}
	for _, key := range []string{"principal", "principal_key_id", "initiator", "nonce"} {
		if getStr(ctx, key) == "" {
			return false
		}
	}
	return true
}

func bme04EnvelopeValid(envelope map[string]any) bool {
	// Reuse the unchanged v1 grammar only on a copy without BME-04's extra
	// option member. The original, fully validated envelope is still hashed.
	question := getMap(envelope["question"])
	options, ok := question["options"].([]any)
	if !ok {
		return false
	}
	oldOptions := make([]any, len(options))
	keys := []string{"label", "reasoning", "action_digest"}
	for i, rawOption := range options {
		option := getMap(rawOption)
		if !resolutionExactKeys(option, keys, keys) || !resolutionIsHash(getStr(option, "action_digest")) {
			return false
		}
		oldOptions[i] = map[string]any{"label": option["label"], "reasoning": option["reasoning"]}
	}
	copyQuestion := make(map[string]any, len(question))
	for key, value := range question {
		copyQuestion[key] = value
	}
	copyQuestion["options"] = oldOptions
	copyEnvelope := make(map[string]any, len(envelope))
	for key, value := range envelope {
		copyEnvelope[key] = value
	}
	copyEnvelope["question"] = copyQuestion
	return resolutionBindingMomentShapeValid(copyEnvelope)
}

func bme04OutcomeValid(resolution, envelope map[string]any) bool {
	if !resolutionIsHash(getStr(resolution, "envelope_digest")) {
		return false
	}
	keys := []string{"envelope_digest", "resolution"}
	question := getMap(envelope["question"])
	hatches := getMap(question["hatches"])
	switch getStr(resolution, "resolution") {
	case "option":
		keys = append(keys, "option_idx")
		index, ok := resolutionIndex(resolution["option_idx"])
		options, _ := question["options"].([]any)
		return resolutionExactKeys(resolution, keys, keys) && ok && index < len(options)
	case "answer":
		keys = append(keys, "answer")
		_, ok := resolution["answer"].(string)
		return resolutionExactKeys(resolution, keys, keys) && ok && hatches["free_text"] == true
	case "question":
		return resolutionExactKeys(resolution, keys, keys) && hatches["dialogue"] == true
	case "declined":
		return resolutionExactKeys(resolution, keys, keys)
	}
	return false
}

// VerifyBME04ResolutionReceipt checks raw JSON before authenticated native
// resolution evidence. It is stateless: the caller must atomically consume the
// outstanding nonce before execution. A valid historical receipt alone never
// grants authority to an action that was not supplied and freshly bound.
func VerifyBME04ResolutionReceipt(receiptJSON string, opts BME04ResolutionOptions) (result ResolutionResult) {
	checks := map[string]bool{}
	outcome := ""
	refuse := func(reason string) ResolutionResult {
		return ResolutionResult{Valid: false, AuthorizesAction: false, Outcome: outcome, RequiresSuccessor: false, Checks: checks, Reason: reason}
	}
	defer func() {
		if recover() != nil {
			result = refuse("malformed_resolution_receipt")
		}
	}()
	checks["profile_policy"] = opts.AcceptedProfile == BME04ResolutionVersion && opts.SourceRevision == BME04SourceRevision && opts.ActionMapping == BME04ActionMapping
	if !checks["profile_policy"] {
		return refuse("bme04_profile_not_admitted")
	}
	receipt, err := bme04ParseRaw(receiptJSON)
	if err != nil {
		return refuse("invalid_raw_json")
	}
	envelope, err := bme04ParseRaw(opts.BindingMomentJSON)
	if err != nil {
		return refuse("invalid_raw_json")
	}
	var action map[string]any
	if opts.ActionJSON != nil {
		action, err = bme04ParseRaw(*opts.ActionJSON)
		if err != nil {
			return refuse("invalid_raw_json")
		}
	}
	checks["structure"] = bme04StructureValid(receipt)
	if !checks["structure"] {
		return refuse("malformed_resolution_receipt")
	}
	signoff := getMap(receipt["signoff"])
	ctx := getMap(signoff["context"])
	resolution := getMap(ctx["resolution"])
	checks["binding_moment_shape"] = bme04EnvelopeValid(envelope)
	if !checks["binding_moment_shape"] {
		return refuse("malformed_binding_moment")
	}
	checks["outcome_shape"] = bme04OutcomeValid(resolution, envelope)
	if !checks["outcome_shape"] {
		return refuse("invalid_outcome_shape")
	}
	outcome = getStr(resolution, "resolution")
	checks["envelope_binding"] = getStr(resolution, "envelope_digest") == bme04Digest(envelope)
	if !checks["envelope_binding"] {
		return refuse("envelope_binding_mismatch")
	}
	checks["selected_option_binding"] = false
	if outcome == "option" && action != nil {
		index, _ := resolutionIndex(resolution["option_idx"])
		options := getMap(envelope["question"])["options"].([]any)
		checks["selected_option_binding"] = getStr(getMap(options[index]), "action_digest") == bme04Digest(action)
	}
	pin := opts.PrincipalKeys[getStr(ctx, "principal_key_id")]
	checks["principal_pin"] = pin != nil && pin["principal"] == getStr(ctx, "principal") && pin["public_key"] != ""
	if !checks["principal_pin"] {
		return refuse("principal_key_not_pinned_for_role")
	}
	// This shared key classifier first requires canonical, unpadded base64url
	// SPKI bytes and then identifies the actual P-256 key, never a label.
	checks["signature_algorithm"] = credentialAlgorithm(pin["public_key"]) == "ES256"
	if !checks["signature_algorithm"] {
		return refuse("unsupported_signature_algorithm")
	}
	initiatorPinned := opts.ExpectedInitiator != nil && *opts.ExpectedInitiator != ""
	checks["initiator_binding"] = opts.ExpectedInitiator == nil || (initiatorPinned && *opts.ExpectedInitiator == getStr(ctx, "initiator"))
	if !checks["initiator_binding"] {
		return refuse("initiator_binding_mismatch")
	}
	noncePinned := opts.ExpectedNonce != nil && *opts.ExpectedNonce != ""
	checks["nonce_binding"] = opts.ExpectedNonce == nil || (noncePinned && *opts.ExpectedNonce == getStr(ctx, "nonce"))
	if !checks["nonce_binding"] {
		return refuse("nonce_binding_mismatch")
	}
	issued, issuedOK := bme04Instant(ctx["issued_at"])
	expires, expiresOK := bme04Instant(ctx["expires_at"])
	checks["time_window"] = issuedOK && expiresOK && issued.Before(expires)
	checks["evaluation_time"] = false
	if !checks["time_window"] {
		return refuse("resolution_outside_validity_window")
	}
	if opts.EvaluationTime != nil {
		at, ok := bme04Instant(*opts.EvaluationTime)
		checks["evaluation_time"] = ok && !at.Before(issued) && !at.After(expires)
		if !checks["evaluation_time"] {
			return refuse("resolution_outside_validity_window")
		}
	}
	checks["rp_id"] = opts.RPID != ""
	if !checks["rp_id"] {
		return refuse("rp_id_required")
	}
	checks["origin"] = len(opts.AllowedOrigins) > 0
	for _, origin := range opts.AllowedOrigins {
		checks["origin"] = checks["origin"] && origin != ""
	}
	if !checks["origin"] {
		return refuse("webauthn_origin_not_allowed")
	}
	// The legacy primitive owns ceremony/signature verification. This profile
	// additionally applies its exact raw-object domain to clientDataJSON before
	// that primitive can replace malformed Unicode or accept rounded numbers.
	wa := getMap(signoff["webauthn"])
	checks["webauthn_encoding"] = true
	for _, field := range []string{"authenticator_data", "client_data_json", "signature"} {
		decoded, decodeErr := b64urlDecode(getStr(wa, field))
		if decodeErr != nil {
			checks["webauthn_encoding"] = false
			break
		}
		if field == "client_data_json" {
			if _, parseErr := bme04ParseRaw(string(decoded)); parseErr != nil {
				checks["webauthn_encoding"] = false
				break
			}
		}
	}
	if !checks["webauthn_encoding"] {
		return refuse("malformed_webauthn_encoding")
	}
	checks["webauthn"] = VerifyWebAuthnSignoffWithOrigins(signoff, pin["public_key"], opts.RPID, opts.AllowedOrigins).Valid
	if !checks["webauthn"] {
		return refuse("webauthn_verification_failed")
	}
	checks["authorization_context"] = checks["selected_option_binding"] && initiatorPinned && noncePinned && checks["evaluation_time"]
	return ResolutionResult{Valid: true, AuthorizesAction: outcome == "option" && checks["authorization_context"], Outcome: outcome, RequiresSuccessor: outcome == "answer" || outcome == "question", Checks: checks}
}
