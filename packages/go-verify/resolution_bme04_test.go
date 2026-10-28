// SPDX-License-Identifier: Apache-2.0
package emiliaverify

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type bme04Vector struct {
	ID          string                 `json:"id"`
	ReceiptJSON string                 `json:"receipt_json"`
	Options     BME04ResolutionOptions `json:"options"`
	Expected    struct {
		Valid            bool    `json:"valid"`
		AuthorizesAction bool    `json:"authorizes_action"`
		Outcome          *string `json:"outcome"`
	} `json:"expected"`
}

type bme04VectorSuite struct {
	Canonicalization []struct {
		ID             string `json:"id"`
		JSON           string `json:"json"`
		Digest         string `json:"digest"`
		CanonicalBytes int    `json:"canonical_bytes"`
	} `json:"canonicalization"`
	Vectors          []bme04Vector `json:"vectors"`
	DigestBoundaries []struct {
		ID     string  `json:"id"`
		Kind   string  `json:"kind"`
		Count  int     `json:"count"`
		Digest *string `json:"digest"`
	} `json:"digest_boundaries"`
}

func loadBME04Vectors(t *testing.T) bme04VectorSuite {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "conformance", "vectors", "resolution.bme04.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var suite bme04VectorSuite
	if err := json.Unmarshal(raw, &suite); err != nil {
		t.Fatal(err)
	}
	if len(suite.Vectors) == 0 || len(suite.Canonicalization) == 0 {
		t.Fatal("empty BME-04 shared corpus")
	}
	return suite
}

func TestBME04SharedVectors(t *testing.T) {
	suite := loadBME04Vectors(t)
	for _, vector := range suite.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			result := VerifyBME04ResolutionReceipt(vector.ReceiptJSON, vector.Options)
			if result.Valid != vector.Expected.Valid || result.AuthorizesAction != vector.Expected.AuthorizesAction {
				t.Fatalf("expected valid=%t authority=%t, got %+v", vector.Expected.Valid, vector.Expected.AuthorizesAction, result)
			}
			if vector.Expected.Outcome != nil && result.Outcome != *vector.Expected.Outcome {
				t.Fatalf("expected outcome=%q, got %+v", *vector.Expected.Outcome, result)
			}
			wantSuccessor := result.Valid && (result.Outcome == "answer" || result.Outcome == "question")
			if result.RequiresSuccessor != wantSuccessor {
				t.Fatalf("wrong successor result: %+v", result)
			}
		})
	}
	for _, example := range suite.Canonicalization {
		t.Run("canonical/"+example.ID, func(t *testing.T) {
			if got := ComputeBME04Digest(example.JSON); got != example.Digest {
				t.Fatalf("digest %q, want %q", got, example.Digest)
			}
			if example.CanonicalBytes != 0 {
				parsed, err := bme04ParseRaw(example.JSON)
				if err != nil || len(Canonicalize(parsed)) != example.CanonicalBytes {
					t.Fatalf("canonical byte count mismatch: err=%v", err)
				}
			}
		})
	}
	for _, boundary := range suite.DigestBoundaries {
		t.Run("boundary/"+boundary.ID, func(t *testing.T) {
			var raw string
			switch boundary.Kind {
			case "depth":
				raw = `{"a":` + strings.Repeat("[", boundary.Count) + strings.Repeat("]", boundary.Count) + `}`
			case "nodes":
				raw = `{"a":[` + strings.TrimSuffix(strings.Repeat("0,", boundary.Count), ",") + `]}`
			case "bytes":
				raw = `{"a":"` + strings.Repeat("x", boundary.Count-8) + `"}`
			default:
				t.Fatalf("unknown boundary recipe %q", boundary.Kind)
			}
			want := ""
			if boundary.Digest != nil {
				want = *boundary.Digest
			}
			if got := ComputeBME04Digest(raw); got != want {
				t.Fatalf("boundary digest %q, want %q", got, want)
			}
		})
	}
	t.Logf("checked %d shared receipt vectors, %d canonicalization cases and %d resource boundaries", len(suite.Vectors), len(suite.Canonicalization), len(suite.DigestBoundaries))
}

func TestBME04ExactNumbers(t *testing.T) {
	accepted := map[string]string{
		"1e3": "1000", "1.000000000000000000": "1", "100000000000000000000000e-23": "1",
		"-0": "0", "0e9999999999999999999999999": "0", "-0.0000e-999999999999999999999": "0",
		"9007199254740991": "9007199254740991", "-9007199254740991": "-9007199254740991",
		"9007199254740991000e-3": "9007199254740991", "1e+0000000000000000000": "1",
	}
	for spelling, canonical := range accepted {
		t.Run(spelling, func(t *testing.T) {
			got := ComputeBME04Digest(`{"n":` + spelling + `}`)
			want := ComputeBME04Digest(`{"n":` + canonical + `}`)
			if got == "" || got != want {
				t.Fatalf("exact integer %s rejected or changed: %q != %q", spelling, got, want)
			}
		})
	}
	for _, spelling := range []string{"1.00000000000000001", "9007199254740991.1", "9007199254740993", "-9007199254740992", "1e-999999", "1e999999999999999999999", "1.5"} {
		t.Run("refuse_"+spelling, func(t *testing.T) {
			if got := ComputeBME04Digest(`{"n":` + spelling + `}`); got != "" {
				t.Fatalf("non-profile number admitted: %s -> %s", spelling, got)
			}
		})
	}
}

func TestBME04RawJSONBoundaries(t *testing.T) {
	for name, raw := range map[string]string{
		"decoded_duplicate":    `{"a":1,"\u0061":2}`,
		"nested_duplicate":     `{"a":{"b":1,"b":2}}`,
		"high_surrogate_value": `{"a":"\ud800"}`,
		"low_surrogate_key":    `{"\udc00":0}`,
		"wrong_surrogate_pair": `{"a":"\ud800\u0061"}`,
		"invalid_utf8":         "{\"a\":\"" + string([]byte{0xff}) + "\"}",
		"trailing_value":       `{} {}`,
		"root_array":           `[]`,
		"depth_65":             `{"a":` + strings.Repeat("[", 64) + strings.Repeat("]", 64) + `}`,
		"over_mebibyte":        `{"a":"` + strings.Repeat("a", 1024*1024-7) + `"}`,
		"100001_values":        `{"a":[` + strings.Repeat("0,", 99998) + `0]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if got := ComputeBME04Digest(raw); got != "" {
				t.Fatalf("invalid raw input admitted: digest=%s", got)
			}
		})
	}
	for name, raw := range map[string]string{
		"scalar_pair":         `{"a":"\ud83d\ude00"}`,
		"literal_replacement": `{"a":"�"}`,
		"escaped_backslash":   `{"a":"\\ud800"}`,
		"depth_64":            `{"a":` + strings.Repeat("[", 63) + strings.Repeat("]", 63) + `}`,
		"one_mebibyte":        `{"a":"` + strings.Repeat("a", 1024*1024-8) + `"}`,
		"100000_values":       `{"a":[` + strings.Repeat("0,", 99997) + `0]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if got := ComputeBME04Digest(raw); got == "" {
				t.Fatal("valid raw boundary refused")
			}
		})
	}
}

func TestBME04UTF16OrderingWithoutNormalization(t *testing.T) {
	// The astral key sorts before U+E000 by UTF-16 code units, unlike UTF-8.
	canonical := `{"😀":1,"":2}`
	sum := sha256.Sum256([]byte(canonical))
	want := "sha256:" + hex.EncodeToString(sum[:])
	if got := ComputeBME04Digest(`{"\ue000":2,"\ud83d\ude00":1}`); got != want {
		t.Fatalf("UTF-16 ordering changed: %q != %q", got, want)
	}
	if ComputeBME04Digest(`{"s":"é"}`) == ComputeBME04Digest(`{"s":"e\u0301"}`) {
		t.Fatal("distinct Unicode sequences were normalized")
	}
}

func TestBME04TimestampDomain(t *testing.T) {
	for _, value := range []string{"0001-01-01T00:00:00Z", "2024-02-29T12:00:00.001Z", "2026-10-26T10:00:00.1+00:00", "2026-10-26T10:00:00+23:59", "9999-12-31T23:59:59.999Z"} {
		if _, ok := bme04Instant(value); !ok {
			t.Errorf("valid timestamp refused: %q", value)
		}
	}
	for _, value := range []string{"0000-01-01T00:00:00Z", "2026-10-26T10:00:00-00:00", "2026-10-26T10:00:00.0001Z", "2026-10-26T10:00:00+23:60", "2026-10-26T10:00:00+24:00", "2026-02-29T10:00:00Z", "2026-10-26T10:00:60Z", "2026-10-26t10:00:00Z", "2026-10-26T10:00:00z", "2026-10-26T10:00:00Z\n"} {
		if _, ok := bme04Instant(value); ok {
			t.Errorf("invalid timestamp admitted: %q", value)
		}
	}
}

func TestBME04OptionalInputPresence(t *testing.T) {
	var accepted *bme04Vector
	suite := loadBME04Vectors(t)
	for i := range suite.Vectors {
		if suite.Vectors[i].ID == "accept_option" {
			accepted = &suite.Vectors[i]
			break
		}
	}
	if accepted == nil {
		t.Fatal("missing positive fixture")
	}
	for _, name := range []string{"action", "nonce", "initiator", "evaluation_time"} {
		t.Run(name, func(t *testing.T) {
			opts := accepted.Options
			var field **string
			switch name {
			case "action":
				field = &opts.ActionJSON
			case "nonce":
				field = &opts.ExpectedNonce
			case "initiator":
				field = &opts.ExpectedInitiator
			case "evaluation_time":
				field = &opts.EvaluationTime
			}
			*field = nil
			if result := VerifyBME04ResolutionReceipt(accepted.ReceiptJSON, opts); !result.Valid || result.AuthorizesAction {
				t.Fatalf("omitted input must allow evidence without authority: %+v", result)
			}
			empty := ""
			*field = &empty
			if result := VerifyBME04ResolutionReceipt(accepted.ReceiptJSON, opts); result.Valid || result.AuthorizesAction {
				t.Fatalf("supplied empty input must refuse: %+v", result)
			}
		})
	}
}

func TestBME04WebAuthnRawDomain(t *testing.T) {
	suite := loadBME04Vectors(t)
	var accepted *bme04Vector
	for i := range suite.Vectors {
		if suite.Vectors[i].ID == "accept_option" {
			accepted = &suite.Vectors[i]
			break
		}
	}
	if accepted == nil {
		t.Fatal("missing positive fixture")
	}
	for name, client := range map[string]string{
		"duplicate":          `{"type":"webauthn.get","type":"webauthn.get"}`,
		"unpaired_surrogate": `{"unused":"\ud800"}`,
		"invalid_utf8":       "{\"unused\":\"" + string([]byte{0xff}) + "\"}",
		"rounded_fraction":   `{"unused":1.00000000000000001}`,
		"underflow":          `{"unused":1e-999999}`,
		"nonobject":          `[]`,
		"depth_65":           `{"a":` + strings.Repeat("[", 64) + strings.Repeat("]", 64) + `}`,
		"100001_values":      `{"a":[` + strings.Repeat("0,", 99998) + `0]}`,
	} {
		t.Run(name, func(t *testing.T) {
			receipt, err := bme04ParseRaw(accepted.ReceiptJSON)
			if err != nil {
				t.Fatal(err)
			}
			getMap(getMap(receipt["signoff"])["webauthn"])["client_data_json"] = base64.RawURLEncoding.EncodeToString([]byte(client))
			raw, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			result := VerifyBME04ResolutionReceipt(string(raw), accepted.Options)
			if result.Valid || result.Reason != "malformed_webauthn_encoding" {
				t.Fatalf("client data reached legacy verifier before raw-domain refusal: %+v", result)
			}
		})
	}
	for _, field := range []string{"authenticator_data", "client_data_json", "signature"} {
		t.Run("padded_"+field, func(t *testing.T) {
			receipt, err := bme04ParseRaw(accepted.ReceiptJSON)
			if err != nil {
				t.Fatal(err)
			}
			wa := getMap(getMap(receipt["signoff"])["webauthn"])
			wa[field] = getStr(wa, field) + "="
			raw, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			result := VerifyBME04ResolutionReceipt(string(raw), accepted.Options)
			if result.Valid || result.Reason != "malformed_webauthn_encoding" {
				t.Fatalf("noncanonical base64url not refused by profile: %+v", result)
			}
		})
	}
}
