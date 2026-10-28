<!-- SPDX-License-Identifier: Apache-2.0 -->
# Experimental BME-04 profile: source validation

Checked 2026-10-26 against base commit
`3f712d28b2cf624342bd98c4172e1a574b39644b`.

This records local implementation evidence for the separately admitted
`EP-RESOLUTION-BME04-v1` profile and `BME04-JCS-ACTION-v1` mapping. It does not
claim a published release, general BME interoperability, a new governed
security-case result, or automatic Gate integration.

## Terminal results

- JavaScript: verify package TypeScript/declaration build passed. The focused
  Node suite passed 137 tests: 117 shared receipt cases, three published-source
  digest examples, six parser-resource boundaries, two input/version-isolation
  tests, and nine existing v1 resolution/source-version regressions.
- Python: the standard-library unittest harness passed all 117 shared receipt
  cases, three digest examples, six resource boundaries, and raw-input/version
  isolation checks. The existing v1 source-version regression also passed.
  `pytest` was absent in the selected runtime; no dependency was installed.
- Go: `GOTOOLCHAIN=local GOPROXY=off go test -run 'BME04|Resolution' ./...`
  passed with Go 1.26.4, including the same corpus and resource checks, native
  parser/encoding negatives, and existing resolution/version-isolation tests.
- The ESM package self-import of
  `@emilia-protocol/verify/resolution-bme04` passed.
- Repository-boundary, standalone-runtime freshness, generated LLM context and
  public-conformance-claim checks passed. The standalone writer generated the
  new test companion and its `.gitattributes` entry.
- Security-case metadata validation passed for the existing 35 claims. All
  264 recorded evidence-file SHA-256 hashes match their current files.
  Existing v1 sources, runtimes and shared vectors are unchanged. Existing
  formal files and their pinned inputs have no changes in this patch.

Corpus SHA-256:
`1fdc5068a75e056af814c86dc006ba68d50280c0f12e1ed22f81aac47197c001`.

## Explicit limits

The executable security-case command was attempted but its selected-scenario
runner stopped because this isolated environment has no `TLA2TOOLS_JAR`.
The existing formal experiment was not rerun or regenerated. The new profile
is outside the governed 21-suite/340-vector headline counts; these counts and
security evidence were not enlarged by this patch. Full repository tests,
application build, hosted CI, package publication and deployment were not run.

The new parsers reject rounded fractional literals, duplicate decoded keys,
unpaired surrogates, extra-depth/size/node input, ambiguous or submillisecond
timestamps, noncanonical binary encodings, and unsupported signature keys.
The signature and action-binding checks preserve the difference between valid
historical evidence and current action authorization. Actual atomic envelope
consumption remains a caller integration responsibility.
