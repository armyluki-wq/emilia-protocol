<!-- SPDX-License-Identifier: Apache-2.0 -->

# BME-04 candidate gate: superseded by the published-source contract

The September candidate plan is superseded by the published
[draft-morrison-binding-moment-envelope-04](https://www.ietf.org/archive/id/draft-morrison-binding-moment-envelope-04.txt)
and the [experimental implementation contract](EP-RESOLUTION-BME04-CONTRACT.md).
The upstream dependency is no longer waiting for publication.

The new opt-in `EP-RESOLUTION-BME04-v1` implementation and separate shared
vectors cover exact per-option action binding and envelope-bound native decline
in JavaScript, Python and Go. Its mapping is explicitly `BME04-JCS-ACTION-v1`.
An authentic selection whose digest differs from the actual action remains
valid evidence and cannot authorize that action. Missing action or freshness
inputs likewise cannot grant authority.

`EP-RESOLUTION-v1` retains the -02 grammar, local option mapping, unchanged wire
format and exports. Neither profile accepts a signature simply relabeled as the
other. The new profile is experimental source code, not a package release; it is
not automatically admitted by Gate or included in headline conformance counts.

Remaining adoption gates are review and publication of the exact profile and
vectors, then caller integration with independent trust pins and atomic
outstanding-envelope consumption. Stateless verification does not establish
exactly-once execution. See the contract for runnable tests and precise limits.
