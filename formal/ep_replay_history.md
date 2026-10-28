# Replay-history completeness model (#906)

Model-only bounded artifact, based on main
`c7408b6e7923095cd359ef976666ce21ba178177`. This does not establish a
production external anchor, an independent witness operator, runtime
implementation refinement, or universal recovery safety.

## Separate hot path and recovery evidence

`ConsumeLinearized` atomically consumes one exact identity and returns an
identity-bound sequence receipt. `ProviderEntry` is a separate later transition
requiring that receipt and complete authoritative history. The receipt cannot
be reused. `CheckpointAnchored` is independent and asynchronous: the first
provider entry may carry `anchored = 0`. A later anchor is never treated as a
pre-entry timestamp. Synchronous anchoring is not modeled or required.

The two stores are (1) authoritative replay log plus local checkpoint, dispatch
and terminal rows, and (2) external anchor root/frontier, retained high-water
mark, and trusted archived payload bytes sealed at that frontier. The archived
payload is explicit retained data, not bytes inferred from a commitment root. A root is the exact ordered sequence, abstracting collision resistance;
frontiers are sequence lengths. `Complete` requires local checkpoint/log root
agreement and consistency with the anchor prefix and high-water mark. This
single-identity, two-attempt abstraction deliberately has only roots `<<>>`
and `<<"identity">>`; it does not model multi-identity cryptography or races.

Loss of replay rows, dispatch rows, terminal evidence, local checkpoint, or
rollback of primary plus checkpoint explicitly invalidates continuity and
outstanding receipts. Unavailable, rolled-back and equivocating anchor views
block entry. `Recover` can restore COMPLETE only for a matching covered root
and frontier. Rollback with an empty anchor stays uncertain even if it happened
in a never-used history: this conservative availability cost prevents treating
an uncovered lost suffix as unused. `RestoreArchivedBytes` restores missing replay and checkpoint bytes from
the explicitly retained trusted archive only when its root matches the current
anchor and its frontier covers the required missing range. `Recover` then
reestablishes completeness. This bounded compaction/restore protocol is not a production compaction implementation.
There is no unconditional
recovery liveness claim: unavailable bytes or an uncovered tail remain blocked.

## Assumptions and their failure

The safe model assumes authoritative consume-if-absent linearization, valid
receipts, complete mediation, trustworthy continuity/loss detection, and an
independent retained anchor high-water mark. The fault labels denote detected
faults, not an implemented loss detector. Arbitrary silent local rollback cannot
be made detectable by a periodic anchor that never saw the missing suffix.
Such a deployment must retain trustworthy continuity evidence or stay uncertain;
this model does not invent that evidence. Dispatch/effect truth is not proved.

`CommonSnapshotRestore` explicitly violates independence: local log/checkpoint,
anchor, high-water mark and continuity view all return to a shared old snapshot.
The observer's provider-entry history remains solely to expose the replay.
The resulting counterexample shows why safe results cannot be extended to an
attacker controlling every continuity witness. Those observer records and the
`linearized` set are specification history, never recovery inputs.

## Checked properties and negative controls

- `TypeOK`: bounded root, frontier, receipt and entry types.
- `AtMostOnce`: at most one entry for this identity, including after destruction.
- `EntryHasPriorConsume`: each observed entry has a prior consume receipt,
  nonzero sequence and complete history at admission.
- `UncertainCannotAdmit`: incomplete or inconsistent history disables entry.
- `NeverUsedEventuallyEnters`: under weak fairness of consume and entry and
  no faults, a never-used identity eventually enters. This prevents a vacuous
  deny-everything model; faulted histories have no general liveness guarantee.
- `EventuallyRecovered`: a directed fair scenario enters, asynchronously seals,
  loses both nonempty replay rows and checkpoint, restores archived bytes, and
  recovers COMPLETE. `RecoveredStillConsumed` proves it cannot consume again.
- `UncoveredTailBlocked`: a directed negative scenario enters before anchoring,
  loses its replay rows, and cannot restore the empty archive, recover COMPLETE,
  or enter again. `EventuallyUncoveredLoss` ensures the scenario reaches loss,
  rather than passing vacuously.

`missing` uses `UnsafeTreatMissingHistoryAsUnused`: H1 consumes and enters, all
local replay evidence is forgotten, and the recovered empty view is treated as
H0 (never used). The shortest trace has no anchor; a second consume and entry
violate AtMostOnce. `rollback` first anchors the consumed root, then deliberately
accepts the earlier empty checkpoint/anchor and resets its high-water pin;
a second consume/entry exposes rollback. `common` produces the analogous
counterexample when every independent-witness assumption fails. These unsafe
transitions are excluded from `safe` and `live` configs.

## Reproduction

```
python3 formal/ep_replay_history_check.py [path/to/tla2tools-1.7.4.jar]
```

The default is `~/.cache/emilia/formal/tla2tools-1.7.4.jar`; SHA256 is checked
against `936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`.
Each run uses one worker, 512 MiB heap and a 60-second wall-time bound, with
isolated temporary state deleted afterwards. Raw logs are preserved here in
`ep_replay_history_results/`. The runner requires success for safe/liveness
and the named mutation, two consumes, two entries and AtMostOnce failure for
each unsafe counterexample. It also requires successful temporal checking for
positive recovery and uncovered-tail reachability/refusal. It does not count a
parser failure as a counterexample.

Current run: safe 94,873 generated / 25,729 distinct states; live 10 / 9;
recovery 9 / 8; uncovered tail 4 / 4; compaction recovery 8 / 7. Expected
unsafe violations: missing 1,728 / 817; rollback and common snapshot each
3,796 / 1,619.
No repository-wide suite or shared evidence generation is needed for this
standalone model. It is not added to existing formal/runtime claim counts.

## Explicit two-run indistinguishability comparison

`ep_replay_history_twoworld.tla` supplements the destructive replay trace with
an independent bounded product of two runs. H0 never consumed or entered; H1
performs a real modeled consume and entry before a crash. Each has separate
operational and external state and an independently enabled crash transition.
Both recover with erased local rows and an uncovered genesis anchor/archive.
`Observe` projects all modeled available recovery inputs (rows, receipt,
checkpoint/frontier, anchor root/frontier/state, archived payload, high-water
mark, coverage and continuity). It excludes only scheduler phase and hidden
observer history, which the recovery decision cannot consult.

`Compare` does **not** require equal observations as a guard. The invariant
`RecoveredViewsEqual` checks that the two independently reached recovered views
are equal. `HistoriesActuallyDiffer` simultaneously checks that H0 never
consumed and H1 did, retaining exactly one extra actual provider entry.
Thus the comparison is not just a renamed single-run erasure counterexample.
Weak fairness and `EventuallyComparedAndDecided` require both histories to
reach comparison and a terminal decision, excluding a vacuous initial-state
or never-decide result.

At this identical observation, the `all` configuration explores both possible
observation-based deterministic decisions, ADMIT and REFUSE. The invariant
`NoDecisionBothSafeAndLive` verifies that neither can give admission to the
actually unused H0 while retaining at-most-once safety in H1. `safe` chooses
REFUSE, preserving replay safety at the availability cost of refusing H0.
`unsafe` chooses ADMIT and produces a concrete H1 replay counterexample with
two actual entries while H0 receives its first. One common decision models a
function of identical recovery inputs; it cannot read hidden prior-effect truth.
This is a bounded impossibility demonstration for the specified observation,
not an unbounded theorem about randomized, interactive, or richer-observation
recovery algorithms. Independent additional continuity evidence can distinguish
the worlds; this experiment explicitly lacks such evidence for the lost suffix.

Run `python3 formal/ep_replay_history_twoworld_check.py [pinned-jar-path]`.
The runner verifies the same JAR hash and uses one worker, a 512 MiB heap and
60-second timeout per configuration. Raw logs are in
`ep_replay_history_results/twoworld-{safe,all,unsafe}.log`. Results: safe 13
states generated / 10 distinct; all decisions 14 / 11; unsafe expected
`ReplaySafe` violation 13 / 10. The unsafe trace is checked for both independent
crashes, consumption, original entry, comparison and the recovery decision.

Remaining acceptance boundaries: integration/review of this supplementary
model, and any separately required runtime or deployment work. This artifact
implements no production anchor, archived storage service, loss detector or
production compaction implementation; it does not establish operator independence or change
existing public formal/runtime claim counts. The broader safe/recovery model
continues to assume trusted archived bytes and independently retained anchor
continuity, and explicitly shows failure when all witnesses roll back together.


## Issue #906 model acceptance mapping

The later issue refinement governs the timing claim: atomic authoritative
consumption precedes entry; asynchronous anchoring establishes recovery
coverage, never a forged pre-entry timestamp. A synchronous deployment could
add an anchor-acknowledgement guard, but that stronger topology is not claimed.

| Requested model criterion | Implemented evidence |
| --- | --- |
| Explicit replay fact, completeness, frontier/root, anchor state | `log`, `coverage`, `frontier`/`checkpoint`, external `anchor`, `highWater`, `anchorState`; `Complete` checks consistency |
| Atomic consumed fact before entry | Separate `ConsumeLinearized` and `ProviderEntry`, one-use receipt, `EntryHasPriorConsume` |
| Replay/dispatch/terminal/checkpoint loss | `LocalLoss` has each of the four named mutations |
| Primary plus checkpoint rollback | `LocalLoss("RollbackPrimaryAndCheckpoint")` invalidates continuity, requires nonempty covering anchor before recovery |
| External anchor advance | `CheckpointAnchored` advances root/frontier and archives payload asynchronously |
| Anchor rollback/equivocation/unavailability | `AnchorFault` models each detected failure and disables entry |
| Monotone independent continuity reference | `AnchorHighWaterMonotone` checked in the safe config; rollback can alter the observed anchor but cannot silently reset its retained high-water pin |
| Complete anchored recovery | `RestoreArchivedBytes` plus `Recover`; fair positive recovery loses both nonempty replay rows and checkpoint |
| Coverage required before compaction | `CompactReplayRows` requires whole-range anchoring and matching archived payload; `UncoveredCannotCompact` refuses uncovered suffix deletion |
| Positive compaction recovery | Fair `CompactionSpec` compacts consumed rows/checkpoint, restores archived bytes and recovers COMPLETE; `CompactedStillConsumed` prevents reopening |
| Uncovered missing suffix fails closed | `UncoveredSpec` reaches real entry/loss, then blocks restoration, recovery and entry |
| Missing-history unsafe replay | `missing` expected `AtMostOnce` counterexample |
| Actual indistinguishable H0/H1 comparison | Separate `twoworld` model, checked projection equality, different histories, both possible decisions, fair comparison/decision, unsafe H1 replay |
| Rolled-back-anchor unsafe replay | `rollback` expected `AtMostOnce` counterexample after anchoring and accepting older history |
| All-anchor common snapshot assumption failure | `common` expected counterexample explicitly restores every continuity witness |
| Nonvacuous never-used liveness | Fair no-fault `LiveSpec` proves eventual initial entry |

All issue-level formal criteria above have executable bounded checks. Remaining
work is independent review and integration of this supplement. Reference
runtime behavior and external deployment evidence are separate evidence layers,
not claims established by this model or prerequisites silently asserted as done.
