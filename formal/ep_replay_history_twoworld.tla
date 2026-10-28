----------------- MODULE ep_replay_history_twoworld -----------------
EXTENDS Naturals, TLC
CONSTANT Policy
VARIABLES worlds, compared, decision
vars == <<worlds, compared, decision>>
Worlds == {"H0", "H1"}
\* Each run owns its own operational/external state and transition history.
\* ActualCalls and EverConsumed are observer-only truth, unavailable to policy.
InitialWorld == [phase |-> "INITIAL", log |-> FALSE, checkpoint |-> FALSE,
  dispatch |-> FALSE, terminal |-> FALSE, frontier |-> 0,
  anchorFrontier |-> 0, anchorRoot |-> "EMPTY", archive |-> "EMPTY",
  anchorState |-> "CURRENT", highWater |-> 0,
  coverage |-> "COMPLETE", continuity |-> TRUE, receipt |-> FALSE,
  actualCalls |-> 0, everConsumed |-> FALSE, recoveryCalls |-> 0]
Init == /\ worlds = [w \in Worlds |-> InitialWorld]
        /\ compared = FALSE /\ decision = "NONE"
ConsumeH1 ==
  /\ worlds["H1"].phase = "INITIAL"
  /\ worlds' = [worlds EXCEPT !["H1"].phase = "CONSUMED",
      !["H1"].log = TRUE, !["H1"].checkpoint = TRUE,
      !["H1"].frontier = 1, !["H1"].receipt = TRUE,
      !["H1"].everConsumed = TRUE]
  /\ UNCHANGED <<compared, decision>>
EnterH1 ==
  /\ worlds["H1"].phase = "CONSUMED" /\ worlds["H1"].receipt
  /\ worlds' = [worlds EXCEPT !["H1"].phase = "ENTERED",
      !["H1"].actualCalls = 1, !["H1"].dispatch = TRUE,
      !["H1"].terminal = TRUE, !["H1"].receipt = FALSE]
  /\ UNCHANGED <<compared, decision>>
\* Independent crash transitions erase recovered local evidence. No anchor
\* ever covered H1's consumed suffix; both external stores remain at genesis.
Crash(w) ==
  /\ IF w = "H0" THEN worlds[w].phase = "INITIAL"
     ELSE worlds[w].phase = "ENTERED"
  /\ worlds' = [worlds EXCEPT ![w].phase = "RECOVERED",
      ![w].log = FALSE, ![w].checkpoint = FALSE,
      ![w].dispatch = FALSE, ![w].terminal = FALSE, ![w].frontier = 0,
      ![w].coverage = "INCOMPLETE", ![w].continuity = FALSE,
      ![w].receipt = FALSE]
  /\ UNCHANGED <<compared, decision>>
\* Explicit observation projection includes all available recovery/policy inputs.
\* Hidden prior-effect history and the scheduler's phase are not policy inputs.
Observe(w) == [log |-> worlds[w].log, checkpoint |-> worlds[w].checkpoint,
  dispatch |-> worlds[w].dispatch, terminal |-> worlds[w].terminal,
  frontier |-> worlds[w].frontier, receipt |-> worlds[w].receipt,
  anchorFrontier |-> worlds[w].anchorFrontier,
  anchorRoot |-> worlds[w].anchorRoot, archive |-> worlds[w].archive,
  anchorState |-> worlds[w].anchorState, highWater |-> worlds[w].highWater,
  coverage |-> worlds[w].coverage, continuity |-> worlds[w].continuity]
Ready == \A w \in Worlds: worlds[w].phase = "RECOVERED"
Compare == /\ Ready /\ ~compared
           /\ compared' = TRUE /\ UNCHANGED <<worlds, decision>>
\* Both runs receive the same observation-based decision. Policy "all" explores
\* both possible deterministic decisions at this observation, not a hidden oracle.
Decide(d) ==
  /\ compared /\ decision = "NONE"
  /\ d \in (CASE Policy = "safe" -> {"REFUSE"}
                 [] Policy = "unsafe" -> {"ADMIT"}
                 [] OTHER -> {"REFUSE", "ADMIT"})
  /\ decision' = d
  /\ worlds' = [w \in Worlds |-> [worlds[w] EXCEPT
      !.actualCalls = @ + (IF d = "ADMIT" THEN 1 ELSE 0),
      !.recoveryCalls = IF d = "ADMIT" THEN 1 ELSE 0]]
  /\ UNCHANGED compared
Next == \/ ConsumeH1 \/ EnterH1 \/ (\E w \in Worlds: Crash(w))
        \/ Compare \/ (\E d \in {"REFUSE", "ADMIT"}: Decide(d))
Spec == Init /\ [][Next]_vars /\ WF_vars(Next)
TypeOK == /\ decision \in {"NONE", "REFUSE", "ADMIT"}
          /\ \A w \in Worlds: worlds[w].actualCalls \in 0..2
RecoveredViewsEqual == compared => Observe("H0") = Observe("H1")
HistoriesActuallyDiffer == compared =>
  /\ ~worlds["H0"].everConsumed /\ worlds["H1"].everConsumed
  /\ worlds["H1"].actualCalls = worlds["H0"].actualCalls + 1
ReplaySafe == worlds["H1"].actualCalls <= 1
NeverUsedAdmitted == worlds["H0"].recoveryCalls = 1
\* Every decision at the indistinguishable observation sacrifices either
\* recovery availability for the genuinely unused run or replay safety for H1.
NoDecisionBothSafeAndLive == decision # "NONE" =>
  ~(ReplaySafe /\ NeverUsedAdmitted)
EventuallyComparedAndDecided == <> (compared /\ decision # "NONE")
=============================================================================
