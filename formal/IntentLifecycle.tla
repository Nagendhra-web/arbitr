--------------------------- MODULE IntentLifecycle ---------------------------
(***************************************************************************)
(* Intent state machine.                                                  *)
(*                                                                         *)
(* Skeleton: models the legal transitions only. It will grow into        *)
(* the full execution protocol (leases, commit points,                    *)
(* crashes, concurrent workers, idempotency modes, recovery) and checks    *)
(* AtMostOnceEffect, NoSilentRetry, NoExecuteWithoutLedger and             *)
(* ApprovalBinding.                                                       *)
(*                                                                         *)
(* The Transitions set below is the single list that the Python transition *)
(* table is checked against.                                              *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS Intents, MaxAttempts

States == {"PROPOSED", "DENIED", "PENDING_APPROVAL", "APPROVED", "REJECTED",
           "EXPIRED", "EXECUTING", "SUCCEEDED", "FAILED", "UNKNOWN",
           "COMPENSATED"}

\* BEGIN TRANSITIONS
Transitions == {
    <<"PROPOSED", "DENIED">>,
    <<"PROPOSED", "PENDING_APPROVAL">>,
    <<"PROPOSED", "APPROVED">>,
    <<"PENDING_APPROVAL", "APPROVED">>,
    <<"PENDING_APPROVAL", "REJECTED">>,
    <<"PENDING_APPROVAL", "EXPIRED">>,
    <<"APPROVED", "EXECUTING">>,
    <<"EXECUTING", "SUCCEEDED">>,
    <<"EXECUTING", "FAILED">>,
    <<"EXECUTING", "UNKNOWN">>,
    <<"FAILED", "EXECUTING">>,
    <<"UNKNOWN", "SUCCEEDED">>,
    <<"UNKNOWN", "EXECUTING">>,
    <<"UNKNOWN", "FAILED">>,
    <<"SUCCEEDED", "COMPENSATED">>
}
\* END TRANSITIONS

Terminal == {"DENIED", "REJECTED", "EXPIRED", "COMPENSATED"}

VARIABLES state, attempt

vars == <<state, attempt>>

TypeOK ==
    /\ state \in [Intents -> States]
    /\ attempt \in [Intents -> 0..MaxAttempts]

Init ==
    /\ state = [i \in Intents |-> "PROPOSED"]
    /\ attempt = [i \in Intents |-> 0]

Move(i, to) ==
    /\ <<state[i], to>> \in Transitions
    /\ to = "EXECUTING" => attempt[i] < MaxAttempts
    /\ state' = [state EXCEPT ![i] = to]
    /\ attempt' = IF to = "EXECUTING"
                    THEN [attempt EXCEPT ![i] = @ + 1]
                    ELSE attempt

(* An intent is at rest when no transition can ever leave its state. *)
AtRest(i) ==
    \/ state[i] \in Terminal
    \/ state[i] = "FAILED" /\ attempt[i] = MaxAttempts

(* Explicit stuttering once every intent is at rest. TLC runs with deadlock *)
(* checking on, so any other state with no way forward is reported.        *)
Done == (\A i \in Intents : AtRest(i)) /\ UNCHANGED vars

Next == (\E i \in Intents, to \in States : Move(i, to)) \/ Done

Spec == Init /\ [][Next]_vars

(* Every state change of every intent is in the transition table. *)
LegalTransitions ==
    [][\A i \in Intents :
        state'[i] # state[i] => <<state[i], state'[i]>> \in Transitions]_vars

(* Nothing leaves a terminal state. *)
TerminalIsFinal ==
    [][\A i \in Intents : state[i] \in Terminal => state'[i] = state[i]]_vars

(* Execution never happens without a prior allow or approval. *)
ExecutesOnlyAfterApproval ==
    \A i \in Intents : attempt[i] > 0 =>
        state[i] \in {"EXECUTING", "SUCCEEDED", "FAILED", "UNKNOWN", "COMPENSATED"}
=============================================================================
