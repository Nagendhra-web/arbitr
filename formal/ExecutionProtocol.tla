-------------------------- MODULE ExecutionProtocol --------------------------
(***************************************************************************)
(* The execution and recovery protocol of src/arbitr/executor.py.          *)
(*                                                                         *)
(* Each idempotency key has at most one intent row (the UNIQUE constraint).*)
(* Workers run tool calls through three ledger commits:                    *)
(*   1. insert the intent and record the gate's decision,                  *)
(*   2. EXECUTING with attempt + 1 and a lease owner (start_execution),    *)
(*   3. after the call: SUCCEEDED, FAILED or UNKNOWN, fenced on the state, *)
(*      the attempt and the lease owner.                                   *)
(* The side effect is its own step between commits 2 and 3, on the         *)
(* service's side: a count of effects per key. Native services dedupe by   *)
(* key, probe services record the key so a probe can find the effect, and  *)
(* "none" services do neither.                                             *)
(*                                                                         *)
(* Workers can crash at any step and lose their local state. The clock is  *)
(* abstract: Expire marks a lease as run out. Recovery moves an EXECUTING  *)
(* intent with an expired lease to UNKNOWN; then native tools run again    *)
(* with the same key, probe tools ask the service first, and none tools    *)
(* follow the on_unknown policy (retry only when the tool allows           *)
(* duplicates, fail, or a human resolves it). A none tool without          *)
(* duplicates that was ever UNKNOWN never runs again on its own, even      *)
(* from FAILED.                                                            *)
(*                                                                         *)
(* Right before the call, a worker confirms its lease (_confirm_lease): it *)
(* renews it, fenced on the owner and the attempt, and stops without       *)
(* calling if the lease was lost.                                          *)
(*                                                                         *)
(* Assumptions:                                                            *)
(* - LeaseOutlivesCall: once a worker has confirmed its lease, the lease   *)
(*   does not run out before the call has reached the service. A running  *)
(*   call cannot be stopped, so the code cannot enforce this; the call    *)
(*   must be shorter than the lease, or the heartbeats must keep it alive. *)
(*   Before the confirm, a lease can run out at any moment. Native tools  *)
(*   do not need the assumption at all: their leases can run out at any   *)
(*   moment, so a worker whose lease was taken over may call the service  *)
(*   late, and the service dedupes the call.                               *)
(* - A clean tool error (FAILED) means the effect did not happen.          *)
(* - A human resolving an UNKNOWN intent checks the service first.         *)
(* - MaxAttempts bounds the attempts so the state space is finite. The     *)
(*   Python code has no such bound.                                        *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Keys,            \* idempotency keys, one intent each
    Workers,         \* worker processes (the scheduler runs on them too)
    Hashes,          \* argument hashes a caller may send for a key
    Modes,           \* tool idempotency modes, a subset of {"native", "probe", "none"}
    OnUnknownRules,  \* policy on_unknown values to explore
    MaxAttempts,     \* bound on attempts per intent
    Nil              \* a model value meaning "nothing"

ASSUME Modes \subseteq {"native", "probe", "none"}
ASSUME OnUnknownRules \subseteq {"require_approval", "retry", "fail"}
ASSUME MaxAttempts \in Nat \ {0}

VARIABLES
    \* The ledger (database rows).
    st,         \* intent state per key, "NONE" before the row exists
    rowHash,    \* args hash stored with the intent (intent_hash)
    apprHash,   \* the hash that was approved, by the gate or a human
    attempt,    \* attempt counter
    owner,      \* lease owner
    expired,    \* the lease has run out on the database clock
    \* Fixed configuration, chosen in Init.
    mode,       \* tool idempotency mode per key
    dup,        \* the tool allows duplicates (only for none tools)
    rule,       \* the policy's on_unknown
    \* The external service and history.
    seen,       \* the service has recorded this key (native and probe)
    effects,    \* how many side effects the service performed for the key
    calls,      \* every call that reached the service: <<attempt, hash, new effect>>
    retries,    \* explicit retry decisions taken from UNKNOWN (none tools)
    wasUnknown, \* the intent was ever UNKNOWN (tx.has_been, from the events)
    \* Each worker's local state, lost on a crash.
    pc, wk, wh, wa, wr,
    \* The transitions the last step recorded, to check them.
    moved

ledger  == <<st, rowHash, apprHash, attempt, owner, expired>>
config  == <<mode, dup, rule>>
service == <<seen, effects, calls, retries>>
local   == <<pc, wk, wh, wa, wr>>
vars    == <<ledger, config, service, local, moved, wasUnknown>>

(* The transition list lives in IntentLifecycle.tla, the one the Python *)
(* transition table is tested against.                                   *)
LC == INSTANCE IntentLifecycle WITH Intents <- Keys, state <- st

PCs == {"idle", "approved", "ready", "confirmed", "called", "probing", "probed"}
Results == {Nil, "ok", "fail", "unknown", "found", "absent"}

TypeOK ==
    /\ st \in [Keys -> LC!States \cup {"NONE"}]
    /\ rowHash \in [Keys -> Hashes \cup {Nil}]
    /\ apprHash \in [Keys -> Hashes \cup {Nil}]
    /\ attempt \in [Keys -> 0..MaxAttempts]
    /\ owner \in [Keys -> Workers \cup {Nil}]
    /\ expired \in [Keys -> BOOLEAN]
    /\ mode \in [Keys -> Modes]
    /\ dup \in [Keys -> BOOLEAN]
    /\ rule \in OnUnknownRules
    /\ seen \in [Keys -> BOOLEAN]
    /\ effects \in [Keys -> 0..MaxAttempts]
    /\ calls \in [Keys -> SUBSET ((1..MaxAttempts) \X Hashes \X BOOLEAN)]
    /\ retries \in [Keys -> 0..MaxAttempts]
    /\ wasUnknown \in [Keys -> BOOLEAN]
    /\ pc \in [Workers -> PCs]
    /\ wk \in [Workers -> Keys \cup {Nil}]
    /\ wh \in [Workers -> Hashes \cup {Nil}]
    /\ wa \in [Workers -> 0..MaxAttempts]
    /\ wr \in [Workers -> Results]
    /\ moved \subseteq (LC!States \X LC!States)

Init ==
    /\ st = [k \in Keys |-> "NONE"]
    /\ rowHash = [k \in Keys |-> Nil]
    /\ apprHash = [k \in Keys |-> Nil]
    /\ attempt = [k \in Keys |-> 0]
    /\ owner = [k \in Keys |-> Nil]
    /\ expired = [k \in Keys |-> FALSE]
    /\ mode \in [Keys -> Modes]
    /\ dup \in {d \in [Keys -> BOOLEAN] : \A k \in Keys : d[k] => mode[k] = "none"}
    /\ rule \in OnUnknownRules
    /\ seen = [k \in Keys |-> FALSE]
    /\ effects = [k \in Keys |-> 0]
    /\ calls = [k \in Keys |-> {}]
    /\ retries = [k \in Keys |-> 0]
    /\ wasUnknown = [k \in Keys |-> FALSE]
    /\ pc =[w \in Workers |-> "idle"]
    /\ wk = [w \in Workers |-> Nil]
    /\ wh = [w \in Workers |-> Nil]
    /\ wa = [w \in Workers |-> 0]
    /\ wr = [w \in Workers |-> Nil]
    /\ moved = {}

----------------------------------------------------------------------------
(* Helpers *)

SetLocal(w, p, k, h, a, r) ==
    /\ pc' = [pc EXCEPT ![w] = p]
    /\ wk' = [wk EXCEPT ![w] = k]
    /\ wh' = [wh EXCEPT ![w] = h]
    /\ wa' = [wa EXCEPT ![w] = a]
    /\ wr' = [wr EXCEPT ![w] = r]

Reset(w) == SetLocal(w, "idle", Nil, Nil, 0, Nil)

SetState(k, s) == st' = [st EXCEPT ![k] = s]

(* start_execution: the next attempt, with a fresh lease owned by w. *)
Lease(k, w) ==
    /\ attempt' = [attempt EXCEPT ![k] = @ + 1]
    /\ owner' = [owner EXCEPT ![k] = w]
    /\ expired' = [expired EXCEPT ![k] = FALSE]

(* A none tool goes to a human unless the policy says fail, or says retry *)
(* and the tool allows duplicates (_on_unknown).                          *)
NoneRetries(k) == rule = "retry" /\ dup[k]
NoneNeedsHuman(k) == mode[k] = "none" /\ rule # "fail" /\ ~NoneRetries(k)

(* _may_have_acted: a none tool without duplicates that went through *)
(* UNKNOWN may have acted, so FAILED does not run it again.          *)
MayHaveActed(k) == mode[k] = "none" /\ ~dup[k] /\ wasUnknown[k]

(* Every step records whether a key became UNKNOWN, also inside a        *)
(* transaction that moves on from UNKNOWN (only one key moves per step). *)
TrackUnknown ==
    wasUnknown' = [k \in Keys |->
        \/ wasUnknown[k]
        \/ st'[k] = "UNKNOWN"
        \/ /\ st'[k] # st[k] \/ attempt'[k] # attempt[k]
           /\ \E p \in moved' : p[2] = "UNKNOWN"]

(* A confirmed call of the current attempt is on its way to the service. *)
CallInFlight(k) ==
    \E w \in Workers : pc[w] = "confirmed" /\ wk[w] = k /\ wa[w] = attempt[k]

(* The LeaseOutlivesCall assumption, as a condition on Expire. *)
LeaseOutlivesCall(k) == mode[k] = "native" \/ ~CallInFlight(k)

----------------------------------------------------------------------------
(* Commit 1 for a new key: insert the intent and record the decision. *)
Insert(w, k, h) ==
    /\ pc[w] = "idle"
    /\ st[k] = "NONE"
    /\ rowHash' = [rowHash EXCEPT ![k] = h]
    /\ \/ /\ SetState(k, "DENIED")
          /\ moved' = {<<"PROPOSED", "DENIED">>}
          /\ UNCHANGED <<apprHash, local>>
       \/ /\ SetState(k, "PENDING_APPROVAL")
          /\ moved' = {<<"PROPOSED", "PENDING_APPROVAL">>}
          /\ UNCHANGED <<apprHash, local>>
       \/ /\ SetState(k, "APPROVED")
          /\ apprHash' = [apprHash EXCEPT ![k] = h]
          /\ moved' = {<<"PROPOSED", "APPROVED">>}
          /\ SetLocal(w, "approved", k, h, 0, Nil)
    /\ UNCHANGED <<attempt, owner, expired, config, service>>

(* _recover after the intent is UNKNOWN; path holds the transitions this *)
(* transaction already recorded.                                         *)
Recover(w, k, h, path) ==
    /\ IF mode[k] = "native" \/ (mode[k] = "none" /\ NoneRetries(k))
       THEN IF attempt[k] < MaxAttempts
            THEN /\ SetState(k, "EXECUTING")
                 /\ Lease(k, w)
                 /\ moved' = path \cup {<<"UNKNOWN", "EXECUTING">>}
                 /\ retries' = IF mode[k] = "none"
                                 THEN [retries EXCEPT ![k] = @ + 1]
                                 ELSE retries
                 /\ SetLocal(w, "ready", k, h, attempt[k] + 1, Nil)
            ELSE /\ SetState(k, "UNKNOWN")
                 /\ moved' = path
                 /\ UNCHANGED <<attempt, owner, expired, retries, local>>
       ELSE IF mode[k] = "probe"
       THEN /\ SetState(k, "UNKNOWN")
            /\ moved' = path
            /\ SetLocal(w, "probing", k, h, attempt[k], Nil)
            /\ UNCHANGED <<attempt, owner, expired, retries>>
       ELSE IF rule = "fail"
       THEN /\ SetState(k, "FAILED")
            /\ moved' = path \cup {<<"UNKNOWN", "FAILED">>}
            /\ UNCHANGED <<attempt, owner, expired, retries, local>>
       ELSE \* an approval is created and a human resolves it (Resolve)
            /\ SetState(k, "UNKNOWN")
            /\ moved' = path
            /\ UNCHANGED <<attempt, owner, expired, retries, local>>
    /\ UNCHANGED <<rowHash, apprHash, config, seen, effects, calls>>

(* Commit 1 for an existing key (_resume). The caller's args hash must *)
(* match the stored one, or the call is refused (IntentError).        *)
Resume(w, k, h) ==
    /\ pc[w] = "idle"
    /\ st[k] # "NONE"
    /\ h = rowHash[k]
    /\ \/ /\ st[k] = "APPROVED"
          /\ SetLocal(w, "approved", k, h, 0, Nil)
          /\ moved' = {}
          /\ UNCHANGED <<ledger, config, service>>
       \/ /\ st[k] = "FAILED"
          /\ ~MayHaveActed(k)   \* else UnknownOutcome: a human must decide
          /\ attempt[k] < MaxAttempts
          /\ SetState(k, "EXECUTING")
          /\ Lease(k, w)
          /\ moved' = {<<"FAILED", "EXECUTING">>}
          /\ SetLocal(w, "ready", k, h, attempt[k] + 1, Nil)
          \* A none tool that allows duplicates, failed after UNKNOWN by
          \* policy and called again: an explicit retry decision.
          /\ retries' = IF mode[k] = "none" /\ wasUnknown[k]
                          THEN [retries EXCEPT ![k] = @ + 1]
                          ELSE retries
          /\ UNCHANGED <<rowHash, apprHash, config, seen, effects, calls>>
       \/ /\ st[k] = "EXECUTING"
          /\ expired[k]
          /\ Recover(w, k, h, {<<"EXECUTING", "UNKNOWN">>})
       \/ /\ st[k] = "UNKNOWN"
          /\ Recover(w, k, h, {})

(* Commit 2 (_start): EXECUTING with a lease, fenced on APPROVED. *)
Start(w) ==
    /\ pc[w] = "approved"
    /\ LET k == wk[w] IN
       \/ /\ st[k] = "APPROVED"
          /\ SetState(k, "EXECUTING")
          /\ Lease(k, w)
          /\ moved' = {<<"APPROVED", "EXECUTING">>}
          /\ SetLocal(w, "ready", k, wh[w], attempt[k] + 1, Nil)
       \/ /\ st[k] # "APPROVED"   \* StaleStateError: the call stops
          /\ moved' = {}
          /\ Reset(w)
          /\ UNCHANGED <<st, attempt, owner, expired>>
    /\ UNCHANGED <<rowHash, apprHash, config, service>>

(* The decision came with a delay: the intent waits in a cancel window. *)
Schedule(w) ==
    /\ pc[w] = "approved"
    /\ st[wk[w]] = "APPROVED"
    /\ SetState(wk[w], "SCHEDULED")
    /\ moved' = {<<"APPROVED", "SCHEDULED">>}
    /\ Reset(w)
    /\ UNCHANGED <<rowHash, apprHash, attempt, owner, expired, config, service>>

(* The scheduler starts a due intent on worker w, with the stored args. *)
Fire(w, k) ==
    /\ pc[w] = "idle"
    /\ st[k] = "SCHEDULED"
    /\ attempt[k] < MaxAttempts
    /\ SetState(k, "EXECUTING")
    /\ Lease(k, w)
    /\ moved' = {<<"SCHEDULED", "EXECUTING">>}
    /\ SetLocal(w, "ready", k, rowHash[k], attempt[k] + 1, Nil)
    /\ UNCHANGED <<rowHash, apprHash, config, service>>

Cancel(k) ==
    /\ st[k] = "SCHEDULED"
    /\ SetState(k, "CANCELLED")
    /\ moved' = {<<"SCHEDULED", "CANCELLED">>}
    /\ UNCHANGED <<rowHash, apprHash, attempt, owner, expired, config, service, local>>

(* The side effect, on the service. A call either reaches the service *)
(* (the result is ok, or unknown after a timeout) or does not (a clean *)
(* error, or unknown).                                               *)
(* _confirm_lease, right before the call: renew the lease, fenced on the *)
(* state, the owner and the attempt, or stop without calling (InFlight). *)
Confirm(w) ==
    /\ pc[w] = "ready"
    /\ LET k == wk[w] IN
       IF st[k] = "EXECUTING" /\ attempt[k] = wa[w] /\ owner[k] = w
       THEN /\ expired' = [expired EXCEPT ![k] = FALSE]
            /\ SetLocal(w, "confirmed", k, wh[w], wa[w], Nil)
       ELSE /\ Reset(w)
            /\ UNCHANGED expired
    /\ moved' = {}
    /\ UNCHANGED <<st, rowHash, apprHash, attempt, owner, config, service>>

Call(w) ==
    /\ pc[w] = "confirmed"
    /\ LET k == wk[w]
           fresh == mode[k] # "native" \/ ~seen[k]
       IN \/ /\ seen' = IF mode[k] = "none" THEN seen ELSE [seen EXCEPT ![k] = TRUE]
             /\ effects' = IF fresh THEN [effects EXCEPT ![k] = @ + 1] ELSE effects
             /\ calls' = [calls EXCEPT ![k] = @ \cup {<<wa[w], wh[w], fresh>>}]
             /\ \E r \in {"ok", "unknown"} : SetLocal(w, "called", k, wh[w], wa[w], r)
          \/ /\ UNCHANGED <<seen, effects, calls>>
             /\ \E r \in {"fail", "unknown"} : SetLocal(w, "called", k, wh[w], wa[w], r)
    /\ moved' = {}
    /\ UNCHANGED <<ledger, config, retries>>

(* Commit 3 (_finish_ok, _finish_error), fenced on the state, the *)
(* attempt and the lease owner. A refused write changes nothing.   *)
Finish(w) ==
    /\ pc[w] = "called"
    /\ LET k == wk[w]
           target == CASE wr[w] = "ok" -> "SUCCEEDED"
                       [] wr[w] = "fail" -> "FAILED"
                       [] OTHER -> "UNKNOWN"
       IN IF st[k] = "EXECUTING" /\ attempt[k] = wa[w] /\ owner[k] = w
          THEN /\ SetState(k, target)
               /\ moved' = {<<"EXECUTING", target>>}
          ELSE /\ moved' = {}
               /\ UNCHANGED st
    /\ Reset(w)
    /\ UNCHANGED <<rowHash, apprHash, attempt, owner, expired, config, service>>

(* _run_probe, part 1: ask the service, outside any transaction. *)
ProbeRead(w) ==
    /\ pc[w] = "probing"
    /\ SetLocal(w, "probed", wk[w], wh[w], wa[w],
                IF seen[wk[w]] THEN "found" ELSE "absent")
    /\ moved' = {}
    /\ UNCHANGED <<ledger, config, service>>

(* _run_probe, part 2: SUCCEEDED if found, else run again. Both commits  *)
(* are fenced on the attempt the probe was asked about (wa, the attempt *)
(* of the row read when the probe was planned).                         *)
ProbeCommit(w) ==
    /\ pc[w] = "probed"
    /\ LET k == wk[w] IN
       IF st[k] = "UNKNOWN" /\ attempt[k] = wa[w] /\ wr[w] = "found"
       THEN /\ SetState(k, "SUCCEEDED")
            /\ moved' = {<<"UNKNOWN", "SUCCEEDED">>}
            /\ Reset(w)
            /\ UNCHANGED <<attempt, owner, expired>>
       ELSE IF st[k] = "UNKNOWN" /\ attempt[k] = wa[w] /\ attempt[k] < MaxAttempts
       THEN /\ SetState(k, "EXECUTING")
            /\ Lease(k, w)
            /\ moved' = {<<"UNKNOWN", "EXECUTING">>}
            /\ SetLocal(w, "ready", k, wh[w], attempt[k] + 1, Nil)
       ELSE /\ moved' = {}   \* stale: another worker moved it first
            /\ Reset(w)
            /\ UNCHANGED <<st, attempt, owner, expired>>
    /\ UNCHANGED <<rowHash, apprHash, config, service>>

(* A worker loses its local state and restarts. *)
Crash(w) ==
    /\ pc[w] # "idle"
    /\ Reset(w)
    /\ moved' = {}
    /\ UNCHANGED <<ledger, config, service>>

(* The lease runs out on the database clock, at any moment except while *)
(* a confirmed call is on its way (LeaseOutlivesCall).                   *)
Expire(k) ==
    /\ st[k] = "EXECUTING"
    /\ ~expired[k]
    /\ LeaseOutlivesCall(k)
    /\ expired' = [expired EXCEPT ![k] = TRUE]
    /\ moved' = {}
    /\ UNCHANGED <<st, rowHash, apprHash, attempt, owner, config, service, local>>

(* recover_stale: an expired EXECUTING intent becomes UNKNOWN. *)
RecoverStale(k) ==
    /\ st[k] = "EXECUTING"
    /\ expired[k]
    /\ SetState(k, "UNKNOWN")
    /\ moved' = {<<"EXECUTING", "UNKNOWN">>}
    /\ UNCHANGED <<rowHash, apprHash, attempt, owner, expired, config, service, local>>

(* A human decides a pending approval. The approval holds the intent's hash. *)
Approve(k) ==
    /\ st[k] = "PENDING_APPROVAL"
    /\ SetState(k, "APPROVED")
    /\ apprHash' = [apprHash EXCEPT ![k] = rowHash[k]]
    /\ moved' = {<<"PENDING_APPROVAL", "APPROVED">>}
    /\ UNCHANGED <<rowHash, attempt, owner, expired, config, service, local>>

Refuse(k) ==
    /\ st[k] = "PENDING_APPROVAL"
    /\ \E s \in {"REJECTED", "EXPIRED"} :
          /\ SetState(k, s)
          /\ moved' = {<<"PENDING_APPROVAL", s>>}
    /\ UNCHANGED <<rowHash, apprHash, attempt, owner, expired, config, service, local>>

(* A human resolves an UNKNOWN none tool after checking the service. *)
Resolve(k) ==
    /\ st[k] = "UNKNOWN"
    /\ NoneNeedsHuman(k)
    /\ LET ran == \E c \in calls[k] : c[1] = attempt[k]
           s == IF ran THEN "SUCCEEDED" ELSE "FAILED"
       IN /\ SetState(k, s)
          /\ moved' = {<<"UNKNOWN", s>>}
    /\ UNCHANGED <<rowHash, apprHash, attempt, owner, expired, config, service, local>>

(* Explicit stuttering once every worker is idle and nothing is running. *)
Done ==
    /\ \A w \in Workers : pc[w] = "idle"
    /\ \A k \in Keys : st[k] # "EXECUTING"
    /\ UNCHANGED vars

(* Every step but Done also updates wasUnknown. *)
T(A) == A /\ TrackUnknown

Next ==
    \/ \E w \in Workers, k \in Keys, h \in Hashes : T(Insert(w, k, h) \/ Resume(w, k, h))
    \/ \E w \in Workers : T(Start(w) \/ Schedule(w) \/ Confirm(w) \/ Call(w)
                            \/ Finish(w) \/ ProbeRead(w) \/ ProbeCommit(w) \/ Crash(w))
    \/ \E w \in Workers, k \in Keys : T(Fire(w, k))
    \/ \E k \in Keys : T(Cancel(k) \/ Expire(k) \/ RecoverStale(k)
                         \/ Approve(k) \/ Refuse(k) \/ Resolve(k))
    \/ Done

(* Workers, leases, the recovery sweep and the scheduler make progress. *)
(* Callers, crashes, cancels and human decisions are never forced.      *)
Fairness ==
    /\ \A w \in Workers : /\ WF_vars(T(Start(w))) /\ WF_vars(T(Confirm(w)))
                          /\ WF_vars(T(Call(w))) /\ WF_vars(T(Finish(w)))
                          /\ WF_vars(T(ProbeRead(w))) /\ WF_vars(T(ProbeCommit(w)))
    /\ \A k \in Keys : /\ WF_vars(T(Expire(k))) /\ WF_vars(T(RecoverStale(k)))
                       /\ SF_vars(\E w \in Workers : T(Fire(w, k)))

Spec == Init /\ [][Next]_vars

LiveSpec == Spec /\ Fairness

----------------------------------------------------------------------------
(* Properties *)

(* Native and probe tools never cause the side effect twice. *)
AtMostOnceEffect ==
    \A k \in Keys : mode[k] \in {"native", "probe"} => effects[k] <= 1

(* A none tool runs a second time only after an explicit retry decision *)
(* taken from UNKNOWN, and never when it does not allow duplicates.     *)
NoSilentRetry ==
    \A k \in Keys : mode[k] = "none" =>
        /\ effects[k] <= 1 + retries[k]
        /\ ~dup[k] => effects[k] <= 1

(* Every call that reached the service ran under an attempt whose       *)
(* EXECUTING commit happened (attempts only grow through start_execution). *)
NoExecuteWithoutLedger ==
    \A k \in Keys : \A c \in calls[k] : c[1] \in 1..attempt[k]

(* Every call carried the args hash that was approved. *)
ApprovalBinding ==
    \A k \in Keys : \A c \in calls[k] : c[2] = apprHash[k]

(* A cancelled intent never reached the service. *)
CancelledNeverRuns ==
    \A k \in Keys : st[k] = "CANCELLED" => calls[k] = {} /\ effects[k] = 0

(* Every recorded transition is in IntentLifecycle's list, and every state *)
(* change was recorded.                                                    *)
LegalTransitions ==
    [][/\ moved' \subseteq LC!Transitions
       /\ \A k \in Keys : st'[k] # st[k] => \E p \in moved' : p[2] = st'[k]]_vars

TerminalIsFinal == LC!TerminalIsFinal

(* Under fairness, a running or scheduled intent always ends up SUCCEEDED, *)
(* FAILED, UNKNOWN or CANCELLED.                                           *)
Settles ==
    \A k \in Keys :
        st[k] \in {"EXECUTING", "SCHEDULED"} ~>
            st[k] \in {"SUCCEEDED", "FAILED", "UNKNOWN", "CANCELLED"}
=============================================================================
