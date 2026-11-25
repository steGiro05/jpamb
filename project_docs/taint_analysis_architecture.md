# Taint Analysis Architecture - Decisions and Implementation Status

Version note (25 November 2026): the review initially used the local checkout
at `0adbf88`, then inspected `origin/project` at `5e4a5c0`. The local
`taint_abstraction` branch was subsequently fast-forwarded to `5e4a5c0`, so
both now contain the reviewed code with the two allowlist sanitizer summaries
enabled. The review introduced no analyzer or fuzzer code changes.

## Purpose

The static taint analysis identifies which parameters of a JPAMB entry method may influence values passed to security-sensitive operations. Its findings guide the fuzzer toward relevant methods, parameters, and sinks. Dynamic execution remains responsible for confirming that a reported flow is exploitable.

The analysis is designed as a **may-analysis**. Its label-set abstraction over-approximates explicit provenance tags, and joins can report infeasible flows. Preservation by the complete analyzer additionally depends on reference/heap coverage, summaries, and control-flow/call-graph coverage. These premises are not established for general Java programs; the proof and current implementation limits are recorded in `taint_abstraction_proof.md`.

## Scope and precision

The initial analysis has the following properties:

- One JPAMB entry method is analyzed at a time.
- Every entry-method parameter receives a distinct source label, such as `p0` or `p1`.
- The analysis is flow-sensitive: it maintains an abstract state at each program counter.
- It is initially path-insensitive: states from different branches are joined.
- It tracks explicit data flows only.
- It is interprocedural but initially context-insensitive: calls to the same method may be joined.

Not tracking implicit flows is a deliberate limitation. For example, a parameter that only controls whether a sink is reached may not appear among the labels passed to that sink. The fuzzer should therefore continue mutating every input parameter, while prioritizing parameters identified by explicit taint flows. Full control-dependence tracking may be added later if needed.

## Taint domain

Let `L = {p0, ..., pn}` be the finite set of labels assigned to the parameters of the entry method. The abstract taint domain is the powerset of `L`:

`T = P(L)`

An element records all sources on which a value may depend. The lattice is:

- order: `T1 <= T2` iff `T1` is a subset of `T2`;
- join: `T1 join T2 = T1 union T2`;
- meet: `T1 meet T2 = T1 intersection T2`;
- bottom: the empty set, meaning no known tainted dependency;
- top: `L`, meaning possible dependency on every source.

Join is used when control-flow paths merge. Meet is part of the lattice definition but is not normally used to merge states in this may-analysis.

## Abstract values and states

The implementation uses a `TaintValue`, separate from the existing sign-analysis `StackValue`. Conceptually it contains:

```text
TaintValue
  labels: TaintSet
  references: optional finite set of abstract reference targets
```

This separation is necessary because a JVM reference can simultaneously point to abstract heap locations and carry taint labels. Null and external references are represented as described below.

The initial implementation uses three kinds of abstract reference target:

- an allocation site, identified by the program counter of an object-producing
  instruction (`new`, array creation, the load site of a constant string, or a summary-return site);
- `EXTERNAL_pi`, for an object supplied through entry-method parameter `pi` and therefore allocated outside the analyzed program;
- `NULL`, which preserves the possibility of a null reference through state joins.

For example, joining the targets `{NULL}` and `{PC15}` produces `{NULL, PC15}`. A general unknown-reference target is not introduced initially. Unsupported operations that return references must instead provide a trusted summary; a general unknown target can be added later if an operation cannot be modeled this way. The absence of a state at a program point represents unreachability and is distinct from every ordinary `TaintValue`.

An abstract JVM state contains abstract locals, an abstract operand stack, and an abstract heap. The whole analysis maps each program counter to one such state:

```text
PC -> (locals, operand stack, heap)
```

Heap objects are represented by non-null abstract targets. Ordinary objects use
their allocation site, identified by the program counter of the instruction
that materializes the reference, while entry-parameter objects use their
synthetic `EXTERNAL_pi` target. This keeps the abstract heap finite, at the cost
of merging objects produced at the same site. `NULL` never identifies a heap
cell.

## Propagation rules

Constants start with no labels, while entry-method parameter `i` starts with `{pi}`. Loads, stores, casts, and returns preserve labels. Operations such as string concatenation combine operand labels using union. Calls propagate argument labels to callee parameters and return labels back to callers. At control-flow merges, states are joined component-wise.

Security sinks are defined explicitly together with their sensitive argument
positions. The initial configuration contains
`Class.forName(String)` argument 0 for CWE-470 and
`simulateReadObject` argument 0 for CWE-502. The original `CWE502` signature is registered explicitly; copies in classes under `jpamb.cases.*` are recognized by helper name, including signatures with additional arguments.
`simulateResolveClassName(String)` is a taint-propagating summary, not a sink.
The CWE-specific `canary()` is treated separately as the dynamic exploit oracle: a
security sink indicates a potentially dangerous flow, while the canary confirms
that the simulated exploit succeeded.

Unsupported library behavior, reflection, and simulated deserialization are
handled through trusted method summaries. The initial summaries propagate taint
through the two simulated deserialization helpers and reflective class loading and
instantiation. The current fallback summarizes every `java.*` call and every
`invokedynamic` by propagating invocation-input labels to its return value.
These return-only summaries do not model heap effects or preserve returned
aliases, and therefore are not conservative for arbitrary library behavior.
Only methods explicitly configured as trusted sanitizers may remove taint.
The default at `5e4a5c0`, now also used by the local branch, enables the two allowlist summaries for
`taint_cases.sanitizePayload` and `taint_cases.sanitizeCommand` in
`DEFAULT_SUMMARIES`. These entries were commented out in the earlier
`0adbf88` checkout. The no-sanitizer experiment requires disabling them.
The current code also defines
the method ID for `filterCommand`, but does not trust it by default; the
deliberately incorrect configuration requires adding its sanitizer summary.
Ordinary comparisons, allowlists, or regular-expression
checks are not automatically assumed to sanitize a value. The analysis guarantee
is therefore conditional on the correctness of sink, sanitizer, and library
summaries. With sanitizers, labels denote policy-relative unsanitized taint,
not every raw input dependency. Removing a label requires safety for all
downstream sink contexts to which that removal applies; the domain is not
separated by vulnerability category.

## Fixpoint computation

The analysis uses the existing worklist architecture. A successor program point is processed again only when joining an incoming state makes its stored state larger. The analysis terminates when the worklist is empty, rather than after an arbitrary number of steps.

The initial bytecode model does not expose exception-handler edges. An explicit
`throw` therefore terminates the current abstract path; propagation into catch
blocks is deferred until exception-table information is retained by the common
JVM model. This limitation does not affect the normal sink-reaching paths in the
initial JPAMB vulnerability cases, but it is part of the whole-analysis
soundness boundary.

No widening is required for the taint domain. For finite programs with compatible JVM state shapes, stored states, continuations, returns, and findings accumulate over finite sets, so there can be only finitely many growth events. This supports termination when transfers return normally. It must not be taken as a proof that every implemented heap transfer is monotone or sound: the proof document records a static-reference-load counterexample to monotonicity under the current heap order.

## Output for the fuzzer

The internal result is a structured set of analysis hints. Each finding should contain at least:

```text
TaintFinding
  taint sink method and program counter
  labels reaching the sink
  relevant entry parameters
  call-graph distance to the exploit target
```

The call-graph adapter uses `call_sites` (caller, opcode-list `instruction_index`,
and `resolved_callees`) for ordinary interprocedural dispatch. Synthetic dynamic
constructor edges remain in the method graph rather than being treated as
ordinary calls with incompatible JVM descriptors. Reflection and simulated
deserialization use summaries instead of interpreting the dynamically selected
constructor bodies in the taint analyzer.

The adapter also computes reverse-BFS distances from configured
`exploit_targets` (`sinks` is accepted as a legacy alias). A finding's distance
is the minimum number of method-call edges from its sink-containing method to
one of these targets, not to the taint sink. The current configuration uses
`__CANARY__Command` constructors as exploit targets, so this is not necessarily
the distance to the `canary()` method itself. The final fuzzer does not consume
this distance; it uses dynamic coverage. Currently a missing finite distance
causes the taint analysis to fail, even though distance is auxiliary metadata.

Python dataclasses are used internally. `taint-analysis` emits JSON with
`entry_method`, `classification`, and `findings`. The classification is
`unflagged` when no configured sink finding is produced, otherwise
`flagged_unverified`. It can load a shared call-graph artifact through
`JPAMB_CALL_GRAPH_PATH`; otherwise it invokes `call-graph` itself.

The taint-guided fuzzer reads this report from `JPAMB_TAINT_REPORT_PATH` or
invokes the executable once. It uses categories to choose vulnerability-value
pools and parameter indices to favor those values for relevant string inputs.
Other parameters remain mutable. However, the current integration skips the
entire method and reports `ok` when classification is `unflagged`. That pruning
is a benchmark heuristic, not a safety result: omitted implicit flows,
constant unsafe sink arguments, or unsupported heap/library behavior can
invalidate the inference. A missing or failed report does not trigger this
skip and instead falls back to fuzzing. Dynamic canary execution confirms a
modeled exploit; `flagged_unverified` alone does not.

## Decisions deferred beyond the initial implementation

The following extensions are intentionally deferred: implicit-flow tracking, path sensitivity, 1-CFA or deeper context sensitivity, precise string-content abstraction, intra-procedural distance metrics, worklist ordering optimizations, and complete modeling of Java libraries. They should be reconsidered only if evaluation shows that the initial analysis is too imprecise or inefficient.
