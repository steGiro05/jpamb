# Correctness of the Taint Abstraction

## Scope

This document proves the correctness of the label-set abstraction and basic label transfer rules. It also states a **conditional** preservation theorem for an interprocedural analysis. This is not an unconditional proof of the implemented JVM analyzer: lifting the value result to heap accesses and calls additionally requires adequate reference targets, initial heaps, and method summaries. The implementation audit below records cases where these requirements are not met for general Java programs.

The finite target set contains instruction sites, synthetic `EXTERNAL_pi` targets for entry-parameter objects, and the distinguished `NULL` target. `NULL` does not address a heap cell. Proving precise points-to information is unnecessary, but proving or assuming **coverage of every concrete alias and accessed location** is necessary for a whole-state soundness claim. Merely separating references from labels does not discharge this obligation.

## Concrete and abstract domains

Let `L = {p0, ..., p(m-1)}` be the finite set of source labels assigned to the `m` parameters of the static JPAMB entry method (`L` is empty when `m = 0`). Let `V` be the nonempty set of concrete JVM values.

A concrete tagged value is a pair `(v, D)`, where `v` is a value in `V` and `D` is a subset of `L` assigned by an instrumented semantics of explicit data provenance. Tags are propagated by the rules below, rather than defined as exact semantic dependence on all possible executions. In particular, branch conditions do not add tags to constants assigned inside a branch. Combining tags can overstate semantic dependence, for example for `x - x`. The collecting concrete domain is

`C = P(V x P(L))`,

ordered by set inclusion.

The abstract domain retains only possible source dependencies:

`A = P(L)`.

For `T1, T2` in `A`, define

```text
T1 <= T2       iff T1 is a subset of T2
T1 join T2     = T1 union T2
T1 meet T2     = T1 intersection T2
bottom         = empty set
top            = L
```

An abstract element `T` allows any subset of the labels in `T`. The empty set represents a reachable value with no provenance tags in this model. An unreachable program state is represented separately by the absence of a state at that program point. In particular, `gamma(empty set) = V x {empty set}` is not empty: value bottom is not state unreachability. A missing or failed analysis report is also not an untainted result.

## Lemma 1: the abstract domain is a lattice

Set inclusion is reflexive, antisymmetric, and transitive, so `(P(L), subset)` is a partially ordered set. For every pair `T1` and `T2`, their union is the least set containing both and is therefore their least upper bound. Their intersection is the greatest set contained in both and is therefore their greatest lower bound. The empty set is contained in every element and is bottom, while every element is contained in `L`, which is top. Therefore

`(P(L), subset, union, intersection, empty set, L)`

is a lattice. It is finite because `L` is finite, and therefore complete. Every strictly ascending chain contains at most `m + 1` elements, although the domain has `2^m` elements.

## Abstraction and concretization

Define the abstraction function `alpha : C -> A` by

`alpha(X) = union of D for every (v, D) in X`.

It forgets concrete values and correlations between individual values and dependency sets, retaining every source dependency that occurs in `X`.

Define the concretization function `gamma : A -> C` by

`gamma(T) = {(v, D) | v in V and D is a subset of T}`.

Thus, `gamma(T)` contains every concrete tagged value whose exact dependencies are allowed by `T`.

## Theorem 1: Galois connection

For every `X` in `C` and `T` in `A`,

`alpha(X) is a subset of T` if and only if `X is a subset of gamma(T)`.

### Proof

Assume first that `alpha(X)` is a subset of `T`. Take any `(v, D)` in `X`. By the definition of `alpha`, `D` is a subset of `alpha(X)`. Hence `D` is a subset of `T`, and by the definition of `gamma`, `(v, D)` belongs to `gamma(T)`. Since this holds for every element of `X`, `X` is a subset of `gamma(T)`.

Conversely, assume that `X` is a subset of `gamma(T)`. For every `(v, D)` in `X`, membership in `gamma(T)` implies that `D` is a subset of `T`. The union of sets that are all subsets of `T` is itself a subset of `T`. By the definition of `alpha`, this union is `alpha(X)`. Therefore `alpha(X)` is a subset of `T`.

This proves the equivalence and establishes a Galois connection between `C` and `A`.

## Corollary 1: abstraction does not discard represented dependencies

Taking `T = alpha(X)` in Theorem 1 gives

`X is a subset of gamma(alpha(X))`.

The abstraction may lose concrete values and correlations, so equality is not required. Concretizing an abstraction may introduce additional possibilities, but it still contains every original concrete tagged value.

## Abstract transfer functions

The analysis uses the following transfer rules for explicit data dependencies.

### Constants

A constant has no dependency on an entry parameter:

`const#(v) = empty set`.

This exactly abstracts its concrete dependency set.

### Copying operations

Operations such as loads, stores, and casts preserve the dependency set:

`copy#(T) = T`.

They therefore preserve the abstraction relation.

### Data-combining operations

For an operation whose result may depend on each of its operands, including arithmetic and string concatenation, define

`op#(T1, ..., Tk) = T1 union ... union Tk`.

In the tagged concrete semantics, applying the corresponding operation to `(v1, D1), ..., (vk, Dk)` produces a result tagged with `D1 union ... union Dk`. Consequently, for collecting operand sets `X1, ..., Xk`,

`alpha(op(X1, ..., Xk))` is a subset of `op#(alpha(X1), ..., alpha(Xk))`.

Therefore the abstract operation cannot omit a dependency produced by its concrete counterpart.

### Control-flow merges

If two control-flow paths produce abstract values `T1` and `T2`, the merged value is

`T1 join T2 = T1 union T2`.

Every concrete value arriving from either path is represented by the result. This is the source of intentional path insensitivity and may introduce dependencies that cannot occur together, but it does not remove dependencies.

### Calls and returns

At a call, each argument label set is copied to the corresponding callee parameter; instance calls also copy the receiver to local slot zero. On return, the return-value label set and the callee heap are passed to each registered caller continuation. Joining callers and returns can introduce spurious combinations. Label copying itself is sound, provided that every actual callee and return continuation is covered and the heap representation remains valid. This is an obligation on the interprocedural model, not a consequence of the value-level Galois connection alone.

### Heap fields and arrays

A reference-valued `TaintValue` contains both a label set and a finite set of abstract reference targets. Non-null targets determine which heap cells may be accessed; the targets are not themselves source labels. Joining reference values uses set union, so a possible `NULL` target is preserved when paths merge.

For a field read, the analysis joins the field values stored at every possible target and conservatively combines their labels with the labels of the receiver reference:

`getfield#(reference, field) = labels(reference) union joined labels of target.field`.

For a field write, every possible target is weakly updated. The stored labels include both the written value labels and the receiver labels, preserving a possible dependency on which object is selected:

`heap'(target.field) = heap(target.field) union labels(reference) union labels(value)`.

Arrays use one abstract contents cell per non-null abstract target. Reads and writes additionally join index labels, so all elements at a target share one cell. Array creation combines dimension labels into the array reference; `arraylength` copies reference labels. These are conservative rules for the modeled accesses **if** the reference sets cover every accessed concrete location, all existing contents are represented, and reference-valued results retain adequate targets. Weak updates alone do not establish those premises. Default zero/null values are justified for freshly initialized cells, not arbitrary externally supplied object graphs or unmodeled class initialization.

### Security sinks and findings

When an invocation matches a configured security sink, its argument values are removed from the operand stack according to the normal JVM calling convention. Before they are removed, the analysis records a `TaintFinding` containing the sink location and the argument labels. Removing the stack value therefore does not discard the result of the analysis: the dependency is preserved in the finding and, when specified by the method summary, in the invocation's abstract return value.

### Trusted summaries and sanitizers

A library summary must cover return labels, returned aliases, and any relevant heap effects or exceptional successors. Propagating argument labels to the return value alone does not establish that property.

For **raw provenance**, a sanitizer cannot in general erase labels: an allowlist may return the original input, which still originates from its parameter. The preservation theorem for raw provenance therefore excludes label-erasing sanitizer summaries.

Alternatively, the same lattice can track **policy-relative unsanitized taint**. In that instrumented semantics, a trusted sanitizer is explicitly allowed to reset the returned tag to the empty set. The value-level Galois proof is unchanged, and the conditional preservation theorem applies to these policy tags, not to raw provenance. To interpret this reset as security assurance, every normally returned value must be safe for all downstream sink uses covered by that reset, with no unmodeled relevant effects. The analyzer has one label set rather than a separate set per vulnerability category, so a sanitizer safe for one context is not automatically safe for every context. The allowlist benchmark uses each sanitizer only in its intended reflection or simulated-deserialization context. Incorrectly trusting `filterCommand` violates the policy premise.

## Lifting the abstraction to JVM states

The value abstraction is lifted component-wise to abstract locals, operand stacks, and heaps. Locals and stack positions contain `TaintValue` instances, each consisting of a label set and, for references, possible abstract targets. Heap cells are addressed by a non-null abstract target together with a field or abstract array-content identifier. An abstract state is

`State# = Locals# x Stack# x Heap#`,

and the global analysis maps each program counter to an abstract state. Interprocedural bookkeeping additionally stores caller continuations and return states; findings accumulate in a separate output component. Locals and stack positions must have compatible JVM kinds and stack shapes at each join. Uninitialized local slots are not ordinary untainted values.

Write `s R a` when a concrete configuration is represented by the global abstract configuration. This relation requires: (1) every concrete value tag is contained in the corresponding abstract labels; (2) every possible concrete reference and alias used by an access is covered by the abstract targets and heap cells; (3) the initial heap, control-flow successors, calls, and continuations are represented. The value-level `alpha` defined earlier is **not** a definition of a whole-JVM-state abstraction function. A full state abstraction would also have to formalize these heap and call-stack components.

The local obligation is: for every `s R a` and modeled step `s -> s'`, the abstract successors produced from `a` represent `s'`. The basic label rules above establish the label part of this obligation. Heap, call-graph, and summary coverage remain additional premises. In particular, over-approximate points-to sets need not be precise, but they must not omit an actual alias.

## Theorem 2: preservation over execution steps

Assume that (1) the initial global abstract configuration represents all modeled initial configurations, (2) every instruction and summary satisfies the local obligation for `R`, (3) joins preserve representation, and (4) the worklist processes all successors until it is closed under the abstract transfers. Then its result represents every modeled concrete configuration reachable after finitely many steps. This is a conditional simulation theorem; it does not assert that every implementation operation meets its premises.

### Proof sketch

The proof is by induction on the number of concrete steps, relative to the final closed abstract configuration. The base case is premise (1): assigning `{pi}` proves the parameter-label part, but does not by itself prove coverage of arbitrary initial heaps or aliases. For the induction step, suppose a configuration is represented. Premise (2) represents each concrete successor by the corresponding abstract successor. Closure in premise (4), together with the representation-preserving joins in premise (3), includes that successor in the final result. This proves the assertion for every finite execution prefix. This is not a claim that the worklist processes configurations in concrete execution order.

## Fixpoint and termination

The worklist repeatedly joins incoming states at program points and reprocesses a point only when its stored state grows. Label copying, union, and a fixed policy reset are monotone. This does not automatically prove monotonicity of all reference and heap operations in the implementation (see the `getstatic` counterexample below).

For a finite program with compatible JVM stack/local shapes, the label universe, program points, stack positions, local slots, field identifiers, abstract targets, continuation keys, and finding keys are finite. Stored states, continuations, returns, and finding labels accumulate by joins. Hence only finitely many strict growth events can enqueue work, and each event creates finite work. Assuming transfers return normally, processing terminates without widening. This argument uses finite accumulation; it does not require every implementation transfer to be monotone. Monotonicity and a sound representation are additionally required for the usual least-fixed-point interpretation of a monotone abstract semantic operator.

If Theorem 2's premises hold, every modeled reachable configuration is represented at closure. If sink observation also covers every relevant sensitive argument or receiver, every remaining concrete taint tag at that sink appears in its finding. This assertion concerns provenance tags without sanitization, or policy tags with trusted resets. It does not assert that every exploitable canary execution contains a tainted sink argument: for example, a constant unsafe class name selected only by a branch can trigger a canary without an explicit taint flow.

## Assumptions and limitations

The established unconditional result is the Galois connection for label sets and correctness of the stated basic label operations. Whole-analysis preservation is conditional on the explicit premises above. The analysis excludes implicit control dependencies and exception-handler edges; `throw` ends an abstract path. Null entry references, arbitrary external heaps and aliases, class initialization, full JVM stack-manipulation support, and general library effects are not covered by the current implementation. Unsupported instructions generally fail instead of producing a successful report.

## Implementation audit (25 November 2026)

The initial checks used the local `taint_abstraction` checkout at `0adbf88`. After fetching the remote on 25 November, they were compared with `origin/project` at `5e4a5c0` (23 November), which includes `integrated-fuzzer` at `fe05a3a`. The local branch was subsequently fast-forwarded to `5e4a5c0`. The reference/heap operations, sink-distance lookup, and unflagged-pruning behavior are unchanged between these versions; the sanitizer default changed as recorded below. The review introduced no analyzer or fuzzer code changes; the branch update incorporated existing upstream changes.

| Area | Observed behavior | Consequence |
| --- | --- | --- |
| External aliasing (`initial_state.py`, `heap_transfers.py`) | Each reference parameter gets a distinct `EXTERNAL_pi`. After `x.value = p2`, reading `y.value` produces `{p1}` if `x` and `y` are parameters 0 and 1, even when they could alias concretely. | The source `p2` is missed for aliased entry objects; arbitrary initial heaps/aliases do not satisfy the whole-state premises. |
| Returned aliases (`summaries.py`) | Every summary reference result gets a fresh instruction-site target. Passing an untainted object with a `p0`-tainted field through `java.util.Objects.requireNonNull` loses access to that field's taint. | Return-label propagation does not cover identity-returning methods followed by heap access. |
| Library heap effects (`summaries.py`) | All `java.*` calls use return-only propagation unless explicitly summarized. `java.util.Arrays.fill(array, p0)` changes no abstract cell; a subsequent load from an initially clean array remains untainted. | Generic summaries are not conservative models of arbitrary Java library behavior. |
| Heap order (`abstractions.py`, `heap_transfers.py`) | A heap with no static reference cell is below one storing a non-null target. `getstatic` yields `NULL` for the former but only the stored target for the latter. These results are not ordered. | The claim that every implemented transfer is monotone under the implemented product order is false. Finite accumulation still supports termination, but no unconditional least-fixed-point or full-state proof follows. |
| Sink-distance dependency (`analyzer.py`) | Every sink invocation requests a finite distance from its containing method to an exploit target, before checking whether arguments have labels. A missing path raises an error. | An otherwise valid sink analysis can fail because auxiliary distance metadata is absent. Analysis failure must not be classified as `unflagged`. |
| Sanitizer configuration (`summaries.py`) | The default at `5e4a5c0`, now also used by the local branch, enables the two allowlist summaries; `filterCommand` has a method-ID constant but is not trusted in `DEFAULT_SUMMARIES`. Both allowlist entries were commented out in the earlier `0adbf88` checkout. | The current default is the trusted-allowlist configuration. The no-sanitizer and incorrectly trusted-filter rows require explicit changes; the earlier observation about disabled defaults no longer applies to either the local branch or the reviewed remote version. |
| Fuzzer pruning (`steps/taint_fuzzer.py`, `stepwise_dynamic.py`) | `unflagged` skips fuzzing and reports `ok`; a failed/missing report falls back to fuzzing. | Skipping is a benchmark heuristic, not a safety proof. Explicit-flow absence does not rule out every canary execution. |

The 62 existing taint tests pass both locally and against an isolated export of the remote taint module at `5e4a5c0`. Focused diagnostic executions reproduced the first four observations against both versions, and the failure on a clean sink invocation with missing distance metadata was reproduced locally in unchanged code. Those tests do not establish whole-tool soundness or reproduce the paper's benchmark counts. The benchmark source shows each allowlist used in its intended sink context; this review did not rerun the reported experiment configurations. The remote additionally contains experiment scripts under `results/`; they do not alter these reference/heap semantics.
