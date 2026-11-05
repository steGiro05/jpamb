"""Worklist-based interprocedural taint analysis."""

from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Protocol

import jvm
from jvm.state import PC

from taint_analysis.abstractions import TaintSet, TaintState, TaintValue
from taint_analysis.calls import (
    Continuation,
    InvokeInstruction,
    prepare_calls,
    resume_call,
)
from taint_analysis.control_flow import MethodReturn, Successor, transfer_control_flow
from taint_analysis.heap_transfers import transfer_heap
from taint_analysis.initial_state import initial_entry_state
from taint_analysis.summaries import (
    DEFAULT_SINKS,
    DEFAULT_SUMMARIES,
    MethodSummary,
    SinkSpec,
    TaintFinding,
    apply_summary,
    builtin_summary,
    inspect_sinks,
)
from taint_analysis.transfers import transfer_base


class BytecodeProgram(Protocol):
    def getmethod(self, methodid: jvm.AbsMethodID) -> jvm.Method: ...

    def __getitem__(self, pc: PC) -> jvm.Opcode: ...


@dataclass(frozen=True, slots=True)
class CallGraph:
    """Call targets and precomputed method distances supplied by prior analysis."""

    edges: Mapping[PC, tuple[jvm.AbsMethodID, ...]] = field(default_factory=dict)
    distances_to_exploit_target: Mapping[jvm.AbsMethodID, int] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        edges = {pc: tuple(targets) for pc, targets in self.edges.items()}
        distances = dict(self.distances_to_exploit_target)
        if any(distance < 0 for distance in distances.values()):
            raise ValueError("call-graph distances cannot be negative")
        object.__setattr__(self, "edges", MappingProxyType(edges))
        object.__setattr__(
            self, "distances_to_exploit_target", MappingProxyType(distances)
        )

    def targets(self, pc: PC) -> tuple[jvm.AbsMethodID, ...]:
        return self.edges.get(pc, ())

    def distance(self, method: jvm.AbsMethodID) -> int:
        try:
            return self.distances_to_exploit_target[method]
        except KeyError as error:
            raise ValueError(f"call graph has no sink distance for {method}") from error


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    states: Mapping[PC, TaintState]
    findings: tuple[TaintFinding, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "states", MappingProxyType(dict(self.states)))


class TaintAnalyzer:
    """Compute a context-insensitive taint fixpoint over JVM bytecode."""

    _BASE_INSTRUCTIONS = (
        jvm.Push,
        jvm.Load,
        jvm.Store,
        jvm.Binary,
        jvm.Negate,
        jvm.Cast,
        jvm.CheckCast,
        jvm.Incr,
        jvm.Dup,
        jvm.Pop,
    )
    _HEAP_INSTRUCTIONS = (
        jvm.New,
        jvm.NewArray,
        jvm.ArrayStore,
        jvm.ArrayLoad,
        jvm.ArrayLength,
        jvm.Put,
        jvm.Get,
    )
    _CONTROL_INSTRUCTIONS = (jvm.Goto, jvm.Ifz, jvm.If, jvm.Return)
    _INVOKE_INSTRUCTIONS = (
        jvm.InvokeStatic,
        jvm.InvokeVirtual,
        jvm.InvokeInterface,
        jvm.InvokeSpecial,
        jvm.InvokeDynamic,
    )

    def __init__(
        self,
        program: BytecodeProgram,
        call_graph: CallGraph,
        *,
        summaries: Mapping[jvm.AbsMethodID, MethodSummary] = DEFAULT_SUMMARIES,
        sinks: tuple[SinkSpec, ...] = DEFAULT_SINKS,
    ):
        self.program = program
        self.call_graph = call_graph
        self.summaries = MappingProxyType(dict(summaries))
        self.sinks = tuple(sinks)
        self.states: dict[PC, TaintState] = {}
        self.worklist: deque[PC] = deque()
        self.continuations: dict[
            jvm.AbsMethodID, dict[tuple[PC, bool], Continuation]
        ] = {}
        self.returns: dict[PC, MethodReturn] = {}
        self.findings: dict[tuple[jvm.AbsMethodID, PC, str, int], TaintFinding] = {}

    def analyze(self, entry_method: jvm.AbsMethodID) -> AnalysisResult:
        """Analyze one static JPAMB entry method until the worklist is empty."""

        self._clear()
        method = self.program.getmethod(entry_method)
        self._enqueue(PC(entry_method, 0), initial_entry_state(method))

        while self.worklist:
            pc = self.worklist.popleft()
            self._step(pc, self.states[pc])

        findings = tuple(
            sorted(
                self.findings.values(),
                key=lambda finding: (
                    finding.call_site.encode(),
                    finding.category,
                ),
            )
        )
        return AnalysisResult(self.states, findings)

    def _clear(self) -> None:
        self.states.clear()
        self.worklist.clear()
        self.continuations.clear()
        self.returns.clear()
        self.findings.clear()

    def _enqueue(self, pc: PC, incoming: TaintState) -> None:
        previous = self.states.get(pc)
        if previous is not None and incoming <= previous:
            return
        self.states[pc] = incoming if previous is None else previous | incoming
        self.worklist.append(pc)

    def _step(self, pc: PC, state: TaintState) -> None:
        instruction = self.program[pc]

        if isinstance(instruction, self._BASE_INSTRUCTIONS):
            self._enqueue(pc + 1, transfer_base(pc, instruction, state))
            return
        if isinstance(instruction, self._HEAP_INSTRUCTIONS):
            self._enqueue(pc + 1, transfer_heap(pc, instruction, state))
            return
        if isinstance(instruction, self._CONTROL_INSTRUCTIONS):
            for result in transfer_control_flow(pc, instruction, state):
                if isinstance(result, Successor):
                    self._enqueue(result.pc, result.state)
                else:
                    self._record_return(pc, result)
            return
        if isinstance(instruction, self._INVOKE_INSTRUCTIONS):
            self._invoke(pc, instruction, state)
            return
        if isinstance(instruction, jvm.Throw):
            # Exception-handler edges are outside the initial bytecode model.
            return
        raise NotImplementedError(
            f"no taint transfer function for {type(instruction).__name__}"
        )

    def _invoke(
        self, pc: PC, instruction: InvokeInstruction, state: TaintState
    ) -> None:
        if any(sink.method == instruction.method for sink in self.sinks):
            for finding in inspect_sinks(
                pc,
                instruction,
                state,
                distance_to_exploit_target=self.call_graph.distance(pc.method),
                sinks=self.sinks,
            ):
                self._record_finding(finding)

        summary = self.summaries.get(instruction.method)
        if summary is None:
            summary = builtin_summary(instruction)
        if summary is not None:
            successor = apply_summary(pc, instruction, state, summary)
            self._enqueue(successor.pc, successor.state)
            return

        if isinstance(instruction, jvm.InvokeDynamic):
            raise AssertionError("invokedynamic should have a builtin summary")

        target_ids = self.call_graph.targets(pc)
        target_methods = tuple(self.program.getmethod(target) for target in target_ids)
        for request in prepare_calls(pc, instruction, state, target_methods):
            self._register_continuation(
                request.callee_pc.method, request.continuation
            )
            self._enqueue(request.callee_pc, request.callee_state)

    def _register_continuation(
        self, callee: jvm.AbsMethodID, incoming: Continuation
    ) -> None:
        by_site = self.continuations.setdefault(callee, {})
        key = (incoming.return_pc, incoming.expects_value)
        previous = by_site.get(key)
        if previous is not None and incoming.caller_state <= previous.caller_state:
            return

        if previous is None:
            continuation = incoming
        else:
            continuation = Continuation(
                incoming.return_pc,
                previous.caller_state | incoming.caller_state,
                incoming.expects_value,
            )
        by_site[key] = continuation

        for return_pc, returned in self.returns.items():
            if return_pc.method == callee:
                successor = resume_call(continuation, returned)
                self._enqueue(successor.pc, successor.state)

    def _record_return(self, pc: PC, incoming: MethodReturn) -> None:
        previous = self.returns.get(pc)
        if previous is not None and self._return_le(incoming, previous):
            return

        returned = incoming if previous is None else self._join_returns(previous, incoming)
        self.returns[pc] = returned
        for continuation in self.continuations.get(pc.method, {}).values():
            successor = resume_call(continuation, returned)
            self._enqueue(successor.pc, successor.state)

    @staticmethod
    def _return_le(left: MethodReturn, right: MethodReturn) -> bool:
        if (left.value is None) != (right.value is None):
            return False
        value_le = left.value is None or left.value <= right.value
        return left.state <= right.state and value_le

    @staticmethod
    def _join_returns(left: MethodReturn, right: MethodReturn) -> MethodReturn:
        if left.value is None and right.value is None:
            value = None
        elif left.value is not None and right.value is not None:
            value = left.value | right.value
        else:
            raise ValueError("cannot join void and value-returning executions")
        return MethodReturn(left.state | right.state, value)

    def _record_finding(self, incoming: TaintFinding) -> None:
        key = (
            incoming.sink,
            incoming.call_site,
            incoming.category,
            incoming.distance_to_exploit_target,
        )
        previous = self.findings.get(key)
        if previous is None:
            self.findings[key] = incoming
            return
        self.findings[key] = TaintFinding(
            sink=incoming.sink,
            call_site=incoming.call_site,
            labels=previous.labels | incoming.labels,
            category=incoming.category,
            distance_to_exploit_target=incoming.distance_to_exploit_target,
        )
