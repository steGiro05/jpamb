"""Trusted method summaries and configured security sinks."""

from dataclasses import dataclass

import jvm
from jvm.state import PC

from taint_analysis.abstractions import AllocationSite, TaintSet, TaintState, TaintValue
from taint_analysis.calls import InvokeInstruction, pop_invocation_operands
from taint_analysis.control_flow import Successor


@dataclass(frozen=True, slots=True)
class MethodSummary:
    """A trusted description of how invocation inputs affect its return value."""

    method: jvm.AbsMethodID
    argument_dependencies: tuple[int, ...] = ()
    receiver_dependency: bool = False
    sanitizer: bool = False

    def __post_init__(self) -> None:
        parameter_count = len(self.method.methodid.params)
        if any(index < 0 or index >= parameter_count for index in self.argument_dependencies):
            raise ValueError("summary argument index is outside the method descriptor")


@dataclass(frozen=True, slots=True)
class SinkSpec:
    method: jvm.AbsMethodID
    category: str
    sensitive_arguments: tuple[int, ...] = ()
    sensitive_receiver: bool = False


@dataclass(frozen=True, slots=True)
class TaintFinding:
    sink: jvm.AbsMethodID
    call_site: PC
    labels: TaintSet
    category: str
    call_graph_distance: int

    @property
    def relevant_parameters(self) -> tuple[int, ...]:
        return tuple(sorted(label.parameter_index for label in self.labels.labels))


def _method(code: str) -> jvm.AbsMethodID:
    return jvm.AbsMethodID.decode(code)


SIMULATE_RESOLVE_CLASS = _method(
    "jpamb.cases.advanced.CWE502.simulateResolveClassName:"
    "(Ljava/lang/String;)Ljava/lang/String;"
)
SIMULATE_READ_OBJECT = _method(
    "jpamb.cases.advanced.CWE502.simulateReadObject:"
    "(Ljava/lang/String;)Ljava/lang/Object;"
)
CLASS_FOR_NAME = _method(
    "java.lang.Class.forName:(Ljava/lang/String;)Ljava/lang/Class;"
)
CLASS_NEW_INSTANCE = _method(
    "java.lang.Class.newInstance:()Ljava/lang/Object;"
)


DEFAULT_SUMMARIES: dict[jvm.AbsMethodID, MethodSummary] = {
    SIMULATE_RESOLVE_CLASS: MethodSummary(
        SIMULATE_RESOLVE_CLASS, argument_dependencies=(0,)
    ),
    SIMULATE_READ_OBJECT: MethodSummary(
        SIMULATE_READ_OBJECT, argument_dependencies=(0,)
    ),
    CLASS_FOR_NAME: MethodSummary(CLASS_FOR_NAME, argument_dependencies=(0,)),
    CLASS_NEW_INSTANCE: MethodSummary(
        CLASS_NEW_INSTANCE, receiver_dependency=True
    ),
}


DEFAULT_SINKS: tuple[SinkSpec, ...] = (
    SinkSpec(CLASS_FOR_NAME, "CWE-470", sensitive_arguments=(0,)),
    SinkSpec(SIMULATE_READ_OBJECT, "CWE-502", sensitive_arguments=(0,)),
)


def sanitizer_summary(method: jvm.AbsMethodID) -> MethodSummary:
    """Create an explicitly trusted summary that removes return-value taint."""

    return MethodSummary(method=method, sanitizer=True)


def propagating_summary(instruction: InvokeInstruction) -> MethodSummary:
    """Conservatively propagate every invocation input to the return value."""

    return MethodSummary(
        method=instruction.method,
        argument_dependencies=tuple(range(len(instruction.method.methodid.params))),
        receiver_dependency=not isinstance(
            instruction, (jvm.InvokeStatic, jvm.InvokeDynamic)
        ),
    )


def builtin_summary(instruction: InvokeInstruction) -> MethodSummary | None:
    """Return a configured or safe conservative summary for known operations."""

    if summary := DEFAULT_SUMMARIES.get(instruction.method):
        return summary
    if isinstance(instruction, jvm.InvokeDynamic):
        # JPAMB uses invokedynamic for string concatenation. Conservatively all
        # bootstrap arguments may affect the resulting string.
        return propagating_summary(instruction)
    if instruction.method.classname == jvm.ClassName("java.lang.String"):
        return propagating_summary(instruction)
    return None


def apply_summary(
    pc: PC,
    instruction: InvokeInstruction,
    state: TaintState,
    summary: MethodSummary,
) -> Successor:
    """Consume an invocation and apply its trusted return-value summary."""

    if instruction.method != summary.method:
        raise ValueError("summary does not match the invoked method")

    operands = pop_invocation_operands(instruction, state)
    labels = TaintSet.bottom()
    if not summary.sanitizer:
        if summary.receiver_dependency:
            if operands.receiver is None:
                raise ValueError("summary requires a receiver for a static invocation")
            labels = labels | operands.receiver.labels
        for index in summary.argument_dependencies:
            labels = labels | operands.arguments[index].labels

    return_type = instruction.method.methodid.return_type
    after = operands.state_after_pop
    if return_type is None:
        return Successor(pc + 1, after)
    if isinstance(return_type, (jvm.Array, jvm.Object, jvm.Reference)):
        result = TaintValue.reference([AllocationSite(pc)], labels)
    else:
        result = TaintValue(labels=labels)
    return Successor(pc + 1, after.push(result))


def inspect_sinks(
    pc: PC,
    instruction: InvokeInstruction,
    state: TaintState,
    *,
    call_graph_distance: int,
    sinks: tuple[SinkSpec, ...] = DEFAULT_SINKS,
) -> tuple[TaintFinding, ...]:
    """Record tainted data reaching configured sensitive invocation inputs."""

    if call_graph_distance < 0:
        raise ValueError("call-graph distance cannot be negative")
    operands = pop_invocation_operands(instruction, state)
    findings = []
    for sink in sinks:
        if instruction.method != sink.method:
            continue
        labels = TaintSet.bottom()
        if sink.sensitive_receiver:
            if operands.receiver is None:
                raise ValueError("sink requires a receiver for a static invocation")
            labels = labels | operands.receiver.labels
        for index in sink.sensitive_arguments:
            labels = labels | operands.arguments[index].labels
        if labels != TaintSet.bottom():
            findings.append(
                TaintFinding(
                    sink=sink.method,
                    call_site=pc,
                    labels=labels,
                    category=sink.category,
                    call_graph_distance=call_graph_distance,
                )
            )
    return tuple(findings)
