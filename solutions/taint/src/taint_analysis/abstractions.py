"""Finite abstract domains used by the JPAMB taint analysis.

This module deliberately contains no bytecode transfer functions or fixpoint
algorithm.  It only defines the values and JVM-state components on which that
analysis will operate.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Self

import jvm
from jvm.state import PC


@dataclass(frozen=True, order=True, slots=True)
class SourceLabel:
    """The source associated with one parameter of the entry method."""

    parameter_index: int

    def __post_init__(self) -> None:
        if self.parameter_index < 0:
            raise ValueError("a source-label index cannot be negative")

    def __str__(self) -> str:
        return f"p{self.parameter_index}"


@dataclass(frozen=True, slots=True)
class TaintSet:
    """A finite set of entry-parameter dependencies.

    The order is subset inclusion, join is union, and meet is intersection.
    Top depends on the entry method and is therefore constructed from the
    complete label universe supplied by the analysis.
    """

    labels: frozenset[SourceLabel] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        labels = frozenset(self.labels)
        if not all(isinstance(label, SourceLabel) for label in labels):
            raise TypeError("taint labels must be SourceLabel values")
        object.__setattr__(self, "labels", labels)

    @classmethod
    def bottom(cls) -> Self:
        return cls()

    @classmethod
    def top(cls, universe: Iterable[SourceLabel]) -> Self:
        return cls(frozenset(universe))

    @classmethod
    def for_parameter(cls, parameter_index: int) -> Self:
        return cls(frozenset({SourceLabel(parameter_index)}))

    def __le__(self, other: object) -> bool:
        if not isinstance(other, TaintSet):
            return NotImplemented
        return self.labels <= other.labels

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, TaintSet):
            return NotImplemented
        return self.labels < other.labels

    def __or__(self, other: object) -> Self:
        if not isinstance(other, TaintSet):
            return NotImplemented
        return type(self)(self.labels | other.labels)

    def __and__(self, other: object) -> Self:
        if not isinstance(other, TaintSet):
            return NotImplemented
        return type(self)(self.labels & other.labels)

    def __str__(self) -> str:
        return "{" + ", ".join(map(str, sorted(self.labels))) + "}"


@dataclass(frozen=True, slots=True)
class AllocationSite:
    """An object allocated by a bytecode instruction in the analyzed program."""

    pc: PC


@dataclass(frozen=True, slots=True)
class ExternalTarget:
    """An object supplied through an entry-method parameter."""

    source: SourceLabel


@dataclass(frozen=True, slots=True)
class NullTarget:
    """The distinguished null reference target."""


NULL_TARGET = NullTarget()

type HeapTarget = AllocationSite | ExternalTarget
type ReferenceTarget = HeapTarget | NullTarget


@dataclass(frozen=True, slots=True)
class ReferenceTargets:
    """A finite may-points-to set.

    NULL_TARGET is an ordinary member of this set, so joins preserve the
    possibility of null rather than accidentally discarding it.
    """

    targets: frozenset[ReferenceTarget] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        targets = frozenset(self.targets)
        if not all(
            isinstance(target, AllocationSite | ExternalTarget | NullTarget)
            for target in targets
        ):
            raise TypeError("invalid abstract reference target")
        object.__setattr__(self, "targets", targets)

    @classmethod
    def null(cls) -> Self:
        return cls(frozenset({NULL_TARGET}))

    @classmethod
    def external(cls, parameter_index: int) -> Self:
        target = ExternalTarget(SourceLabel(parameter_index))
        return cls(frozenset({target}))

    @property
    def may_be_null(self) -> bool:
        return NULL_TARGET in self.targets

    @property
    def heap_targets(self) -> frozenset[HeapTarget]:
        return frozenset(
            target for target in self.targets if not isinstance(target, NullTarget)
        )

    def __le__(self, other: object) -> bool:
        if not isinstance(other, ReferenceTargets):
            return NotImplemented
        return self.targets <= other.targets

    def __or__(self, other: object) -> Self:
        if not isinstance(other, ReferenceTargets):
            return NotImplemented
        return type(self)(self.targets | other.targets)

    def __and__(self, other: object) -> Self:
        if not isinstance(other, ReferenceTargets):
            return NotImplemented
        return type(self)(self.targets & other.targets)


@dataclass(frozen=True, slots=True)
class TaintValue:
    """A taint value, optionally carrying reference targets.

    ``references is None`` denotes a non-reference JVM value.  A reference
    always has a ReferenceTargets value; null is represented explicitly by
    NULL_TARGET inside it.
    """

    labels: TaintSet = field(default_factory=TaintSet.bottom)
    references: ReferenceTargets | None = None

    @classmethod
    def untainted(cls) -> Self:
        return cls()

    @classmethod
    def parameter(cls, parameter_index: int) -> Self:
        return cls(labels=TaintSet.for_parameter(parameter_index))

    @classmethod
    def external_reference(cls, parameter_index: int) -> Self:
        return cls(
            labels=TaintSet.for_parameter(parameter_index),
            references=ReferenceTargets.external(parameter_index),
        )

    @classmethod
    def null_reference(cls) -> Self:
        return cls(references=ReferenceTargets.null())

    @classmethod
    def reference(
        cls,
        targets: Iterable[ReferenceTarget],
        labels: TaintSet | None = None,
    ) -> Self:
        return cls(
            labels=labels if labels is not None else TaintSet.bottom(),
            references=ReferenceTargets(frozenset(targets)),
        )

    @property
    def is_reference(self) -> bool:
        return self.references is not None

    def __le__(self, other: object) -> bool:
        if not isinstance(other, TaintValue):
            return NotImplemented
        self._require_same_kind(other)
        references_le = (
            True if self.references is None else self.references <= other.references
        )
        return self.labels <= other.labels and references_le

    def __or__(self, other: object) -> Self:
        if not isinstance(other, TaintValue):
            return NotImplemented
        self._require_same_kind(other)
        references = (
            None if self.references is None else self.references | other.references
        )
        return type(self)(self.labels | other.labels, references)

    def __and__(self, other: object) -> Self:
        if not isinstance(other, TaintValue):
            return NotImplemented
        self._require_same_kind(other)
        references = (
            None if self.references is None else self.references & other.references
        )
        return type(self)(self.labels & other.labels, references)

    def _require_same_kind(self, other: Self) -> None:
        if self.is_reference != other.is_reference:
            raise TypeError("cannot combine a reference and a non-reference value")


@dataclass(frozen=True, slots=True)
class FieldLocation:
    target: HeapTarget
    field: jvm.AbsFieldID


@dataclass(frozen=True, slots=True)
class ArrayContentsLocation:
    """The single abstract contents cell of one array allocation site."""

    target: HeapTarget


type HeapLocation = FieldLocation | ArrayContentsLocation


@dataclass(frozen=True, slots=True)
class TaintHeap:
    """An immutable map from abstract heap cells to taint values."""

    cells: Mapping[HeapLocation, TaintValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "cells", MappingProxyType(dict(self.cells)))

    def get(self, location: HeapLocation) -> TaintValue | None:
        return self.cells.get(location)

    def weak_store(self, location: HeapLocation, value: TaintValue) -> Self:
        """Join a value into a cell, preserving every previous possibility."""

        cells = dict(self.cells)
        previous = cells.get(location)
        cells[location] = value if previous is None else previous | value
        return type(self)(cells)

    def __le__(self, other: object) -> bool:
        if not isinstance(other, TaintHeap):
            return NotImplemented
        return all(
            location in other.cells and value <= other.cells[location]
            for location, value in self.cells.items()
        )

    def __or__(self, other: object) -> Self:
        if not isinstance(other, TaintHeap):
            return NotImplemented
        result = self
        for location, value in other.cells.items():
            result = result.weak_store(location, value)
        return result


def _join_optional_values(
    left: TaintValue | None, right: TaintValue | None
) -> TaintValue | None:
    if left is None:
        return right
    if right is None:
        return left
    return left | right


@dataclass(frozen=True, slots=True)
class TaintState:
    """The abstract locals, operand stack, and heap at one program point."""

    locals: tuple[TaintValue | None, ...]
    stack: tuple[TaintValue, ...] = ()
    heap: TaintHeap = field(default_factory=TaintHeap)

    def __or__(self, other: object) -> Self:
        if not isinstance(other, TaintState):
            return NotImplemented
        if len(self.locals) != len(other.locals):
            raise ValueError("cannot join states with different local counts")
        if len(self.stack) != len(other.stack):
            raise ValueError("cannot join states with different stack heights")

        return type(self)(
            locals=tuple(
                _join_optional_values(left, right)
                for left, right in zip(self.locals, other.locals, strict=True)
            ),
            stack=tuple(
                left | right
                for left, right in zip(self.stack, other.stack, strict=True)
            ),
            heap=self.heap | other.heap,
        )

    def __le__(self, other: object) -> bool:
        if not isinstance(other, TaintState):
            return NotImplemented
        if len(self.locals) != len(other.locals) or len(self.stack) != len(other.stack):
            return False

        locals_le = all(
            left is None or (right is not None and left <= right)
            for left, right in zip(self.locals, other.locals, strict=True)
        )
        stack_le = all(
            left <= right for left, right in zip(self.stack, other.stack, strict=True)
        )
        return locals_le and stack_le and self.heap <= other.heap

    def push(self, value: TaintValue) -> Self:
        return type(self)(self.locals, self.stack + (value,), self.heap)

    def pop(self, count: int = 1) -> tuple[tuple[TaintValue, ...], Self]:
        if count < 0:
            raise ValueError("pop count cannot be negative")
        if count > len(self.stack):
            raise IndexError("operand-stack underflow")
        if count == 0:
            return (), self
        values = self.stack[-count:]
        return values, type(self)(self.locals, self.stack[:-count], self.heap)

    def load(self, index: int) -> TaintValue:
        value = self.locals[index]
        if value is None:
            raise IndexError(f"local {index} has no value")
        return value

    def store(self, index: int, value: TaintValue) -> Self:
        locals_ = list(self.locals)
        locals_[index] = value
        return type(self)(tuple(locals_), self.stack, self.heap)
