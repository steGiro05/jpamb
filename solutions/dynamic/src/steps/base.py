import random

from enum import Enum
from dataclasses import dataclass
from typing import List, Tuple

def _debug_log(*args, **kwargs):
    with open('debug.log', 'a', encoding='utf-8') as f:
        print(*args, file=f, **kwargs)

class OutOfBudget(Exception):
    """Raised when the global cap on interpreter runs is reached."""


# --- DATACLASSES and ENUMS---
class VulnFamily(Enum):
    CWE470 = "CWE470"
    CWE502 = "CWE502"

@dataclass
class ClassInfo:
    shortname: str
    params: List[Tuple[int, str]]  # (order, type_string)

class Fuzzer:
    def __init__(self, rand: random.Random, methodid, bc, suite):
        self.rand = rand
        self.methodid = methodid
        self.bc = bc
        self.suite = suite

    def generate_values(self, trial: int) -> list:
        raise NotImplementedError("Subclasses must implement this method")