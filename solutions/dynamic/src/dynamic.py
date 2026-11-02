import random
import sys
import subprocess
import json

import jpamb
import jvm
import jvm.state as jvmc

from itertools import permutations, combinations

def _debug_log(*args, **kwargs):
    with open("debug.log", "a", encoding="utf-8") as f:
        print(*args, file=f, **kwargs)

def binary(op, v1: int, v2: int) -> int | str:
    match op:
        case jvm.BinaryOpr.Div:
            try:
                return v1 // v2
            except ZeroDivisionError:
                return "divide by zero"
        case a:
            raise NotImplementedError(f"Unhandled binary {op!r}")


def compare(op, v1: int, v2: int) -> bool:
    match op:
        case jvm.CmpOpr.Eq:
            return v1 == v2
        case _:
            raise NotImplementedError(f"Unhandled comparation {op!r}")


def step(bc: jpamb.Bytecode, state: jvmc.State) -> tuple[jvmc.PC, jvmc.State | str]:
    assert isinstance(state, jvmc.State), f"expected state but got {state}"
    frame = state.frames.peek()
    pc = frame.pc
    opr = bc[pc]
    output = state
    print(f"Stepping {pc}:\n > {opr}", file=sys.stderr)
    match opr:
        case jvm.Push(type=t, value=v):
            if t is jvm.Int():
                frame.stack.push(jvmc.StackInt(v))
            else:
                raise NotImplementedError("Error")
            frame.pc += 1

        case jvm.Binary(type=jvm.Int(), operant=op):
            v2, v1 = frame.stack.pop(), frame.stack.pop()
            assert isinstance(v1, jvmc.StackInt), f"expected int, but got {v1}"
            assert isinstance(v2, jvmc.StackInt), f"expected int, but got {v2}"

            value = binary(op, v1.value, v2.value)

            if isinstance(value, str):
                output = value
            else:
                frame.stack.push(jvmc.StackInt(value))
                frame.pc += 1

        case jvm.Return(type=t):
            if t is not None:
                raise NotImplementedError("Still to be done")

            state.frames.pop()

            if state.frames:
                raise NotImplementedError("Still to be done")
            else:
                output = "ok"

        case jvm.Get(static=True, field=field):
            # Hack - Only handle the assertion case
            assert field.extension.name == "$assertionsDisabled"

            # Hack - Assuming assertions are never disabled
            frame.stack.push(jvmc.StackInt(0))
            frame.pc += 1

        case jvm.New(classname=jvm.ClassName("java.lang.AssertionError")):
            # Hack -- if we create an assertion error, we probably also throw it.
            output = "assertion error"

        case jvm.New(classname=c):
            obj = jvmc.HeapObject(classname=c, fields={})
            ref = state.heap.new(obj)
            frame.stack.push(ref)
            frame.pc += 1

        case jvm.ArrayStore(type=t):
            val, index, ref = frame.stack.pop(), frame.stack.pop(), frame.stack.pop()

            if ref.value == 0:
                output = "null pointer"
            else:
                arr = state.heap[ref]
                if index.value < 0 or index.value >= len(arr.values):
                    output = "out of bounds"
                else:
                    arr.values[index.value] = val.value
                    frame.pc += 1

        case jvm.Store(type=t, index=i):
            val = frame.stack.pop()
            frame.locals.locals[i] = val
            frame.pc += 1

        case jvm.ArrayLength():
            arr_ref = frame.stack.pop()

            if arr_ref.value == 0:
                output = "null pointer"
            else:
                arr = state.heap[arr_ref]

                length_value = len(arr.values)
                frame.stack.push(jvmc.StackInt(length_value))

                frame.pc += 1

        case jvm.InvokeVirtual(method=m) if m.classname == jvm.ClassName("java.lang.Class") and m.extension.name == "newInstance":
            class_ref = frame.stack.pop()
            class_obj = state.heap[class_ref]
            target_class_name = class_obj.fields["target_class"]
            
            target_class = jvm.ClassName(target_class_name)  
                      
            new_instance = jvmc.HeapObject(classname=target_class, fields={})
            ref = state.heap.new(new_instance)
            
            frame.stack.push(ref)
            frame.pc += 1
            
            init_methodid = jvm.AbsMethodID(
                classname=target_class,
                extension=jvm.MethodID(
                    name="<init>",
                    params=jvm.Parameters(()),
                    return_type=None
                )
            )
            
            loc = [ref] + [None] * 14
            
            new_pc = jvmc.PC(init_methodid, 0)
            new_locals = jvmc.Locals(loc)
            new_stack = jvmc.OperandStack([])
            new_frame = jvmc.Frame(new_locals, new_stack, new_pc)
            
            state.frames = state.frames.push(new_frame)

        case jvm.InvokeVirtual(method=m) if m.classname == jvm.ClassName(
            "java.lang.String"
        ):
            name = m.extension.name
            if name not in STRING_METHODS:
                raise NotImplementedError(f"String.{name} is not supported")

            # Pop the arguments (the last one is on top), then the receiver
            args = [frame.stack.pop() for _ in m.extension.params][::-1]
            this = frame.stack.pop()
            values = [from_stack(state.heap, v) for v in args]

            if this.value == 0 or (name not in NULL_SAFE_STRING_METHODS and None in values):
                output = "null pointer"
            else:
                try:
                    result = STRING_METHODS[name](state.heap[this].content, *values)
                except IndexError:
                    output = "out of bounds"
                else:
                    frame.stack.push(to_stack(state.heap, m.extension.return_type, result))
                    frame.pc += 1

        case jvm.InvokeVirtual(method=m):
            # General InvokeVirtual handling (simplified)
            len_params = len(m.methodid.params)
            
            args = []
            for _ in range(len_params):
                args.insert(0, frame.stack.pop())
            
            this_ref = frame.stack.pop()

            loc = [this_ref] + args
            loc = loc + [None] * (15 - len(loc))

            new_pc = jvmc.PC(m, 0)
            new_locals = jvmc.Locals(loc)
            new_stack = jvmc.OperandStack([])
            new_frame = jvmc.Frame(new_locals, new_stack, new_pc)
            
            state.frames = state.frames.push(new_frame)

        case jvm.InvokeStatic(method=m) if m.classname == jvm.ClassName("java.lang.Class") and m.extension.name == "forName":
            name_ref = frame.stack.pop()
            class_name = state.heap[name_ref].content

            try:
                bc.suite.findclass(jvm.ClassName(class_name), eff=bc.eff)
            except (FileNotFoundError, KeyError):
                output = "ok" # we assume normal exception handled by the program
                return pc, output
            
            class_obj = jvmc.HeapObject(classname=jvm.ClassName("java.lang.Class"), fields={"target_class": class_name})
            ref = state.heap.new(class_obj)
            
            frame.stack.push(ref)
            frame.pc += 1

        case jvm.InvokeStatic(method=m) if (
            m.classname,
            m.extension.name,
        ) in STATIC_METHODS:
            args = [frame.stack.pop() for _ in m.extension.params][::-1]
            values = [from_stack(state.heap, v) for v in args]
            try:
                result = STATIC_METHODS[(m.classname, m.extension.name)](*values)
            except ValueError as e:
                # A Java exception that is not one of the JPAMB outcomes
                raise NotImplementedError(f"Exceptions are not supported yet: {e}") from e
            frame.stack.push(to_stack(state.heap, m.extension.return_type, result))
            frame.pc += 1

        case jvm.InvokeStatic(method=m):
            assert (isinstance(m, jvm.AbsMethodID), f"expected method id but got {m}")
            len_params = len(m.methodid.params)

            print(f"param length: {len_params}", file=sys.stderr)
            args = []
            for _ in range(len_params):
                args.insert(0, frame.stack.pop())

            loc = args + [None] * (15 - len(args))

            new_pc = jvmc.PC(m, 0)
            new_locals = jvmc.Locals(loc)
            new_stack = jvmc.OperandStack([])
            new_frame = jvmc.Frame(new_locals, new_stack, new_pc)
            state.frames = state.frames.push(new_frame)

        case jvm.InvokeSpecial(method=m) if (m.classname, m.extension.name) in SPECIAL_METHODS:
            args = [frame.stack.pop() for _ in m.extension.params][::-1]
            
            this_ref = frame.stack.pop()
            
            SPECIAL_METHODS[(m.classname, m.extension.name)](this_ref, *args)
            
            frame.pc += 1

        case jvm.InvokeSpecial(method=m):
            len_params = len(m.methodid.params)
            
            args = []
            for _ in range(len_params):
                args.insert(0, frame.stack.pop())
            
            this_ref = frame.stack.pop()

            loc = [this_ref] + args
            loc = loc + [None] * (15 - len(loc))

            new_pc = jvmc.PC(m, 0)
            new_locals = jvmc.Locals(loc)
            new_stack = jvmc.OperandStack([])
            new_frame = jvmc.Frame(new_locals, new_stack, new_pc)
            
            state.frames = state.frames.push(new_frame)

        case jvm.InvokeDynamic(index=i, method=m) if (
            m.extension.name == "makeConcatWithConstants"
        ):
            # The recipe has one \u0001 for each dynamic argument and one
            # \u0002 for each extra constant of the bootstrap method
            recipe, *constants = bootstrap_args(bc, pc.method.classname, i)
            params = list(m.extension.params)
            # The last argument is on top of the stack
            args = [frame.stack.pop() for _ in params][::-1]
            parts = iter(java_to_string(state.heap, t, v) for t, v in zip(params, args))
            extra = iter(c["value"] for c in constants)

            result = ""
            for char in recipe["value"]:
                if char == "\u0001":
                    result += next(parts)
                elif char == "\u0002":
                    result += str(next(extra))
                else:
                    result += char

            frame.stack.push(state.heap.new(jvmc.HeapString(result)))
            frame.pc += 1

        case jvm.Cast(from_=jvm.Int(), to_=jvm.Short()):
            # Pop the integer from the operand stack
            value = frame.stack.pop()
            # Convert to a signed 16-bit Java short
            short_value = (value.value + (1 << 15)) % (1 << 16) - (1 << 15)
            # JVM stores short results as integer stack values
            frame.stack.push(jvmc.StackInt(short_value))
            frame.pc += 1

        case jvm.CheckCast(type=t):
            ref = frame.stack.pop()
            frame.stack.push(ref)
            frame.pc += 1

        case a:
            raise NotImplementedError(a.help())

    assert isinstance(output, (jvmc.State, str))

    return pc, output


def initial(bc: jpamb.Bytecode, methodid: jvm.AbsMethodID, input: jpamb.Input):
    frame = jvmc.Frame.from_method(bc.getmethod(methodid))
    state = jvmc.State(jvmc.Heap(), jvmc.CallStack.from_frames([frame]))
    for i, v in enumerate(input.values):
        # Convert arbitrary values into local values
        match v:
            case jpamb.case.Boolean(value):
                frame.locals[i] = jvmc.StackInt(1 if value else 0)
            case jpamb.case.Int(value):
                frame.locals[i] = jvmc.StackInt(value)
            case jpamb.case.Array(contains=type, values=values):
                match type:
                    case jvm.Char():
                        ref = state.heap.new(
                            jvmc.HeapArray(type, [ord(a) for a in values])
                        )
                    case jvm.Int():
                        ref = state.heap.new(jvmc.HeapArray(type, [a for a in values]))
                frame.locals[i] = ref
            case jpamb.case.String(value=value):
                ref = state.heap.new(jvmc.HeapString(value))
                frame.locals[i] = ref
            case a:
                raise NotImplementedError(
                    f"Do not know how to convert values of type {a!r} to a local value"
                )

    return state


def interpret():
    """The entry point for the interpreter"""

    methodid, input, max_steps = jpamb.getcase(
        "dynamic",
        "1.0",
        "The Rice Theorem Cookers",
        ["dynamic", "python"],
        for_science=True,
    )

    suite, eff = jpamb.setup()
    bc = jpamb.Bytecode(suite, eff, {})

    state = initial(bc, methodid, input)

    last = jpamb.emit_init(state)

    for x in range(max_steps):
        pc, state = step(bc, state)
        last = jpamb.emit_step(last, pc, state)

        if isinstance(state, str):
            break


# ============================================================
# STRING-ONLY FUZZING
# Taint analysis on strings: only String parameters are tainted,
# so only they are fuzzed. Every other type gets a fixed value.
# ============================================================

FIXED_INT = 1
FIXED_BOOLEAN = False

def is_string(param: jvm.Type) -> bool:
    return isinstance(param, jvm.Object) and param.name == jvm.ClassName(
        "java.lang.String"
    )

def fixed_value(param: jvm.Type):
    """The constant used for every parameter that is not a (tainted) string."""
    match param:
        case jvm.Int():
            return jpamb.case.Int(FIXED_INT)
        case jvm.Boolean():
            return jpamb.case.Boolean(FIXED_BOOLEAN)
        case jvm.Array(contains=jvm.Int()):
            return jpamb.case.Array(jvm.Int(), [FIXED_INT])
        case jvm.Array(contains=jvm.Char()):
            return jpamb.case.Array(jvm.Char(), "a")
        case _:
            raise NotImplementedError(f"Unsupported input type: {param!r}")

def fuzz_input(
    rand: random.Random,
    methodid: jvm.AbsMethodID,
    trial: int,
    string_pool: list[str],
    max_distance_value: int
) -> jpamb.case.Input:
    values = []
    string_position = 0 
    
    if not string_pool:
        string_pool = ["", "__CANARY__"]
        
    for param in methodid.extension.params:
        if not is_string(param):
            values.append(fixed_value(param))
            continue

        index = (trial // (len(string_pool) ** string_position)) % len(string_pool)
        value = string_pool[index]

        values.append(jpamb.case.String(value))
        string_position += 1

    return jpamb.case.Input(values)

def run(bc, methodid, test_input, max_steps: int) -> str | None:
    """Execute one input. Returns the outcome, or None if it did not finish."""
    state = initial(bc, methodid, test_input)
    for _ in range(max_steps):
        pc, state = step(bc, state)

        if isinstance(state, str):
            return state

        # Unconditional jump to itself: infinite loop
        if isinstance(bc[pc], jvm.Goto) and state.frames.peek().pc.offset == pc.offset:
            return "*"
    return None

def build_call_graph(methodid: jvm.AbsMethodID) -> dict | None:
    """Run solutions/syntactic/src/call_graph.py on the method and parse its JSON."""
    result = subprocess.run(
        ["uv", "run", "python", "solutions/syntactic/src/call_graph.py", str(methodid)],
        capture_output=True,  # keeps stdout clean for the analyser's own output
        text=True,
    )
    if result.returncode != 0:
        return None  # unknown method, missing target/decompiled, ...
    return json.loads(result.stdout)

def build_dictionary(methodid: jvm.AbsMethodID) -> list[dict]:
    """Run solutions/syntactic/src/string_dictionary.py on the method and parse its JSON."""
    result = subprocess.run(
        ["uv", "run", "python", "solutions/syntactic/src/string_dictionary.py", str(methodid)],
        capture_output=True,  # keeps stdout clean for the analyser's own output
        text=True,
    )
    if result.returncode != 0:
        return []
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

def max_distance(start_method: str, call_graph_data: dict) -> int:
    graph = call_graph_data.get("graph", {})
    sinks = set(call_graph_data.get("sinks", []))
    
    if start_method not in graph:
        return -1

    def dfs(node, path_visited):
        if node in path_visited:
            return -1
            
        path_visited.add(node)
        
        max_d = 0 if node in sinks else -1
        
        for callee in graph.get(node, []):
            dist = dfs(callee, path_visited)
            
            if dist != -1:
                max_d = max(max_d, dist + 1)
                
        path_visited.remove(node)
        
        return max_d

    return dfs(start_method, set())

def generate_parameter(operation: str, strings: list[str], base_payload: str) -> list[str]:
    generated = []
    
    if operation == "concatenation":
        stripped_payload = base_payload
        for s in strings:
            if isinstance(s, str):
                stripped_payload = stripped_payload.replace(s, "")
        generated.append(stripped_payload)
        
        for s in strings:
            if isinstance(s, str):
                generated.append(base_payload.replace(s, ""))
                
    else:
        for s in strings:
            if not isinstance(s, str):
                continue
                
            if operation == "equals":
                generated.append(s)
                generated.append("")
                
            elif operation == "equalsIgnoreCase":
                generated.append(s.lower())
                generated.append(s.upper())
                
            elif operation == "startsWith" or operation == "contains":
                generated.append(s + base_payload)
                generated.append(base_payload)
                
            elif operation == "endsWith":
                generated.append(base_payload + s)
                generated.append(base_payload)
            
    return generated

def analyse():
    """Dynamic analysis: fuzz the string parameters, keep the rest fixed."""

    methodid = jpamb.getmethodid(
        "dynamic",
        "1.0",
        "bests analyzers ",
        ["dynamic", "python", "fuzzing", "random", "dictionary", "syntatic"],
        for_science=True,
    )

    suite, eff = jpamb.setup()
    bc = jpamb.Bytecode(suite, eff, {})

    call_graph_data = build_call_graph(methodid)
    all_methods = set()
    
    if call_graph_data and "graph" in call_graph_data:
        all_methods.update(call_graph_data["graph"].keys())
    else:
        all_methods.add(str(methodid))

    merged_dictionaries = []
    for m in all_methods:
        method_dicts = build_dictionary(m)
        for entry in method_dicts:
            if entry not in merged_dictionaries:
                merged_dictionaries.append(entry)

    max_steps_to_sink = max_distance(str(methodid), call_graph_data) if call_graph_data else -1

    base_payloads = []
    if call_graph_data and "dynamic_edges" in call_graph_data:
        for edge in call_graph_data["dynamic_edges"]:
            if edge.get("kind") == "reflection":
                callee = edge.get("callee", "")
                if callee:
                    class_name = callee.split(":")[0].rsplit(".", 1)[0]
                    base_payloads.append(class_name)

    raw_string_pool = []
    
    for base_payload in base_payloads:
        for entry in merged_dictionaries:
            operation = entry.get("method")
            strings = entry.get("strings", [])
            
            if operation and strings:
                mutations = generate_parameter(operation, strings, base_payload)
                raw_string_pool.extend(mutations)

    string_pool = list(dict.fromkeys(raw_string_pool))

    MAX_STEPS = 200  # instructions per input
    MAX_TESTS = 100  # different inputs to try
    rand = random.Random(0)  # deterministic

    has_tainted = any(is_string(p) for p in methodid.extension.params)

    n_trials = MAX_TESTS if has_tainted else 1

    behaviors = set()

    for trial in range(n_trials):
        test_input = fuzz_input(rand, methodid, trial, string_pool, max_steps_to_sink)
        outcome = run(bc, methodid, test_input, MAX_STEPS)

        if outcome is not None:
            behaviors.add(outcome)
        elif not has_tainted:
            behaviors.add("*")

    for query in jpamb.QUERIES:
        print(f"{query};{'found' if query in behaviors else 'not-found'}")
