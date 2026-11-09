import random
from itertools import islice, product
import jpamb
import jvm
from settings import (
    SYSTEMATIC_TRIALS, 
    INTERESTING_INTS, 
    INTERESTING_INT_ARRAYS, 
    INTERESTING_CHAR_ARRAYS, 
    INTERESTING_FLOATS,
    LOWERCASE, 
    MAX_PARAM_COMBINATIONS, 
    PARAM_SEPARATOR, 
    SERIAL_PREFIX, 
    SERIAL_SEPARATOR, 
    JVM_INTS,
    JVM_BOOLS,
    JVM_FLOATS,
    JVM_CHARS,
    JVM_STRINGS
)

def is_string(param: jvm.Type) -> bool:
    return isinstance(param, jvm.Object) and param.name == jvm.ClassName('java.lang.String')

def fuzz_values(rand: random.Random, methodid: jvm.AbsMethodID, trial: int, string_pool: list[str]) -> tuple[list, dict[int, str]]:
    values = []
    strings: dict[int, str] = {}
    string_position = 0
    int_position = 0     # rank among int params: the index must not depend on the absolute position,
    bool_position = 0    # otherwise params in high positions get the same value for every small trial
    if not string_pool:
        string_pool = ['', '__CANARY__']
    for (position, param) in enumerate(methodid.extension.params):
        match param:
            case _ if is_string(param):
                index = trial // len(string_pool) ** string_position % len(string_pool)
                value = string_pool[index]
                values.append(jpamb.case.String(value))
                strings[position] = value
                string_position += 1 # ensures all string combinations for multiple string parameters
            case jvm.Int():
                if trial < SYSTEMATIC_TRIALS:
                    index = trial // len(INTERESTING_INTS) ** int_position % len(INTERESTING_INTS)
                    value = INTERESTING_INTS[index]
                else:
                    value = rand.randint(-(1 << 31), (1 << 31) - 1)
                values.append(jpamb.case.Int(value))
                int_position += 1
            case jvm.Boolean():
                values.append(jpamb.case.Boolean(bool(trial // 2 ** bool_position % 2)))
                bool_position += 1
            case jvm.Array(contains=jvm.Int()):
                if trial < SYSTEMATIC_TRIALS:
                    array = INTERESTING_INT_ARRAYS[trial % len(INTERESTING_INT_ARRAYS)]
                else:
                    length = rand.randint(0, 6)
                    array = [rand.choice(INTERESTING_INTS) for _ in range(length)]
                values.append(jpamb.case.Array(jvm.Int(), array))
            case jvm.Array(contains=jvm.Char()):
                if trial < SYSTEMATIC_TRIALS:
                    chars = INTERESTING_CHAR_ARRAYS[trial % len(INTERESTING_CHAR_ARRAYS)]
                else:
                    length = rand.randint(0, 8)
                    chars = ''.join((rand.choice(LOWERCASE) for _ in range(length)))
                values.append(jpamb.case.Array(jvm.Char(), chars))
            case _:
                raise NotImplementedError(f'Unsupported input type: {param!r}')
    return (values, strings)

def parse_descriptor(descriptor: str) -> list[str]:
    """Parameter types of a JVM descriptor: "(ILjava/lang/String;)V" -> ["I", "Ljava/lang/String;"]."""
    params = descriptor[descriptor.index('(') + 1:descriptor.index(')')]
    types = []
    i = 0
    while i < len(params):
        j = i
        while params[j] == '[':
            j += 1
        if params[j] == 'L':
            j = params.index(';', j)
        types.append(params[i:j + 1])
        i = j + 1
    return types

def generate_object_params(param_types: list[str]) -> list[str]:
    """Serialized `params` field for a constructor, from interesting values per type."""
    if not param_types:
        return ['']
    options = []
    for t in param_types:
        if t in JVM_INTS:
            options.append([str(v) for v in INTERESTING_INTS])
        elif t in JVM_BOOLS:
            options.append(['true', 'false'])
        elif t in JVM_FLOATS:
            options.append([str(v) for v in INTERESTING_FLOATS])
        elif t in JVM_CHARS:
            options.append([ch for ch in LOWERCASE])
        elif t in JVM_STRINGS:
            options.append(INTERESTING_CHAR_ARRAYS)
        else:
            options.append([''])
    combinations = islice(product(*options), MAX_PARAM_COMBINATIONS) # generate at most MAX_PARAM_COMBINATIONS combinations 
    return [PARAM_SEPARATOR.join(c) for c in combinations]

def dynamic_payloads(call_graph_data: dict) -> list[str]:
    ''' Generates either a serialized payload or a class name'''
    names = []
    for edge in call_graph_data.get('dynamic_edges', []):
        kind = edge.get('kind')
        callee = edge.get('callee', '')
        if not callee:
            continue
        (method_part, rest) = callee.split(':(', 1)
        full_class_name = method_part.rsplit('.', 1)[0]
        short_class_name = full_class_name.split('$')[-1].split('.')[-1]
        if kind == 'reflection':
            names.append(short_class_name)
        elif kind == 'deserialization':
            param_types = parse_descriptor('(' + rest)
            for params in generate_object_params(param_types):
                payload = f'{SERIAL_PREFIX}{SERIAL_SEPARATOR}{short_class_name}{SERIAL_SEPARATOR}{params}'
                names.append(payload)
    return list(dict.fromkeys(names))

def generate_parameter(operation: str, strings: list[str], base_payload: str) -> list[str]:
    ''' Generate strings to break comparisons based on the operation and the strings used in the method. '''
    generated = []
    if operation == 'concatenation':
        stripped_payload = base_payload
        for s in strings: #replace all occurrences of the strings in the base payload with empty string
            if isinstance(s, str):
                stripped_payload = stripped_payload.replace(s, '')
        generated.append(stripped_payload)

        for s in strings: #replace occurrences of the strings in the base payload with empty string one by one
            if isinstance(s, str):
                generated.append(base_payload.replace(s, ''))

    else:
        for s in strings:
            if not isinstance(s, str):
                continue
            if operation == 'equals':
                generated.append(s)
                generated.append('')
            elif operation == 'equalsIgnoreCase':
                generated.append(s.lower())
                generated.append(s.upper())
                generated.append('')
            elif operation == 'startsWith' or operation == 'contains':
                generated.append(s + base_payload)
                generated.append(base_payload)
                generated.append(base_payload.replace(s, ''))
            elif operation == 'endsWith':
                generated.append(base_payload + s)
                generated.append(base_payload)
                generated.append(base_payload.replace(s, ''))
    return generated