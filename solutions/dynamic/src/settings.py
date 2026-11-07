SYSTEMATIC_TRIALS = 80
NODE_ATTEMPTS = 30
MAX_PARAM_COMBINATIONS = 12

# Interesting values for fuzzing, based on common edge cases and typical values used in testing.
LOWERCASE = 'abcdefghijklmnopqrstuvwxyz'
INTERESTING_INTS = [0, 1, -1, 2, -2, 3, -3, 5, -5, 10, -10, 42, -42, 100, -100, 10054202, 10054203, 10054204, -10054202, -10054203, -10054204, 2147483647, -2147483648]
INTERESTING_FLOATS = [0.0, 1.0, -1.0, 2.0, -2.0, 3.0, -3.0, 5.0, -5.0, 10.0, -10.0, 42.0, -42.0, 100.0, -100.0]
INTERESTING_INT_ARRAYS = [[], [0], [1], [-1], [0, 0], [1, 2, 3], [-1, 0, 1], [42], [100]]
INTERESTING_CHAR_ARRAYS = ['', 'a', 'x', 'hello', 'Hello', 'test']

# Parameter parsing
JVM_INTS = ('I', 'J', 'S', 'B')
JVM_BOOLS = ('Z',)
JVM_FLOATS = ('F', 'D')
JVM_CHARS = ('C',)
JVM_STRINGS = ('Ljava/lang/String;',)

# Serialization constants 
SERIAL_PREFIX = 'SER'
SERIAL_SEPARATOR = '|'
PARAM_SEPARATOR = ','