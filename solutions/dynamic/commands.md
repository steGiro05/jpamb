# Compile edited analysis
uv pip install --editable solutions/*

# Build
## New test cases
uv run jpamb build
## Add new test cases to benchmark
uv run jpamb build --benchmark dynamic-interpreter

# Run fuzzer on a particular function
FUZZER_MODE=graph JPAMB_WITNESS_PATH=witnesses.txt jpamb -vv analyse stepwise-analysis -f post_reflection_chain -N 1 --timeout 20

# Run taint analysis
jpamb -vv analyse taint-analysis -f jpamb.cases.advanced.CWE502_Graph -N 1
