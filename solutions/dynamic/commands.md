# Compile edited analysis
```bash
uv pip install $(for d in solutions/*/; do echo "-e $d"; done)
```

# Build
## New test cases
```bash
uv run jpamb build
```
## Add new test cases to benchmark
```bash
uv run jpamb build --benchmark dynamic-interpreter
```

# Run fuzzer
## Global
```bash
rm -f witnesses.txt
FUZZER_MODE=graph JPAMB_WITNESS_PATH=witnesses.txt jpamb -vv analyse stepwise-analysis -f jpamb.cases.advanced -N 1 --timeout 20
```
## Per function
```bash
FUZZER_MODE=graph jpamb -vv analyse stepwise-analysis -f post_reflection_chain -N 1 --timeout 20
```

# Run taint analysis
```bash
jpamb -vv analyse taint-analysis -f jpamb.cases.advanced.CWE502_Graph -N 1
```

# Automatic test generation
## Taint: one JSON report per method in witnesses.txt (optional, adds the verdict to the tests)
```bash
mkdir -p reports
cut -d' ' -f1 witnesses.txt | sort -u | while read m; do taint-analysis "$m" > "reports/$(echo "$m" | cut -d: -f1).json"; done
```

## Generate the Java test class
```bash
python solutions/dynamic/src/synthesis.py witnesses.txt reports/*.json > SynthesizedTests.java
```

## Compile and run the tests (needs uv run jpamb build for target/classes)
```bash
javac -cp target/classes -d target/synthesized SynthesizedTests.java
java -cp target/classes:target/synthesized SynthesizedTests
```
## Same thing on the jpamb build JDK, via docker:
```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/workspace" -w /workspace ghcr.io/kalhauge/jvm2json:jdk-latest sh -c "javac -cp target/classes -d target/synthesized SynthesizedTests.java && java -cp target/classes:target/synthesized SynthesizedTests"
```

# Fuzzer benchmark (results/)
Runs every @Case method of the CWE files in jpamb.cases.advanced, ITERATIONS times per method.
Hyperparameters (ITERATIONS, TIMEOUT, WORKERS, CLASSES) are constants at the top of the script;
MAX_TESTS / MAX_STEPS are in solutions/dynamic/src/stepwise_dynamic.py.
Output: results/<mode>/ (one .md per file, SUMMARY.md, raw.json) + results/comparison.md
## One configuration
```bash
python3 results/run_fuzzer_benchmark.py naive        # or: dictionary | graph | taint (full)
```
## All configurations
```bash
for m in naive dictionary graph taint; do python3 results/run_fuzzer_benchmark.py $m; done
```

# Compare two configurations on one method (results/compare_configs.py)
Runs the method --trials times (default 5) for each configuration and prints the median (and standard deviation) of the number of
inputs generated before the first assertion error (runs that never find it are excluded from the median).
The signature can be omitted if the method name is unique in its class.
```bash
python3 results/compare_configs.py jpamb.cases.advanced.CWE502_Graph.multiple_checks naive graph
python3 results/compare_configs.py "jpamb.cases.advanced.CWE502_Graph.multiple_checks:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V" graph taint --trials 5 --timeout 20
```
