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
