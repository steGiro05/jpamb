"""Compare two fuzzer configurations on a single method.

Usage:
    python3 results/compare_configs.py <method> <modeA> <modeB> [--trials 5] [--timeout 20]

    method: full method id, e.g. jpamb.cases.advanced.CWE502_Graph.foo:(Ljava/lang/String;)V
            (the signature can be omitted if the name is unique in its class)
    modeA/modeB: naive | dictionary | graph | taint

For each configuration it runs `stepwise-analysis <method>` --trials times (in parallel,
each run in its own working directory, see run_fuzzer_benchmark.run_one) and prints the
median (and sample standard deviation) of the inputs generated before the first assertion error
(= index of the first failing trial + 1, read from debug.log).
Runs that never hit the assertion error are reported separately and excluded from the median.
"""
import argparse
import statistics
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_fuzzer_benchmark as bench  # noqa: E402


def resolve(method):
    if ":" in method:
        return method
    cls, name = method.rsplit(".", 1)
    matches = [m for m in bench.case_methods(cls.split(".")[-1])
               if m.split(":")[0] == method]
    if len(matches) != 1:
        sys.exit(f"cannot resolve {method!r} uniquely: {matches or 'no match'} — pass the full signature")
    return matches[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("method")
    ap.add_argument("mode_a", choices=bench.MODES)
    ap.add_argument("mode_b", choices=bench.MODES)
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--timeout", type=int, default=bench.TIMEOUT, help="seconds per run")
    args = ap.parse_args()

    bench.TIMEOUT = args.timeout
    mid = resolve(args.method)
    modes = [args.mode_a, args.mode_b]
    print(f"{mid}\n{args.trials} trials per configuration, timeout {args.timeout}s\n")

    with ThreadPoolExecutor(min(bench.WORKERS, 2 * args.trials)) as ex:
        futs = {m: [ex.submit(bench.run_one, m, mid) for _ in range(args.trials)] for m in modes}
        results = {m: [f.result() for f in fs] for m, fs in futs.items()}

    for label, m in zip("AB", modes):
        rs = results[m]
        inputs = [r["trial"] + 1 if r["trial"] is not None else None for r in rs]
        found = [n for n in inputs if n is not None]
        med = statistics.median(found) if found else None
        std = statistics.stdev(found) if len(found) > 1 else None
        print(f"[{label}] {m:<10} median inputs = {bench.fmt(med):>8}   "
              f"min = {bench.fmt(min(found) if found else None):>6}   max = {bench.fmt(max(found) if found else None):>6}   "
              f"std = {bench.fmt(std):>8}   "
              f"found {len(found)}/{len(rs)}   per run: {[bench.fmt(n) for n in inputs]}   "
              f"timeouts: {sum(r['timed_out'] for r in rs)}")
        for r in rs:
            if r["stderr_tail"]:
                print(f"    error: {r['stderr_tail'].strip()[-200:]}")


if __name__ == "__main__":
    main()
