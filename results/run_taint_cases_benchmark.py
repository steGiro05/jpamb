"""Benchmark every fuzzer configuration on the vulnerable methods of taint_cases.java.

Usage:
    python3 results/run_taint_cases_benchmark.py [mode ...]   (default: all modes)

taint_cases mixes CWE-502 and CWE-470, so the non-taint fuzzers (which infer the
vulnerability from the file name) get it via FUZZER_VULN; the taint configuration
gets nothing and detects it on its own. Methods without an expected assertion
error (deser_sanitized, reflect_sanitized) are skipped.
Hyperparameters (ITERATIONS, TIMEOUT, WORKERS) come from run_fuzzer_benchmark.py.

Output: results/taint_cases/<mode>.json (raw runs) and results/taint_cases/SUMMARY.md
"""
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_fuzzer_benchmark as rb

CLS = "taint_cases"
VULN = {  # method -> CWE the non-taint fuzzers are told to target
    "deser_import": "CWE502", "deser_gadget": "CWE502",
    "reflect_command": "CWE470", "reflect_filtered": "CWE470",
}
OUT = rb.RESULTS / "taint_cases"


def name(mid):
    return mid.split(".")[-1].split(":")[0]


def run_mode(mode, mids):
    jobs = [(mid, i) for mid in mids for i in range(rb.ITERATIONS)]
    extra = lambda mid: {} if mode == "taint" else {"FUZZER_VULN": VULN[name(mid)]}
    with ThreadPoolExecutor(rb.WORKERS) as ex:
        res = list(ex.map(lambda j: rb.run_one(mode, j[0], extra(j[0])), jobs))
    return {f"{mid}#{i}": r for (mid, i), r in zip(jobs, res)}


def main():
    modes = sys.argv[1:] or rb.MODES
    mids = [m for m in rb.case_methods(CLS) if rb.expects_error(CLS, name(m))]
    assert sorted(map(name, mids)) == sorted(VULN), mids
    OUT.mkdir(exist_ok=True)
    for mode in modes:
        print(f"[{mode}] running {len(mids)} methods x {rb.ITERATIONS}...", flush=True)
        json.dump(run_mode(mode, mids), open(OUT / f"{mode}.json", "w"), indent=1)

    rows = [f"# taint_cases ({rb.ITERATIONS} trial, timeout={rb.TIMEOUT}s, "
            f"MAX_TESTS={rb.fuzzer_constant('MAX_TESTS')}, MAX_STEPS={rb.fuzzer_constant('MAX_STEPS')})", "",
            "| config | % ritrovamenti | hit rate per metodo | timeout totali | trial mediano (per metodo) |",
            "|---|---|---|---|---|"]
    for mode in rb.MODES:
        f = OUT / f"{mode}.json"
        if not f.exists():
            continue
        raw = json.load(open(f))
        runs = list(raw.values())
        found = sum(r["found"] for r in runs)
        per = {}
        for k, r in raw.items():
            per.setdefault(name(k.split("#")[0]), []).append(r)
        hit = ", ".join(f"{m} {sum(r['found'] for r in rs)}/{len(rs)}" for m, rs in per.items())
        med = ", ".join(f"{m} {rb.fmt(sorted(t)[len(t) // 2]) if (t := [r['trial'] for r in rs if r['trial'] is not None]) else '–'}"
                        for m, rs in per.items())
        rows.append(f"| {mode} | {100 * found / len(runs):.0f}% ({found}/{len(runs)}) | {hit} | "
                    f"{sum(r['timed_out'] for r in runs)}/{len(runs)} | {med} |")
    (OUT / "SUMMARY.md").write_text("\n".join(rows) + "\n")
    print("\n".join(rows))


if __name__ == "__main__":
    main()
