"""Benchmark the dynamic fuzzer on the jpamb.cases.advanced CWE cases.

Usage (from anywhere):
    python3 results/run_fuzzer_benchmark.py <mode>
    mode: naive | dictionary | graph | taint   (taint = full configuration)

For every case method it runs `stepwise-analysis <method>` ITERATIONS times with
FUZZER_MODE=<mode>, and records the first trial whose outcome is "assertion error"
(parsed from the fuzzer's debug.log). Each run uses its own working directory
(symlinks to the repo) so parallel runs do not share debug.log.

Output in results/<mode>/:
    <Class>.md   per-file report: vulnerabilities found + mean of the per-iteration medians
    SUMMARY.md   one line per file
    raw.json     raw result of every run
and results/comparison.md, rebuilt from all the mode folders present.

Note: the number of inputs per run (MAX_TESTS) and the interpreter steps per
execution (MAX_STEPS) are constants of the fuzzer itself, in
solutions/dynamic/src/stepwise_dynamic.py; they are read from there for the reports.
"""
import json
import os
import re
import statistics
import subprocess
import sys
import tempfile
import time
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# --- Hyperparameters -------------------------------------------------------
ITERATIONS = 5          # runs per method
TIMEOUT = 20            # seconds per run (same meaning as `jpamb analyse --timeout`)
WORKERS = 8             # runs executed in parallel
CLASSES = [             # files under cases/jpamb/cases/advanced/
    "CWE470", "CWE502",
    "CWE470_Naive", "CWE502_Naive",
    "CWE470_Dict", "CWE502_Dict",
    "CWE470_Graph", "CWE502_Graph",
]
MODES = ["naive", "dictionary", "graph", "taint"]
WORK_DIR = Path(__file__).resolve().parent / ".work"   # per-run working directories (removed after each run)
# ---------------------------------------------------------------------------

RESULTS = Path(__file__).resolve().parent
ROOT = RESULTS.parent
VENV_BIN = ROOT / ".venv/bin"
SKIP_LINKS = {"debug.log", "witnesses.txt", "out.json", "results"}
BASE_TYPES = {"int": "I", "boolean": "Z", "char": "C", "long": "J", "byte": "B",
              "short": "S", "float": "F", "double": "D"}


def fuzzer_constant(name):
    src = (ROOT / "solutions/dynamic/src/stepwise_dynamic.py").read_text()
    m = re.search(rf"{name}\s*=\s*(\d+)", src)
    return int(m.group(1)) if m else "?"


def descriptor(t):
    if t.get("kind") == "class":
        return f"L{t['name']};"
    if t.get("kind") == "array":
        return "[" + descriptor(t["type"])
    return BASE_TYPES[t["base"]]


def case_methods(cls):
    """Method ids of the @Case-annotated methods of a class (from the decompiled json)."""
    d = json.load(open(ROOT / f"target/decompiled/jpamb/cases/advanced/{cls}.json"))
    for m in d["methods"]:
        if not any(a["type"] in ("jpamb/utils/Case", "jpamb/utils/Cases") for a in m["annotations"]):
            continue
        ret = "V" if m["returns"]["type"] is None else descriptor(m["returns"]["type"])
        params = "".join(descriptor(p["type"]) for p in m["params"])
        yield f"jpamb.cases.advanced.{cls}.{m['name']}:({params}){ret}"


def expects_error(cls, name):
    """True if one of the method's @Case annotations expects an assertion error."""
    src = (ROOT / f"cases/jpamb/cases/advanced/{cls}.java").read_text()
    block = re.search(r"((?:\s*@Case\([^\n]*\)\s*)+)public static \w+ " + re.escape(name) + r"\(", src)
    return block is not None and "assertion error" in block.group(1)


def run_one(mode, mid, extra_env=None):
    WORK_DIR.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=WORK_DIR) as wd:
        for e in ROOT.iterdir():
            if e.name not in SKIP_LINKS:
                os.symlink(e, Path(wd) / e.name)
        env = dict(os.environ, FUZZER_MODE=mode, PATH=f"{VENV_BIN}:{os.environ['PATH']}")
        env.pop("JPAMB_WITNESS_PATH", None)
        env.update(extra_env or {})
        t0 = time.time()
        stderr = ""
        try:
            p = subprocess.run([str(VENV_BIN / "stepwise-analysis"), mid], cwd=wd, env=env,
                               capture_output=True, text=True, timeout=TIMEOUT)
            out, timed_out, rc, stderr = p.stdout, False, p.returncode, p.stderr
        except subprocess.TimeoutExpired as e:
            out = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
            timed_out, rc = True, None
        found = "assertion error;found" in out
        first = None
        log = Path(wd) / "debug.log"
        if log.exists():
            for line in log.read_text().splitlines():
                m = re.match(r"trial (\d+):", line)
                if m and "outcome=assertion error" in line:
                    first = int(m.group(1))
                    break
        if timed_out and first is not None:  # found before being killed
            found = True
        return dict(mid=mid, found=found, trial=first, timed_out=timed_out, rc=rc,
                    secs=round(time.time() - t0, 2),
                    stderr_tail=stderr[-300:] if rc not in (0, None) else "")


def fmt(x):
    return "–" if x is None else (f"{x:.1f}" if isinstance(x, float) else str(x))


def report(mode, jobs, res, out):
    header = (f"FUZZER_MODE={mode}, MAX_TESTS={fuzzer_constant('MAX_TESTS')}, "
              f"MAX_STEPS={fuzzer_constant('MAX_STEPS')}, timeout={TIMEOUT}s, {ITERATIONS} iterazioni")
    summary = []
    for cls in CLASSES:
        mids = [m for c, m in jobs if c == cls]
        vuln = [m for m in mids if expects_error(cls, m.split(".")[-1].split(":")[0])]
        runs = {m: [res[(cls, m, i)] for i in range(ITERATIONS)] for m in mids}
        always = [m for m in vuln if all(r["found"] for r in runs[m])]
        ever = [m for m in vuln if any(r["found"] for r in runs[m])]
        false_pos = [m for m in mids if m not in vuln and any(r["found"] for r in runs[m])]
        per_iter = []
        for i in range(ITERATIONS):
            trials = [runs[m][i]["trial"] for m in vuln if runs[m][i]["trial"] is not None]
            per_iter.append(statistics.median(trials) if trials else None)
        meds = [x for x in per_iter if x is not None]
        mean_med = statistics.mean(meds) if meds else None

        lines = [f"# {cls}  ({header})", "",
                 f"Vulnerabilità identificate: {len(always)}/{len(vuln)} (in tutte le {ITERATIONS} iterazioni), "
                 f"{len(ever)}/{len(vuln)} (in almeno una)"]
        if false_pos:
            lines.append(f"Falsi positivi (assertion error su metodi senza vuln attesa): {len(false_pos)}")
        lines += [f"Mediana trial-per-trovare per iterazione: {[fmt(x) for x in per_iter]}",
                  f"Media delle mediane (trial per identificare): {fmt(mean_med)}", "",
                  f"| metodo | vuln attesa | trovata (x/{ITERATIONS}) | trial per iterazione | mediana | timeout |",
                  "|---|---|---|---|---|---|"]
        for m in mids:
            rs = runs[m]
            valid = [r["trial"] for r in rs if r["trial"] is not None]
            lines.append(f"| {m.split('.')[-1]} | {'sì' if m in vuln else 'no'} | "
                         f"{sum(r['found'] for r in rs)}/{ITERATIONS} | {[r['trial'] for r in rs]} | "
                         f"{fmt(statistics.median(valid)) if valid else '–'} | "
                         f"{sum(r['timed_out'] for r in rs)}/{ITERATIONS} |")
        errs = [r for m in mids for r in runs[m] if r["stderr_tail"]]
        if errs:
            lines += ["", f"Run terminate con errore: {len(errs)} (es.: {errs[0]['stderr_tail'].strip()[-200:]})"]
        (out / f"{cls}.md").write_text("\n".join(lines) + "\n")
        summary.append(f"{cls}: {len(always)}/{len(vuln)} sempre, {len(ever)}/{len(vuln)} almeno una volta; "
                       f"media mediane = {fmt(mean_med)}")
    (out / "SUMMARY.md").write_text("\n".join(summary) + "\n")
    return summary


def comparison():
    """Rebuild results/comparison.md from the SUMMARY.md of every mode folder present."""
    modes = [m for m in MODES if (RESULTS / m / "SUMMARY.md").exists()]
    rows = {}
    for m in modes:
        for line in (RESULTS / m / "SUMMARY.md").read_text().splitlines():
            cls, rest = line.split(":", 1)
            a = re.search(r"(\d+/\d+) sempre, (\d+/\d+) almeno", rest)
            mean = rest.split("= ")[1].strip().replace("None", "–")
            rows.setdefault(cls, {})[m] = f"{a.group(1)} ({a.group(2)}) · {mean}"
    out = ["# Confronto configurazioni fuzzer",
           f"(MAX_TESTS={fuzzer_constant('MAX_TESTS')}, MAX_STEPS={fuzzer_constant('MAX_STEPS')}, "
           f"timeout={TIMEOUT}s, {ITERATIONS} iterazioni)", "",
           "Cella: vuln trovate in tutte le iterazioni (in almeno una) · media delle mediane dei trial per identificarle",
           "", "| File | " + " | ".join(modes) + " |", "|---|" + "---|" * len(modes)]
    for cls, v in rows.items():
        out.append(f"| {cls} | " + " | ".join(v.get(m, "–") for m in modes) + " |")
    (RESULTS / "comparison.md").write_text("\n".join(out) + "\n")


class Progress:
    """Single-line progress bar on stderr: runs done, found / timed out, elapsed, ETA, last method."""
    BAR_WIDTH = 30

    def __init__(self, mode, total):
        self.mode, self.total = mode, total
        self.done = self.found = self.timeouts = 0
        self.start = time.time()
        self.tty = sys.stderr.isatty()
        self._draw("")

    def update(self, result, mid):
        self.done += 1
        self.found += result["found"]
        self.timeouts += result["timed_out"]
        self._draw(mid.split(".")[-2] + "." + mid.split(".")[-1].split(":")[0])

    def _draw(self, last):
        elapsed = time.time() - self.start
        eta = elapsed / self.done * (self.total - self.done) if self.done else 0
        filled = self.BAR_WIDTH * self.done // self.total
        bar = "█" * filled + "░" * (self.BAR_WIDTH - filled)
        line = (f"[{self.mode}] {bar} {self.done}/{self.total} ({100 * self.done // self.total}%) "
                f"| found {self.found} | timeout {self.timeouts} "
                f"| {elapsed:.0f}s, ETA {eta:.0f}s | {last}")
        if self.tty:
            width = shutil.get_terminal_size().columns
            sys.stderr.write("\r\033[K" + line[:width - 1])
        elif self.done % 10 == 0 or self.done == self.total:  # e.g. redirected to a file
            sys.stderr.write(line + "\n")
        sys.stderr.flush()

    def close(self):
        if self.tty:
            sys.stderr.write("\n")


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in MODES:
        sys.exit(f"usage: {sys.argv[0]} <{'|'.join(MODES)}>")
    mode = sys.argv[1]
    out = RESULTS / mode
    out.mkdir(exist_ok=True)

    jobs = [(cls, mid) for cls in CLASSES for mid in case_methods(cls)]
    res = {}
    with ThreadPoolExecutor(WORKERS) as ex:
        futs = {ex.submit(run_one, mode, mid): (cls, mid, i)
                for cls, mid in jobs for i in range(ITERATIONS)}
        progress = Progress(mode, len(futs))
        for f in as_completed(futs):
            key = futs[f]
            res[key] = f.result()
            progress.update(res[key], key[1])
        progress.close()
    json.dump({f"{k[1]}#{k[2]}": v for k, v in res.items()}, open(out / "raw.json", "w"), indent=1)

    print("\n".join(report(mode, jobs, res, out)))
    comparison()


if __name__ == "__main__":
    main()
