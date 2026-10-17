#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run every fuzz target of _TEST/fuzz for a while, from its seeds and its corpus.

    python run_fuzz.py <build_fuzz dir> <seconds per target>

Seeds come from vectors/wire.json (gen_fuzz_corpus.py, into <build>/seeds);
the corpus grows in <build>/corpus/<target>; a crash is written to
<build>/crash/ and fails the run. Used by _TEST/run_tests.ps1 -Fuzz and CI.
"""

import os
import pathlib
import subprocess
import sys

TARGETS = {                       # target: extra libFuzzer options
    "setu_rx": [],
    "fscmd": [],
    "uds_cmd": [],
    "uds_client": [],
    "uds_job": ["-max_len=4096"],
}


def main():
    build = pathlib.Path(sys.argv[1]).resolve()
    seconds = int(sys.argv[2])
    tools = pathlib.Path(__file__).resolve().parent
    subprocess.run([sys.executable, str(tools / "gen_fuzz_corpus.py"),
                    str(tools.parent / "vectors" / "wire.json"), str(build / "seeds")], check=True)
    (build / "crash").mkdir(exist_ok=True)
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
    failed = []
    for name, extra in TARGETS.items():
        exe = build / (f"fuzz_{name}.exe" if os.name == "nt" else f"fuzz_{name}")
        corpus = build / "corpus" / name
        corpus.mkdir(parents=True, exist_ok=True)
        seeds = build / "seeds" / name                # not every target has seeds
        dirs = [str(corpus)] + ([str(seeds)] if seeds.is_dir() else [])
        print(f"==> fuzz_{name}: {seconds} s", flush=True)
        r = subprocess.run([str(exe), *dirs, f"-max_total_time={seconds}",
                            f"-artifact_prefix={build / 'crash'}{os.sep}", "-print_final_stats=1", *extra],
                           env=env)
        if r.returncode != 0:
            failed.append(name)
    if failed:
        print("fuzzing FAILED:", ", ".join(failed), f"(inputs in {build / 'crash'})")
        return 1
    print("fuzzing: no crash")
    return 0


if __name__ == "__main__":
    sys.exit(main())
