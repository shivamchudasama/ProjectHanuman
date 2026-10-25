#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Static analysis gate, run the same way by _TEST/run_tests.ps1 -Static and CI.

    python run_static.py <repo root>

- cppcheck (warning, performance, portability) over _ASW and _LIB, with the
  project's own include paths only (it cannot preprocess Zephyr's arch headers);
  BT_GATT_SERVICE_DEFINE files are skipped for syntaxError, a macro it cannot
  expand.
- ruff with the pyflakes rules and syntax errors (E9, F) over _TOOLS.
- bandit, medium severity and up, over _TOOLS.

A tool that is not installed is reported and skipped; any finding fails.
"""

import pathlib
import shutil
import subprocess
import sys

GATT_MACRO_FILES = ("GAP_GATT.c", "PairSvc.c", "SETUSvc.c")


def run(name, cmd):
    print(f"==> {name}: {' '.join(cmd[:3])} ...", flush=True)
    return subprocess.run(cmd).returncode


def find(tool, *extra):
    path = shutil.which(tool)
    for e in extra:
        if not path and pathlib.Path(e).exists():
            path = e
    return path


def main():
    repo = pathlib.Path(sys.argv[1]).resolve()
    failed = []

    cppcheck = find("cppcheck", r"C:\Program Files\Cppcheck\cppcheck.exe")
    if cppcheck:
        dirs = [d for top in ("_ASW", "_LIB") for d in (repo / top).rglob("*")
                if d.is_dir() and d.name != "oem"]
        srcs = [str(f) for top in ("_ASW", "_LIB") for f in (repo / top).rglob("*.c") if "oem" not in f.parts]
        cmd = [cppcheck, "--enable=warning,performance,portability", "--error-exitcode=1", "--inline-suppr",
               "--suppress=missingIncludeSystem", "--suppress=missingInclude", "--suppress=unknownMacro",
               "-DCONFIG_UDS=1", "-DCONFIG_CANIF=1", "-DCONFIG_FS_CMD=1", "-DCONFIG_UDS_CMD=1", "--quiet",
               "--template={file}:{line}: {severity}/{id}: {message}",
               f"--include={pathlib.Path(__file__).resolve().parent / 'cppcheck_zephyr.h'}"]
        cmd += [f"--suppress=syntaxError:*{f}" for f in GATT_MACRO_FILES]
        cmd += [f"-I{d}" for d in dirs] + srcs
        if run("cppcheck", cmd) != 0:
            failed.append("cppcheck")
    else:
        print("cppcheck not found: skipped")

    tools = str(repo / "_TOOLS")
    if run("ruff", [sys.executable, "-m", "ruff", "check", tools, "--select", "E9,F", "--quiet"]) != 0:
        failed.append("ruff")
    if run("bandit", [sys.executable, "-m", "bandit", "-r", tools, "-q", "-ll"]) != 0:
        failed.append("bandit")

    if failed:
        print("static analysis FAILED:", ", ".join(failed))
        return 1
    print("static analysis: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
