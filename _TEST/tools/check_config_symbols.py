#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fail when the firmware sources test a Kconfig symbol the build does not know.

    python check_config_symbols.py <repo root> <build>/zephyr/.config

Every CONFIG_ symbol in a preprocessor condition (#if, #ifdef, #ifndef, #elif)
under _ASW and _LIB must appear in the build's .config, set or "is not set", or
be defined by the application Kconfig (_DI/Kconfig). A symbol that is neither
was mistyped or belongs to another configuration (audit finding F6: NCS
"trusted storage" symbols in a build that uses Zephyr's secure storage), so
its branch is silently dead and the unit tests that define it test code the
firmware does not contain. Run by CI on each firmware build.
"""

import pathlib
import re
import sys

COND = re.compile(r"^\s*#\s*(?:if|ifdef|ifndef|elif)\b(.*)$")
SYMBOL = re.compile(r"\bCONFIG_\w+")


def unknown_symbols(repo: pathlib.Path, dotconfig: str, app_kconfig: str) -> dict:
    known = set(SYMBOL.findall(dotconfig))
    known |= {"CONFIG_" + s for s in re.findall(r"^\s*(?:menu)?config\s+(\w+)", app_kconfig, re.M)}
    found = {}
    for top in ("_ASW", "_LIB"):
        for f in sorted((repo / top).rglob("*.[ch]")):
            if "oem" in f.parts:
                continue
            for n, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
                m = COND.match(line)
                for s in SYMBOL.findall(m.group(1)) if m else ():
                    if s not in known:
                        found.setdefault(s, []).append(f"{f.relative_to(repo).as_posix()}:{n}")
    return found


def main() -> int:
    repo = pathlib.Path(sys.argv[1])
    dotconfig = pathlib.Path(sys.argv[2]).read_text()
    app_kconfig = (repo / "_DI" / "Kconfig").read_text()
    found = unknown_symbols(repo, dotconfig, app_kconfig)
    for s, where in sorted(found.items()):
        print(f"{s}: unknown to this build's Kconfig, tested at {', '.join(where)}")
    if found:
        return 1
    print("Kconfig symbols: every CONFIG_ symbol the sources test is known to the build")
    return 0


if __name__ == "__main__":
    sys.exit(main())
