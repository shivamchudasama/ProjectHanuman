# SPDX-License-Identifier: MIT
"""_TEST/tools/check_config_symbols.py: the CI guard that every CONFIG_ symbol
the firmware sources test is known to the build (audit finding F6)."""

import importlib.util
import pathlib

TOOL = pathlib.Path(__file__).resolve().parents[1] / "tools" / "check_config_symbols.py"
spec = importlib.util.spec_from_file_location("check_config_symbols", TOOL)
ccs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ccs)

DOTCONFIG = "CONFIG_UDS=y\n# CONFIG_FSMGR_FLASH_IF_SQSPI is not set\n"
KCONFIG = 'menu "Application"\nconfig DS_HEX_DUMP\n\tbool "dump"\nendmenu\n'


def make_repo(tmp_path, source: str) -> pathlib.Path:
    (tmp_path / "_ASW" / "_X").mkdir(parents=True)
    (tmp_path / "_LIB").mkdir()
    (tmp_path / "_ASW" / "_X" / "x.c").write_text(source)
    return tmp_path


def test_known_symbols_pass(tmp_path):
    repo = make_repo(tmp_path, "#if defined(CONFIG_UDS) && !defined(CONFIG_FSMGR_FLASH_IF_SQSPI)\n"
                               "#ifdef CONFIG_DS_HEX_DUMP\n#endif\n#endif\n")
    assert ccs.unknown_symbols(repo, DOTCONFIG, KCONFIG) == {}


def test_unknown_symbol_is_reported_with_its_place(tmp_path):
    repo = make_repo(tmp_path, "int a;\n#elif defined(CONFIG_TRUSTED_STORAGE_STORAGE_BACKEND_SETTINGS)\n")
    assert ccs.unknown_symbols(repo, DOTCONFIG, KCONFIG) == {
        "CONFIG_TRUSTED_STORAGE_STORAGE_BACKEND_SETTINGS": ["_ASW/_X/x.c:2"]}


def test_only_conditions_count_and_include_guards_are_not_symbols(tmp_path):
    repo = make_repo(tmp_path, "#ifndef CSR_GENERATOR_CONFIG_H\n"
                               "int x = CONFIG_NOT_A_CONDITION; /* CONFIG_IN_A_COMMENT */\n#endif\n")
    assert ccs.unknown_symbols(repo, DOTCONFIG, KCONFIG) == {}


def test_private_oem_folder_is_skipped(tmp_path):
    repo = make_repo(tmp_path, "")
    (repo / "_ASW" / "_X" / "oem").mkdir()
    (repo / "_ASW" / "_X" / "oem" / "k.c").write_text("#ifdef CONFIG_OEM_ONLY\n#endif\n")
    assert ccs.unknown_symbols(repo, DOTCONFIG, KCONFIG) == {}
