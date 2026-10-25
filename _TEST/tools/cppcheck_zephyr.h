/* SPDX-License-Identifier: MIT */
/* Prelude for cppcheck (tools/run_static.py --include): the Zephyr macros that
   appear in preprocessor conditions, which cppcheck must evaluate but cannot
   reach (it is given the project's include paths only, not Zephyr's). */
#define DT_ALIAS(alias)                 alias
#define DT_NODE_HAS_STATUS_OKAY(node)   1
