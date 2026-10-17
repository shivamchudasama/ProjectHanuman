/* SPDX-License-Identifier: MIT */
/* Force-included on Windows (clang targeting the MSVC runtime), which has no
   POSIX ssize_t; the shim and the code under test use it. */
#ifndef FUZZ_WIN_H
#define FUZZ_WIN_H
#include <stdint.h>
typedef intptr_t ssize_t;
#endif
