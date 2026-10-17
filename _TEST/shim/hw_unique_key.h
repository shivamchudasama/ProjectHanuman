/* SPDX-License-Identifier: MIT */
/* Host-test stand-in for NCS's hw_unique_key.h: declared only; a test that
   builds with CONFIG_HW_UNIQUE_KEY defines the functions. */
#ifndef _SHIM_HW_UNIQUE_KEY_H
#define _SHIM_HW_UNIQUE_KEY_H
#include "zephyr_shim.h"
#define HW_UNIQUE_KEY_SUCCESS (0)
extern bool hw_unique_key_are_any_written(void);
#endif //!_SHIM_HW_UNIQUE_KEY_H
