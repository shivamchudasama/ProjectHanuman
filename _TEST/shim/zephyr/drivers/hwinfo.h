/* SPDX-License-Identifier: MIT */
/* Host-test stand-in for zephyr/drivers/hwinfo.h: declared only; a test that
   reaches it defines it. The RESET_* flags are Zephyr's. */
#ifndef _SHIM_HWINFO_H
#define _SHIM_HWINFO_H
#include "zephyr_shim.h"
#define RESET_PIN             (1U << 0)
#define RESET_SOFTWARE        (1U << 1)
#define RESET_BROWNOUT        (1U << 2)
#define RESET_POR             (1U << 3)
#define RESET_WATCHDOG        (1U << 4)
#define RESET_DEBUG           (1U << 5)
#define RESET_SECURITY        (1U << 6)
#define RESET_LOW_POWER_WAKE  (1U << 7)
#define RESET_CPU_LOCKUP      (1U << 8)
#define RESET_PARITY          (1U << 9)
#define RESET_PLL             (1U << 10)
#define RESET_CLOCK           (1U << 11)
#define RESET_HARDWARE        (1U << 12)
#define RESET_USER            (1U << 13)
#define RESET_TEMPERATURE     (1U << 14)
#define RESET_BOOTLOADER      (1U << 15)
#define RESET_FLASH           (1U << 16)
extern ssize_t hwinfo_get_device_id(uint8_t *buffer, size_t length);
extern int hwinfo_get_reset_cause(uint32_t *cause);
extern int hwinfo_clear_reset_cause(void);
#endif //!_SHIM_HWINFO_H
