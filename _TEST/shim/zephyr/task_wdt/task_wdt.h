/* SPDX-License-Identifier: MIT */
/* Host-test stand-in for zephyr/task_wdt/task_wdt.h: Zephyr's task watchdog
   API, declared only (the test defines it). task_wdt_add() returns the channel
   ID (>= 0) or a negative errno; a NULL callback means reboot on expiry. */
#ifndef _SHIM_TASK_WDT_H
#define _SHIM_TASK_WDT_H
#include "zephyr/device.h"
typedef void (*task_wdt_callback_t)(int channel_id, void *user_data);
extern int task_wdt_init(const struct device *hw_wdt);
extern int task_wdt_add(uint32_t reload_period, task_wdt_callback_t callback, void *user_data);
extern int task_wdt_delete(int channel_id);
extern int task_wdt_feed(int channel_id);
#endif //!_SHIM_TASK_WDT_H
