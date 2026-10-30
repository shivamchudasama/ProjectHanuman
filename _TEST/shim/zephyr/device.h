/* SPDX-License-Identifier: MIT */
/* Host-test stand-in for zephyr/device.h and the devicetree macros a driver
   user needs. DEVICE_DT_GET(DT_CHOSEN(x)) and DEVICE_DT_GET(DT_ALIAS(x)) name
   the device gst_simDev_x, which the test defines; device_is_ready() and
   device_init() (a zephyr,deferred-init device) are declared only (the test
   defines what it uses). */
#ifndef _SHIM_DEVICE_H
#define _SHIM_DEVICE_H
#include "zephyr_shim.h"
struct device
{
   const char *name;
};
#define DT_CHOSEN(prop)       prop
#define DT_HAS_CHOSEN(prop)   1
#define DEVICE_DT_GET(node)   (&SHIM_CAT(gst_simDev_, node))
/* DT_ALIAS(x) is the node x; whether it is enabled is the test's
   SHIM_DT_OKAY_x (1 or 0), so a test can build with and without the node */
#define DT_ALIAS(alias)       alias
#define DT_NODE_HAS_STATUS_OKAY(node) SHIM_CAT(SHIM_DT_OKAY_, node)
extern bool device_is_ready(const struct device *dev);
extern int device_init(const struct device *dev);
#endif //!_SHIM_DEVICE_H
