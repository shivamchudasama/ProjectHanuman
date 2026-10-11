/* SPDX-License-Identifier: MIT */
/* Host-test stand-in for zephyr/device.h and the devicetree macros a driver
   user needs. DEVICE_DT_GET(DT_CHOSEN(x)) names the device gst_simDev_x, which
   the test defines; device_is_ready() is declared only (the test defines it). */
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
extern bool device_is_ready(const struct device *dev);
#endif //!_SHIM_DEVICE_H
