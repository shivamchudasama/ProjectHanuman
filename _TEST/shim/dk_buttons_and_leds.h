/* SPDX-License-Identifier: MIT */
/* Host-test stand-in for NCS's DK library (dk_buttons_and_leds.h): buttons and
   LEDs. Functions are declared only; a test that reaches them defines them
   (dk_buttons_init() or dk_button_handler_add() keeps the handler, then the
   test calls it as the library would on a change; the LED calls are
   recorded). */
#ifndef _SHIM_DK_BUTTONS_AND_LEDS_H
#define _SHIM_DK_BUTTONS_AND_LEDS_H
#include "zephyr_shim.h"
#define DK_BTN1_MSK           (1U << 0)
#define DK_BTN2_MSK           (1U << 1)
#define DK_BTN3_MSK           (1U << 2)
#define DK_BTN4_MSK           (1U << 3)
#define DK_LED1               0
#define DK_LED2               1
#define DK_LED3               2
#define DK_LED4               3
typedef void (*button_handler_t)(uint32_t button_state, uint32_t has_changed);
struct button_handler { button_handler_t cb; void *node; };
extern int dk_buttons_init(button_handler_t button_handler);
extern void dk_button_handler_add(struct button_handler *handler);
extern int dk_leds_init(void);
extern int dk_set_led(uint8_t led_idx, uint32_t val);
#endif //!_SHIM_DK_BUTTONS_AND_LEDS_H
