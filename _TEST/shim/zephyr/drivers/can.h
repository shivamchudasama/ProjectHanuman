/* SPDX-License-Identifier: MIT */
/* Host-test stand-in for zephyr/drivers/can.h (Zephyr 4.4): the types, flags,
   modes and states with Zephyr's names, values and layouts, the DLC helpers,
   and the controller API declared only; a test that reaches it defines the
   functions (a scripted controller). CAN_MAX_DLEN follows CONFIG_CAN_FD_MODE
   as in Zephyr. */
#ifndef _SHIM_CAN_H
#define _SHIM_CAN_H
#include "zephyr_shim.h"
#include "zephyr/device.h"

#define CAN_STD_ID_MASK       0x7FFU
#define CAN_EXT_ID_MASK       0x1FFFFFFFU
#define CAN_MAX_DLC           8U
#define CANFD_MAX_DLC         15U
#ifndef CONFIG_CAN_FD_MODE
#define CAN_MAX_DLEN          8U
#else
#define CAN_MAX_DLEN          64U
#endif // CONFIG_CAN_FD_MODE

typedef uint32_t can_mode_t;
#define CAN_MODE_NORMAL           0
#define CAN_MODE_LOOPBACK         (1U << 0)
#define CAN_MODE_LISTENONLY       (1U << 1)
#define CAN_MODE_FD               (1U << 2)
#define CAN_MODE_ONE_SHOT         (1U << 3)
#define CAN_MODE_3_SAMPLES        (1U << 4)
#define CAN_MODE_MANUAL_RECOVERY  (1U << 5)

enum can_state
{
   CAN_STATE_ERROR_ACTIVE,
   CAN_STATE_ERROR_WARNING,
   CAN_STATE_ERROR_PASSIVE,
   CAN_STATE_BUS_OFF,
   CAN_STATE_STOPPED,
};

#define CAN_FRAME_IDE         (1U << 0)
#define CAN_FRAME_RTR         (1U << 1)
#define CAN_FRAME_FDF         (1U << 2)
#define CAN_FRAME_BRS         (1U << 3)
#define CAN_FRAME_ESI         (1U << 4)

struct can_frame
{
   uint32_t id;
   uint8_t dlc;
   uint8_t flags;
   uint16_t reserved;
   union
   {
      uint8_t data[CAN_MAX_DLEN];
      uint32_t data_32[(CAN_MAX_DLEN + 3U) / 4U];
   };
};

#define CAN_FILTER_IDE        (1U << 0)

struct can_filter
{
   uint32_t id;
   uint32_t mask;
   uint8_t flags;
};

struct can_bus_err_cnt
{
   uint8_t tx_err_cnt;
   uint8_t rx_err_cnt;
};

typedef void (*can_tx_callback_t)(const struct device *dev, int error, void *user_data);
typedef void (*can_rx_callback_t)(const struct device *dev, struct can_frame *frame,
   void *user_data);
typedef void (*can_state_change_callback_t)(const struct device *dev, enum can_state state,
   struct can_bus_err_cnt err_cnt, void *user_data);

static inline uint8_t can_dlc_to_bytes(uint8_t dlc)
{
   static const uint8_t dlc_table[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64 };

   return dlc_table[MIN(dlc, ARRAY_SIZE(dlc_table) - 1U)];
}

static inline uint8_t can_bytes_to_dlc(uint8_t num_bytes)
{
   return num_bytes <= 8 ? num_bytes :
      num_bytes <= 12 ? 9 :
      num_bytes <= 16 ? 10 :
      num_bytes <= 20 ? 11 :
      num_bytes <= 24 ? 12 :
      num_bytes <= 32 ? 13 :
      num_bytes <= 48 ? 14 :
      15;
}

extern int can_get_capabilities(const struct device *dev, can_mode_t *cap);
extern int can_start(const struct device *dev);
extern int can_stop(const struct device *dev);
extern int can_set_mode(const struct device *dev, can_mode_t mode);
extern int can_set_bitrate(const struct device *dev, uint32_t bitrate);
#ifdef CONFIG_CAN_FD_MODE
extern int can_set_bitrate_data(const struct device *dev, uint32_t bitrate_data);
#endif // CONFIG_CAN_FD_MODE
extern int can_send(const struct device *dev, const struct can_frame *frame,
   k_timeout_t timeout, can_tx_callback_t callback, void *user_data);
extern int can_add_rx_filter(const struct device *dev, can_rx_callback_t callback,
   void *user_data, const struct can_filter *filter);
extern void can_remove_rx_filter(const struct device *dev, int filter_id);
extern int can_get_state(const struct device *dev, enum can_state *state,
   struct can_bus_err_cnt *err_cnt);
extern void can_set_state_change_callback(const struct device *dev,
   can_state_change_callback_t callback, void *user_data);
#endif //!_SHIM_CAN_H
