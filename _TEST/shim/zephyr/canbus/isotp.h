/* SPDX-License-Identifier: MIT */
/* Host-test stand-in for zephyr/canbus/isotp.h (Zephyr 4.4): the address and
   flow-control types, flags and error codes with Zephyr's names and values, the
   receive context's recv_buf (non-NULL while a message is only partly read), and
   the API declared only; a test that reaches it defines the functions. */
#ifndef _SHIM_ISOTP_H
#define _SHIM_ISOTP_H
#include "zephyr_shim.h"
#include "zephyr/device.h"

#define ISOTP_N_OK              0
#define ISOTP_N_TIMEOUT_A      -1
#define ISOTP_N_TIMEOUT_BS     -2
#define ISOTP_N_TIMEOUT_CR     -3
#define ISOTP_N_WRONG_SN       -4
#define ISOTP_N_INVALID_FS     -5
#define ISOTP_N_UNEXP_PDU      -6
#define ISOTP_N_WFT_OVRN       -7
#define ISOTP_N_BUFFER_OVERFLW -8
#define ISOTP_N_ERROR          -9
#define ISOTP_NO_FREE_FILTER    -10
#define ISOTP_NO_NET_BUF_LEFT   -11
#define ISOTP_NO_BUF_DATA_LEFT  -12
#define ISOTP_NO_CTX_LEFT       -13
#define ISOTP_RECV_TIMEOUT      -14

#define ISOTP_MSG_EXT_ADDR    (1U << 0)
#define ISOTP_MSG_FIXED_ADDR  (1U << 1)
#define ISOTP_MSG_IDE         (1U << 2)
#define ISOTP_MSG_FDF         (1U << 3)
#define ISOTP_MSG_BRS         (1U << 4)

struct isotp_msg_id
{
   union
   {
      uint32_t std_id : 11;
      uint32_t ext_id : 29;
   };
   uint8_t ext_addr;
   uint8_t dl;
   uint8_t flags;
};

struct isotp_fc_opts
{
   uint8_t bs;
   uint8_t stmin;
};

struct net_buf;

struct isotp_recv_ctx
{
   int filter_id;
   const struct device *can_dev;
   struct net_buf *recv_buf;
   struct isotp_msg_id rx_addr;
   struct isotp_msg_id tx_addr;
   struct isotp_fc_opts opts;
};

struct isotp_send_ctx
{
   int filter_id;
   const struct device *can_dev;
};

typedef void (*isotp_tx_callback_t)(int error_nr, void *arg);

extern int isotp_bind(struct isotp_recv_ctx *rctx, const struct device *can_dev,
   const struct isotp_msg_id *rx_addr, const struct isotp_msg_id *tx_addr,
   const struct isotp_fc_opts *opts, k_timeout_t timeout);
extern void isotp_unbind(struct isotp_recv_ctx *rctx);
extern int isotp_recv(struct isotp_recv_ctx *rctx, uint8_t *data, size_t len, k_timeout_t timeout);
extern int isotp_send(struct isotp_send_ctx *sctx, const struct device *can_dev,
   const uint8_t *data, size_t len, const struct isotp_msg_id *tx_addr,
   const struct isotp_msg_id *rx_addr, isotp_tx_callback_t complete_cb, void *cb_arg);
#endif //!_SHIM_ISOTP_H
