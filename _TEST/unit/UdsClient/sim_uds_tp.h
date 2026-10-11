/**
 * @file          sim_uds_tp.h
 * @brief         Scripted UdsTp_T transport for the UDS tests: records every bind
 *                and request, and hands out queued responses. A response is
 *                released only after a given number of requests were sent (so a
 *                response "to the next request" is not drained by the client's
 *                clean-up before it), may arrive after a delay, and may be an
 *                error instead. Waiting advances simulated time (gi64_simNowMs).
 *                An optional responder (an ECU written in C) is called on every
 *                request and queues its answers. Included by the test.
 *
 * @date          12/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#ifndef _SIM_UDS_TP_H
#define _SIM_UDS_TP_H

#include <stdio.h>
#include "UdsClient_Types.h"

#define SIM_TP_MSG_MAX                       (320U)
#define SIM_TP_QUEUE                         (64U)
#define SIM_TP_SENT_MAX                      (600U)

typedef struct
{
   uint32_t u32_afterSend;                   /* released once this many requests went */
   int64_t i64_delayMs;                      /* then arrives after this long          */
   int i_ret;                                /* error instead of a message (0: none)  */
   size_t t_len;
   uint8_t u8ar_data[SIM_TP_MSG_MAX];
} SimTpRsp_T;

typedef void (*SimTpResponder_F)(const uint8_t *u8pt_req, size_t t_len, bool b_functional);

static struct
{
   SimTpRsp_T star_q[SIM_TP_QUEUE];
   uint32_t u32_head;
   uint32_t u32_count;
   uint32_t u32_sends;
   uint8_t u8ar_sent[SIM_TP_SENT_MAX][24];   /* first bytes of each request           */
   size_t tar_sentLen[SIM_TP_SENT_MAX];
   bool bar_sentFunc[SIM_TP_SENT_MAX];
   int i_bindRet;
   int i_sendRet;
   uint32_t u32_binds;
   uint32_t u32_unbinds;
   UdsTarget_T st_bound;
   SimTpResponder_F fpt_responder;
} sst_tp;

/** Bytes from a hex string ("62f190"); returns the count. */
static size_t st_SimHex(const char *cpt_hex, uint8_t *u8pt_out, size_t t_max)
{
   size_t t_n = 0U;
   unsigned int u_byte;

   while ((cpt_hex[0] != '\0') && (cpt_hex[1] != '\0') && (t_n < t_max))
   {
      if (sscanf(cpt_hex, "%2x", &u_byte) != 1)
      {
         break;
      }
      u8pt_out[t_n++] = (uint8_t)u_byte;
      cpt_hex += 2;
   }
   return t_n;
}

static void sv_SimTpQueueBytes(uint32_t u32_afterSend, int64_t i64_delayMs, const uint8_t *u8pt_data,
   size_t t_len, int i_ret)
{
   SimTpRsp_T *stpt_rsp;

   if ((sst_tp.u32_count >= SIM_TP_QUEUE) || (t_len > SIM_TP_MSG_MAX))
   {
      printf("sim_uds_tp: queue full\n");
      abort();
   }
   stpt_rsp = &sst_tp.star_q[(sst_tp.u32_head + sst_tp.u32_count) % SIM_TP_QUEUE];
   stpt_rsp->u32_afterSend = u32_afterSend;
   stpt_rsp->i64_delayMs = i64_delayMs;
   stpt_rsp->i_ret = i_ret;
   stpt_rsp->t_len = t_len;
   if (t_len > 0U)
   {
      memcpy(stpt_rsp->u8ar_data, u8pt_data, t_len);
   }
   sst_tp.u32_count++;
}

/** Queue a response released after u32_afterSend requests, arriving after a delay. */
static void sv_SimTpQueue(uint32_t u32_afterSend, int64_t i64_delayMs, const char *cpt_hex)
{
   uint8_t u8ar_data[SIM_TP_MSG_MAX];

   sv_SimTpQueueBytes(u32_afterSend, i64_delayMs, u8ar_data, st_SimHex(cpt_hex, u8ar_data, sizeof(u8ar_data)), 0);
}

/** The response to the next request. */
#define SIM_RSP(hex)                         sv_SimTpQueue(sst_tp.u32_sends + 1U, 0, (hex))
/** The response to the next request, after a delay. */
#define SIM_RSP_AFTER(ms, hex)               sv_SimTpQueue(sst_tp.u32_sends + 1U, (ms), (hex))
/** A response to the request after the next, and so on. */
#define SIM_RSP_N(n, hex)                    sv_SimTpQueue(sst_tp.u32_sends + (n), 0, (hex))
/** A transport error instead of the response to the next request. */
#define SIM_RSP_ERR(err)                     sv_SimTpQueueBytes(sst_tp.u32_sends + 1U, 0, NULL, 0U, (err))

static void sv_SimTpReset(void)
{
   memset(&sst_tp, 0, sizeof(sst_tp));
}

/** Request number u32_idx (0-based) equals the hex string. */
static bool sb_SimTpSent(uint32_t u32_idx, const char *cpt_hex)
{
   uint8_t u8ar_want[24];
   size_t t_len = st_SimHex(cpt_hex, u8ar_want, sizeof(u8ar_want));

   return (u32_idx < sst_tp.u32_sends) && (u32_idx < SIM_TP_SENT_MAX) && (sst_tp.tar_sentLen[u32_idx] == t_len)
      && (memcmp(sst_tp.u8ar_sent[u32_idx], u8ar_want, MIN(t_len, sizeof(sst_tp.u8ar_sent[0]))) == 0);
}

static int si_SimTpBind(void *vpt_ctx, const UdsTarget_T *stpt_target)
{
   (void)vpt_ctx;
   sst_tp.u32_binds++;
   sst_tp.st_bound = *stpt_target;
   return sst_tp.i_bindRet;
}

static void sv_SimTpUnbind(void *vpt_ctx)
{
   (void)vpt_ctx;
   sst_tp.u32_unbinds++;
}

static int si_SimTpSend(void *vpt_ctx, const uint8_t *u8pt_data, size_t t_len, bool b_functional)
{
   uint32_t u32_idx = sst_tp.u32_sends;

   (void)vpt_ctx;
   if (sst_tp.i_sendRet != 0)
   {
      return sst_tp.i_sendRet;
   }
   if (u32_idx < SIM_TP_SENT_MAX)
   {
      memcpy(sst_tp.u8ar_sent[u32_idx], u8pt_data, MIN(t_len, sizeof(sst_tp.u8ar_sent[0])));
      sst_tp.tar_sentLen[u32_idx] = t_len;
      sst_tp.bar_sentFunc[u32_idx] = b_functional;
   }
   sst_tp.u32_sends++;
   if (sst_tp.fpt_responder != NULL)
   {
      sst_tp.fpt_responder(u8pt_data, t_len, b_functional);
   }
   return 0;
}

static int si_SimTpRecv(void *vpt_ctx, uint8_t *u8pt_buf, size_t t_max, k_timeout_t t_timeout)
{
   SimTpRsp_T *stpt_rsp = &sst_tp.star_q[sst_tp.u32_head];
   int64_t i64_wait = (t_timeout.ms < 0) ? INT64_MAX / 4 : t_timeout.ms;
   size_t t_len;

   (void)vpt_ctx;

   // Nothing released yet, or not arrived within the wait
   if ((sst_tp.u32_count == 0U) || (stpt_rsp->u32_afterSend > sst_tp.u32_sends)
      || (stpt_rsp->i64_delayMs > i64_wait))
   {
      if ((sst_tp.u32_count > 0U) && (stpt_rsp->u32_afterSend <= sst_tp.u32_sends))
      {
         stpt_rsp->i64_delayMs -= i64_wait;
      }
      gi64_simNowMs += i64_wait;
      return -EAGAIN;
   }

   gi64_simNowMs += stpt_rsp->i64_delayMs;
   sst_tp.u32_head = (sst_tp.u32_head + 1U) % SIM_TP_QUEUE;
   sst_tp.u32_count--;
   if (stpt_rsp->i_ret != 0)
   {
      return stpt_rsp->i_ret;
   }
   t_len = stpt_rsp->t_len;
   if (t_len > t_max)
   {
      return -EMSGSIZE;
   }
   memcpy(u8pt_buf, stpt_rsp->u8ar_data, t_len);
   return (int)t_len;
}

static const UdsTp_T sst_simTp = { si_SimTpBind, sv_SimTpUnbind, si_SimTpSend, si_SimTpRecv, NULL };

#endif //!_SIM_UDS_TP_H
