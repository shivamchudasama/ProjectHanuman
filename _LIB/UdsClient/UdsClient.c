/**
 * @file          UdsClient.c
 * @brief         UDS client (ISO 14229-1, tester side). A request is sent through
 *                the transport; responses are read until one matches it: a positive
 *                response (SID + 0x40, with the sub-function echoed), or a negative
 *                one (7F SID NRC). NRC 0x78 extends the wait to P2*, NRC 0x21
 *                repeats the request a few times, anything else (a late answer to an
 *                earlier request, another SID) is skipped. The service helpers build
 *                the requests ECU programming needs and check what comes back.
 *                See _DOC/UdsClient/API_REFERENCE.md.
 *
 * @date          12/10/2026
 * @author        Shivam Chudasama [SC]
 * @license       MIT
 */

/* SPDX-License-Identifier: MIT */

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include "UdsClient.h"
#include <errno.h>
#include <string.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(UdsClient, LOG_LEVEL_INF);

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
/**
 * @def           UDS_DRAIN_BUF
 * @brief         Scratch buffer that discards stale responses before a request.
 */
#define UDS_DRAIN_BUF                        (16U)

/**
 * @def           UDS_DRAIN_MAX
 * @brief         Most stale responses discarded before a request.
 */
#define UDS_DRAIN_MAX                        (8U)

/**
 * @def           UDS_CAN_STD_ID_MAX
 * @brief         Largest 11-bit identifier.
 */
#define UDS_CAN_STD_ID_MAX                   (0x7FFUL)

/**
 * @def           UDS_CAN_EXT_ID_MAX
 * @brief         Largest 29-bit identifier.
 */
#define UDS_CAN_EXT_ID_MAX                   (0x1FFFFFFFUL)

/**
 * @def           UDS_FUNC_SF_MAX
 * @brief         Longest functional request: one classic single frame.
 */
#define UDS_FUNC_SF_MAX                      (7U)

/******************************************************************************/
/*                                                                            */
/*                                   ENUMS                                    */
/*                                                                            */
/******************************************************************************/

/******************************************************************************/
/*                                                                            */
/*                                 STRUCTURES                                 */
/*                                                                            */
/******************************************************************************/

/******************************************************************************/
/*                                                                            */
/*                                   UNIONS                                   */
/*                                                                            */
/******************************************************************************/

/******************************************************************************/
/*                                                                            */
/*                       PRIVATE FUNCTION DECLARATIONS                        */
/*                                                                            */
/******************************************************************************/
static bool sb_HasSubFunction(uint8_t u8_sid);
static bool sb_ValidDl(uint8_t u8_dl, bool b_fd);
static int si_CheckTarget(const UdsTarget_T *stpt_target);
static void sv_Drain(UdsClient_T *stpt_client);
static void sv_AfterPositive(UdsClient_T *stpt_client, const uint8_t *u8pt_req, const uint8_t *u8pt_rsp,
   size_t t_rspLen);
static int si_Exchange(UdsClient_T *stpt_client, const uint8_t *u8pt_req, size_t t_reqLen, bool b_functional,
   uint8_t *u8pt_rsp, size_t t_rspMax, size_t *tpt_rspLen);
static int si_Simple(UdsClient_T *stpt_client, size_t t_reqLen, size_t t_minRsp);
static void sv_PutBe(uint8_t *u8pt_dst, uint32_t u32_value, uint8_t u8_bytes);

/******************************************************************************/
/*                                                                            */
/*                              EXTERN VARIABLES                              */
/*                                                                            */
/******************************************************************************/

/******************************************************************************/
/*                                                                            */
/*                             PRIVATE VARIABLES                              */
/*                                                                            */
/******************************************************************************/

/******************************************************************************/
/*                                                                            */
/*                              EXTERN FUNCTIONS                              */
/*                                                                            */
/******************************************************************************/

/******************************************************************************/
/*                                                                            */
/*                        PRIVATE FUNCTION DEFINITIONS                        */
/*                                                                            */
/******************************************************************************/
/**
 * @private       sb_HasSubFunction
 * @brief         Whether a service's second byte is a sub-function (echoed in the
 *                positive response, bit 7 = suppress the positive response).
 * @param[in]     u8_sid Service identifier.
 * @return        true for the services with a sub-function this client knows.
 */
static bool sb_HasSubFunction(uint8_t u8_sid)
{
   switch (u8_sid)
   {
      case UDS_SID_SESSION:
      case UDS_SID_ECU_RESET:
      case UDS_SID_READ_DTC:
      case UDS_SID_SECURITY:
      case UDS_SID_COMM_CONTROL:
      case UDS_SID_ROUTINE:
      case UDS_SID_TESTER_PRESENT:
      case UDS_SID_DTC_SETTING:
         return true;

      default:
         return false;
   }
}

/**
 * @private       sb_ValidDl
 * @brief         Whether a TX frame length is allowed (0 = the default).
 * @param[in]     u8_dl Frame length.
 * @param[in]     b_fd CAN FD target.
 * @return        true if valid.
 */
static bool sb_ValidDl(uint8_t u8_dl, bool b_fd)
{
   switch (u8_dl)
   {
      case 0U:
      case 8U:
         return true;

      case 12U:
      case 16U:
      case 20U:
      case 24U:
      case 32U:
      case 48U:
      case 64U:
         return b_fd;

      default:
         return false;
   }
}

/**
 * @private       si_CheckTarget
 * @brief         Check a target's flags, identifiers and frame length.
 * @param[in]     stpt_target Target.
 * @return        0; -EINVAL for unknown flags, an identifier out of range, BRS
 *                without FD or a bad frame length; -ENOTSUP for extended
 *                addressing.
 */
static int si_CheckTarget(const UdsTarget_T *stpt_target)
{
   uint32_t u32_idMax = ((stpt_target->u8_flags & UDS_TGT_EXT_ID) != 0U) ? UDS_CAN_EXT_ID_MAX : UDS_CAN_STD_ID_MAX;
   bool b_fd = ((stpt_target->u8_flags & UDS_TGT_FD) != 0U);

   if (((stpt_target->u8_flags & (uint8_t)~UDS_TGT_FLAGS) != 0U)
      || (stpt_target->u32_txId > u32_idMax) || (stpt_target->u32_rxId > u32_idMax)
      || (((stpt_target->u8_flags & UDS_TGT_FUNC) != 0U) && (stpt_target->u32_funcId > u32_idMax))
      || (((stpt_target->u8_flags & UDS_TGT_BRS) != 0U) && !b_fd)
      || !sb_ValidDl(stpt_target->u8_txDl, b_fd))
   {
      return -EINVAL;
   }

   if ((stpt_target->u8_flags & UDS_TGT_EXT_ADDR) != 0U)
   {
      return -ENOTSUP;
   }

   return 0;
}

/**
 * @private       sv_Drain
 * @brief         Discard responses that arrived after their request was finished
 *                (late answers, a TesterPresent's negative response), so they are
 *                not taken for the next request's.
 * @param[in]     stpt_client Client.
 * @return        None.
 */
static void sv_Drain(UdsClient_T *stpt_client)
{
   uint8_t u8ar_scratch[UDS_DRAIN_BUF];
   uint32_t i;
   int i_ret;

   for (i = 0U; i < UDS_DRAIN_MAX; i++)
   {
      i_ret = stpt_client->stpt_tp->fpt_recv(stpt_client->stpt_tp->vpt_ctx, u8ar_scratch,
         sizeof(u8ar_scratch), K_NO_WAIT);
      if ((i_ret < 0) && (i_ret != -EMSGSIZE))
      {
         break;
      }
      LOG_DBG("stale response (%d) discarded", i_ret);
   }
}

/**
 * @private       sv_AfterPositive
 * @brief         Follow what a positive response changes: the session (and with it
 *                the keep-alive) and, unless the target overrides them, P2 and P2*
 *                from a DiagnosticSessionControl response.
 * @param[in]     stpt_client Client.
 * @param[in]     u8pt_req Request.
 * @param[in]     u8pt_rsp Positive response.
 * @param[in]     t_rspLen Response length.
 * @return        None.
 */
static void sv_AfterPositive(UdsClient_T *stpt_client, const uint8_t *u8pt_req, const uint8_t *u8pt_rsp,
   size_t t_rspLen)
{
   uint8_t u8_sub = (uint8_t)(u8pt_req[1] & (uint8_t)~UDS_SUPPRESS_POS_RSP);

   switch (u8pt_req[0])
   {
      case UDS_SID_SESSION:
         stpt_client->b_session = (u8_sub != UDS_SESSION_DEFAULT);
         // sessionParameterRecord: P2server (ms) and P2*server (10 ms), big-endian
         if (t_rspLen >= 6U)
         {
            if (stpt_client->st_target.u16_p2Ms == 0U)
            {
               stpt_client->u32_p2Ms = (((uint32_t)u8pt_rsp[2] << 8) | u8pt_rsp[3]) + UDS_P2_MARGIN_MS;
            }
            if (stpt_client->st_target.u16_p2StarMs == 0U)
            {
               stpt_client->u32_p2StarMs = ((((uint32_t)u8pt_rsp[4] << 8) | u8pt_rsp[5]) * 10U)
                  + UDS_P2_MARGIN_MS;
            }
         }
         break;

      case UDS_SID_ECU_RESET:
         // The ECU restarts in the default session
         stpt_client->b_session = false;
         break;

      default:
         break;
   }
}

/**
 * @private       si_Exchange
 * @brief         Send a request and wait for its response (see the file comment).
 * @param[in]     stpt_client Client (bound).
 * @param[in]     u8pt_req Request.
 * @param[in]     t_reqLen Request length.
 * @param[in]     b_functional Send to the functional identifier.
 * @param[out]    u8pt_rsp Response buffer.
 * @param[in]     t_rspMax Its size.
 * @param[out]    tpt_rspLen Response length (0 when none came for a suppressed
 *                positive response).
 * @return        0 positive; the NRC (1..255) for a negative response; -ETIMEDOUT
 *                (no response in P2/P2*); -EBADMSG (positive response without the
 *                sub-function echo); otherwise the transport's error.
 */
static int si_Exchange(UdsClient_T *stpt_client, const uint8_t *u8pt_req, size_t t_reqLen, bool b_functional,
   uint8_t *u8pt_rsp, size_t t_rspMax, size_t *tpt_rspLen)
{
   const UdsTp_T *stpt_tp = stpt_client->stpt_tp;
   uint8_t u8_sid = u8pt_req[0];
   bool b_sub = sb_HasSubFunction(u8_sid) && (t_reqLen >= 2U);
   bool b_suppress = b_sub && ((u8pt_req[1] & UDS_SUPPRESS_POS_RSP) != 0U);
   uint32_t u32_busy = 0U;
   int64_t i64_deadline;
   int64_t i64_left;
   size_t t_len;
   int i_ret;

   *tpt_rspLen = 0U;
   stpt_client->u8_lastSid = u8_sid;
   stpt_client->u8_lastNrc = 0U;
   stpt_client->u32_pending = 0U;

   sv_Drain(stpt_client);
   i_ret = stpt_tp->fpt_send(stpt_tp->vpt_ctx, u8pt_req, t_reqLen, b_functional);
   if (i_ret < 0)
   {
      return i_ret;
   }
   stpt_client->i64_lastTxMs = k_uptime_get();
   i64_deadline = stpt_client->i64_lastTxMs + stpt_client->u32_p2Ms;

   while (true)
   {
      i64_left = MAX(i64_deadline - k_uptime_get(), 0);
      i_ret = stpt_tp->fpt_recv(stpt_tp->vpt_ctx, u8pt_rsp, t_rspMax, K_MSEC(i64_left));

      // Check if the wait ran out: success only when no positive response was due
      if (i_ret == -EAGAIN)
      {
         return b_suppress ? 0 : -ETIMEDOUT;
      }
      if (i_ret < 0)
      {
         return i_ret;
      }
      t_len = (size_t)i_ret;

      // A negative response to this service
      if ((t_len >= 3U) && (u8pt_rsp[0] == UDS_NEGATIVE_RESPONSE) && (u8pt_rsp[1] == u8_sid))
      {
         if ((u8pt_rsp[2] == UDS_NRC_PENDING) && (stpt_client->u32_pending < UDS_PENDING_MAX))
         {
            stpt_client->u32_pending++;
            i64_deadline = k_uptime_get() + stpt_client->u32_p2StarMs;
            continue;
         }
         if ((u8pt_rsp[2] == UDS_NRC_BUSY_REPEAT) && (u32_busy < UDS_BUSY_RETRIES))
         {
            u32_busy++;
            (void)k_msleep(UDS_BUSY_DELAY_MS);
            i_ret = stpt_tp->fpt_send(stpt_tp->vpt_ctx, u8pt_req, t_reqLen, b_functional);
            if (i_ret < 0)
            {
               return i_ret;
            }
            stpt_client->i64_lastTxMs = k_uptime_get();
            i64_deadline = stpt_client->i64_lastTxMs + stpt_client->u32_p2Ms;
            continue;
         }
         stpt_client->u8_lastNrc = u8pt_rsp[2];
         *tpt_rspLen = t_len;
         return u8pt_rsp[2];
      }

      // The positive response to this service
      if ((t_len >= 1U) && (u8pt_rsp[0] == (uint8_t)(u8_sid + UDS_POSITIVE_OFFSET)))
      {
         *tpt_rspLen = t_len;
         if (b_sub && ((t_len < 2U) || ((u8pt_rsp[1] & 0x7FU) != (u8pt_req[1] & 0x7FU))))
         {
            return -EBADMSG;
         }
         sv_AfterPositive(stpt_client, u8pt_req, u8pt_rsp, t_len);
         return 0;
      }

      LOG_DBG("response 0x%02x to another request skipped", (t_len > 0U) ? u8pt_rsp[0] : 0U);

      // Check if skipped messages used up the wait
      if (k_uptime_get() >= i64_deadline)
      {
         return b_suppress ? 0 : -ETIMEDOUT;
      }
   }
}

/**
 * @private       si_Simple
 * @brief         Send the request in u8ar_req and check the positive response in
 *                u8ar_rsp is long enough.
 * @param[in]     stpt_client Client.
 * @param[in]     t_reqLen Request length.
 * @param[in]     t_minRsp Shortest acceptable positive response.
 * @return        As gi_UdsClient_Request(), -EBADMSG for a short response.
 */
static int si_Simple(UdsClient_T *stpt_client, size_t t_reqLen, size_t t_minRsp)
{
   size_t t_rspLen = 0U;
   int i_ret;

   i_ret = gi_UdsClient_Request(stpt_client, stpt_client->u8ar_req, t_reqLen, false, stpt_client->u8ar_rsp,
      sizeof(stpt_client->u8ar_rsp), &t_rspLen);
   if ((i_ret == 0) && (t_rspLen < t_minRsp))
   {
      i_ret = -EBADMSG;
   }

   return i_ret;
}

/**
 * @private       sv_PutBe
 * @brief         Write the low u8_bytes bytes of a value, big-endian.
 * @param[out]    u8pt_dst Destination.
 * @param[in]     u32_value Value.
 * @param[in]     u8_bytes 1..4.
 * @return        None.
 */
static void sv_PutBe(uint8_t *u8pt_dst, uint32_t u32_value, uint8_t u8_bytes)
{
   uint8_t i;

   for (i = 0U; i < u8_bytes; i++)
   {
      u8pt_dst[i] = (uint8_t)(u32_value >> (8U * (u8_bytes - 1U - i)));
   }
}

/******************************************************************************/
/*                                                                            */
/*                        PUBLIC FUNCTION DEFINITIONS                         */
/*                                                                            */
/******************************************************************************/
/**
 * @public        gi_UdsClient_Init
 * @brief         Set up a client on a transport (no target yet).
 * @param[out]    stpt_client Client.
 * @param[in]     stpt_tp Transport (kept; must outlive the client).
 * @return        0, or -EINVAL for NULL or an incomplete transport.
 */
int gi_UdsClient_Init(UdsClient_T *stpt_client, const UdsTp_T *stpt_tp)
{
   if ((stpt_client == NULL) || (stpt_tp == NULL) || (stpt_tp->fpt_bind == NULL) || (stpt_tp->fpt_unbind == NULL)
      || (stpt_tp->fpt_send == NULL) || (stpt_tp->fpt_recv == NULL))
   {
      return -EINVAL;
   }

   memset(stpt_client, 0, sizeof(*stpt_client));
   stpt_client->stpt_tp = stpt_tp;
   stpt_client->u32_p2Ms = UDS_P2_MS;
   stpt_client->u32_p2StarMs = UDS_P2STAR_MS;

   return 0;
}

/**
 * @public        gi_UdsClient_SetTarget
 * @brief         Talk to a (new) ECU: check the target, bind the transport to it,
 *                and start from the default session with the target's or the
 *                default timing.
 * @param[in,out] stpt_client Client.
 * @param[in]     stpt_target Target (copied).
 * @return        0; -EINVAL for NULL or a bad target; -ENOTSUP for extended
 *                addressing; otherwise the transport's bind error (the client is
 *                then unbound).
 */
int gi_UdsClient_SetTarget(UdsClient_T *stpt_client, const UdsTarget_T *stpt_target)
{
   int i_ret;

   if ((stpt_client == NULL) || (stpt_client->stpt_tp == NULL) || (stpt_target == NULL))
   {
      return -EINVAL;
   }

   i_ret = si_CheckTarget(stpt_target);
   if (i_ret != 0)
   {
      return i_ret;
   }

   gv_UdsClient_Close(stpt_client);
   stpt_client->st_target = *stpt_target;
   stpt_client->u32_p2Ms = (stpt_target->u16_p2Ms != 0U) ? stpt_target->u16_p2Ms : UDS_P2_MS;
   stpt_client->u32_p2StarMs = (stpt_target->u16_p2StarMs != 0U) ? stpt_target->u16_p2StarMs : UDS_P2STAR_MS;

   i_ret = stpt_client->stpt_tp->fpt_bind(stpt_client->stpt_tp->vpt_ctx, stpt_target);
   stpt_client->b_bound = (i_ret == 0);

   return i_ret;
}

/**
 * @public        gv_UdsClient_Close
 * @brief         Stop talking to the target: unbind the transport, forget the
 *                session.
 * @param[in,out] stpt_client Client.
 * @return        None.
 */
void gv_UdsClient_Close(UdsClient_T *stpt_client)
{
   if ((stpt_client == NULL) || (stpt_client->stpt_tp == NULL))
   {
      return;
   }

   if (stpt_client->b_bound)
   {
      stpt_client->stpt_tp->fpt_unbind(stpt_client->stpt_tp->vpt_ctx);
   }
   stpt_client->b_bound = false;
   stpt_client->b_session = false;
}

/**
 * @public        gi_UdsClient_Request
 * @brief         Send any request and wait for its response.
 * @param[in,out] stpt_client Client.
 * @param[in]     u8pt_req Request (SID first).
 * @param[in]     t_reqLen Request length (a functional one fits one classic frame:
 *                at most 7 bytes).
 * @param[in]     b_functional Send to the target's functional identifier.
 * @param[out]    u8pt_rsp Response buffer (positive or negative response).
 * @param[in]     t_rspMax Its size.
 * @param[out]    tpt_rspLen Response length; 0 if a suppressed positive response
 *                was not answered.
 * @return        0 for a positive response; the NRC (1..255) for a negative one
 *                (never 0x78 or 0x21 while retries last); -EINVAL for bad
 *                arguments; -ENOTCONN without a target; -ETIMEDOUT for no response
 *                within P2 (P2* after NRC 0x78); -EBADMSG for a positive response
 *                without the sub-function echo; -EMSGSIZE for a response longer
 *                than t_rspMax; otherwise the transport's error.
 */
int gi_UdsClient_Request(UdsClient_T *stpt_client, const uint8_t *u8pt_req, size_t t_reqLen,
   bool b_functional, uint8_t *u8pt_rsp, size_t t_rspMax, size_t *tpt_rspLen)
{
   if ((stpt_client == NULL) || (u8pt_req == NULL) || (t_reqLen == 0U) || (u8pt_rsp == NULL)
      || (t_rspMax == 0U) || (tpt_rspLen == NULL))
   {
      return -EINVAL;
   }
   *tpt_rspLen = 0U;
   if (!stpt_client->b_bound)
   {
      return -ENOTCONN;
   }

   // Check if a functional request is possible
   if (b_functional && (((stpt_client->st_target.u8_flags & UDS_TGT_FUNC) == 0U) || (t_reqLen > UDS_FUNC_SF_MAX)))
   {
      return -EINVAL;
   }

   return si_Exchange(stpt_client, u8pt_req, t_reqLen, b_functional, u8pt_rsp, t_rspMax, tpt_rspLen);
}

/**
 * @public        gi32_UdsClient_KeepAlive
 * @brief         Keep a non-default session alive: send TesterPresent (3E 80, no
 *                response) when nothing was sent for UDS_TESTER_PRESENT_MS. Call it
 *                from the owner's thread, at the latest when the returned time is
 *                up.
 * @param[in,out] stpt_client Client.
 * @return        Milliseconds until the next call is due, or UDS_KEEPALIVE_NONE if
 *                there is no session to keep.
 */
int32_t gi32_UdsClient_KeepAlive(UdsClient_T *stpt_client)
{
   int64_t i64_idle;
   int i_ret;

   if ((stpt_client == NULL) || !stpt_client->b_bound || !stpt_client->b_session)
   {
      return UDS_KEEPALIVE_NONE;
   }

   i64_idle = k_uptime_get() - stpt_client->i64_lastTxMs;
   if (i64_idle < UDS_TESTER_PRESENT_MS)
   {
      return (int32_t)(UDS_TESTER_PRESENT_MS - i64_idle);
   }

   i_ret = gi_UdsClient_TesterPresent(stpt_client);
   if (i_ret != 0)
   {
      LOG_WRN("TesterPresent failed (%d)", i_ret);
   }

   return UDS_TESTER_PRESENT_MS;
}

/**
 * @public        gv_UdsClient_EndSession
 * @brief         Stop keeping the session alive without a request (e.g. after a
 *                failed job): the ECU falls back to its default session once S3
 *                runs out.
 * @param[in,out] stpt_client Client.
 * @return        None.
 */
void gv_UdsClient_EndSession(UdsClient_T *stpt_client)
{
   if (stpt_client != NULL)
   {
      stpt_client->b_session = false;
   }
}

/**
 * @public        gi_UdsClient_Session
 * @brief         DiagnosticSessionControl (0x10). Takes the ECU's P2/P2* from the
 *                response (unless the target overrides them) and starts or stops
 *                the keep-alive.
 * @param[in,out] stpt_client Client.
 * @param[in]     u8_session Session (1 default, 2 programming, 3 extended, …).
 * @return        As gi_UdsClient_Request().
 */
int gi_UdsClient_Session(UdsClient_T *stpt_client, uint8_t u8_session)
{
   if (stpt_client == NULL)
   {
      return -EINVAL;
   }
   stpt_client->u8ar_req[0] = UDS_SID_SESSION;
   stpt_client->u8ar_req[1] = u8_session;
   return si_Simple(stpt_client, 2U, 2U);
}

/**
 * @public        gi_UdsClient_EcuReset
 * @brief         ECUReset (0x11). The ECU restarts in the default session.
 * @param[in,out] stpt_client Client.
 * @param[in]     u8_type Reset type (1 hard, 3 soft, …).
 * @return        As gi_UdsClient_Request().
 */
int gi_UdsClient_EcuReset(UdsClient_T *stpt_client, uint8_t u8_type)
{
   if (stpt_client == NULL)
   {
      return -EINVAL;
   }
   stpt_client->u8ar_req[0] = UDS_SID_ECU_RESET;
   stpt_client->u8ar_req[1] = u8_type;
   return si_Simple(stpt_client, 2U, 2U);
}

/**
 * @public        gi_UdsClient_CommControl
 * @brief         CommunicationControl (0x28).
 * @param[in,out] stpt_client Client.
 * @param[in]     u8_control controlType (0 enable, 3 disable RX and TX, …).
 * @param[in]     u8_type communicationType (1 normal messages, …).
 * @return        As gi_UdsClient_Request().
 */
int gi_UdsClient_CommControl(UdsClient_T *stpt_client, uint8_t u8_control, uint8_t u8_type)
{
   if (stpt_client == NULL)
   {
      return -EINVAL;
   }
   stpt_client->u8ar_req[0] = UDS_SID_COMM_CONTROL;
   stpt_client->u8ar_req[1] = u8_control;
   stpt_client->u8ar_req[2] = u8_type;
   return si_Simple(stpt_client, 3U, 2U);
}

/**
 * @public        gi_UdsClient_DtcSetting
 * @brief         ControlDTCSetting (0x85).
 * @param[in,out] stpt_client Client.
 * @param[in]     u8_type 1 on, 2 off.
 * @return        As gi_UdsClient_Request().
 */
int gi_UdsClient_DtcSetting(UdsClient_T *stpt_client, uint8_t u8_type)
{
   if (stpt_client == NULL)
   {
      return -EINVAL;
   }
   stpt_client->u8ar_req[0] = UDS_SID_DTC_SETTING;
   stpt_client->u8ar_req[1] = u8_type;
   return si_Simple(stpt_client, 2U, 2U);
}

/**
 * @public        gi_UdsClient_SecurityAccess
 * @brief         SecurityAccess (0x27): request the seed of a level, compute the
 *                key with fpt_key, send it. An all-zero seed means the level is
 *                unlocked already: no key is sent.
 * @param[in,out] stpt_client Client.
 * @param[in]     u8_level requestSeed level: odd, 0x01..0x7D.
 * @param[in]     fpt_key Seed -> key.
 * @param[in]     vpt_user Passed to fpt_key.
 * @return        As gi_UdsClient_Request() (the NRC of either request: 0x35
 *                invalidKey, 0x36 exceededNumberOfAttempts, 0x37
 *                requiredTimeDelayNotExpired, …); -EINVAL for an even or out-of-range
 *                level or NULL; -EBADMSG for an empty seed; -EMSGSIZE for a seed or
 *                key that does not fit; fpt_key's error.
 */
int gi_UdsClient_SecurityAccess(UdsClient_T *stpt_client, uint8_t u8_level, UdsKey_F fpt_key,
   void *vpt_user)
{
   uint8_t u8ar_seed[UDS_CLIENT_BUF_SIZE];
   size_t t_seedLen;
   size_t t_keyLen = 0U;
   size_t t_rspLen = 0U;
   bool b_zero = true;
   size_t i;
   int i_ret;

   if ((stpt_client == NULL) || (fpt_key == NULL) || ((u8_level & 1U) == 0U) || (u8_level > 0x7DU))
   {
      return -EINVAL;
   }

   // requestSeed
   stpt_client->u8ar_req[0] = UDS_SID_SECURITY;
   stpt_client->u8ar_req[1] = u8_level;
   i_ret = gi_UdsClient_Request(stpt_client, stpt_client->u8ar_req, 2U, false, stpt_client->u8ar_rsp,
      sizeof(stpt_client->u8ar_rsp), &t_rspLen);
   if (i_ret != 0)
   {
      return i_ret;
   }
   if (t_rspLen < 3U)
   {
      return -EBADMSG;
   }
   t_seedLen = t_rspLen - 2U;
   memcpy(u8ar_seed, &stpt_client->u8ar_rsp[2], t_seedLen);
   for (i = 0U; i < t_seedLen; i++)
   {
      b_zero = b_zero && (u8ar_seed[i] == 0U);
   }

   // Check if the level is unlocked already
   if (b_zero)
   {
      LOG_INF("security level 0x%02x already unlocked", u8_level);
      return 0;
   }

   // sendKey: [27][level + 1][key]
   i_ret = fpt_key(u8_level, u8ar_seed, t_seedLen, &stpt_client->u8ar_req[2], sizeof(stpt_client->u8ar_req) - 2U,
      &t_keyLen, vpt_user);
   if (i_ret != 0)
   {
      return i_ret;
   }
   if ((t_keyLen == 0U) || (t_keyLen > (sizeof(stpt_client->u8ar_req) - 2U)))
   {
      return -EMSGSIZE;
   }
   stpt_client->u8ar_req[0] = UDS_SID_SECURITY;
   stpt_client->u8ar_req[1] = (uint8_t)(u8_level + 1U);
   return si_Simple(stpt_client, 2U + t_keyLen, 2U);
}

/**
 * @public        gi_UdsClient_ReadDid
 * @brief         ReadDataByIdentifier (0x22) of one DID.
 * @param[in,out] stpt_client Client.
 * @param[in]     u16_did Data identifier.
 * @param[out]    u8pt_data Buffer: the whole response lands here, then only the
 *                data record is kept (so it needs 3 bytes more than the data).
 * @param[in]     t_max Its size (at least 3).
 * @param[out]    tpt_len Data length.
 * @return        As gi_UdsClient_Request(); -EBADMSG if the DID is not echoed.
 */
int gi_UdsClient_ReadDid(UdsClient_T *stpt_client, uint16_t u16_did, uint8_t *u8pt_data, size_t t_max,
   size_t *tpt_len)
{
   uint8_t u8ar_req[3];
   size_t t_rspLen = 0U;
   int i_ret;

   if ((stpt_client == NULL) || (u8pt_data == NULL) || (t_max < 3U) || (tpt_len == NULL))
   {
      return -EINVAL;
   }
   *tpt_len = 0U;

   u8ar_req[0] = UDS_SID_READ_DID;
   sv_PutBe(&u8ar_req[1], u16_did, 2U);
   i_ret = gi_UdsClient_Request(stpt_client, u8ar_req, sizeof(u8ar_req), false, u8pt_data, t_max, &t_rspLen);
   if (i_ret != 0)
   {
      return i_ret;
   }
   if ((t_rspLen < 3U) || (u8pt_data[1] != u8ar_req[1]) || (u8pt_data[2] != u8ar_req[2]))
   {
      return -EBADMSG;
   }

   *tpt_len = t_rspLen - 3U;
   memmove(u8pt_data, &u8pt_data[3], *tpt_len);
   return 0;
}

/**
 * @public        gi_UdsClient_WriteDid
 * @brief         WriteDataByIdentifier (0x2E).
 * @param[in,out] stpt_client Client.
 * @param[in]     u16_did Data identifier.
 * @param[in]     u8pt_data Data record.
 * @param[in]     t_len 1..UDS_CLIENT_BUF_SIZE - 3 bytes.
 * @return        As gi_UdsClient_Request(); -EMSGSIZE for data too long; -EBADMSG
 *                if the DID is not echoed.
 */
int gi_UdsClient_WriteDid(UdsClient_T *stpt_client, uint16_t u16_did, const uint8_t *u8pt_data, size_t t_len)
{
   int i_ret;

   if ((stpt_client == NULL) || (u8pt_data == NULL) || (t_len == 0U))
   {
      return -EINVAL;
   }
   if (t_len > (sizeof(stpt_client->u8ar_req) - 3U))
   {
      return -EMSGSIZE;
   }

   stpt_client->u8ar_req[0] = UDS_SID_WRITE_DID;
   sv_PutBe(&stpt_client->u8ar_req[1], u16_did, 2U);
   memcpy(&stpt_client->u8ar_req[3], u8pt_data, t_len);
   i_ret = si_Simple(stpt_client, 3U + t_len, 3U);
   if ((i_ret == 0) && ((stpt_client->u8ar_rsp[1] != stpt_client->u8ar_req[1])
      || (stpt_client->u8ar_rsp[2] != stpt_client->u8ar_req[2])))
   {
      i_ret = -EBADMSG;
   }

   return i_ret;
}

/**
 * @public        gi_UdsClient_Routine
 * @brief         RoutineControl (0x31).
 * @param[in,out] stpt_client Client.
 * @param[in]     u8_type 1 start, 2 stop, 3 request results.
 * @param[in]     u16_rid Routine identifier.
 * @param[in]     u8pt_args routineControlOptionRecord, or NULL.
 * @param[in]     t_argLen Its length (at most UDS_CLIENT_BUF_SIZE - 4).
 * @param[out]    u8pt_status routineStatusRecord, or NULL.
 * @param[in]     t_statusMax Its size (a longer record is cut).
 * @param[out]    tpt_statusLen Bytes written to u8pt_status, or NULL.
 * @return        As gi_UdsClient_Request(); -EMSGSIZE for arguments too long;
 *                -EBADMSG if the routine identifier is not echoed.
 */
int gi_UdsClient_Routine(UdsClient_T *stpt_client, uint8_t u8_type, uint16_t u16_rid,
   const uint8_t *u8pt_args, size_t t_argLen, uint8_t *u8pt_status, size_t t_statusMax,
   size_t *tpt_statusLen)
{
   size_t t_rspLen = 0U;
   size_t t_copy;
   int i_ret;

   if ((stpt_client == NULL) || ((u8pt_args == NULL) && (t_argLen != 0U)))
   {
      return -EINVAL;
   }
   if (tpt_statusLen != NULL)
   {
      *tpt_statusLen = 0U;
   }
   if (t_argLen > (sizeof(stpt_client->u8ar_req) - 4U))
   {
      return -EMSGSIZE;
   }

   stpt_client->u8ar_req[0] = UDS_SID_ROUTINE;
   stpt_client->u8ar_req[1] = u8_type;
   sv_PutBe(&stpt_client->u8ar_req[2], u16_rid, 2U);
   if (t_argLen > 0U)
   {
      memcpy(&stpt_client->u8ar_req[4], u8pt_args, t_argLen);
   }
   i_ret = gi_UdsClient_Request(stpt_client, stpt_client->u8ar_req, 4U + t_argLen, false, stpt_client->u8ar_rsp,
      sizeof(stpt_client->u8ar_rsp), &t_rspLen);
   if (i_ret != 0)
   {
      return i_ret;
   }
   if ((t_rspLen < 4U) || (stpt_client->u8ar_rsp[2] != stpt_client->u8ar_req[2])
      || (stpt_client->u8ar_rsp[3] != stpt_client->u8ar_req[3]))
   {
      return -EBADMSG;
   }

   // Check if the caller wants the status record
   if ((u8pt_status != NULL) && (tpt_statusLen != NULL))
   {
      t_copy = MIN(t_rspLen - 4U, t_statusMax);
      memcpy(u8pt_status, &stpt_client->u8ar_rsp[4], t_copy);
      *tpt_statusLen = t_copy;
   }

   return 0;
}

/**
 * @public        gi_UdsClient_RequestDownload
 * @brief         RequestDownload (0x34): announce a block of memory to write.
 * @param[in,out] stpt_client Client.
 * @param[in]     u8_dfi dataFormatIdentifier (0x00: neither compressed nor
 *                encrypted).
 * @param[in]     u8_alfid addressAndLengthFormatIdentifier: high nibble = size
 *                bytes, low nibble = address bytes, each 1..4.
 * @param[in]     u32_address memoryAddress.
 * @param[in]     u32_size memorySize.
 * @param[out]    u32pt_maxBlock maxNumberOfBlockLength: the longest TransferData
 *                request, SID and block counter included.
 * @return        As gi_UdsClient_Request(); -EINVAL for a bad ALFID or a value
 *                that does not fit its bytes; -EBADMSG for a response without a
 *                usable block length (fewer than 3 bytes).
 */
int gi_UdsClient_RequestDownload(UdsClient_T *stpt_client, uint8_t u8_dfi, uint8_t u8_alfid,
   uint32_t u32_address, uint32_t u32_size, uint32_t *u32pt_maxBlock)
{
   uint8_t u8_addrLen = (uint8_t)(u8_alfid & 0x0FU);
   uint8_t u8_sizeLen = (uint8_t)(u8_alfid >> 4);
   uint8_t u8_lenBytes;
   uint32_t u32_max = 0U;
   size_t t_rspLen = 0U;
   uint8_t i;
   int i_ret;

   if ((stpt_client == NULL) || (u32pt_maxBlock == NULL) || (u8_addrLen == 0U) || (u8_addrLen > 4U)
      || (u8_sizeLen == 0U) || (u8_sizeLen > 4U)
      || ((u8_addrLen < 4U) && ((u32_address >> (8U * u8_addrLen)) != 0U))
      || ((u8_sizeLen < 4U) && ((u32_size >> (8U * u8_sizeLen)) != 0U)))
   {
      return -EINVAL;
   }
   *u32pt_maxBlock = 0U;

   stpt_client->u8ar_req[0] = UDS_SID_REQUEST_DOWNLOAD;
   stpt_client->u8ar_req[1] = u8_dfi;
   stpt_client->u8ar_req[2] = u8_alfid;
   sv_PutBe(&stpt_client->u8ar_req[3], u32_address, u8_addrLen);
   sv_PutBe(&stpt_client->u8ar_req[3U + u8_addrLen], u32_size, u8_sizeLen);
   i_ret = gi_UdsClient_Request(stpt_client, stpt_client->u8ar_req, 3U + u8_addrLen + u8_sizeLen, false,
      stpt_client->u8ar_rsp, sizeof(stpt_client->u8ar_rsp), &t_rspLen);
   if (i_ret != 0)
   {
      return i_ret;
   }

   // [74][lengthFormatIdentifier: high nibble = bytes][maxNumberOfBlockLength]
   u8_lenBytes = (t_rspLen >= 2U) ? (uint8_t)(stpt_client->u8ar_rsp[1] >> 4) : 0U;
   if ((u8_lenBytes == 0U) || (t_rspLen < (2U + (size_t)u8_lenBytes)))
   {
      return -EBADMSG;
   }
   for (i = 0U; i < u8_lenBytes; i++)
   {
      // A length beyond 32 bits is more than the tester can send anyway
      u32_max = (u32_max > 0x00FFFFFFUL) ? 0xFFFFFFFFUL : ((u32_max << 8) | stpt_client->u8ar_rsp[2U + i]);
   }
   if (u32_max < 3U)
   {
      return -EBADMSG;
   }

   *u32pt_maxBlock = u32_max;
   return 0;
}

/**
 * @public        gi_UdsClient_TransferData
 * @brief         TransferData (0x36) of one block, sent from the caller's buffer
 *                without a copy.
 * @param[in,out] stpt_client Client.
 * @param[in]     u8_bsc blockSequenceCounter (1, 2, … 0xFF, 0x00, …).
 * @param[in,out] u8pt_req The request: 2 free bytes, then the data; the SID and
 *                counter are written into the free bytes.
 * @param[in]     t_dataLen Data length (1..maxNumberOfBlockLength - 2).
 * @return        As gi_UdsClient_Request(); -EBADMSG if the counter is not echoed.
 */
int gi_UdsClient_TransferData(UdsClient_T *stpt_client, uint8_t u8_bsc, uint8_t *u8pt_req, size_t t_dataLen)
{
   size_t t_rspLen = 0U;
   int i_ret;

   if ((stpt_client == NULL) || (u8pt_req == NULL) || (t_dataLen == 0U))
   {
      return -EINVAL;
   }

   u8pt_req[0] = UDS_SID_TRANSFER_DATA;
   u8pt_req[1] = u8_bsc;
   i_ret = gi_UdsClient_Request(stpt_client, u8pt_req, 2U + t_dataLen, false, stpt_client->u8ar_rsp,
      sizeof(stpt_client->u8ar_rsp), &t_rspLen);
   if ((i_ret == 0) && ((t_rspLen < 2U) || (stpt_client->u8ar_rsp[1] != u8_bsc)))
   {
      i_ret = -EBADMSG;
   }

   return i_ret;
}

/**
 * @public        gi_UdsClient_TransferExit
 * @brief         RequestTransferExit (0x37).
 * @param[in,out] stpt_client Client.
 * @return        As gi_UdsClient_Request().
 */
int gi_UdsClient_TransferExit(UdsClient_T *stpt_client)
{
   if (stpt_client == NULL)
   {
      return -EINVAL;
   }
   stpt_client->u8ar_req[0] = UDS_SID_TRANSFER_EXIT;
   return si_Simple(stpt_client, 1U, 1U);
}

/**
 * @public        gi_UdsClient_TesterPresent
 * @brief         TesterPresent (3E 80): no positive response is awaited; a
 *                negative one, if any, is returned.
 * @param[in,out] stpt_client Client.
 * @return        As gi_UdsClient_Request().
 */
int gi_UdsClient_TesterPresent(UdsClient_T *stpt_client)
{
   if (stpt_client == NULL)
   {
      return -EINVAL;
   }
   stpt_client->u8ar_req[0] = UDS_SID_TESTER_PRESENT;
   stpt_client->u8ar_req[1] = UDS_SUPPRESS_POS_RSP;
   return si_Simple(stpt_client, 2U, 0U);
}

/**
 * @public        gu8_UdsClient_LastNrc
 * @brief         NRC of the last request (0 if it got none).
 * @param[in]     stpt_client Client.
 * @return        The NRC.
 */
uint8_t gu8_UdsClient_LastNrc(const UdsClient_T *stpt_client)
{
   return (stpt_client != NULL) ? stpt_client->u8_lastNrc : 0U;
}

/**
 * @public        gu8_UdsClient_LastSid
 * @brief         SID of the last request sent.
 * @param[in]     stpt_client Client.
 * @return        The SID (0 before the first).
 */
uint8_t gu8_UdsClient_LastSid(const UdsClient_T *stpt_client)
{
   return (stpt_client != NULL) ? stpt_client->u8_lastSid : 0U;
}
