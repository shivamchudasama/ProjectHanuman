/**
 * @file          UdsTp_Isotp.c
 * @brief         The UDS client's transport on Zephyr's ISO-TP. Binding listens on
 *                the response identifier (flow control: block size 0, STmin 0, so
 *                the ECU sends a long response in one go); a request is sent with
 *                a blocking isotp_send() to the physical or functional identifier.
 *                isotp_recv() hands a long message over in pieces, so a receive that
 *                fills the buffer drains the rest of that message and reports
 *                -EMSGSIZE: a leftover must never pass for the next response.
 *                Zephyr's ISO-TP runs on the system work queue; never call this
 *                from there. See _DOC/UdsClient/API_REFERENCE.md.
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
#include "UdsTp_Isotp.h"
#include <errno.h>
#include <string.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(UdsTpIsotp, LOG_LEVEL_INF);

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
/**
 * @def           UDS_TP_DRAIN_BUF
 * @brief         Scratch buffer that discards the rest of an oversized message.
 */
#define UDS_TP_DRAIN_BUF                     (32U)

/**
 * @def           UDS_TP_FUNC_MAX
 * @brief         Longest functional request: one classic single frame.
 */
#define UDS_TP_FUNC_MAX                      (7U)

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
static void sv_SetAddr(struct isotp_msg_id *stpt_addr, uint32_t u32_id, uint8_t u8_flags, uint8_t u8_dl);
static int si_Bind(void *vpt_ctx, const UdsTarget_T *stpt_target);
static void sv_Unbind(void *vpt_ctx);
static int si_Send(void *vpt_ctx, const uint8_t *u8pt_data, size_t t_len, bool b_functional);
static int si_Recv(void *vpt_ctx, uint8_t *u8pt_buf, size_t t_max, k_timeout_t t_timeout);

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
 * @private       sv_SetAddr
 * @brief         Fill an ISO-TP address.
 * @param[out]    stpt_addr Address.
 * @param[in]     u32_id CAN identifier.
 * @param[in]     u8_flags UDS_TGT_* flags of the target.
 * @param[in]     u8_dl Frame length (0: 8, or 64 with CAN FD).
 * @return        None.
 */
static void sv_SetAddr(struct isotp_msg_id *stpt_addr, uint32_t u32_id, uint8_t u8_flags, uint8_t u8_dl)
{
   memset(stpt_addr, 0, sizeof(*stpt_addr));
   if ((u8_flags & UDS_TGT_EXT_ID) != 0U)
   {
      stpt_addr->ext_id = u32_id;
      stpt_addr->flags |= ISOTP_MSG_IDE;
   }
   else
   {
      stpt_addr->std_id = u32_id;
   }
   if ((u8_flags & UDS_TGT_FD) != 0U)
   {
      stpt_addr->flags |= ISOTP_MSG_FDF;
   }
   if ((u8_flags & UDS_TGT_BRS) != 0U)
   {
      stpt_addr->flags |= ISOTP_MSG_BRS;
   }
   stpt_addr->dl = u8_dl;
}

/**
 * @private       si_Bind
 * @brief         UdsTp_T bind: listen on the target's response identifier.
 * @param[in]     vpt_ctx UdsTpIsotp_T.
 * @param[in]     stpt_target Target (checked by the client).
 * @return        0; -ENODEV without a CAN controller; -ENOSPC if the controller has
 *                no filter left; otherwise gi_UdsTpIsotp_Errno() of the error.
 */
static int si_Bind(void *vpt_ctx, const UdsTarget_T *stpt_target)
{
   UdsTpIsotp_T *stpt_ctx = (UdsTpIsotp_T *)vpt_ctx;
   struct isotp_fc_opts st_fc = { .bs = 0U, .stmin = 0U };
   int i_ret;

   sv_Unbind(vpt_ctx);
   if (stpt_ctx->stpt_can == NULL)
   {
      return -ENODEV;
   }

   sv_SetAddr(&stpt_ctx->st_txAddr, stpt_target->u32_txId, stpt_target->u8_flags, stpt_target->u8_txDl);
   sv_SetAddr(&stpt_ctx->st_rxAddr, stpt_target->u32_rxId, stpt_target->u8_flags, 0U);
   sv_SetAddr(&stpt_ctx->st_funcAddr, stpt_target->u32_funcId, stpt_target->u8_flags, stpt_target->u8_txDl);
   stpt_ctx->b_func = ((stpt_target->u8_flags & UDS_TGT_FUNC) != 0U);

   // Responses arrive on rxId; our flow control frames go out on txId
   i_ret = isotp_bind(&stpt_ctx->st_recv, stpt_ctx->stpt_can, &stpt_ctx->st_rxAddr, &stpt_ctx->st_txAddr, &st_fc,
      K_NO_WAIT);
   if (i_ret != ISOTP_N_OK)
   {
      stpt_ctx->i_lastIsotpErr = i_ret;
      LOG_ERR("isotp_bind failed (%d)", i_ret);
      return gi_UdsTpIsotp_Errno(i_ret);
   }

   stpt_ctx->b_bound = true;
   return 0;
}

/**
 * @private       sv_Unbind
 * @brief         UdsTp_T unbind.
 * @param[in]     vpt_ctx UdsTpIsotp_T.
 * @return        None.
 */
static void sv_Unbind(void *vpt_ctx)
{
   UdsTpIsotp_T *stpt_ctx = (UdsTpIsotp_T *)vpt_ctx;

   if (stpt_ctx->b_bound)
   {
      isotp_unbind(&stpt_ctx->st_recv);
      stpt_ctx->b_bound = false;
   }
}

/**
 * @private       si_Send
 * @brief         UdsTp_T send: one request, blocking until it is on the bus.
 * @param[in]     vpt_ctx UdsTpIsotp_T.
 * @param[in]     u8pt_data Request.
 * @param[in]     t_len Its length.
 * @param[in]     b_functional To the functional identifier (one single frame).
 * @return        0; -ENOTCONN if not bound; -EINVAL for a functional request
 *                without a functional identifier; -EMSGSIZE for one longer than a
 *                single frame; otherwise gi_UdsTpIsotp_Errno() of the error.
 */
static int si_Send(void *vpt_ctx, const uint8_t *u8pt_data, size_t t_len, bool b_functional)
{
   UdsTpIsotp_T *stpt_ctx = (UdsTpIsotp_T *)vpt_ctx;
   int i_ret;

   if (!stpt_ctx->b_bound)
   {
      return -ENOTCONN;
   }
   if (b_functional && !stpt_ctx->b_func)
   {
      return -EINVAL;
   }
   if (b_functional && (t_len > UDS_TP_FUNC_MAX))
   {
      return -EMSGSIZE;
   }

   i_ret = isotp_send(&stpt_ctx->st_send, stpt_ctx->stpt_can, u8pt_data, t_len,
      b_functional ? &stpt_ctx->st_funcAddr : &stpt_ctx->st_txAddr, &stpt_ctx->st_rxAddr, NULL, NULL);
   if (i_ret != ISOTP_N_OK)
   {
      stpt_ctx->i_lastIsotpErr = i_ret;
      LOG_WRN("isotp_send failed (%d)", i_ret);
      return gi_UdsTpIsotp_Errno(i_ret);
   }

   return 0;
}

/**
 * @private       si_Recv
 * @brief         UdsTp_T recv: one whole message.
 * @param[in]     vpt_ctx UdsTpIsotp_T.
 * @param[out]    u8pt_buf Buffer.
 * @param[in]     t_max Its size.
 * @param[in]     t_timeout Wait.
 * @return        The message length; -EAGAIN on timeout; -ENOTCONN if not bound;
 *                -EMSGSIZE if the message did not fit (its rest is discarded);
 *                otherwise gi_UdsTpIsotp_Errno() of the reception error.
 */
static int si_Recv(void *vpt_ctx, uint8_t *u8pt_buf, size_t t_max, k_timeout_t t_timeout)
{
   UdsTpIsotp_T *stpt_ctx = (UdsTpIsotp_T *)vpt_ctx;
   uint8_t u8ar_scratch[UDS_TP_DRAIN_BUF];
   int i_ret;

   if (!stpt_ctx->b_bound)
   {
      return -ENOTCONN;
   }

   i_ret = isotp_recv(&stpt_ctx->st_recv, u8pt_buf, t_max, t_timeout);
   if (i_ret == ISOTP_RECV_TIMEOUT)
   {
      return -EAGAIN;
   }
   if (i_ret < 0)
   {
      stpt_ctx->i_lastIsotpErr = i_ret;
      LOG_WRN("isotp_recv failed (%d)", i_ret);
      return gi_UdsTpIsotp_Errno(i_ret);
   }

   // Check if part of the message is still waiting: it did not fit
   if (stpt_ctx->st_recv.recv_buf != NULL)
   {
      while ((stpt_ctx->st_recv.recv_buf != NULL)
         && (isotp_recv(&stpt_ctx->st_recv, u8ar_scratch, sizeof(u8ar_scratch), K_NO_WAIT) > 0))
      {
      }
      LOG_WRN("message longer than %u bytes discarded", (unsigned int)t_max);
      return -EMSGSIZE;
   }

   return i_ret;
}

/******************************************************************************/
/*                                                                            */
/*                        PUBLIC FUNCTION DEFINITIONS                         */
/*                                                                            */
/******************************************************************************/
/**
 * @public        gv_UdsTpIsotp_Init
 * @brief         Make stpt_tp the ISO-TP transport kept in stpt_ctx (both must
 *                outlive the client that uses them).
 * @param[out]    stpt_tp Transport for gi_UdsClient_Init().
 * @param[out]    stpt_ctx Its state.
 * @param[in]     stpt_can CAN controller (gstpt_CanIf_GetDevice()); NULL makes every
 *                bind fail with -ENODEV.
 * @return        None.
 */
void gv_UdsTpIsotp_Init(UdsTp_T *stpt_tp, UdsTpIsotp_T *stpt_ctx, const struct device *stpt_can)
{
   memset(stpt_ctx, 0, sizeof(*stpt_ctx));
   stpt_ctx->stpt_can = stpt_can;

   stpt_tp->fpt_bind = si_Bind;
   stpt_tp->fpt_unbind = sv_Unbind;
   stpt_tp->fpt_send = si_Send;
   stpt_tp->fpt_recv = si_Recv;
   stpt_tp->vpt_ctx = stpt_ctx;
}

/**
 * @public        gi_UdsTpIsotp_Errno
 * @brief         Map an ISO-TP error to an errno.
 * @param[in]     i_isotpErr ISOTP_N_* or ISOTP_* (negative).
 * @return        -ETIMEDOUT for the N_As/N_Bs/N_Cr timeouts; -ENOSPC without a
 *                free filter; -ENOMEM without a buffer or context; -EMSGSIZE for a
 *                buffer overflow; -EIO for any other protocol error; 0 for
 *                ISOTP_N_OK.
 */
int gi_UdsTpIsotp_Errno(int i_isotpErr)
{
   switch (i_isotpErr)
   {
      case ISOTP_N_OK:
         return 0;

      case ISOTP_N_TIMEOUT_A:
      case ISOTP_N_TIMEOUT_BS:
      case ISOTP_N_TIMEOUT_CR:
         return -ETIMEDOUT;

      case ISOTP_NO_FREE_FILTER:
         return -ENOSPC;

      case ISOTP_NO_NET_BUF_LEFT:
      case ISOTP_NO_BUF_DATA_LEFT:
      case ISOTP_NO_CTX_LEFT:
         return -ENOMEM;

      case ISOTP_N_BUFFER_OVERFLW:
         return -EMSGSIZE;

      default:
         return -EIO;
   }
}
