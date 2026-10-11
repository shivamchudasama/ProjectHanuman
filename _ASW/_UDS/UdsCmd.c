/**
 * @file          UdsCmd.c
 * @brief         Source file containing UDS over BLE. The router callback (SETU
 *                engine thread) only decodes a message and hands it to UdsJob, or
 *                refuses it at once; the outcome is sent from the job thread: RESULT
 *                for TARGET, UNLOCK, FLASH and ABORT, DIAG_RSP (in parts) for a
 *                diagnostic request, STATUS for a flash job's progress. Contract:
 *                _DOC/UDS/PROTOCOL.md.
 * @date          12/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include "UdsCmd.h"
#include <errno.h>
#include <string.h>
#include <zephyr/sys/byteorder.h>
#include "SETU.h"
#include "SETURouter.h"
#include "UdsJob.h"
#include "AppLog.h"

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
/**
 * @def           UDSCMD_SHORT_TIMEOUT_MS
 * @brief         Maximum wait for a CTRL credit when sending a reply.
 */
#define UDSCMD_SHORT_TIMEOUT_MS              (200)

/**
 * @def           UDSCMD_DIAG_HDR_LEN
 * @brief         [seq][flags] in front of a DIAG_REQ's request.
 */
#define UDSCMD_DIAG_HDR_LEN                  (2U)

/**
 * @def           UDSCMD_RSP_HDR_LEN
 * @brief         [seq][status][u16 total][u16 offset] in front of a DIAG_RSP part.
 */
#define UDSCMD_RSP_HDR_LEN                   (6U)

/**
 * @def           UDSCMD_DIAG_FUNCTIONAL
 * @brief         DIAG_REQ flag: send to the functional identifier.
 */
#define UDSCMD_DIAG_FUNCTIONAL               (0x01U)

/**
 * @def           UDSCMD_TGT_EXT_ADDR
 * @brief         TARGET flag: extended addressing (uses the ext addr byte).
 */
#define UDSCMD_TGT_EXT_ADDR                  (0x10U)

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
static void sv_Send(uint8_t u8_appType, const uint8_t *u8pt_data, uint8_t u8_len);
static void sv_SendResult(uint8_t u8_seq, uint8_t u8_refType, uint8_t u8_status, const uint8_t *u8pt_data,
   uint8_t u8_len);
static void sv_SendDiagRsp(uint8_t u8_seq, uint8_t u8_status, const uint8_t *u8pt_rsp, size_t t_len);
static void sv_SendStatus(const UdsJobStatus_T *stpt_status);
static void sv_OnTargetDone(uint8_t u8_result, const uint8_t *u8pt_data, size_t t_len, void *vpt_user);
static void sv_OnUnlockDone(uint8_t u8_result, const uint8_t *u8pt_data, size_t t_len, void *vpt_user);
static void sv_OnDiagDone(uint8_t u8_result, const uint8_t *u8pt_data, size_t t_len, void *vpt_user);
static void sv_OnFlashStatus(const UdsJobStatus_T *stpt_status, void *vpt_user);
static uint8_t su8_Target(const uint8_t *u8pt_data);
static uint8_t su8_Flash(const uint8_t *u8pt_data, uint8_t u8_len);
static void sv_OnRxShort(uint8_t u8_appType, const uint8_t *u8pt_data, uint8_t u8_len);

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
/**
 * @var           su8ar_part
 * @brief         A DIAG_RSP part (job thread).
 */
static uint8_t su8ar_part[UDSCMD_RSP_HDR_LEN + UDSCMD_PART_MAX];

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
 * @private       sv_Send
 * @brief         Send a short message to the host; a failure is only logged.
 * @param[in]     u8_appType appType.
 * @param[in]     u8pt_data Payload.
 * @param[in]     u8_len Payload length.
 * @return        None.
 */
static void sv_Send(uint8_t u8_appType, const uint8_t *u8pt_data, uint8_t u8_len)
{
   int i_ret = gi_SETUS_SendShort(u8_appType, u8pt_data, u8_len, K_MSEC(UDSCMD_SHORT_TIMEOUT_MS));

   // Check if the reply could not be sent (no link, not subscribed, no credit)
   if (i_ret != 0)
   {
      APP_LOG_WRN("0x%02x not sent (%d)", u8_appType, i_ret);
   }
}

/**
 * @private       sv_SendResult
 * @brief         RESULT [seq][refAppType][status][data].
 * @param[in]     u8_seq Sequence number of the request.
 * @param[in]     u8_refType Its appType.
 * @param[in]     u8_status UdsResult_E.
 * @param[in]     u8pt_data Data, or NULL.
 * @param[in]     u8_len Data length (0 or 1).
 * @return        None.
 */
static void sv_SendResult(uint8_t u8_seq, uint8_t u8_refType, uint8_t u8_status, const uint8_t *u8pt_data,
   uint8_t u8_len)
{
   uint8_t u8ar_msg[4];

   u8ar_msg[0] = u8_seq;
   u8ar_msg[1] = u8_refType;
   u8ar_msg[2] = u8_status;
   u8_len = MIN(u8_len, 1U);
   if (u8_len > 0U)
   {
      u8ar_msg[3] = u8pt_data[0];
   }
   sv_Send(UDSCMD_APP_TYPE_RESULT, u8ar_msg, (uint8_t)(3U + u8_len));
}

/**
 * @private       sv_SendDiagRsp
 * @brief         DIAG_RSP: the response in parts of UDSCMD_PART_MAX, each
 *                [seq][status][u16 total][u16 offset][bytes]; none: one part with
 *                total 0.
 * @param[in]     u8_seq Sequence number of the request.
 * @param[in]     u8_status UdsResult_E.
 * @param[in]     u8pt_rsp Response, or NULL.
 * @param[in]     t_len Its length.
 * @return        None.
 */
static void sv_SendDiagRsp(uint8_t u8_seq, uint8_t u8_status, const uint8_t *u8pt_rsp, size_t t_len)
{
   size_t t_off = 0U;
   size_t t_part;

   do
   {
      t_part = MIN(t_len - t_off, UDSCMD_PART_MAX);
      su8ar_part[0] = u8_seq;
      su8ar_part[1] = u8_status;
      sys_put_le16((uint16_t)t_len, &su8ar_part[2]);
      sys_put_le16((uint16_t)t_off, &su8ar_part[4]);
      if (t_part > 0U)
      {
         memcpy(&su8ar_part[UDSCMD_RSP_HDR_LEN], &u8pt_rsp[t_off], t_part);
      }
      sv_Send(UDSCMD_APP_TYPE_DIAG_RSP, su8ar_part, (uint8_t)(UDSCMD_RSP_HDR_LEN + t_part));
      t_off += t_part;
   } while (t_off < t_len);
}

/**
 * @private       sv_SendStatus
 * @brief         STATUS [state][step][rec idx][rec cnt][u32 done][u32 total]
 *                [last SID][last NRC][status].
 * @param[in]     stpt_status Status.
 * @return        None.
 */
static void sv_SendStatus(const UdsJobStatus_T *stpt_status)
{
   uint8_t u8ar_msg[UDSCMD_STATUS_LEN];

   u8ar_msg[0] = stpt_status->u8_state;
   u8ar_msg[1] = stpt_status->u8_step;
   u8ar_msg[2] = stpt_status->u8_recIdx;
   u8ar_msg[3] = stpt_status->u8_recCnt;
   sys_put_le32(stpt_status->u32_done, &u8ar_msg[4]);
   sys_put_le32(stpt_status->u32_total, &u8ar_msg[8]);
   u8ar_msg[12] = stpt_status->u8_lastSid;
   u8ar_msg[13] = stpt_status->u8_lastNrc;
   u8ar_msg[14] = stpt_status->u8_result;
   sv_Send(UDSCMD_APP_TYPE_STATUS, u8ar_msg, sizeof(u8ar_msg));
}

/**
 * @private       sv_OnTargetDone
 * @brief         UdsJobResult_F of TARGET: RESULT.
 * @param[in]     u8_result UdsResult_E.
 * @param[in]     u8pt_data Unused.
 * @param[in]     t_len Unused.
 * @param[in]     vpt_user The sequence number.
 * @return        None.
 */
static void sv_OnTargetDone(uint8_t u8_result, const uint8_t *u8pt_data, size_t t_len, void *vpt_user)
{
   ARG_UNUSED(u8pt_data);
   ARG_UNUSED(t_len);
   sv_SendResult((uint8_t)(uintptr_t)vpt_user, UDSCMD_APP_TYPE_TARGET, u8_result, NULL, 0U);
}

/**
 * @private       sv_OnUnlockDone
 * @brief         UdsJobResult_F of UNLOCK: RESULT, with the NRC if any.
 * @param[in]     u8_result UdsResult_E.
 * @param[in]     u8pt_data The NRC, or NULL.
 * @param[in]     t_len 0 or 1.
 * @param[in]     vpt_user The sequence number.
 * @return        None.
 */
static void sv_OnUnlockDone(uint8_t u8_result, const uint8_t *u8pt_data, size_t t_len, void *vpt_user)
{
   sv_SendResult((uint8_t)(uintptr_t)vpt_user, UDSCMD_APP_TYPE_UNLOCK, u8_result, u8pt_data, (uint8_t)t_len);
}

/**
 * @private       sv_OnDiagDone
 * @brief         UdsJobResult_F of DIAG_REQ: DIAG_RSP.
 * @param[in]     u8_result UdsResult_E.
 * @param[in]     u8pt_data The ECU's response, or NULL.
 * @param[in]     t_len Its length.
 * @param[in]     vpt_user The sequence number.
 * @return        None.
 */
static void sv_OnDiagDone(uint8_t u8_result, const uint8_t *u8pt_data, size_t t_len, void *vpt_user)
{
   sv_SendDiagRsp((uint8_t)(uintptr_t)vpt_user, u8_result, u8pt_data, t_len);
}

/**
 * @private       sv_OnFlashStatus
 * @brief         UdsJobStatus_F of FLASH: STATUS.
 * @param[in]     stpt_status Status.
 * @param[in]     vpt_user Unused.
 * @return        None.
 */
static void sv_OnFlashStatus(const UdsJobStatus_T *stpt_status, void *vpt_user)
{
   ARG_UNUSED(vpt_user);
   sv_SendStatus(stpt_status);
}

/**
 * @private       su8_Target
 * @brief         Decode TARGET and hand it to UdsJob.
 * @param[in]     u8pt_data Payload (UDSCMD_TARGET_LEN bytes).
 * @return        eUDS_OK (accepted) or the refusal.
 */
static uint8_t su8_Target(const uint8_t *u8pt_data)
{
   UdsJobTarget_T st_target;
   uint8_t u8_flags = u8pt_data[1];
   uint8_t u8_extAddr = u8pt_data[22];
   uint8_t u8_pad = u8pt_data[24];

   // Zephyr's ISO-TP pads with 0xCC only; no extended addressing
   if (((u8_pad != 0U) && (u8_pad != UDSCMD_PAD_BYTE)) || ((u8_flags & UDSCMD_TGT_EXT_ADDR) != 0U))
   {
      return eUDS_NOT_SUPPORTED;
   }
   if (u8_extAddr != 0U)
   {
      return eUDS_BAD_ARG;
   }

   memset(&st_target, 0, sizeof(st_target));
   st_target.st_can.b_fd = ((u8_flags & UDS_TGT_FD) != 0U);
   st_target.st_can.u32_bitrate = sys_get_le32(&u8pt_data[2]);
   st_target.st_can.u32_bitrateData = sys_get_le32(&u8pt_data[6]);
   st_target.st_uds.u32_txId = sys_get_le32(&u8pt_data[10]);
   st_target.st_uds.u32_rxId = sys_get_le32(&u8pt_data[14]);
   st_target.st_uds.u32_funcId = sys_get_le32(&u8pt_data[18]);
   st_target.st_uds.u8_flags = u8_flags;
   st_target.st_uds.u8_txDl = u8pt_data[23];
   st_target.st_uds.u16_p2Ms = sys_get_le16(&u8pt_data[25]);
   st_target.st_uds.u16_p2StarMs = sys_get_le16(&u8pt_data[27]);

   return gu8_UdsJob_SetTarget(&st_target, sv_OnTargetDone, (void *)(uintptr_t)u8pt_data[0]);
}

/**
 * @private       su8_Flash
 * @brief         Decode FLASH ([seq][params][u8 name len][name]) and start the job.
 * @param[in]     u8pt_data Payload.
 * @param[in]     u8_len Payload length.
 * @return        eUDS_OK (accepted) or the refusal.
 */
static uint8_t su8_Flash(const uint8_t *u8pt_data, uint8_t u8_len)
{
   const uint8_t *u8pt_p = &u8pt_data[1];
   UdsFlashParams_T st_params;
   uint8_t u8_nameLen;

   if (u8_len < (2U + UDSCMD_PARAMS_LEN))
   {
      return eUDS_BAD_ARG;
   }
   u8_nameLen = u8pt_data[1U + UDSCMD_PARAMS_LEN];
   if (u8_len != (2U + UDSCMD_PARAMS_LEN + u8_nameLen))
   {
      return eUDS_BAD_ARG;
   }

   memset(&st_params, 0, sizeof(st_params));
   st_params.u16_flags = sys_get_le16(&u8pt_p[0]);
   st_params.u8_securityLevel = u8pt_p[2];
   st_params.u8_keyAlgo = u8pt_p[3];
   st_params.u8_commControl = u8pt_p[4];
   st_params.u8_commType = u8pt_p[5];
   st_params.u8_resetType = u8pt_p[6];
   st_params.u8_alfid = u8pt_p[7];
   st_params.u8_dfi = u8pt_p[8];
   st_params.u16_eraseRid = sys_get_le16(&u8pt_p[9]);
   st_params.u16_checkRid = sys_get_le16(&u8pt_p[11]);
   st_params.u16_maxBlock = sys_get_le16(&u8pt_p[13]);
   st_params.u16_fingerprintDid = sys_get_le16(&u8pt_p[15]);
   st_params.u8_fingerprintLen = u8pt_p[17];
   memcpy(st_params.u8ar_fingerprint, &u8pt_p[18], UDS_FP_MAX);

   return gu8_UdsJob_Flash((const char *)&u8pt_data[2U + UDSCMD_PARAMS_LEN], u8_nameLen, &st_params,
      sv_OnFlashStatus, NULL);
}

/**
 * @private       sv_OnRxShort
 * @brief         SETURxShort_F, on the SETU engine thread: decode a message, hand
 *                it to UdsJob, or answer it at once.
 * @param[in]     u8_appType Application type.
 * @param[in]     u8pt_data Payload (valid only during the call).
 * @param[in]     u8_len Payload length.
 * @return        None.
 */
static void sv_OnRxShort(uint8_t u8_appType, const uint8_t *u8pt_data, uint8_t u8_len)
{
   UdsJobStatus_T st_status;
   uint8_t u8_seq;
   uint8_t u8_result;

   // Every request starts with its sequence number
   if (u8_len == 0U)
   {
      APP_LOG_WRN("empty 0x%02x ignored", u8_appType);
      return;
   }
   u8_seq = u8pt_data[0];

   switch (u8_appType)
   {
      case UDSCMD_APP_TYPE_TARGET:
         u8_result = (u8_len == UDSCMD_TARGET_LEN) ? su8_Target(u8pt_data) : (uint8_t)eUDS_BAD_ARG;
         if (u8_result != eUDS_OK)
         {
            sv_SendResult(u8_seq, u8_appType, u8_result, NULL, 0U);
         }
         break;

      case UDSCMD_APP_TYPE_DIAG_REQ:
         u8_result = eUDS_BAD_ARG;
         if ((u8_len > UDSCMD_DIAG_HDR_LEN) && ((u8pt_data[1] & (uint8_t)~UDSCMD_DIAG_FUNCTIONAL) == 0U))
         {
            u8_result = gu8_UdsJob_Diag(&u8pt_data[UDSCMD_DIAG_HDR_LEN], u8_len - UDSCMD_DIAG_HDR_LEN,
               (u8pt_data[1] & UDSCMD_DIAG_FUNCTIONAL) != 0U, sv_OnDiagDone, (void *)(uintptr_t)u8_seq);
         }
         if (u8_result != eUDS_OK)
         {
            sv_SendDiagRsp(u8_seq, u8_result, NULL, 0U);
         }
         break;

      case UDSCMD_APP_TYPE_UNLOCK:
         u8_result = (u8_len == 3U)
            ? gu8_UdsJob_Unlock(u8pt_data[1], u8pt_data[2], sv_OnUnlockDone, (void *)(uintptr_t)u8_seq)
            : (uint8_t)eUDS_BAD_ARG;
         if (u8_result != eUDS_OK)
         {
            sv_SendResult(u8_seq, u8_appType, u8_result, NULL, 0U);
         }
         break;

      case UDSCMD_APP_TYPE_FLASH:
         // Accepted or not, the host gets a RESULT at once; STATUS follows
         sv_SendResult(u8_seq, u8_appType, su8_Flash(u8pt_data, u8_len), NULL, 0U);
         break;

      case UDSCMD_APP_TYPE_ABORT:
         sv_SendResult(u8_seq, u8_appType, (u8_len == 1U) ? gu8_UdsJob_Abort() : (uint8_t)eUDS_BAD_ARG, NULL, 0U);
         break;

      case UDSCMD_APP_TYPE_STATUS_REQ:
         gv_UdsJob_GetStatus(&st_status);
         sv_SendStatus(&st_status);
         break;

      default:
         APP_LOG_WRN("0x%02x (%u bytes) ignored", u8_appType, u8_len);
         break;
   }
}

/******************************************************************************/
/*                                                                            */
/*                        PUBLIC FUNCTION DEFINITIONS                         */
/*                                                                            */
/******************************************************************************/
/**
 * @public        gi_UdsCmd_Init
 * @brief         Register the UDS appType range (0x50-0x5F) with the SETU router
 *                (short messages only: transfers are refused). Call once, before
 *                gi_SETURouter_Start(). Does nothing without CONFIG_UDS_CMD.
 * @return        0 on success, otherwise the error from gi_SETURouter_Register().
 */
int gi_UdsCmd_Init(void)
{
   SETURoute_T st_route = { 0 };
   int i_ret = 0;

   // Check if UDS over BLE is built in
   if (!IS_ENABLED(CONFIG_UDS_CMD))
   {
      return 0;
   }

   st_route.u8_firstAppType = UDSCMD_APP_TYPE_TARGET;
   st_route.u8_lastAppType = UDSCMD_APP_TYPE_LAST;
   st_route.fpt_onRxShort = sv_OnRxShort;

   i_ret = gi_SETURouter_Register(&st_route);
   if (i_ret != 0)
   {
      APP_LOG_ERR("gi_SETURouter_Register failed (%d)", i_ret);
   }
   else
   {
      APP_LOG_INF("UDS commands ready");
   }

   return i_ret;
}

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shivam Chudasama [SC]
 */
