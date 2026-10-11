/**
 * @file          UdsClient.h
 * @brief         UDS client (ISO 14229-1, the tester side) over a transport such as
 *                ISO-TP (UdsTp_T). It sends a request, matches the response to it,
 *                waits through NRC 0x78 (P2*), repeats after NRC 0x21, follows the
 *                ECU's session timing, keeps a non-default session alive with
 *                TesterPresent (gi32_UdsClient_KeepAlive(), called by the owner),
 *                and builds the services ECU programming needs.
 *
 *                Calls block the calling thread; one thread owns a client. Never
 *                call it from the system work queue: Zephyr's ISO-TP runs there.
 *                See _DOC/UdsClient/API_REFERENCE.md for the full contract.
 *
 * @date          12/10/2026
 * @author        Shivam Chudasama [SC]
 * @license       MIT
 */

/* SPDX-License-Identifier: MIT */

#ifndef _UDS_CLIENT_H
#define _UDS_CLIENT_H

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <zephyr/kernel.h>
#include "UdsClient_Types.h"
#include "UdsClient_Config.h"

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
/**
 * @def           UDS_KEEPALIVE_NONE
 * @brief         gi32_UdsClient_KeepAlive(): no session to keep alive.
 */
#define UDS_KEEPALIVE_NONE                   (-1)

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
/**
 * @struct        UdsClient_T
 * @brief         One client: its transport, target, timing and buffers. Opaque:
 *                use the functions below.
 */
typedef struct
{
   const UdsTp_T *stpt_tp;                   /**< Transport.                           */
   UdsTarget_T st_target;                    /**< Target set by SetTarget.             */
   bool b_bound;                             /**< A target is bound.                   */
   bool b_session;                           /**< Non-default session: keep alive.     */
   uint32_t u32_p2Ms;                        /**< P2 in use.                           */
   uint32_t u32_p2StarMs;                    /**< P2* in use.                          */
   int64_t i64_lastTxMs;                     /**< Time of the last request sent.       */
   uint8_t u8_lastSid;                       /**< SID of the last request.             */
   uint8_t u8_lastNrc;                       /**< NRC of the last request (0: none).   */
   uint32_t u32_pending;                     /**< NRC 0x78 seen by the last request.   */
   uint8_t u8ar_req[UDS_CLIENT_BUF_SIZE];    /**< Service helpers' request.            */
   uint8_t u8ar_rsp[UDS_CLIENT_BUF_SIZE];    /**< Service helpers' response.           */
} UdsClient_T;

/******************************************************************************/
/*                                                                            */
/*                                   UNIONS                                   */
/*                                                                            */
/******************************************************************************/

/******************************************************************************/
/*                                                                            */
/*                              EXTERN VARIABLES                              */
/*                                                                            */
/******************************************************************************/

/******************************************************************************/
/*                                                                            */
/*                              EXTERN FUNCTIONS                              */
/*                                                                            */
/******************************************************************************/
extern int gi_UdsClient_Init(UdsClient_T *stpt_client, const UdsTp_T *stpt_tp);
extern int gi_UdsClient_SetTarget(UdsClient_T *stpt_client, const UdsTarget_T *stpt_target);
extern void gv_UdsClient_Close(UdsClient_T *stpt_client);
extern int gi_UdsClient_Request(UdsClient_T *stpt_client, const uint8_t *u8pt_req, size_t t_reqLen,
   bool b_functional, uint8_t *u8pt_rsp, size_t t_rspMax, size_t *tpt_rspLen);
extern int32_t gi32_UdsClient_KeepAlive(UdsClient_T *stpt_client);
extern int gi_UdsClient_Session(UdsClient_T *stpt_client, uint8_t u8_session);
extern int gi_UdsClient_EcuReset(UdsClient_T *stpt_client, uint8_t u8_type);
extern int gi_UdsClient_CommControl(UdsClient_T *stpt_client, uint8_t u8_control, uint8_t u8_type);
extern int gi_UdsClient_DtcSetting(UdsClient_T *stpt_client, uint8_t u8_type);
extern int gi_UdsClient_SecurityAccess(UdsClient_T *stpt_client, uint8_t u8_level, UdsKey_F fpt_key,
   void *vpt_user);
extern int gi_UdsClient_ReadDid(UdsClient_T *stpt_client, uint16_t u16_did, uint8_t *u8pt_data,
   size_t t_max, size_t *tpt_len);
extern int gi_UdsClient_WriteDid(UdsClient_T *stpt_client, uint16_t u16_did, const uint8_t *u8pt_data,
   size_t t_len);
extern int gi_UdsClient_Routine(UdsClient_T *stpt_client, uint8_t u8_type, uint16_t u16_rid,
   const uint8_t *u8pt_args, size_t t_argLen, uint8_t *u8pt_status, size_t t_statusMax,
   size_t *tpt_statusLen);
extern int gi_UdsClient_RequestDownload(UdsClient_T *stpt_client, uint8_t u8_dfi, uint8_t u8_alfid,
   uint32_t u32_address, uint32_t u32_size, uint32_t *u32pt_maxBlock);
extern int gi_UdsClient_TransferData(UdsClient_T *stpt_client, uint8_t u8_bsc, uint8_t *u8pt_req,
   size_t t_dataLen);
extern int gi_UdsClient_TransferExit(UdsClient_T *stpt_client);
extern int gi_UdsClient_TesterPresent(UdsClient_T *stpt_client);
extern uint8_t gu8_UdsClient_LastNrc(const UdsClient_T *stpt_client);
extern uint8_t gu8_UdsClient_LastSid(const UdsClient_T *stpt_client);

#endif //!_UDS_CLIENT_H
