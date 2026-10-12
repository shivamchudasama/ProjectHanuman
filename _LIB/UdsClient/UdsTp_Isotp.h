/**
 * @file          UdsTp_Isotp.h
 * @brief         The UDS client's transport (UdsTp_T) on Zephyr's ISO-TP
 *                (ISO 15765-2, CONFIG_ISOTP): normal addressing with 11- or 29-bit
 *                identifiers, classic CAN or CAN FD (with BRS), physical and
 *                functional requests. Padding follows CONFIG_ISOTP_ENABLE_TX_PADDING
 *                (byte 0xCC). See _DOC/UdsClient/API_REFERENCE.md.
 *
 * @date          12/10/2026
 * @author        Shivam Chudasama [SC]
 * @license       MIT
 */

/* SPDX-License-Identifier: MIT */

#ifndef _UDS_TP_ISOTP_H
#define _UDS_TP_ISOTP_H

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include <stdbool.h>
#include <zephyr/device.h>
#include <zephyr/canbus/isotp.h>
#include "UdsClient_Types.h"

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/

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
 * @struct        UdsTpIsotp_T
 * @brief         State of one ISO-TP transport (one bound target). Opaque.
 */
typedef struct
{
   const struct device *stpt_can;            /**< CAN controller.                      */
   struct isotp_recv_ctx st_recv;            /**< Bound receive context.               */
   struct isotp_send_ctx st_send;            /**< Send context (blocking sends).       */
   struct isotp_msg_id st_txAddr;            /**< Physical request address.            */
   struct isotp_msg_id st_rxAddr;            /**< Response address.                    */
   struct isotp_msg_id st_funcAddr;          /**< Functional request address.          */
   bool b_bound;                             /**< st_recv is bound.                    */
   bool b_func;                              /**< st_funcAddr is valid.                */
   int i_lastIsotpErr;                       /**< Last ISOTP_N_* / ISOTP_* error.      */
} UdsTpIsotp_T;

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
extern void gv_UdsTpIsotp_Init(UdsTp_T *stpt_tp, UdsTpIsotp_T *stpt_ctx, const struct device *stpt_can);
extern int gi_UdsTpIsotp_Errno(int i_isotpErr);

#endif //!_UDS_TP_ISOTP_H
