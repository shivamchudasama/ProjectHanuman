/**
 * @file          SETURouter.h
 * @brief         Header file containing the appType router of the SETU Server.
 *
 *                The SETU Server takes a single set of receive callbacks. The
 *                router owns that set and forwards every callback to the module
 *                that registered the appType range it belongs to, so several
 *                modules (hex upload, provisioning) share one Server.
 * @date          01/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#ifndef _SETU_ROUTER_H
#define _SETU_ROUTER_H

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include <stdbool.h>
#include <stdint.h>
#include "SETU.h"

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
/**
 * @def           SETU_ROUTER_MAX_ROUTES
 * @brief         Maximum number of registered appType ranges: hex upload, file
 *                commands, provisioning, pairing, UDS and host authentication.
 */
#define SETU_ROUTER_MAX_ROUTES               (6U)

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
 * @typedef       SETURouterAdmit_F
 * @brief         Gate: whether the link the Server serves may reach an appType
 *                now. Consulted for every new transfer and short message while
 *                no filter applies. Runs on the SETU engine thread with the
 *                SETU lock held: it must not block.
 * @param[in]     u8_appType Application type.
 * @return        true to admit, false to refuse.
 */
typedef bool (*SETURouterAdmit_F)(uint8_t u8_appType);

/**
 * @typedef       SETURouterRefused_F
 * @brief         Told about every transfer or short message the gate refused
 *                (same thread rules as SETURouterAdmit_F).
 * @param[in]     u8_appType Application type refused.
 * @return        None.
 */
typedef void (*SETURouterRefused_F)(uint8_t u8_appType);

/**
 * @struct        SETURoute_T
 * @brief         One module's appType range and its callbacks. Every callback
 *                is optional: a range without fpt_onRxStart or fpt_onRxData
 *                rejects transfers, one without fpt_onRxShort ignores short
 *                messages. fpt_onTxDone receives the result of the module's own
 *                Client transfers (by appType), fpt_onCliReady the result of a
 *                gi_SETURouter_ClientAttach() the module asked for. The callbacks
 *                run on the SETU engine thread with the SETU lock held
 *                (see the SETU API reference).
 */
typedef struct
{
   uint8_t u8_firstAppType;                  /**< First appType of the range.            */
   uint8_t u8_lastAppType;                   /**< Last appType (inclusive).              */
   SETURxStart_F fpt_onRxStart;               /**< Accept or reject a transfer.           */
   SETURxData_F fpt_onRxData;                 /**< In-order chunk.                        */
   SETURxDone_F fpt_onRxDone;                 /**< Transfer result.                       */
   SETURxShort_F fpt_onRxShort;               /**< Short message.                         */
#if SETU_ENABLE_CLIENT
   SETUTxDone_F fpt_onTxDone;                 /**< Own Client transfer finished.          */
   SETUCliReady_F fpt_onCliReady;             /**< Client attach finished.                */
#endif // SETU_ENABLE_CLIENT
} SETURoute_T;

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
extern int gi_SETURouter_Register(const SETURoute_T *stpt_route);
extern int gi_SETURouter_Start(void);
extern int gi_SETURouter_SetGate(SETURouterAdmit_F fpt_admit, SETURouterRefused_F fpt_refused);
extern void gv_SETURouter_SetFilter(uint8_t u8_first, uint8_t u8_last);
extern void gv_SETURouter_ClearFilter(void);
#if SETU_ENABLE_CLIENT
extern int gi_SETURouter_ClientAttach(struct bt_conn *stpt_conn, uint8_t u8_ownerAppType);
#endif // SETU_ENABLE_CLIENT

#endif //!_SETU_ROUTER_H

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shivam Chudasama [SC]
 */
