/**
 * @file          UdsCmd.h
 * @brief         Header file containing UDS over BLE: the host (setu_client.py uds
 *                and flash) sends SETU short messages (appTypes 0x50-0x5F) to set
 *                the target ECU, send diagnostic requests, unlock, and start, follow
 *                and abort a flash job; UdsJob runs them. Contract:
 *                _DOC/UDS/PROTOCOL.md.
 * @date          12/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#ifndef _UDS_CMD_H
#define _UDS_CMD_H

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include <zephyr/kernel.h>

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
/**
 * @def           UDSCMD_APP_TYPE_*
 * @brief         The messages (_DOC/UDS/PROTOCOL.md §1).
 */
#define UDSCMD_APP_TYPE_TARGET               (0x50U)   /**< host -> device               */
#define UDSCMD_APP_TYPE_RESULT               (0x51U)   /**< device -> host               */
#define UDSCMD_APP_TYPE_DIAG_REQ             (0x52U)   /**< host -> device               */
#define UDSCMD_APP_TYPE_DIAG_RSP             (0x53U)   /**< device -> host               */
#define UDSCMD_APP_TYPE_UNLOCK               (0x54U)   /**< host -> device               */
#define UDSCMD_APP_TYPE_FLASH                (0x55U)   /**< host -> device               */
#define UDSCMD_APP_TYPE_STATUS               (0x56U)   /**< device -> host               */
#define UDSCMD_APP_TYPE_ABORT                (0x57U)   /**< host -> device               */
#define UDSCMD_APP_TYPE_STATUS_REQ           (0x58U)   /**< host -> device               */
#define UDSCMD_APP_TYPE_LAST                 (0x5FU)   /**< Last appType of the range.   */

/**
 * @def           UDSCMD_TARGET_LEN
 * @brief         TARGET payload length.
 */
#define UDSCMD_TARGET_LEN                    (29U)

/**
 * @def           UDSCMD_PARAMS_LEN
 * @brief         The flash parameters in FLASH.
 */
#define UDSCMD_PARAMS_LEN                    (34U)

/**
 * @def           UDSCMD_STATUS_LEN
 * @brief         STATUS payload length.
 */
#define UDSCMD_STATUS_LEN                    (15U)

/**
 * @def           UDSCMD_PART_MAX
 * @brief         Response bytes in one DIAG_RSP.
 */
#define UDSCMD_PART_MAX                      (236U)

/**
 * @def           UDSCMD_PAD_BYTE
 * @brief         The only pad byte (Zephyr's ISO-TP pads with 0xCC).
 */
#define UDSCMD_PAD_BYTE                      (0xCCU)

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
/*                              EXTERN VARIABLES                              */
/*                                                                            */
/******************************************************************************/

/******************************************************************************/
/*                                                                            */
/*                              EXTERN FUNCTIONS                              */
/*                                                                            */
/******************************************************************************/
extern int gi_UdsCmd_Init(void);

#endif //!_UDS_CMD_H

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shivam Chudasama [SC]
 */
