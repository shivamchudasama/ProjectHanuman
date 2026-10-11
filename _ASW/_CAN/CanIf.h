/**
 * @file          CanIf.h
 * @brief         Header file containing the CAN / CAN FD interface: the one owner
 *                of the CAN controller chosen as zephyr,canbus (the MCP2518FD
 *                Click). It sets the controller's mode and bitrates, starts it,
 *                follows its error state, and gives other modules frame TX and
 *                filtered RX (callbacks on its own thread). Contract and wiring:
 *                _DOC/CAN/README.md.
 * @date          12/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#ifndef _CAN_IF_H
#define _CAN_IF_H

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include <stdbool.h>
#include <stdint.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/can.h>

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
/**
 * @def           CANIF_STATE_LISTENERS
 * @brief         Most state listeners registered at a time.
 */
#define CANIF_STATE_LISTENERS                (2U)

/**
 * @def           CANIF_TEST_ID
 * @brief         Standard ID of the self-test and test frames.
 */
#define CANIF_TEST_ID                        (0x5A5U)

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
 * @struct        CanIfConfig_T
 * @brief         Controller configuration: mode and bitrates.
 */
typedef struct
{
   bool b_fd;                                /**< CAN FD mode (classic + FD frames).  */
   bool b_listenOnly;                        /**< Neither acknowledge nor send.       */
   uint32_t u32_bitrate;                     /**< Nominal bitrate (bit/s).            */
   uint32_t u32_bitrateData;                 /**< FD data-phase bitrate (bit/s).      */
} CanIfConfig_T;

/**
 * @struct        CanIfStatus_T
 * @brief         Snapshot of the interface (gi_CanIf_GetStatus()).
 */
typedef struct
{
   bool b_ready;                             /**< Controller found and set up.        */
   bool b_started;                           /**< Controller started.                 */
   bool b_locked;                            /**< A session holds gi_CanIf_Lock().    */
   bool b_monitor;                           /**< Traffic log on.                     */
   CanIfConfig_T st_config;                  /**< Configuration in use.               */
   enum can_state e_state;                   /**< Error state.                        */
   struct can_bus_err_cnt st_errCnt;         /**< TX/RX error counters.               */
   uint32_t u32_txFrames;                    /**< Frames sent by gi_CanIf_Send().     */
   uint32_t u32_rxFrames;                    /**< Frames queued for a filter or log.  */
   uint32_t u32_rxDropped;                   /**< Frames lost: receive queue full.    */
   uint32_t u32_busOffCount;                 /**< Times the controller went bus-off.  */
} CanIfStatus_T;

/**
 * @typedef       CanIfRx_F
 * @brief         A received frame matched the filter. Runs on the CAN interface
 *                thread.
 * @param[in]     stpt_frame Frame (valid only during the call).
 * @param[in]     vpt_user The user pointer given with the filter.
 */
typedef void (*CanIfRx_F)(const struct can_frame *stpt_frame, void *vpt_user);

/**
 * @typedef       CanIfState_F
 * @brief         The error state changed (bus-off and recovery included). Runs on
 *                the CAN interface thread.
 * @param[in]     e_state New state.
 * @param[in]     stpt_errCnt TX/RX error counters (valid only during the call).
 * @param[in]     vpt_user The user pointer given with the listener.
 */
typedef void (*CanIfState_F)(enum can_state e_state, const struct can_bus_err_cnt *stpt_errCnt,
   void *vpt_user);

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
extern int gi_CanIf_Init(void);
extern int gi_CanIf_Configure(const CanIfConfig_T *stpt_config, const void *vpt_owner);
extern int gi_CanIf_Lock(const void *vpt_owner);
extern int gi_CanIf_Unlock(const void *vpt_owner);
extern int gi_CanIf_Send(const struct can_frame *stpt_frame, k_timeout_t t_timeout);
extern int gi_CanIf_AddRxFilter(const struct can_filter *stpt_filter, CanIfRx_F fpt_cb,
   void *vpt_user);
extern int gi_CanIf_RemoveRxFilter(int i_filterId);
extern int gi_CanIf_AddStateListener(CanIfState_F fpt_cb, void *vpt_user);
extern int gi_CanIf_RemoveStateListener(CanIfState_F fpt_cb, void *vpt_user);
extern void gv_CanIf_SetMonitor(bool b_on);
extern int gi_CanIf_GetStatus(CanIfStatus_T *stpt_status);
extern const struct device *gstpt_CanIf_GetDevice(void);

#endif //!_CAN_IF_H

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shivam Chudasama [SC]
 */
