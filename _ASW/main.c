/**
 * @file          main.c
 * @brief         Source file containing the main function which performs all initialization
 *                activity.
 * @date          16/02/26
 * @author        Yash Sunil Giramkar [YSG], Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include "CanIf.h"
#include "ConnectionHandling.h"
#include "DataStore.h"
#include "FsCmd.h"
#include "FileSysManager.h"
#include "Prov.h"
#include "ProvButton.h"
#include "Pair.h"
#include "HostAuth.h"
#include "HostAuthButton.h"
#include "SETURouter.h"
#if defined(CONFIG_APP_WDT)
#include "Wdt.h"
#endif // CONFIG_APP_WDT
#if defined(CONFIG_UDS)
#include "UdsJob.h"
#include "UdsCmd.h"
#endif // CONFIG_UDS

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/

/******************************************************************************/
/*                                                                            */
/*                             PRIVATE VARIABLES                              */
/*                                                                            */
/******************************************************************************/

/******************************************************************************/
/*                                                                            */
/*                       PRIVATE FUNCTION DEFINITIONS                          */
/*                                                                            */
/******************************************************************************/

/******************************************************************************/
/*                                                                            */
/*                        PUBLIC FUNCTION DEFINITIONS                         */
/*                                                                            */
/******************************************************************************/
/**
 * @public        main
 * @brief         Starts the watchdog, the File System Manager, initializes the SETU users (hex
 *                upload, file commands, provisioning, pairing, UDS, host
 *                authentication and its gate), the CAN
 *                interface, the SETU Server and Client, the BLE stack and starts
 *                advertising.
 * @return        0 upon successful execution.
 */
int main(void)
{
#if defined(CONFIG_APP_WDT)
   // First: log why the device reset, and supervise the rest of the boot
   (void)gi_Wdt_Init();
#endif // CONFIG_APP_WDT

   // Mount the FAT volume on the external flash (on its own thread; commands
   // submitted before it is mounted wait in its queue)
   (void)gi_FSMGR_Start();

   // Register the SETU appType ranges: hex upload, file commands, then
   // provisioning. The provisioning init also restores the stored certificates,
   // or generates (first boot) or loads the device key and CSR.
   (void)gi_DataStore_Init();
   (void)gi_FsCmd_Init();
   (void)gi_Prov_Init();

   // Holding DK Button 0 wipes the provisioning credentials
   (void)gi_ProvButton_Init();

   // Certificate-based pairing with another device: its appType range, the SMP
   // callbacks and the LED
   (void)gi_Pair_Init();

   // Host authentication: its appType range, the router's gate (only the
   // trusted host reaches the device), and DK Button 3 for the host window
   (void)gi_HostAuth_Init();
   (void)gi_HostAuthButton_Init();

#if defined(CONFIG_CANIF)
   // The CAN / CAN FD controller (MCP2518FD Click): its driver (deferred until
   // the DK buttons have their GPIO callbacks), boot configuration, traffic
   // log. Without the click it logs an error and the rest runs on.
   (void)gi_CanIf_Init();
#endif // CONFIG_CANIF

#if defined(CONFIG_UDS)
   // UDS over the CAN bus: the job engine follows the bus state; its BLE
   // messages (appTypes 0x50-0x5F) register with the router
   (void)gi_UdsJob_Init();
   (void)gi_UdsCmd_Init();
#endif // CONFIG_UDS

   // Start the SETU Server and Client before advertising, so they are ready
   // for the first connection. They need no Bluetooth stack yet.
   (void)gi_SETURouter_Start();

   // Init and start BLE advertising
   gv_BLEInitStartAdv();

   return 0;
}

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Yash Sunil Giramkar [YSG], Shivam Chudasama [SC]
 */
