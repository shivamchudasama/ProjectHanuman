/**
 * @file          HostAuthButton.c
 * @brief         Source file containing the DK button of the host window
 *                (Button 3, SW3: the DK library's second button, since the board
 *                overlay deletes button1 and button2 for the CAN click).
 *                - A press released before CONFIG_HOST_AUTH_FORGET_HOLD_MS opens
 *                  the host window: the device advertises, and the bonded host
 *                  (or, with none bonded, a new one) can connect.
 *                - A press held that long forgets the bonded host (its bond,
 *                  its record, its link), then opens the window for a new host.
 *                A second handler on the DK library (dk_button_handler_add()),
 *                beside the wipe button's; kept apart from HostAuth.c so the
 *                host tests of HostAuth.c need no button timing.
 * @date          25/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include "HostAuthButton.h"
#include <zephyr/kernel.h>
#include <zephyr/sys/atomic.h>
#include <dk_buttons_and_leds.h>
#include "HostAuth.h"
#include "AppLog.h"

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
#ifndef CONFIG_HOST_AUTH_FORGET_HOLD_MS
#define CONFIG_HOST_AUTH_FORGET_HOLD_MS      (3000)
#endif // CONFIG_HOST_AUTH_FORGET_HOLD_MS

/**
 * @def           HOST_AUTH_BUTTON_MSK
 * @brief         Button of the host window (SW3 on the nRF54L15 DK).
 */
#define HOST_AUTH_BUTTON_MSK                 (DK_BTN2_MSK)

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
static void sv_ForgetHeld(struct k_work *stpt_work);
static void sv_ButtonChanged(uint32_t u32_buttonState, uint32_t u32_hasChanged);

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
 * @var           sst_holdWork
 * @brief         Runs once the button has been held for
 *                CONFIG_HOST_AUTH_FORGET_HOLD_MS.
 */
static K_WORK_DELAYABLE_DEFINE(sst_holdWork, sv_ForgetHeld);

/**
 * @var           st_pressed
 * @brief         1 between a press and its release, while the hold has not
 *                fired (a release then is a short press).
 */
static atomic_t st_pressed = ATOMIC_INIT(0);

/**
 * @var           sst_handler
 * @brief         The DK library's dynamic handler entry.
 */
static struct button_handler sst_handler = {
   .cb = sv_ButtonChanged,
};

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
 * @private       sv_ForgetHeld
 * @brief         The button was held long enough: forget the host, open the
 *                window.
 * @param[in]     stpt_work Work item (unused).
 * @return        None.
 */
static void sv_ForgetHeld(struct k_work *stpt_work)
{
   ARG_UNUSED(stpt_work);

   // Check if the press is still the one that armed this (not released meanwhile)
   if (atomic_cas(&st_pressed, 1, 0))
   {
      APP_LOG_WRN("button held %d ms: forgetting the host", CONFIG_HOST_AUTH_FORGET_HOLD_MS);
      gv_HostAuth_ForgetHostAndOpen();
   }
}

/**
 * @private       sv_ButtonChanged
 * @brief         DK library button handler: arm the hold on press; a release
 *                before it fires is a short press.
 * @param[in]     u32_buttonState Current state of all buttons.
 * @param[in]     u32_hasChanged Buttons that changed.
 * @return        None.
 */
static void sv_ButtonChanged(uint32_t u32_buttonState, uint32_t u32_hasChanged)
{
   // Check if the window button changed
   if ((u32_hasChanged & HOST_AUTH_BUTTON_MSK) == 0U)
   {
      return;
   }

   // Check if it was pressed or released
   if ((u32_buttonState & HOST_AUTH_BUTTON_MSK) != 0U)
   {
      (void)atomic_set(&st_pressed, 1);
      (void)k_work_reschedule(&sst_holdWork, K_MSEC(CONFIG_HOST_AUTH_FORGET_HOLD_MS));
   }
   else
   {
      (void)k_work_cancel_delayable(&sst_holdWork);

      // Check if the hold had not fired: a short press
      if (atomic_cas(&st_pressed, 1, 0))
      {
         APP_LOG_INF("button pressed: opening the host window");
         gv_HostAuth_OpenWindow();
      }
   }
}

/******************************************************************************/
/*                                                                            */
/*                        PUBLIC FUNCTION DEFINITIONS                         */
/*                                                                            */
/******************************************************************************/
/**
 * @public        gi_HostAuthButton_Init
 * @brief         Start watching the window button. Call once from main(), after
 *                gi_ProvButton_Init() (which initialises the DK buttons).
 * @return        0.
 */
int gi_HostAuthButton_Init(void)
{
   dk_button_handler_add(&sst_handler);

   return 0;
}

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shivam Chudasama [SC]
 */
