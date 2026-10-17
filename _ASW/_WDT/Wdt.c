/**
 * @file          Wdt.c
 * @brief         Source file containing the application watchdog. At boot it
 *                logs the reset cause (hwinfo) and clears it, so a reset by the
 *                watchdog or by the fatal error handler
 *                (CONFIG_RESET_ON_FATAL_ERROR) shows on the next start. It then
 *                starts the task watchdog with the hardware watchdog as fallback
 *                (paused while a debugger halts the CPU) and adds one channel,
 *                which the supervisor thread feeds every CONFIG_APP_WDT_FEED_MS.
 *                The thread runs at the lowest application priority: it is fed
 *                only while every other thread lets the CPU go, so a hang or a
 *                starved CPU ends in a reset after CONFIG_APP_WDT_TIMEOUT_MS. An
 *                expired channel reboots the device (no callback).
 *                Built only with CONFIG_APP_WDT.
 * @date          18/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include "Wdt.h"
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/hwinfo.h>
#include <zephyr/task_wdt/task_wdt.h>
#include "AppLog.h"

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
/**
 * @def           WDT_HW_DEVICE
 * @brief         The hardware watchdog behind the task watchdog: the devicetree
 *                alias watchdog0 (wdt31 on the nRF54L15 DK, enabled in the board
 *                overlay), or none (the task watchdog then reboots from a kernel
 *                timer, which a hang with interrupts locked does not reach).
 */
#if DT_NODE_HAS_STATUS_OKAY(DT_ALIAS(watchdog0))
#define WDT_HW_DEVICE                        (DEVICE_DT_GET(DT_ALIAS(watchdog0)))
#else
#define WDT_HW_DEVICE                        (NULL)
#endif // DT_NODE_HAS_STATUS_OKAY(DT_ALIAS(watchdog0))

/**
 * @def           WDT_THREAD_STACK_SIZE
 * @brief         Stack of the supervisor thread: a feed and a sleep, plus the log
 *                call of a failed feed (about 0.5 KiB on its static path).
 */
#define WDT_THREAD_STACK_SIZE                (1024)

BUILD_ASSERT(CONFIG_APP_WDT_FEED_MS < CONFIG_APP_WDT_TIMEOUT_MS,
   "the supervisor must feed the watchdog well before it expires");

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
 * @struct        WdtCauseName_T
 * @brief         One hwinfo reset cause flag and its name in the boot log.
 */
typedef struct
{
   uint32_t u32_flag;                        /**< RESET_* flag.                       */
   const char *cpt_name;                     /**< Name logged.                        */
} WdtCauseName_T;

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
static void sv_LogResetCause(void);
static void sv_Feed(void);
static void sv_WdtThread(void *vpt_p1, void *vpt_p2, void *vpt_p3);

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
 * @var           scstar_causeNames
 * @brief         Reset causes in the order they are logged.
 */
static const WdtCauseName_T scstar_causeNames[] =
{
   { RESET_WATCHDOG, "watchdog" },
   { RESET_SOFTWARE, "software (fatal error or reboot)" },
   { RESET_CPU_LOCKUP, "CPU lockup" },
   { RESET_BROWNOUT, "brownout" },
   { RESET_POR, "power-on" },
   { RESET_PIN, "reset pin" },
   { RESET_DEBUG, "debugger" },
   { RESET_LOW_POWER_WAKE, "wake from low power" },
   { RESET_SECURITY, "security" },
};

/**
 * @var           su32_resetCause
 * @brief         The RESET_* flags read at boot (0 if hwinfo could not tell).
 */
static uint32_t su32_resetCause = 0U;

/**
 * @var           si_channel
 * @brief         The supervisor's task watchdog channel, or -1 before init.
 */
static int si_channel = -1;

/**
 * @var           sb_feedFailed
 * @brief         A failed feed was logged already (logged once).
 */
static bool sb_feedFailed = false;

/**
 * @var           sst_wdtThread
 * @brief         The supervisor thread, started by gi_Wdt_Init() once its
 *                channel exists.
 */
K_THREAD_DEFINE(sst_wdtThread, WDT_THREAD_STACK_SIZE, sv_WdtThread, NULL, NULL, NULL,
   K_LOWEST_APPLICATION_THREAD_PRIO, 0, K_TICKS_FOREVER);

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
 * @private       sv_LogResetCause
 * @brief         Read, log and clear the reset cause. A watchdog, software or
 *                lockup reset is a warning: the device did not stop on its own.
 * @return        None.
 */
static void sv_LogResetCause(void)
{
   uint32_t u32_cause = 0U;
   bool b_named = false;
   size_t i;
   int i_ret;

   i_ret = hwinfo_get_reset_cause(&u32_cause);

   // Check if the hardware can tell why it reset
   if (i_ret != 0)
   {
      APP_LOG_WRN("reset cause unknown (%d)", i_ret);
      return;
   }

   su32_resetCause = u32_cause;
   for (i = 0U; i < ARRAY_SIZE(scstar_causeNames); i++)
   {
      if ((u32_cause & scstar_causeNames[i].u32_flag) == 0U)
      {
         continue;
      }
      b_named = true;
      if ((scstar_causeNames[i].u32_flag & (RESET_WATCHDOG | RESET_SOFTWARE | RESET_CPU_LOCKUP)) != 0U)
      {
         APP_LOG_WRN("reset by %s", scstar_causeNames[i].cpt_name);
      }
      else
      {
         APP_LOG_INF("reset by %s", scstar_causeNames[i].cpt_name);
      }
   }

   // Check if none of the causes has a name
   if (!b_named)
   {
      APP_LOG_INF("reset cause 0x%08x", u32_cause);
   }

   // The flags accumulate until cleared: clear them for the next boot
   (void)hwinfo_clear_reset_cause();
}

/**
 * @private       sv_Feed
 * @brief         Feed the supervisor's channel; log the first failure.
 * @return        None.
 */
static void sv_Feed(void)
{
   int i_ret = task_wdt_feed(si_channel);

   // Check if the feed failed for the first time
   if ((i_ret != 0) && !sb_feedFailed)
   {
      sb_feedFailed = true;
      APP_LOG_ERR("task_wdt_feed failed (%d)", i_ret);
   }
}

/**
 * @private       sv_WdtThread
 * @brief         The supervisor: feed, sleep, for ever.
 * @param[in]     vpt_p1 Unused.
 * @param[in]     vpt_p2 Unused.
 * @param[in]     vpt_p3 Unused.
 * @return        None.
 */
static void sv_WdtThread(void *vpt_p1, void *vpt_p2, void *vpt_p3)
{
   ARG_UNUSED(vpt_p1);
   ARG_UNUSED(vpt_p2);
   ARG_UNUSED(vpt_p3);

   for (;;)
   {
      sv_Feed();
      (void)k_msleep(CONFIG_APP_WDT_FEED_MS);
   }
}

/******************************************************************************/
/*                                                                            */
/*                        PUBLIC FUNCTION DEFINITIONS                         */
/*                                                                            */
/******************************************************************************/
/**
 * @public        gi_Wdt_Init
 * @brief         Log the reset cause, start the task watchdog (hardware fallback
 *                when watchdog0 is ready) and the supervisor. Call once, first in
 *                main(), so the rest of the boot is supervised too.
 * @return        0 on success, otherwise the task_wdt_init() or task_wdt_add()
 *                error (the device then runs without the watchdog).
 */
int gi_Wdt_Init(void)
{
   const struct device *stpt_hw = WDT_HW_DEVICE;
   int i_ret;

   sv_LogResetCause();

   // Check if the hardware watchdog is missing or not ready
   if ((stpt_hw != NULL) && !device_is_ready(stpt_hw))
   {
      APP_LOG_WRN("hardware watchdog not ready: task watchdog without fallback");
      stpt_hw = NULL;
   }

   i_ret = task_wdt_init(stpt_hw);

   // Check if the task watchdog could be started
   if (i_ret != 0)
   {
      APP_LOG_ERR("task_wdt_init failed (%d): no watchdog", i_ret);
      return i_ret;
   }

   i_ret = task_wdt_add(CONFIG_APP_WDT_TIMEOUT_MS, NULL, NULL);

   // Check if the supervisor's channel could be added
   if (i_ret < 0)
   {
      APP_LOG_ERR("task_wdt_add failed (%d): no watchdog", i_ret);
      return i_ret;
   }

   si_channel = i_ret;
   k_thread_start(sst_wdtThread);
   APP_LOG_INF("watchdog: %d ms, fed every %d ms%s", CONFIG_APP_WDT_TIMEOUT_MS, CONFIG_APP_WDT_FEED_MS,
      (stpt_hw != NULL) ? ", hardware fallback" : "");

   return 0;
}

/**
 * @public        gu32_Wdt_ResetCause
 * @brief         The RESET_* flags read at boot by gi_Wdt_Init() (0 before it, or
 *                when the hardware cannot tell). Any thread.
 * @return        The flags.
 */
uint32_t gu32_Wdt_ResetCause(void)
{
   return su32_resetCause;
}

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shivam Chudasama [SC]
 */
