/**
 * @file          test_wdt.c
 * @brief         Host unit tests for the application watchdog (_ASW/_WDT/Wdt.c):
 *                the reset cause logged and cleared at boot, the task watchdog
 *                started on the hardware watchdog (or without it), the
 *                supervisor's channel, its feed, and every init failure. The
 *                task watchdog, hwinfo and the device are recorded stubs.
 *                Built as wdt (alias watchdog0 enabled, the firmware's overlay)
 *                and wdt_nohw (no hardware watchdog node).
 *
 * @date          18/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

/* Kconfig values the module reads (prj.conf / _DI/Kconfig defaults) */
#define CONFIG_APP_WDT_TIMEOUT_MS            8000
#define CONFIG_APP_WDT_FEED_MS               1000
#ifndef SHIM_DT_OKAY_watchdog0
#define SHIM_DT_OKAY_watchdog0               1
#endif

/* DEVICE_DT_GET(DT_ALIAS(watchdog0)) in the module names this device */
#include "zephyr/device.h"
struct device gst_simDev_watchdog0 = { "wdt31" };

#include "Wdt.c"
#include "unity.h"

/******************************************************************************/
/*  Stubs: the hardware watchdog device, hwinfo, the task watchdog            */
/******************************************************************************/
static bool sb_hwReady;
static uint32_t su32_readyCalls;

static uint32_t su32_cause;
static int si_causeRet;
static uint32_t su32_clears;

static int si_initRet;
static uint32_t su32_inits;
static const struct device *sstpt_initHw;
static int si_addRet;
static uint32_t su32_adds;
static uint32_t su32_addPeriod;
static task_wdt_callback_t sfpt_addCb;
static int si_feedRet;
static uint32_t su32_feeds;
static int si_fedChannel;

bool device_is_ready(const struct device *dev)
{
   TEST_ASSERT_EQUAL_PTR(&gst_simDev_watchdog0, dev);
   su32_readyCalls++;
   return sb_hwReady;
}

ssize_t hwinfo_get_device_id(uint8_t *buffer, size_t length)
{
   (void)buffer;
   (void)length;
   return -ENOSYS;
}

int hwinfo_get_reset_cause(uint32_t *cause)
{
   *cause = su32_cause;
   return si_causeRet;
}

int hwinfo_clear_reset_cause(void)
{
   su32_clears++;
   return 0;
}

int task_wdt_init(const struct device *hw_wdt)
{
   su32_inits++;
   sstpt_initHw = hw_wdt;
   return si_initRet;
}

int task_wdt_add(uint32_t reload_period, task_wdt_callback_t callback, void *user_data)
{
   (void)user_data;
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(1U, su32_inits, "channel added after the init");
   su32_adds++;
   su32_addPeriod = reload_period;
   sfpt_addCb = callback;
   return si_addRet;
}

int task_wdt_delete(int channel_id)
{
   (void)channel_id;
   return 0;
}

int task_wdt_feed(int channel_id)
{
   su32_feeds++;
   si_fedChannel = channel_id;
   return si_feedRet;
}

void setUp(void)
{
   sb_hwReady = true;
   su32_readyCalls = 0U;
   su32_cause = 0U;
   si_causeRet = 0;
   su32_clears = 0U;
   si_initRet = 0;
   su32_inits = 0U;
   sstpt_initHw = NULL;
   si_addRet = 2;
   su32_adds = 0U;
   su32_addPeriod = 0U;
   sfpt_addCb = (task_wdt_callback_t)1;
   si_feedRet = 0;
   su32_feeds = 0U;
   si_fedChannel = -100;
   su32_resetCause = 0U;
   si_channel = -1;
   sb_feedFailed = false;
   gv_SimLogClear();
}

void tearDown(void) {}

/******************************************************************************/
/*  Start                                                                     */
/******************************************************************************/
static void test_InitStartsTheTaskWatchdogAndItsChannel(void)
{
   TEST_ASSERT_EQUAL_INT(0, gi_Wdt_Init());
   TEST_ASSERT_EQUAL_UINT32(1U, su32_inits);
#if SHIM_DT_OKAY_watchdog0
   // The hardware watchdog backs it up
   TEST_ASSERT_EQUAL_PTR(&gst_simDev_watchdog0, sstpt_initHw);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("hardware fallback"));
#else
   // No node: a software task watchdog, and the device is never asked
   TEST_ASSERT_NULL(sstpt_initHw);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_readyCalls);
   TEST_ASSERT_NULL(gcpt_SimLogFind("hardware fallback"));
#endif
   // One channel, the configured timeout, no callback: an expiry reboots
   TEST_ASSERT_EQUAL_UINT32(1U, su32_adds);
   TEST_ASSERT_EQUAL_UINT32(CONFIG_APP_WDT_TIMEOUT_MS, su32_addPeriod);
   TEST_ASSERT_NULL(sfpt_addCb);
   TEST_ASSERT_EQUAL_INT(2, si_channel);
}

static void test_HardwareNotReadyRunsWithoutTheFallback(void)
{
   sb_hwReady = false;
   TEST_ASSERT_EQUAL_INT(0, gi_Wdt_Init());
   TEST_ASSERT_NULL(sstpt_initHw);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_adds);
#if SHIM_DT_OKAY_watchdog0
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("hardware watchdog not ready"));
#endif
}

static void test_InitFailureLeavesNoChannel(void)
{
   si_initRet = -ENODEV;
   TEST_ASSERT_EQUAL_INT(-ENODEV, gi_Wdt_Init());
   TEST_ASSERT_EQUAL_UINT32(0U, su32_adds);
   TEST_ASSERT_EQUAL_INT(-1, si_channel);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("task_wdt_init failed (-19)"));
}

static void test_AddFailureLeavesNoChannel(void)
{
   si_addRet = -ENOMEM;
   TEST_ASSERT_EQUAL_INT(-ENOMEM, gi_Wdt_Init());
   TEST_ASSERT_EQUAL_INT(-1, si_channel);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("task_wdt_add failed"));
}

/******************************************************************************/
/*  Feed                                                                      */
/******************************************************************************/
static void test_SupervisorFeedsItsChannel(void)
{
   TEST_ASSERT_EQUAL_INT(0, gi_Wdt_Init());
   sv_Feed();
   sv_Feed();
   TEST_ASSERT_EQUAL_UINT32(2U, su32_feeds);
   TEST_ASSERT_EQUAL_INT(2, si_fedChannel);
   TEST_ASSERT_NULL(gcpt_SimLogFind("task_wdt_feed failed"));
}

static void test_FeedFailureIsLoggedOnce(void)
{
   uint32_t i;
   uint32_t u32_lines = 0U;

   TEST_ASSERT_EQUAL_INT(0, gi_Wdt_Init());
   si_feedRet = -EINVAL;
   for (i = 0U; i < 3U; i++) { sv_Feed(); }
   TEST_ASSERT_EQUAL_UINT32(3U, su32_feeds);
   for (i = 0U; i < gu32_SimLogCount(); i++)
   {
      if (strstr(gcpt_SimLogLine(i), "task_wdt_feed failed (-22)") != NULL) { u32_lines++; }
   }
   TEST_ASSERT_EQUAL_UINT32(1U, u32_lines);
}

/******************************************************************************/
/*  Reset cause                                                               */
/******************************************************************************/
static void test_WatchdogResetIsReportedAndCleared(void)
{
   su32_cause = RESET_WATCHDOG;
   TEST_ASSERT_EQUAL_UINT32(0U, gu32_Wdt_ResetCause());
   TEST_ASSERT_EQUAL_INT(0, gi_Wdt_Init());
   TEST_ASSERT_EQUAL_HEX32(RESET_WATCHDOG, gu32_Wdt_ResetCause());
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("reset by watchdog"));
   TEST_ASSERT_EQUAL_UINT32(1U, su32_clears);
}

static void test_FatalErrorResetIsSoftware(void)
{
   su32_cause = RESET_SOFTWARE;
   TEST_ASSERT_EQUAL_INT(0, gi_Wdt_Init());
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("reset by software (fatal error or reboot)"));
}

static void test_EveryCauseIsNamed(void)
{
   su32_cause = RESET_POR | RESET_PIN | RESET_CPU_LOCKUP;
   TEST_ASSERT_EQUAL_INT(0, gi_Wdt_Init());
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("reset by power-on"));
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("reset by reset pin"));
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("reset by CPU lockup"));
   TEST_ASSERT_NULL(gcpt_SimLogFind("reset cause 0x"));
}

static void test_UnnamedCauseIsLoggedAsFlags(void)
{
   su32_cause = RESET_PLL;
   TEST_ASSERT_EQUAL_INT(0, gi_Wdt_Init());
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("reset cause 0x00000400"));
   TEST_ASSERT_EQUAL_UINT32(1U, su32_clears);
}

static void test_UnreadableCauseIsNotCleared(void)
{
   su32_cause = RESET_WATCHDOG;
   si_causeRet = -ENOSYS;
   TEST_ASSERT_EQUAL_INT(0, gi_Wdt_Init());
   TEST_ASSERT_EQUAL_UINT32(0U, gu32_Wdt_ResetCause());
   TEST_ASSERT_EQUAL_UINT32(0U, su32_clears);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("reset cause unknown (-"));
   // The watchdog still starts
   TEST_ASSERT_EQUAL_UINT32(1U, su32_adds);
}

int main(void)
{
   (void)setvbuf(stdout, NULL, _IONBF, 0);

   UNITY_BEGIN();
   RUN_TEST(test_InitStartsTheTaskWatchdogAndItsChannel);
   RUN_TEST(test_HardwareNotReadyRunsWithoutTheFallback);
   RUN_TEST(test_InitFailureLeavesNoChannel);
   RUN_TEST(test_AddFailureLeavesNoChannel);
   RUN_TEST(test_SupervisorFeedsItsChannel);
   RUN_TEST(test_FeedFailureIsLoggedOnce);
   RUN_TEST(test_WatchdogResetIsReportedAndCleared);
   RUN_TEST(test_FatalErrorResetIsSoftware);
   RUN_TEST(test_EveryCauseIsNamed);
   RUN_TEST(test_UnnamedCauseIsLoggedAsFlags);
   RUN_TEST(test_UnreadableCauseIsNotCleared);
   return UNITY_END();
}
