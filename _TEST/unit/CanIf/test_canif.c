/**
 * @file          test_canif.c
 * @brief         Host unit tests for the CAN / CAN FD interface
 *                (_ASW/_CAN/CanIf.c), run against a scripted controller that
 *                implements Zephyr's CAN API (shim/zephyr/drivers/can.h): it
 *                records the mode, bitrates and start/stop, echoes frames in
 *                loopback mode, matches frames against the installed filters
 *                like the driver, reports state changes and returns scripted
 *                errors. CanIf.c is included to reach its thread and state.
 *                Built twice: "canif" (CAN FD, self-test and traffic log on) and
 *                "canif_classic" (a CAN 2.0 build, both off).
 *                Contract: _DOC/CAN/README.md.
 *
 * @date          12/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#define CONFIG_CANIF_BITRATE                 500000
#ifdef CONFIG_CAN_FD_MODE
#define CONFIG_CANIF_BITRATE_DATA            2000000
#endif // CONFIG_CAN_FD_MODE
#define CONFIG_CANIF_LOG_RX_MAX_PER_SEC      3
#define CONFIG_CANIF_TEST_TX_PERIOD_MS       1000
#define CONFIG_CANIF_MAX_FILTERS             4
#define CONFIG_CANIF_RX_QUEUE_DEPTH          6
#define CONFIG_CANIF_STACK_SIZE              2048
#define CONFIG_CANIF_PRIORITY                6

#include <zephyr/device.h>
extern const struct device gst_simDev_zephyr_canbus;

#include "CanIf.c"
#include "unity.h"

/******************************************************************************/
/*  Scripted controller                                                       */
/******************************************************************************/
#define SIM_FILTERS                          (16U)
#define SIM_SENT_MAX                         (8U)

const struct device gst_simDev_zephyr_canbus = { "can@0" };

typedef struct
{
   bool b_used;
   can_rx_callback_t fpt_cb;
   void *vpt_user;
   struct can_filter st_filter;
} SimFilter_T;

static struct
{
   uint32_t u32_initCalls;                   /* device_init()                      */
   int i_initRet;
   bool b_ready;                             /* device_is_ready()                  */
   can_mode_t t_cap;                         /* can_get_capabilities()             */
   int i_capRet;
   can_mode_t t_mode;                        /* last can_set_mode()                */
   uint32_t u32_bitrate;
   uint32_t u32_bitrateData;
   uint32_t u32_badBitrate;                  /* can_set_bitrate() refuses it       */
   bool b_started;
   uint32_t u32_startCalls;
   uint32_t u32_startFailAt;                 /* fail this start and later (1-based)*/
   int i_startRet;
   int i_stopRet;
   int i_sendRet;
   bool b_echo;                              /* loopback mode echoes sent frames   */
   bool b_corrupt;                           /* ... with a changed byte            */
   uint32_t u32_sends;
   struct can_frame star_sent[SIM_SENT_MAX];
   can_mode_t tar_sentMode[SIM_SENT_MAX];
   uint32_t u32_filterCap;                   /* driver filters available           */
   SimFilter_T star_filters[SIM_FILTERS];
   can_state_change_callback_t fpt_state;
   enum can_state e_state;
   struct can_bus_err_cnt st_errCnt;
   int i_getStateRet;
} sst_can;

int device_init(const struct device *dev)
{
   TEST_ASSERT_EQUAL_PTR(&gst_simDev_zephyr_canbus, dev);
   sst_can.u32_initCalls++;
   return sst_can.i_initRet;
}

bool device_is_ready(const struct device *dev)
{
   TEST_ASSERT_EQUAL_PTR(&gst_simDev_zephyr_canbus, dev);
   // The driver is deferred (zephyr,deferred-init): initialised first
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(1U, sst_can.u32_initCalls, "device_init() before device_is_ready()");
   return sst_can.b_ready;
}

int can_get_capabilities(const struct device *dev, can_mode_t *cap)
{
   ARG_UNUSED(dev);
   *cap = sst_can.t_cap;
   return sst_can.i_capRet;
}

int can_set_mode(const struct device *dev, can_mode_t mode)
{
   ARG_UNUSED(dev);
   if (sst_can.b_started)
   {
      return -EBUSY;
   }
   if ((mode & ~sst_can.t_cap) != 0U)
   {
      return -ENOTSUP;
   }
   sst_can.t_mode = mode;
   return 0;
}

int can_set_bitrate(const struct device *dev, uint32_t bitrate)
{
   ARG_UNUSED(dev);
   if (sst_can.b_started)
   {
      return -EBUSY;
   }
   if (bitrate == sst_can.u32_badBitrate)
   {
      return -ENOTSUP;
   }
   sst_can.u32_bitrate = bitrate;
   return 0;
}

#ifdef CONFIG_CAN_FD_MODE
int can_set_bitrate_data(const struct device *dev, uint32_t bitrate_data)
{
   ARG_UNUSED(dev);
   if (sst_can.b_started)
   {
      return -EBUSY;
   }
   sst_can.u32_bitrateData = bitrate_data;
   return 0;
}
#endif // CONFIG_CAN_FD_MODE

int can_start(const struct device *dev)
{
   ARG_UNUSED(dev);
   if (sst_can.b_started)
   {
      return -EALREADY;
   }
   sst_can.u32_startCalls++;
   if ((sst_can.u32_startFailAt != 0U) && (sst_can.u32_startCalls >= sst_can.u32_startFailAt))
   {
      return sst_can.i_startRet;
   }
   sst_can.b_started = true;
   return 0;
}

int can_stop(const struct device *dev)
{
   ARG_UNUSED(dev);
   if (!sst_can.b_started)
   {
      return -EALREADY;
   }
   if (sst_can.i_stopRet != 0)
   {
      return sst_can.i_stopRet;
   }
   sst_can.b_started = false;
   return 0;
}

/** The driver's matching: the IDE flag must agree, then id under mask. */
static bool sb_SimMatches(const struct can_filter *stpt_filter, const struct can_frame *stpt_frame)
{
   bool b_ext = ((stpt_frame->flags & CAN_FRAME_IDE) != 0U);

   if (b_ext != ((stpt_filter->flags & CAN_FILTER_IDE) != 0U))
   {
      return false;
   }
   return (stpt_frame->id & stpt_filter->mask) == (stpt_filter->id & stpt_filter->mask);
}

/** A frame arrives from the bus: every matching filter's callback, as the
    driver's interrupt thread would call them. */
static void sv_SimDeliver(const struct can_frame *stpt_frame)
{
   struct can_frame st_copy;
   uint32_t i;

   for (i = 0U; i < SIM_FILTERS; i++)
   {
      if (sst_can.star_filters[i].b_used && sb_SimMatches(&sst_can.star_filters[i].st_filter, stpt_frame))
      {
         st_copy = *stpt_frame;
         sst_can.star_filters[i].fpt_cb(&gst_simDev_zephyr_canbus, &st_copy,
            sst_can.star_filters[i].vpt_user);
      }
   }
}

int can_send(const struct device *dev, const struct can_frame *frame, k_timeout_t timeout,
   can_tx_callback_t callback, void *user_data)
{
   struct can_frame st_echo;

   ARG_UNUSED(dev);
   ARG_UNUSED(timeout);
   TEST_ASSERT_NULL_MESSAGE(callback, "CanIf sends blocking");
   TEST_ASSERT_NULL(user_data);

   if (sst_can.u32_sends < SIM_SENT_MAX)
   {
      sst_can.star_sent[sst_can.u32_sends] = *frame;
      sst_can.tar_sentMode[sst_can.u32_sends] = sst_can.t_mode;
   }
   sst_can.u32_sends++;

   if (sst_can.i_sendRet != 0)
   {
      return sst_can.i_sendRet;
   }
   if (!sst_can.b_started)
   {
      return -ENETDOWN;
   }
   if (((sst_can.t_mode & CAN_MODE_LOOPBACK) != 0U) && sst_can.b_echo)
   {
      st_echo = *frame;
      if (sst_can.b_corrupt)
      {
         st_echo.data[0] ^= 0xFFU;
      }
      sv_SimDeliver(&st_echo);
   }
   return 0;
}

int can_add_rx_filter(const struct device *dev, can_rx_callback_t callback, void *user_data,
   const struct can_filter *filter)
{
   uint32_t i;

   ARG_UNUSED(dev);
   for (i = 0U; i < sst_can.u32_filterCap; i++)
   {
      if (!sst_can.star_filters[i].b_used)
      {
         sst_can.star_filters[i].b_used = true;
         sst_can.star_filters[i].fpt_cb = callback;
         sst_can.star_filters[i].vpt_user = user_data;
         sst_can.star_filters[i].st_filter = *filter;
         return (int)i;
      }
   }
   return -ENOSPC;
}

void can_remove_rx_filter(const struct device *dev, int filter_id)
{
   ARG_UNUSED(dev);
   TEST_ASSERT_TRUE_MESSAGE((filter_id >= 0) && (filter_id < (int)SIM_FILTERS), "valid driver id");
   TEST_ASSERT_TRUE_MESSAGE(sst_can.star_filters[filter_id].b_used, "removes an installed filter");
   sst_can.star_filters[filter_id].b_used = false;
}

int can_get_state(const struct device *dev, enum can_state *state, struct can_bus_err_cnt *err_cnt)
{
   ARG_UNUSED(dev);
   if (sst_can.i_getStateRet != 0)
   {
      return sst_can.i_getStateRet;
   }
   *state = sst_can.e_state;
   *err_cnt = sst_can.st_errCnt;
   return 0;
}

void can_set_state_change_callback(const struct device *dev, can_state_change_callback_t callback,
   void *user_data)
{
   ARG_UNUSED(dev);
   TEST_ASSERT_NULL(user_data);
   sst_can.fpt_state = callback;
}

/* A k_sem_take() that would block (the self-test waiting for its echo) */
void gv_SimOnBlock(struct k_sem *stpt_sem)
{
   ARG_UNUSED(stpt_sem);
}

/******************************************************************************/
/*  Helpers                                                                   */
/******************************************************************************/
#define USER_A                               ((void *)&sst_can.u32_sends)
#define USER_B                               ((void *)&sst_can.u32_startCalls)
#define GOT_MAX                              (8U)
#define START_CALL_OF_INIT                   (IS_ENABLED(CONFIG_CANIF_SELFTEST) ? 2U : 1U)

static const CanIfConfig_T scst_boot =
{
   IS_ENABLED(CONFIG_CANIF_FD), false, CONFIG_CANIF_BITRATE, CANIF_BOOT_BITRATE_DATA
};

static struct can_frame sstar_got[GOT_MAX];
static uint32_t su32_got;
static void *svpt_gotUser;

static enum can_state se_heard;
static struct can_bus_err_cnt sst_heardErr;
static uint32_t su32_heard;

static void sv_OnRx(const struct can_frame *stpt_frame, void *vpt_user)
{
   if (su32_got < GOT_MAX)
   {
      sstar_got[su32_got] = *stpt_frame;
   }
   su32_got++;
   svpt_gotUser = vpt_user;
}

static void sv_OnStateHeard(enum can_state e_state, const struct can_bus_err_cnt *stpt_errCnt,
   void *vpt_user)
{
   ARG_UNUSED(vpt_user);
   se_heard = e_state;
   sst_heardErr = *stpt_errCnt;
   su32_heard++;
}

static void sv_OnStateOther(enum can_state e_state, const struct can_bus_err_cnt *stpt_errCnt,
   void *vpt_user)
{
   ARG_UNUSED(e_state);
   ARG_UNUSED(stpt_errCnt);
   ARG_UNUSED(vpt_user);
}

/** Driver filters installed now. */
static uint32_t su32_ActiveFilters(void)
{
   uint32_t u32_n = 0U;
   uint32_t i;

   for (i = 0U; i < SIM_FILTERS; i++)
   {
      u32_n += sst_can.star_filters[i].b_used ? 1U : 0U;
   }
   return u32_n;
}

/** A frame with a standard or extended id and len payload bytes (0x10, 0x11, …). */
static struct can_frame sst_Frame(uint32_t u32_id, uint8_t u8_flags, uint8_t u8_len)
{
   struct can_frame st_frame;
   uint32_t i;

   memset(&st_frame, 0, sizeof(st_frame));
   st_frame.id = u32_id;
   st_frame.flags = u8_flags;
   st_frame.dlc = can_bytes_to_dlc(u8_len);
   for (i = 0U; i < u8_len; i++)
   {
      st_frame.data[i] = (uint8_t)(0x10U + i);
   }
   return st_frame;
}

static void sv_Inject(uint32_t u32_id, uint8_t u8_flags, uint8_t u8_len)
{
   struct can_frame st_frame = sst_Frame(u32_id, u8_flags, u8_len);

   sv_SimDeliver(&st_frame);
}

static void sv_InjectState(enum can_state e_state, uint8_t u8_tx, uint8_t u8_rx)
{
   struct can_bus_err_cnt st_err = { u8_tx, u8_rx };

   TEST_ASSERT_NOT_NULL_MESSAGE(sst_can.fpt_state, "init registers the state callback");
   sst_can.fpt_state(&gst_simDev_zephyr_canbus, e_state, st_err, NULL);
}

/** Let the CAN interface thread drain its queue. */
static void sv_RunThread(void)
{
   gv_SimRunThread(sv_CanIfThread);
}

static CanIfStatus_T sst_Status(void)
{
   CanIfStatus_T st_status;

   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_GetStatus(&st_status));
   return st_status;
}

static void sv_InitOk(void)
{
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_Init());
   gv_SimLogClear();
}

void setUp(void)
{
   uint32_t i;

   // The controller: present, every mode, filters free
   memset(&sst_can, 0, sizeof(sst_can));
   sst_can.b_ready = true;
   sst_can.t_cap = CAN_MODE_LOOPBACK | CAN_MODE_LISTENONLY;
#ifdef CONFIG_CAN_FD_MODE
   sst_can.t_cap |= CAN_MODE_FD;
#endif // CONFIG_CAN_FD_MODE
   sst_can.b_echo = true;
   sst_can.u32_filterCap = SIM_FILTERS;
   sst_can.i_startRet = -EIO;

   // The module, as after boot
   sb_ready = false;
   sb_started = false;
   sb_capFd = false;
   sb_monitor = false;
   sst_config = scst_boot;
   se_state = CAN_STATE_STOPPED;
   memset(sstar_slots, 0, sizeof(sstar_slots));
   memset(sstar_listeners, 0, sizeof(sstar_listeners));
   for (i = 0U; i < CANIF_MONITOR_FILTERS; i++)
   {
      siar_monitorIds[i] = -1;
   }
   (void)atomic_ptr_set(&st_owner, NULL);
   (void)atomic_set(&st_txFrames, 0);
   (void)atomic_set(&st_rxFrames, 0);
   (void)atomic_set(&st_rxDropped, 0);
   su32_busOffCount = 0U;
   si64_logWindowMs = 0;
   su32_logCount = 0U;
   su32_logSuppressed = 0U;
   su32_testCount = 0U;
   k_sem_reset(&sst_selfTestSem);
   k_msgq_purge(&sst_canIfMsgq);
   (void)k_work_cancel_delayable(&sst_testTxWork);

   su32_got = 0U;
   svpt_gotUser = NULL;
   su32_heard = 0U;
   gi64_simNowMs = 0;
   gv_SimLogClear();
}

void tearDown(void)
{
   TEST_ASSERT_EQUAL_INT_MESSAGE(0, sst_canIfMutex.i_held, "mutex released");
}

/******************************************************************************/
/*  Init                                                                      */
/******************************************************************************/
static void test_InitWithoutTheControllerLeavesEverythingRefused(void)
{
   CanIfConfig_T st_config = scst_boot;
   struct can_filter st_filter = { 0x100U, CAN_STD_ID_MASK, 0U };
   struct can_frame st_frame = sst_Frame(0x100U, 0U, 1U);
   CanIfStatus_T st_status;

   // The driver's init finds no controller
   sst_can.i_initRet = -EIO;
   sst_can.b_ready = false;
   TEST_ASSERT_EQUAL_INT(-ENODEV, gi_CanIf_Init());
   TEST_ASSERT_EQUAL_UINT32(1U, sst_can.u32_initCalls);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("can@0 init failed (-5)"));
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("can@0 not ready: check the click"));

   TEST_ASSERT_EQUAL_INT(-ENODEV, gi_CanIf_Send(&st_frame, K_NO_WAIT));
   TEST_ASSERT_EQUAL_INT(-ENODEV, gi_CanIf_AddRxFilter(&st_filter, sv_OnRx, NULL));
   TEST_ASSERT_EQUAL_INT(-ENODEV, gi_CanIf_RemoveRxFilter(0));
   TEST_ASSERT_EQUAL_INT(-ENODEV, gi_CanIf_Configure(&st_config, NULL));
   TEST_ASSERT_NULL(gstpt_CanIf_GetDevice());
   gv_CanIf_SetMonitor(true);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("CAN not ready"));

   st_status = sst_Status();
   TEST_ASSERT_FALSE(st_status.b_ready);
   TEST_ASSERT_FALSE(st_status.b_started);
   TEST_ASSERT_EQUAL_INT(CAN_STATE_STOPPED, st_status.e_state);
   TEST_ASSERT_EQUAL_UINT32(CONFIG_CANIF_BITRATE, st_status.st_config.u32_bitrate);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, sst_can.u32_startCalls, "controller untouched");
   TEST_ASSERT_FALSE(k_work_delayable_is_pending(&sst_testTxWork));
}

static void test_InitTwiceIsRefused(void)
{
   sv_InitOk();
   TEST_ASSERT_EQUAL_INT(-EALREADY, gi_CanIf_Init());
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(1U, sst_can.u32_initCalls, "driver initialised once");
}

static void test_InitInitialisesTheDeferredDriver(void)
{
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_Init());
   TEST_ASSERT_EQUAL_UINT32(1U, sst_can.u32_initCalls);
   TEST_ASSERT_TRUE(sst_can.b_started);
   TEST_ASSERT_NULL(gcpt_SimLogFind("init failed"));
}

static void test_InitAcceptsADriverInitialisedAtBoot(void)
{
   // Without zephyr,deferred-init the kernel has initialised it already
   sst_can.i_initRet = -EALREADY;
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_Init());
   TEST_ASSERT_TRUE(sst_can.b_started);
   TEST_ASSERT_NULL(gcpt_SimLogFind("init failed"));
}

static void test_InitCapabilitiesErrorIsReturned(void)
{
   sst_can.i_capRet = -EIO;
   TEST_ASSERT_EQUAL_INT(-EIO, gi_CanIf_Init());
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("can_get_capabilities failed (-"));
   TEST_ASSERT_NULL(gstpt_CanIf_GetDevice());
}

#ifdef CONFIG_CAN_FD_MODE
static void test_InitFdBootModeNeedsAnFdController(void)
{
   sst_can.t_cap &= ~CAN_MODE_FD;
   TEST_ASSERT_EQUAL_INT(-ENOTSUP, gi_CanIf_Init());
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("can@0 has no CAN FD"));
   TEST_ASSERT_EQUAL_UINT32(0U, sst_can.u32_startCalls);
}
#endif // CONFIG_CAN_FD_MODE

static void test_InitStartsWithTheBootConfiguration(void)
{
   CanIfStatus_T st_status;

   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_Init());
   TEST_ASSERT_TRUE(sst_can.b_started);
   TEST_ASSERT_EQUAL_UINT32(CONFIG_CANIF_BITRATE, sst_can.u32_bitrate);
   TEST_ASSERT_NOT_NULL(sst_can.fpt_state);
   TEST_ASSERT_EQUAL_PTR(&gst_simDev_zephyr_canbus, gstpt_CanIf_GetDevice());
#ifdef CONFIG_CAN_FD_MODE
   TEST_ASSERT_EQUAL_UINT32(CAN_MODE_FD, sst_can.t_mode);
   TEST_ASSERT_EQUAL_UINT32(CONFIG_CANIF_BITRATE_DATA, sst_can.u32_bitrateData);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("can@0 started: CAN FD, 500000 bit/s, data 2000000 bit/s"));
#else
   TEST_ASSERT_EQUAL_UINT32(CAN_MODE_NORMAL, sst_can.t_mode);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("can@0 started: classic CAN, 500000 bit/s"));
#endif // CONFIG_CAN_FD_MODE

   st_status = sst_Status();
   TEST_ASSERT_TRUE(st_status.b_ready);
   TEST_ASSERT_TRUE(st_status.b_started);
   TEST_ASSERT_FALSE(st_status.b_locked);
   TEST_ASSERT_EQUAL(IS_ENABLED(CONFIG_CANIF_LOG_RX), st_status.b_monitor);
   TEST_ASSERT_EQUAL(IS_ENABLED(CONFIG_CANIF_FD), st_status.st_config.b_fd);
   TEST_ASSERT_FALSE(st_status.st_config.b_listenOnly);

   // The traffic log's two filters (all standard, all extended IDs), nothing else
   TEST_ASSERT_EQUAL_UINT32(IS_ENABLED(CONFIG_CANIF_LOG_RX) ? CANIF_MONITOR_FILTERS : 0U,
      su32_ActiveFilters());
}

static void test_InitStartFailureLeavesTheInterfaceReadyButStopped(void)
{
   CanIfConfig_T st_config = scst_boot;
   struct can_frame st_frame = sst_Frame(0x100U, 0U, 1U);
   CanIfStatus_T st_status;

   sst_can.u32_startFailAt = START_CALL_OF_INIT;
   TEST_ASSERT_EQUAL_INT(-EIO, gi_CanIf_Init());
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("can@0 not started (-"));
   st_status = sst_Status();
   TEST_ASSERT_TRUE(st_status.b_ready);
   TEST_ASSERT_FALSE(st_status.b_started);
   TEST_ASSERT_EQUAL_INT(-ENETDOWN, gi_CanIf_Send(&st_frame, K_NO_WAIT));

   // Configure may try again
   sst_can.u32_startFailAt = 0U;
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_Configure(&st_config, NULL));
   TEST_ASSERT_TRUE(sst_Status().b_started);
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_Send(&st_frame, K_NO_WAIT));
}

static void test_InitInListenOnlyMode(void)
{
   struct can_frame st_frame = sst_Frame(0x100U, 0U, 1U);

   sst_config.b_listenOnly = true;
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_Init());
   TEST_ASSERT_TRUE((sst_can.t_mode & CAN_MODE_LISTENONLY) != 0U);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("bit/s, listen-only"));
   TEST_ASSERT_EQUAL_INT(-EACCES, gi_CanIf_Send(&st_frame, K_NO_WAIT));
}

#ifdef CONFIG_CANIF_SELFTEST
/******************************************************************************/
/*  Self-test                                                                 */
/******************************************************************************/
static void test_SelfTestSendsAClassicAndAnFdFrameInLoopback(void)
{
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_Init());

   TEST_ASSERT_EQUAL_UINT32(IS_ENABLED(CONFIG_CAN_FD_MODE) ? 2U : 1U, sst_can.u32_sends);
   TEST_ASSERT_TRUE((sst_can.tar_sentMode[0] & CAN_MODE_LOOPBACK) != 0U);
   TEST_ASSERT_EQUAL_HEX32(CANIF_TEST_ID, sst_can.star_sent[0].id);
   TEST_ASSERT_EQUAL_UINT8(8U, sst_can.star_sent[0].dlc);
   TEST_ASSERT_EQUAL_UINT8(0U, sst_can.star_sent[0].flags);
#ifdef CONFIG_CAN_FD_MODE
   TEST_ASSERT_EQUAL_UINT32(CAN_MODE_LOOPBACK | CAN_MODE_FD, sst_can.tar_sentMode[1]);
   TEST_ASSERT_EQUAL_UINT8(CAN_FRAME_FDF | CAN_FRAME_BRS, sst_can.star_sent[1].flags);
   TEST_ASSERT_EQUAL_UINT8(64U, can_dlc_to_bytes(sst_can.star_sent[1].dlc));
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("loopback self-test passed (classic and FD)"));
#else
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("loopback self-test passed (classic)"));
#endif // CONFIG_CAN_FD_MODE

   // Then the boot mode, without loopback, and the self-test's filter is gone
   TEST_ASSERT_EQUAL_UINT32(0U, sst_can.t_mode & CAN_MODE_LOOPBACK);
   TEST_ASSERT_EQUAL_UINT32(IS_ENABLED(CONFIG_CANIF_LOG_RX) ? CANIF_MONITOR_FILTERS : 0U,
      su32_ActiveFilters());
}

static void sv_ExpectSelfTestFailure(void)
{
   TEST_ASSERT_EQUAL_INT(-EIO, gi_CanIf_Init());
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("loopback self-test failed (-"));
   TEST_ASSERT_FALSE(sst_can.b_started);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, su32_ActiveFilters(), "self-test filter removed");
   TEST_ASSERT_NULL(gstpt_CanIf_GetDevice());
   TEST_ASSERT_FALSE(sst_Status().b_ready);
}

static void test_SelfTestFailsWhenNothingComesBack(void)
{
   sst_can.b_echo = false;
   sv_ExpectSelfTestFailure();
}

static void test_SelfTestFailsWhenTheFrameComesBackChanged(void)
{
   sst_can.b_corrupt = true;
   sv_ExpectSelfTestFailure();
}

static void test_SelfTestFailsWhenSendingFails(void)
{
   sst_can.i_sendRet = -EIO;
   sv_ExpectSelfTestFailure();
}

static void test_SelfTestFailsWhenTheControllerDoesNotStart(void)
{
   sst_can.u32_startFailAt = 1U;
   sv_ExpectSelfTestFailure();
   TEST_ASSERT_EQUAL_UINT32(0U, sst_can.u32_sends);
}
#endif // CONFIG_CANIF_SELFTEST

/******************************************************************************/
/*  Send                                                                      */
/******************************************************************************/
static void test_SendClassicFrame(void)
{
   struct can_frame st_frame = sst_Frame(0x7E0U, 0U, 8U);
   uint32_t u32_before;

   sv_InitOk();
   u32_before = sst_can.u32_sends;
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_Send(&st_frame, K_MSEC(10)));
   TEST_ASSERT_EQUAL_UINT32(u32_before + 1U, sst_can.u32_sends);
   TEST_ASSERT_EQUAL_MEMORY(&st_frame, &sst_can.star_sent[u32_before], sizeof(st_frame));
   TEST_ASSERT_EQUAL_UINT32(1U, sst_Status().u32_txFrames);

   // Extended ID at the top of the range
   st_frame = sst_Frame(CAN_EXT_ID_MASK, CAN_FRAME_IDE, 0U);
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_Send(&st_frame, K_NO_WAIT));
}

#ifdef CONFIG_CAN_FD_MODE
static void test_SendFdFrameWithBitRateSwitching(void)
{
   struct can_frame st_frame = sst_Frame(0x18DA10F1U, CAN_FRAME_IDE | CAN_FRAME_FDF | CAN_FRAME_BRS, 64U);

   sv_InitOk();
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_Send(&st_frame, K_NO_WAIT));
   TEST_ASSERT_EQUAL_UINT8(15U, sst_can.star_sent[sst_can.u32_sends - 1U].dlc);
}
#endif // CONFIG_CAN_FD_MODE

static void test_SendRejectsBadFrames(void)
{
   struct can_frame st_frame;
   uint32_t u32_before;

   sv_InitOk();
   u32_before = sst_can.u32_sends;

   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_CanIf_Send(NULL, K_NO_WAIT));
   st_frame = sst_Frame(0x100U, CAN_FRAME_ESI, 1U);
   TEST_ASSERT_EQUAL_INT_MESSAGE(-EINVAL, gi_CanIf_Send(&st_frame, K_NO_WAIT), "ESI is RX only");
   st_frame = sst_Frame(0x800U, 0U, 1U);
   TEST_ASSERT_EQUAL_INT_MESSAGE(-EINVAL, gi_CanIf_Send(&st_frame, K_NO_WAIT), "11-bit ID");
   st_frame = sst_Frame(0x20000000U, CAN_FRAME_IDE, 1U);
   TEST_ASSERT_EQUAL_INT_MESSAGE(-EINVAL, gi_CanIf_Send(&st_frame, K_NO_WAIT), "29-bit ID");
   st_frame = sst_Frame(0x100U, 0U, 8U);
   st_frame.dlc = 9U;
   TEST_ASSERT_EQUAL_INT_MESSAGE(-EINVAL, gi_CanIf_Send(&st_frame, K_NO_WAIT), "classic DLC");
   st_frame = sst_Frame(0x100U, CAN_FRAME_BRS, 1U);
   TEST_ASSERT_EQUAL_INT_MESSAGE(-EINVAL, gi_CanIf_Send(&st_frame, K_NO_WAIT), "BRS without FDF");
   st_frame = sst_Frame(0x100U, CAN_FRAME_FDF, 8U);
   st_frame.dlc = 16U;
   TEST_ASSERT_EQUAL_INT_MESSAGE(-EINVAL, gi_CanIf_Send(&st_frame, K_NO_WAIT), "FD DLC");
   st_frame = sst_Frame(0x100U, CAN_FRAME_FDF | CAN_FRAME_RTR, 0U);
   TEST_ASSERT_EQUAL_INT_MESSAGE(-EINVAL, gi_CanIf_Send(&st_frame, K_NO_WAIT), "FD has no RTR");

   TEST_ASSERT_EQUAL_UINT32(u32_before, sst_can.u32_sends);
   TEST_ASSERT_EQUAL_UINT32(0U, sst_Status().u32_txFrames);
}

static void test_SendFdFrameInClassicModeIsNotSupported(void)
{
   CanIfConfig_T st_config = { false, false, 250000U, 0U };
   struct can_frame st_frame = sst_Frame(0x100U, CAN_FRAME_FDF, 8U);

   sv_InitOk();
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_Configure(&st_config, NULL));
   TEST_ASSERT_EQUAL_INT(-ENOTSUP, gi_CanIf_Send(&st_frame, K_NO_WAIT));
}

static void test_SendErrorsPassThrough(void)
{
   struct can_frame st_frame = sst_Frame(0x100U, 0U, 2U);

   sv_InitOk();
   sst_can.i_sendRet = -ENETUNREACH;
   TEST_ASSERT_EQUAL_INT(-ENETUNREACH, gi_CanIf_Send(&st_frame, K_NO_WAIT));
   sst_can.i_sendRet = -EAGAIN;
   TEST_ASSERT_EQUAL_INT(-EAGAIN, gi_CanIf_Send(&st_frame, K_NO_WAIT));
   TEST_ASSERT_EQUAL_UINT32(0U, sst_Status().u32_txFrames);
}

/******************************************************************************/
/*  Receive filters                                                           */
/******************************************************************************/
static void test_FilterDeliversMatchingFramesOnTheThread(void)
{
   struct can_filter st_filter = { 0x700U, 0x7F0U, 0U };
   int i_id;

   sv_InitOk();
   i_id = gi_CanIf_AddRxFilter(&st_filter, sv_OnRx, USER_A);
   TEST_ASSERT_EQUAL_INT(0, i_id);

   sv_Inject(0x705U, 0U, 3U);
   sv_Inject(0x123U, 0U, 1U);
   sv_Inject(0x705U, CAN_FRAME_IDE, 1U);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, su32_got, "not on the driver's thread");

   sv_RunThread();
   TEST_ASSERT_EQUAL_UINT32(1U, su32_got);
   TEST_ASSERT_EQUAL_PTR(USER_A, svpt_gotUser);
   TEST_ASSERT_EQUAL_HEX32(0x705U, sstar_got[0].id);
   TEST_ASSERT_EQUAL_UINT8(3U, sstar_got[0].dlc);
   TEST_ASSERT_EQUAL_HEX8(0x12U, sstar_got[0].data[2]);

   // The traffic log saw all three
   TEST_ASSERT_EQUAL_UINT32(1U + (IS_ENABLED(CONFIG_CANIF_LOG_RX) ? 3U : 0U), sst_Status().u32_rxFrames);
}

static void test_ExtendedFilterMatchesExtendedIdsOnly(void)
{
   struct can_filter st_filter = { 0x18DAF100U, 0x1FFFFF00U, CAN_FILTER_IDE };

   sv_InitOk();
   gv_CanIf_SetMonitor(false);
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_AddRxFilter(&st_filter, sv_OnRx, NULL));
   sv_Inject(0x18DAF110U, CAN_FRAME_IDE, 8U);
   sv_Inject(0x100U, 0U, 8U);
#ifdef CONFIG_CAN_FD_MODE
   sv_Inject(0x18DAF1F1U, CAN_FRAME_IDE | CAN_FRAME_FDF | CAN_FRAME_BRS, 48U);
#endif // CONFIG_CAN_FD_MODE
   sv_RunThread();
   TEST_ASSERT_EQUAL_UINT32(IS_ENABLED(CONFIG_CAN_FD_MODE) ? 2U : 1U, su32_got);
   TEST_ASSERT_EQUAL_HEX32(0x18DAF110U, sstar_got[0].id);
#ifdef CONFIG_CAN_FD_MODE
   TEST_ASSERT_EQUAL_UINT8(48U, can_dlc_to_bytes(sstar_got[1].dlc));
   TEST_ASSERT_EQUAL_HEX8(0x10U + 47U, sstar_got[1].data[47]);
#endif // CONFIG_CAN_FD_MODE
}

static void test_FilterLimitAndBadArguments(void)
{
   struct can_filter st_filter = { 0x100U, CAN_STD_ID_MASK, 0U };
   int i;

   sv_InitOk();
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_CanIf_AddRxFilter(NULL, sv_OnRx, NULL));
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_CanIf_AddRxFilter(&st_filter, NULL, NULL));
   for (i = 0; i < CONFIG_CANIF_MAX_FILTERS; i++)
   {
      TEST_ASSERT_EQUAL_INT(i, gi_CanIf_AddRxFilter(&st_filter, sv_OnRx, NULL));
   }
   TEST_ASSERT_EQUAL_INT(-ENOSPC, gi_CanIf_AddRxFilter(&st_filter, sv_OnRx, NULL));

   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_CanIf_RemoveRxFilter(-1));
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_CanIf_RemoveRxFilter(CONFIG_CANIF_MAX_FILTERS));
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_RemoveRxFilter(2));
   TEST_ASSERT_EQUAL_INT_MESSAGE(-EINVAL, gi_CanIf_RemoveRxFilter(2), "already removed");
   TEST_ASSERT_EQUAL_INT_MESSAGE(2, gi_CanIf_AddRxFilter(&st_filter, sv_OnRx, NULL), "slot reused");
}

static void test_DriverFilterErrorFreesTheSlot(void)
{
   struct can_filter st_filter = { 0x100U, CAN_STD_ID_MASK, 0U };

   sv_InitOk();
   sst_can.u32_filterCap = su32_ActiveFilters();
   TEST_ASSERT_EQUAL_INT(-ENOSPC, gi_CanIf_AddRxFilter(&st_filter, sv_OnRx, NULL));
   sst_can.u32_filterCap = SIM_FILTERS;
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_AddRxFilter(&st_filter, sv_OnRx, NULL));
}

static void test_FramesQueuedForARemovedFilterAreDropped(void)
{
   struct can_filter st_filter = { 0x100U, CAN_STD_ID_MASK, 0U };
   int i_id;

   sv_InitOk();
   i_id = gi_CanIf_AddRxFilter(&st_filter, sv_OnRx, USER_A);
   sv_Inject(0x100U, 0U, 1U);
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_RemoveRxFilter(i_id));

   // The slot is taken again before the thread runs: the old frame is not its
   TEST_ASSERT_EQUAL_INT(i_id, gi_CanIf_AddRxFilter(&st_filter, sv_OnRx, USER_B));
   sv_RunThread();
   TEST_ASSERT_EQUAL_UINT32(0U, su32_got);

   sv_Inject(0x100U, 0U, 1U);
   sv_RunThread();
   TEST_ASSERT_EQUAL_UINT32(1U, su32_got);
   TEST_ASSERT_EQUAL_PTR(USER_B, svpt_gotUser);
}

static void test_FullQueueDropsFramesButKeepsRoomForStateChanges(void)
{
   struct can_filter st_filter = { 0x100U, CAN_STD_ID_MASK, 0U };
   CanIfStatus_T st_status;
   uint32_t i;

   sv_InitOk();
   gv_CanIf_SetMonitor(false);
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_AddRxFilter(&st_filter, sv_OnRx, NULL));
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_AddStateListener(sv_OnStateHeard, NULL));

   for (i = 0U; i < CONFIG_CANIF_RX_QUEUE_DEPTH; i++)
   {
      sv_Inject(0x100U, 0U, 1U);
   }
   st_status = sst_Status();
   TEST_ASSERT_EQUAL_UINT32(CONFIG_CANIF_RX_QUEUE_DEPTH - CANIF_STATE_RESERVE, st_status.u32_rxFrames);
   TEST_ASSERT_EQUAL_UINT32(CANIF_STATE_RESERVE, st_status.u32_rxDropped);

   sv_InjectState(CAN_STATE_BUS_OFF, 255U, 0U);
   sv_RunThread();
   TEST_ASSERT_EQUAL_UINT32(CONFIG_CANIF_RX_QUEUE_DEPTH - CANIF_STATE_RESERVE, su32_got);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_heard);
   TEST_ASSERT_EQUAL_INT(CAN_STATE_BUS_OFF, se_heard);
}

/******************************************************************************/
/*  Error state                                                               */
/******************************************************************************/
static void test_StateChangesAreLoggedCountedAndReported(void)
{
   sv_InitOk();
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_AddStateListener(sv_OnStateHeard, USER_A));

   sv_InjectState(CAN_STATE_ERROR_WARNING, 96U, 0U);
   sv_RunThread();
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("state ERROR_WARNING (tx err 96, rx err 0)"));
   TEST_ASSERT_EQUAL_UINT32(1U, su32_heard);
   TEST_ASSERT_EQUAL_UINT8(96U, sst_heardErr.tx_err_cnt);

   sv_InjectState(CAN_STATE_BUS_OFF, 255U, 3U);
   sv_InjectState(CAN_STATE_ERROR_ACTIVE, 0U, 0U);
   sv_InjectState(CAN_STATE_BUS_OFF, 255U, 0U);
   sv_RunThread();
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("state BUS_OFF (tx err 255, rx err 3)"));
   TEST_ASSERT_EQUAL_UINT32(4U, su32_heard);
   TEST_ASSERT_EQUAL_INT(CAN_STATE_BUS_OFF, se_heard);
   TEST_ASSERT_EQUAL_UINT32(2U, sst_Status().u32_busOffCount);

   // A repeated bus-off report is not a second bus-off
   sv_InjectState(CAN_STATE_BUS_OFF, 255U, 0U);
   sv_RunThread();
   TEST_ASSERT_EQUAL_UINT32(2U, sst_Status().u32_busOffCount);
}

static void test_StateListenerRegistration(void)
{
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_CanIf_AddStateListener(NULL, NULL));
   TEST_ASSERT_EQUAL_INT_MESSAGE(0, gi_CanIf_AddStateListener(sv_OnStateHeard, USER_A), "before init");
   TEST_ASSERT_EQUAL_INT(-EALREADY, gi_CanIf_AddStateListener(sv_OnStateHeard, USER_A));
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_AddStateListener(sv_OnStateOther, USER_B));
   TEST_ASSERT_EQUAL_INT(-ENOSPC, gi_CanIf_AddStateListener(sv_OnStateHeard, USER_B));

   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_CanIf_RemoveStateListener(NULL, NULL));
   TEST_ASSERT_EQUAL_INT(-ENOENT, gi_CanIf_RemoveStateListener(sv_OnStateHeard, USER_B));
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_RemoveStateListener(sv_OnStateHeard, USER_A));

   sv_InitOk();
   sv_InjectState(CAN_STATE_ERROR_PASSIVE, 128U, 0U);
   sv_RunThread();
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, su32_heard, "removed listener not called");
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_AddStateListener(sv_OnStateHeard, USER_B));
}

static void test_StatusReadsTheControllerState(void)
{
   CanIfStatus_T st_status;

   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_CanIf_GetStatus(NULL));
   sv_InitOk();
   sst_can.e_state = CAN_STATE_ERROR_PASSIVE;
   sst_can.st_errCnt.tx_err_cnt = 130U;
   sst_can.st_errCnt.rx_err_cnt = 5U;
   st_status = sst_Status();
   TEST_ASSERT_EQUAL_INT(CAN_STATE_ERROR_PASSIVE, st_status.e_state);
   TEST_ASSERT_EQUAL_UINT8(130U, st_status.st_errCnt.tx_err_cnt);
   TEST_ASSERT_EQUAL_UINT8(5U, st_status.st_errCnt.rx_err_cnt);

   // Without a live reading: the last state the interface knows
   sst_can.i_getStateRet = -EIO;
   st_status = sst_Status();
   TEST_ASSERT_EQUAL_INT(CAN_STATE_ERROR_ACTIVE, st_status.e_state);
   TEST_ASSERT_EQUAL_UINT8(0U, st_status.st_errCnt.tx_err_cnt);
}

/******************************************************************************/
/*  Traffic log                                                               */
/******************************************************************************/
static void test_TrafficLogIsRateLimited(void)
{
   sv_InitOk();
   gv_CanIf_SetMonitor(true);

   sv_Inject(0x123U, 0U, 8U);
   sv_Inject(0x18DAF110U, CAN_FRAME_IDE, 0U);
   sv_Inject(0x7DFU, CAN_FRAME_RTR, 0U);
   sv_RunThread();
   sv_Inject(0x124U, 0U, 1U);
   sv_Inject(0x125U, 0U, 1U);
   sv_RunThread();
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("RX 0x123 [8]"));
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("RX data (8 bytes)"));
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("RX 0x18daf110 [0]"));
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("RX 0x7df [0] RTR"));
   TEST_ASSERT_NULL_MESSAGE(gcpt_SimLogFind("RX 0x124"), "over the budget of 3 a second");
   TEST_ASSERT_NULL(gcpt_SimLogFind("RX 0x125"));

   gi64_simNowMs += CANIF_LOG_WINDOW_MS;
#ifdef CONFIG_CAN_FD_MODE
   sv_Inject(0x126U, CAN_FRAME_FDF | CAN_FRAME_BRS, 20U);
   sv_RunThread();
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("RX 0x126 [20] FD BRS"));
#else
   sv_Inject(0x126U, 0U, 2U);
   sv_RunThread();
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("RX 0x126 [2]"));
#endif // CONFIG_CAN_FD_MODE
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("2 frames not logged"));
}

static void test_TrafficLogSwitchesAtRuntime(void)
{
   sv_InitOk();
   gv_CanIf_SetMonitor(true);
   gv_CanIf_SetMonitor(true);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(CANIF_MONITOR_FILTERS, su32_ActiveFilters(), "installed once");
   TEST_ASSERT_TRUE(sst_Status().b_monitor);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("traffic log on"));

   gv_CanIf_SetMonitor(false);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_ActiveFilters());
   TEST_ASSERT_FALSE(sst_Status().b_monitor);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("traffic log off"));
   sv_Inject(0x123U, 0U, 1U);
   sv_RunThread();
   TEST_ASSERT_NULL(gcpt_SimLogFind("RX 0x123"));
   TEST_ASSERT_EQUAL_UINT32(0U, sst_Status().u32_rxFrames);
}

static void test_TrafficLogFilterErrorLeavesItOff(void)
{
   sv_InitOk();
   gv_CanIf_SetMonitor(false);
   sst_can.u32_filterCap = 1U;
   gv_CanIf_SetMonitor(true);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("traffic log not installed (-"));
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, su32_ActiveFilters(), "the half-installed one removed");
   TEST_ASSERT_FALSE(sst_Status().b_monitor);
}

/******************************************************************************/
/*  Configure and lock                                                        */
/******************************************************************************/
static void test_ConfigureChangesModeAndBitrates(void)
{
   CanIfConfig_T st_classic = { false, false, 250000U, 0U };
   CanIfStatus_T st_status;

   sv_InitOk();
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_Configure(&st_classic, NULL));
   TEST_ASSERT_TRUE(sst_can.b_started);
   TEST_ASSERT_EQUAL_UINT32(CAN_MODE_NORMAL, sst_can.t_mode);
   TEST_ASSERT_EQUAL_UINT32(250000U, sst_can.u32_bitrate);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("can@0 reconfigured: classic CAN, 250000 bit/s"));
   st_status = sst_Status();
   TEST_ASSERT_FALSE(st_status.st_config.b_fd);
   TEST_ASSERT_EQUAL_UINT32(250000U, st_status.st_config.u32_bitrate);

#ifdef CONFIG_CAN_FD_MODE
   {
      CanIfConfig_T st_fd = { true, true, 1000000U, 5000000U };

      TEST_ASSERT_EQUAL_INT(0, gi_CanIf_Configure(&st_fd, NULL));
      TEST_ASSERT_EQUAL_UINT32(CAN_MODE_FD | CAN_MODE_LISTENONLY, sst_can.t_mode);
      TEST_ASSERT_EQUAL_UINT32(1000000U, sst_can.u32_bitrate);
      TEST_ASSERT_EQUAL_UINT32(5000000U, sst_can.u32_bitrateData);
      TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("reconfigured: CAN FD, 1000000 bit/s, data 5000000 bit/s, listen-only"));
   }
#endif // CONFIG_CAN_FD_MODE
}

static void test_ConfigureRejectsBadConfigurations(void)
{
   CanIfConfig_T st_config = { false, false, 0U, 0U };
   uint32_t u32_starts;

   sv_InitOk();
   u32_starts = sst_can.u32_startCalls;
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_CanIf_Configure(NULL, NULL));
   TEST_ASSERT_EQUAL_INT_MESSAGE(-EINVAL, gi_CanIf_Configure(&st_config, NULL), "zero bitrate");

   st_config.b_fd = true;
   st_config.u32_bitrate = 500000U;
#ifdef CONFIG_CAN_FD_MODE
   TEST_ASSERT_EQUAL_INT_MESSAGE(-EINVAL, gi_CanIf_Configure(&st_config, NULL), "zero data bitrate");
#else
   TEST_ASSERT_EQUAL_INT_MESSAGE(-ENOTSUP, gi_CanIf_Configure(&st_config, NULL), "no CAN FD in the build");
#endif // CONFIG_CAN_FD_MODE

   TEST_ASSERT_EQUAL_UINT32_MESSAGE(u32_starts, sst_can.u32_startCalls, "controller untouched");
   TEST_ASSERT_TRUE(sst_can.b_started);
}

#ifdef CONFIG_CAN_FD_MODE
static void test_ConfigureFdOnAClassicControllerIsNotSupported(void)
{
   CanIfConfig_T st_fd = { true, false, 500000U, 2000000U };

   sst_config.b_fd = false;
   sst_can.t_cap &= ~CAN_MODE_FD;
   sv_InitOk();
   TEST_ASSERT_EQUAL_INT(-ENOTSUP, gi_CanIf_Configure(&st_fd, NULL));
}
#endif // CONFIG_CAN_FD_MODE

static void test_ConfigureRestoresThePreviousConfigurationOnFailure(void)
{
   CanIfConfig_T st_config = { false, false, 123456U, 0U };

   sv_InitOk();
   sst_can.u32_badBitrate = 123456U;
   TEST_ASSERT_EQUAL_INT(-ENOTSUP, gi_CanIf_Configure(&st_config, NULL));
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("configuration refused (-"));
   TEST_ASSERT_TRUE(sst_can.b_started);
   TEST_ASSERT_EQUAL_UINT32(CONFIG_CANIF_BITRATE, sst_can.u32_bitrate);
   TEST_ASSERT_EQUAL_UINT32(CONFIG_CANIF_BITRATE, sst_Status().st_config.u32_bitrate);
   TEST_ASSERT_TRUE(sst_Status().b_started);
}

static void test_ConfigureLeavesTheControllerStoppedIfRestoringFails(void)
{
   CanIfConfig_T st_config = { false, false, 250000U, 0U };

   sv_InitOk();
   sst_can.u32_startFailAt = sst_can.u32_startCalls + 1U;
   TEST_ASSERT_EQUAL_INT(-EIO, gi_CanIf_Configure(&st_config, NULL));
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("can@0 left stopped (-"));
   TEST_ASSERT_FALSE(sst_Status().b_started);
}

static void test_ConfigureStopFailureIsReturned(void)
{
   CanIfConfig_T st_config = { false, false, 250000U, 0U };

   sv_InitOk();
   sst_can.i_stopRet = -EIO;
   TEST_ASSERT_EQUAL_INT(-EIO, gi_CanIf_Configure(&st_config, NULL));
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("can_stop failed (-"));
   TEST_ASSERT_TRUE(sst_Status().b_started);
}

static void test_LockReservesConfigurationForItsOwner(void)
{
   CanIfConfig_T st_config = { false, false, 250000U, 0U };

   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_CanIf_Lock(NULL));
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_CanIf_Unlock(NULL));
   sv_InitOk();

   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_Lock(USER_A));
   TEST_ASSERT_TRUE(sst_Status().b_locked);
   TEST_ASSERT_EQUAL_INT(-EALREADY, gi_CanIf_Lock(USER_A));
   TEST_ASSERT_EQUAL_INT(-EBUSY, gi_CanIf_Lock(USER_B));
   TEST_ASSERT_EQUAL_INT(-EBUSY, gi_CanIf_Configure(&st_config, NULL));
   TEST_ASSERT_EQUAL_INT(-EBUSY, gi_CanIf_Configure(&st_config, USER_B));
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_Configure(&st_config, USER_A));
   TEST_ASSERT_EQUAL_INT(-EPERM, gi_CanIf_Unlock(USER_B));
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_Unlock(USER_A));
   TEST_ASSERT_FALSE(sst_Status().b_locked);
   TEST_ASSERT_EQUAL_INT(-EPERM, gi_CanIf_Unlock(USER_A));
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_Configure(&st_config, NULL));
}

/******************************************************************************/
/*  Test frames                                                               */
/******************************************************************************/
/** Let one test-frame period pass; true if the work ran. */
static bool sb_TestPeriod(void)
{
   gi64_simNowMs += CONFIG_CANIF_TEST_TX_PERIOD_MS;
   return gb_SimRunDelayedWork(&sst_testTxWork);
}

static void test_TestFramesFollowThePeriodAndPauseWhileLocked(void)
{
   const struct can_frame *stpt_sent;
   uint32_t u32_sends;

   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_Init());
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("test frame (ID 0x5a5) every 1000 ms: bench only"));
   u32_sends = sst_can.u32_sends;

   TEST_ASSERT_TRUE(sb_TestPeriod());
   TEST_ASSERT_EQUAL_UINT32(u32_sends + 1U, sst_can.u32_sends);
   stpt_sent = &sst_can.star_sent[u32_sends];
   TEST_ASSERT_EQUAL_HEX32(CANIF_TEST_ID, stpt_sent->id);
   TEST_ASSERT_EQUAL_UINT8(8U, stpt_sent->dlc);
   TEST_ASSERT_EQUAL_UINT32(0U, sys_get_le32(stpt_sent->data));
   TEST_ASSERT_EQUAL_HEX8(7U, stpt_sent->data[7]);

   TEST_ASSERT_TRUE(sb_TestPeriod());
   stpt_sent = &sst_can.star_sent[u32_sends + 1U];
   TEST_ASSERT_EQUAL_UINT32(1U, sys_get_le32(stpt_sent->data));
#ifdef CONFIG_CAN_FD_MODE
   TEST_ASSERT_EQUAL_UINT8(CAN_FRAME_FDF | CAN_FRAME_BRS, stpt_sent->flags);
   TEST_ASSERT_EQUAL_UINT8(64U, can_dlc_to_bytes(stpt_sent->dlc));
#else
   TEST_ASSERT_EQUAL_UINT8(0U, stpt_sent->flags);
#endif // CONFIG_CAN_FD_MODE

   // Paused while a session holds the bus, but still scheduled
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_Lock(USER_A));
   TEST_ASSERT_TRUE(sb_TestPeriod());
   TEST_ASSERT_EQUAL_UINT32(u32_sends + 2U, sst_can.u32_sends);
   TEST_ASSERT_TRUE(k_work_delayable_is_pending(&sst_testTxWork));
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_Unlock(USER_A));

   // A send error is logged and the counter moves on
   sst_can.i_sendRet = -ENETUNREACH;
   TEST_ASSERT_TRUE(sb_TestPeriod());
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("test frame 2 not sent (-"));
   sst_can.i_sendRet = 0;
   TEST_ASSERT_TRUE(sb_TestPeriod());
   TEST_ASSERT_EQUAL_UINT32(3U, sys_get_le32(sst_can.star_sent[sst_can.u32_sends - 1U].data));
}

static void test_NoTestFramesInListenOnlyMode(void)
{
   uint32_t u32_sends;

   sst_config.b_listenOnly = true;
   TEST_ASSERT_EQUAL_INT(0, gi_CanIf_Init());
   u32_sends = sst_can.u32_sends;
   TEST_ASSERT_TRUE(sb_TestPeriod());
   TEST_ASSERT_EQUAL_UINT32(u32_sends, sst_can.u32_sends);
}

int main(void)
{
   (void)setvbuf(stdout, NULL, _IONBF, 0);
   UNITY_BEGIN();
   RUN_TEST(test_InitWithoutTheControllerLeavesEverythingRefused);
   RUN_TEST(test_InitTwiceIsRefused);
   RUN_TEST(test_InitInitialisesTheDeferredDriver);
   RUN_TEST(test_InitAcceptsADriverInitialisedAtBoot);
   RUN_TEST(test_InitCapabilitiesErrorIsReturned);
#ifdef CONFIG_CAN_FD_MODE
   RUN_TEST(test_InitFdBootModeNeedsAnFdController);
#endif // CONFIG_CAN_FD_MODE
   RUN_TEST(test_InitStartsWithTheBootConfiguration);
   RUN_TEST(test_InitStartFailureLeavesTheInterfaceReadyButStopped);
   RUN_TEST(test_InitInListenOnlyMode);
#ifdef CONFIG_CANIF_SELFTEST
   RUN_TEST(test_SelfTestSendsAClassicAndAnFdFrameInLoopback);
   RUN_TEST(test_SelfTestFailsWhenNothingComesBack);
   RUN_TEST(test_SelfTestFailsWhenTheFrameComesBackChanged);
   RUN_TEST(test_SelfTestFailsWhenSendingFails);
   RUN_TEST(test_SelfTestFailsWhenTheControllerDoesNotStart);
#endif // CONFIG_CANIF_SELFTEST
   RUN_TEST(test_SendClassicFrame);
#ifdef CONFIG_CAN_FD_MODE
   RUN_TEST(test_SendFdFrameWithBitRateSwitching);
#endif // CONFIG_CAN_FD_MODE
   RUN_TEST(test_SendRejectsBadFrames);
   RUN_TEST(test_SendFdFrameInClassicModeIsNotSupported);
   RUN_TEST(test_SendErrorsPassThrough);
   RUN_TEST(test_FilterDeliversMatchingFramesOnTheThread);
   RUN_TEST(test_ExtendedFilterMatchesExtendedIdsOnly);
   RUN_TEST(test_FilterLimitAndBadArguments);
   RUN_TEST(test_DriverFilterErrorFreesTheSlot);
   RUN_TEST(test_FramesQueuedForARemovedFilterAreDropped);
   RUN_TEST(test_FullQueueDropsFramesButKeepsRoomForStateChanges);
   RUN_TEST(test_StateChangesAreLoggedCountedAndReported);
   RUN_TEST(test_StateListenerRegistration);
   RUN_TEST(test_StatusReadsTheControllerState);
   RUN_TEST(test_TrafficLogIsRateLimited);
   RUN_TEST(test_TrafficLogSwitchesAtRuntime);
   RUN_TEST(test_TrafficLogFilterErrorLeavesItOff);
   RUN_TEST(test_ConfigureChangesModeAndBitrates);
   RUN_TEST(test_ConfigureRejectsBadConfigurations);
#ifdef CONFIG_CAN_FD_MODE
   RUN_TEST(test_ConfigureFdOnAClassicControllerIsNotSupported);
#endif // CONFIG_CAN_FD_MODE
   RUN_TEST(test_ConfigureRestoresThePreviousConfigurationOnFailure);
   RUN_TEST(test_ConfigureLeavesTheControllerStoppedIfRestoringFails);
   RUN_TEST(test_ConfigureStopFailureIsReturned);
   RUN_TEST(test_LockReservesConfigurationForItsOwner);
   RUN_TEST(test_TestFramesFollowThePeriodAndPauseWhileLocked);
   RUN_TEST(test_NoTestFramesInListenOnlyMode);
   return UNITY_END();
}
