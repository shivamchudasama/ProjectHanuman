/**
 * @file          CanIf.c
 * @brief         Source file containing the CAN / CAN FD interface. It owns the
 *                controller chosen as zephyr,canbus (the MCP2518FD Click on
 *                spi21): sets its mode and bitrates (boot values from Kconfig,
 *                then gi_CanIf_Configure()), starts it, follows its error state
 *                and lets other modules send frames and receive the ones that
 *                match their filters. The driver's callbacks run on its interrupt
 *                thread; they only queue the frame or state change, and this
 *                module's thread hands them on, so a slow user never holds the
 *                driver. Contract and wiring: _DOC/CAN/README.md.
 * @date          12/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include "CanIf.h"
#include <errno.h>
#include <string.h>
#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/byteorder.h>
#include "AppLog.h"

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
/**
 * @def           CANIF_MONITOR_FILTERS
 * @brief         Driver filters the traffic log takes: all standard and all
 *                extended IDs.
 */
#define CANIF_MONITOR_FILTERS                (2U)

/**
 * @def           CANIF_MONITOR_SLOT
 * @brief         Slot number of the traffic log's frames in the queue.
 */
#define CANIF_MONITOR_SLOT                   (0xFFU)

/**
 * @def           CANIF_STATE_RESERVE
 * @brief         Queue entries frames leave free, so a state change is never lost
 *                behind a burst of frames.
 */
#define CANIF_STATE_RESERVE                  (2U)

/**
 * @def           CANIF_SELFTEST_TIMEOUT_MS
 * @brief         Wait for a self-test frame to be sent, and again for it to come
 *                back.
 */
#define CANIF_SELFTEST_TIMEOUT_MS            (100)

/**
 * @def           CANIF_TEST_TX_TIMEOUT_MS
 * @brief         Wait for a test frame to be sent.
 */
#define CANIF_TEST_TX_TIMEOUT_MS             (100)

/**
 * @def           CANIF_LOG_WINDOW_MS
 * @brief         Window of the traffic log's rate limit.
 */
#define CANIF_LOG_WINDOW_MS                  (1000)

/**
 * @def           CANIF_FD_TEST_LEN
 * @brief         Payload of the FD self-test and test frames.
 */
#define CANIF_FD_TEST_LEN                    (64U)

/**
 * @def           CANIF_TX_FLAGS
 * @brief         Frame flags a sender may set (ESI is reported on reception only).
 */
#define CANIF_TX_FLAGS                       (CAN_FRAME_IDE | CAN_FRAME_RTR | CAN_FRAME_FDF | CAN_FRAME_BRS)

/**
 * @def           CANIF_BOOT_BITRATE_DATA
 * @brief         Boot data-phase bitrate (0 without CAN FD support).
 */
#if defined(CONFIG_CANIF_BITRATE_DATA)
#define CANIF_BOOT_BITRATE_DATA              (CONFIG_CANIF_BITRATE_DATA)
#else
#define CANIF_BOOT_BITRATE_DATA              (0U)
#endif // CONFIG_CANIF_BITRATE_DATA

BUILD_ASSERT(DT_HAS_CHOSEN(zephyr_canbus), "no zephyr,canbus controller in the devicetree");
BUILD_ASSERT(CONFIG_CANIF_RX_QUEUE_DEPTH > CANIF_STATE_RESERVE, "CANIF_RX_QUEUE_DEPTH too small");
#if defined(CONFIG_CAN_MCP251XFD_MAX_FILTERS)
BUILD_ASSERT((CONFIG_CANIF_MAX_FILTERS + CANIF_MONITOR_FILTERS) <= CONFIG_CAN_MCP251XFD_MAX_FILTERS,
   "CANIF_MAX_FILTERS plus the traffic log exceed the driver's filters");
#endif // CONFIG_CAN_MCP251XFD_MAX_FILTERS
#if defined(CONFIG_DK_LIBRARY)
// dk_buttons_init() puts one gpio_callback on the list of every port with a
// button, so the callbacks added to those ports before it are cut off: the
// controller's INT callback among them, and its level interrupt then never
// ends. The driver is initialised by gi_CanIf_Init(), after the DK library.
BUILD_ASSERT(DT_PROP(DT_CHOSEN(zephyr_canbus), zephyr_deferred_init),
   "the zephyr,canbus node needs zephyr,deferred-init (see gi_CanIf_Init())");
#endif // CONFIG_DK_LIBRARY

/******************************************************************************/
/*                                                                            */
/*                                   ENUMS                                    */
/*                                                                            */
/******************************************************************************/
/**
 * @enum          CanIfEventType_E
 * @brief         What a queue entry carries.
 */
typedef enum
{
   eCANIF_EVT_FRAME   = 0,                   /**< Frame for a user filter.             */
   eCANIF_EVT_MONITOR = 1,                   /**< Frame for the traffic log.           */
   eCANIF_EVT_STATE   = 2,                   /**< Error state change.                  */
} CanIfEventType_E;

/******************************************************************************/
/*                                                                            */
/*                                 STRUCTURES                                 */
/*                                                                            */
/******************************************************************************/
/**
 * @struct        CanIfEvent_T
 * @brief         Queue entry, from the driver's thread to the CAN interface
 *                thread.
 */
typedef struct
{
   uint8_t u8_type;                          /**< CanIfEventType_E.                    */
   uint8_t u8_slot;                          /**< Filter slot (frames).                */
   uint16_t u16_gen;                         /**< Slot generation when queued.         */
   enum can_state e_state;                   /**< New state (state changes).           */
   struct can_bus_err_cnt st_errCnt;         /**< Error counters (state changes).      */
   struct can_frame st_frame;                /**< Frame (frames).                      */
} CanIfEvent_T;

/**
 * @struct        CanIfSlot_T
 * @brief         One user filter. The generation changes whenever the slot is
 *                taken or freed, so frames queued for a removed filter are
 *                dropped instead of reaching its successor.
 */
typedef struct
{
   bool b_used;                              /**< Slot taken.                          */
   uint16_t u16_gen;                         /**< Generation.                          */
   int i_driverId;                           /**< can_add_rx_filter() id.              */
   CanIfRx_F fpt_cb;                         /**< User callback.                       */
   void *vpt_user;                           /**< User pointer.                        */
} CanIfSlot_T;

/**
 * @struct        CanIfListener_T
 * @brief         One state listener.
 */
typedef struct
{
   CanIfState_F fpt_cb;                      /**< Callback (NULL: free).               */
   void *vpt_user;                           /**< User pointer.                        */
} CanIfListener_T;

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
static const char *scpt_StateName(enum can_state e_state);
static void sv_LogConfig(const char *cpt_what);
static void sv_PostFrame(CanIfEvent_T *stpt_event);
static void sv_OnDriverRx(const struct device *stpt_dev, struct can_frame *stpt_frame,
   void *vpt_user);
static void sv_OnDriverState(const struct device *stpt_dev, enum can_state e_state,
   struct can_bus_err_cnt st_errCnt, void *vpt_user);
static void sv_OnSelfTestRx(const struct device *stpt_dev, struct can_frame *stpt_frame,
   void *vpt_user);
static int si_SelfTestFrame(const struct can_frame *stpt_tx);
static int si_SelfTest(void);
static int si_Apply(const CanIfConfig_T *stpt_config);
static int si_Stop(void);
static int si_CheckConfig(const CanIfConfig_T *stpt_config);
static int si_CheckFrame(const struct can_frame *stpt_frame);
static int si_MonitorOn(void);
static void sv_MonitorOff(void);
static void sv_LogFrame(const struct can_frame *stpt_frame);
static void sv_OnState(enum can_state e_state, const struct can_bus_err_cnt *stpt_errCnt);
static void sv_HandleEvent(const CanIfEvent_T *stpt_event);
static void sv_TestTx(struct k_work *stpt_work);
static void sv_CanIfThread(void *vpt_p1, void *vpt_p2, void *vpt_p3);

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
 * @var           sstpt_dev
 * @brief         The CAN controller (devicetree chosen zephyr,canbus).
 */
static const struct device *const sstpt_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_canbus));

/**
 * @var           sb_ready
 * @brief         The controller was found (and passed the self-test).
 */
static bool sb_ready = false;

/**
 * @var           sb_started
 * @brief         The controller is started.
 */
static bool sb_started = false;

/**
 * @var           sb_capFd
 * @brief         The controller (and this build) supports CAN FD.
 */
static bool sb_capFd = false;

/**
 * @var           sb_monitor
 * @brief         The traffic log's filters are installed.
 */
static bool sb_monitor = false;

/**
 * @var           sst_config
 * @brief         Configuration in use; the Kconfig boot values until
 *                gi_CanIf_Configure() changes it.
 */
static CanIfConfig_T sst_config =
{
   IS_ENABLED(CONFIG_CANIF_FD), IS_ENABLED(CONFIG_CANIF_LISTEN_ONLY),
   CONFIG_CANIF_BITRATE, CANIF_BOOT_BITRATE_DATA
};

/**
 * @var           se_state
 * @brief         Last error state (CAN interface thread, and start/stop).
 */
static enum can_state se_state = CAN_STATE_STOPPED;

/**
 * @var           sstar_slots
 * @brief         User filters. Guarded by sst_canIfMutex.
 */
static CanIfSlot_T sstar_slots[CONFIG_CANIF_MAX_FILTERS];

/**
 * @var           sstar_listeners
 * @brief         State listeners. Guarded by sst_canIfMutex.
 */
static CanIfListener_T sstar_listeners[CANIF_STATE_LISTENERS];

/**
 * @var           siar_monitorIds
 * @brief         Driver filter ids of the traffic log (-1: not installed).
 */
static int siar_monitorIds[CANIF_MONITOR_FILTERS] = { -1, -1 };

/**
 * @var           st_owner
 * @brief         Owner of the bus lock (gi_CanIf_Lock()), or NULL.
 */
static atomic_ptr_t st_owner = ATOMIC_PTR_INIT(NULL);

/**
 * @var           st_txFrames
 * @brief         Frames sent by gi_CanIf_Send().
 */
static atomic_t st_txFrames = ATOMIC_INIT(0);

/**
 * @var           st_rxFrames
 * @brief         Frames queued for a filter or the traffic log.
 */
static atomic_t st_rxFrames = ATOMIC_INIT(0);

/**
 * @var           st_rxDropped
 * @brief         Frames lost because the queue was full.
 */
static atomic_t st_rxDropped = ATOMIC_INIT(0);

/**
 * @var           su32_busOffCount
 * @brief         Times the controller went bus-off (CAN interface thread).
 */
static uint32_t su32_busOffCount = 0U;

/**
 * @var           si64_logWindowMs
 * @brief         Start of the traffic log's current one-second window.
 */
static int64_t si64_logWindowMs = 0;

/**
 * @var           su32_logCount
 * @brief         Frames logged in the current window.
 */
static uint32_t su32_logCount = 0U;

/**
 * @var           su32_logSuppressed
 * @brief         Frames not logged in the current window.
 */
static uint32_t su32_logSuppressed = 0U;

/**
 * @var           su32_testCount
 * @brief         Counter carried by the test frames.
 */
static uint32_t su32_testCount = 0U;

/**
 * @var           sst_selfTestRx
 * @brief         Frame the self-test got back.
 */
static struct can_frame sst_selfTestRx;

/**
 * @var           sst_selfTestSem
 * @brief         Given when the self-test frame came back.
 */
static K_SEM_DEFINE(sst_selfTestSem, 0, 1);

/**
 * @var           sst_canIfMutex
 * @brief         Guards the controller's configuration, the filters and the
 *                listeners.
 */
static K_MUTEX_DEFINE(sst_canIfMutex);

/**
 * @var           sst_testTxWork
 * @brief         Sends the test frame every CONFIG_CANIF_TEST_TX_PERIOD_MS.
 */
static K_WORK_DELAYABLE_DEFINE(sst_testTxWork, sv_TestTx);

/**
 * @var           sst_canIfMsgq
 * @brief         Frames and state changes from the driver's thread.
 */
K_MSGQ_DEFINE(sst_canIfMsgq, sizeof(CanIfEvent_T), CONFIG_CANIF_RX_QUEUE_DEPTH, 4);

/**
 * @var           sst_canIfThread
 * @brief         Hands frames to their filters' callbacks, logs traffic and state
 *                changes, and calls the state listeners.
 */
K_THREAD_DEFINE(sst_canIfThread, CONFIG_CANIF_STACK_SIZE, sv_CanIfThread, NULL, NULL, NULL,
   CONFIG_CANIF_PRIORITY, 0, 0);

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
 * @private       scpt_StateName
 * @brief         Name of an error state for the log.
 * @param[in]     e_state State.
 * @return        The name.
 */
static const char *scpt_StateName(enum can_state e_state)
{
   static const char *const scptar_names[] =
   {
      "ERROR_ACTIVE", "ERROR_WARNING", "ERROR_PASSIVE", "BUS_OFF", "STOPPED"
   };

   return ((uint32_t)e_state < ARRAY_SIZE(scptar_names)) ? scptar_names[e_state] : "?";
}

/**
 * @private       sv_LogConfig
 * @brief         Log the configuration in use.
 * @param[in]     cpt_what What happened ("started", "reconfigured").
 * @return        None.
 */
static void sv_LogConfig(const char *cpt_what)
{
   const char *cpt_mode = sst_config.b_listenOnly ? ", listen-only" : "";

   // Check if the data phase has its own bitrate
   if (sst_config.b_fd)
   {
      APP_LOG_INF("%s %s: CAN FD, %u bit/s, data %u bit/s%s", sstpt_dev->name, cpt_what,
         sst_config.u32_bitrate, sst_config.u32_bitrateData, cpt_mode);
   }
   else
   {
      APP_LOG_INF("%s %s: classic CAN, %u bit/s%s", sstpt_dev->name, cpt_what,
         sst_config.u32_bitrate, cpt_mode);
   }
}

/**
 * @private       sv_PostFrame
 * @brief         Queue a received frame without blocking, leaving
 *                CANIF_STATE_RESERVE entries for state changes; count it as
 *                queued or dropped.
 * @param[in]     stpt_event Event.
 * @return        None.
 */
static void sv_PostFrame(CanIfEvent_T *stpt_event)
{
   // Check if the queue has room for a frame
   if (((k_msgq_num_used_get(&sst_canIfMsgq) + CANIF_STATE_RESERVE) >= CONFIG_CANIF_RX_QUEUE_DEPTH)
      || (k_msgq_put(&sst_canIfMsgq, stpt_event, K_NO_WAIT) != 0))
   {
      (void)atomic_inc(&st_rxDropped);
      return;
   }

   (void)atomic_inc(&st_rxFrames);
}

/**
 * @private       sv_OnDriverRx
 * @brief         can_rx_callback_t, on the driver's interrupt thread: queue the
 *                frame for its filter (vpt_user is the slot) or for the traffic
 *                log (vpt_user is NULL).
 * @param[in]     stpt_dev Controller.
 * @param[in]     stpt_frame Frame.
 * @param[in]     vpt_user Slot, or NULL.
 * @return        None.
 */
static void sv_OnDriverRx(const struct device *stpt_dev, struct can_frame *stpt_frame,
   void *vpt_user)
{
   CanIfSlot_T *stpt_slot = (CanIfSlot_T *)vpt_user;
   CanIfEvent_T st_event;

   ARG_UNUSED(stpt_dev);

   memset(&st_event, 0, sizeof(st_event));
   if (stpt_slot == NULL)
   {
      st_event.u8_type = (uint8_t)eCANIF_EVT_MONITOR;
      st_event.u8_slot = CANIF_MONITOR_SLOT;
   }
   else
   {
      st_event.u8_type = (uint8_t)eCANIF_EVT_FRAME;
      st_event.u8_slot = (uint8_t)(stpt_slot - sstar_slots);
      st_event.u16_gen = stpt_slot->u16_gen;
   }
   st_event.st_frame = *stpt_frame;

   sv_PostFrame(&st_event);
}

/**
 * @private       sv_OnDriverState
 * @brief         can_state_change_callback_t, on the driver's interrupt thread:
 *                queue the change (it may use the reserved entries).
 * @param[in]     stpt_dev Controller.
 * @param[in]     e_state New state.
 * @param[in]     st_errCnt Error counters.
 * @param[in]     vpt_user Unused.
 * @return        None.
 */
static void sv_OnDriverState(const struct device *stpt_dev, enum can_state e_state,
   struct can_bus_err_cnt st_errCnt, void *vpt_user)
{
   CanIfEvent_T st_event;

   ARG_UNUSED(stpt_dev);
   ARG_UNUSED(vpt_user);

   memset(&st_event, 0, sizeof(st_event));
   st_event.u8_type = (uint8_t)eCANIF_EVT_STATE;
   st_event.e_state = e_state;
   st_event.st_errCnt = st_errCnt;

   // Check if the change could be queued
   if (k_msgq_put(&sst_canIfMsgq, &st_event, K_NO_WAIT) != 0)
   {
      APP_LOG_WRN("state %s not reported: queue full", scpt_StateName(e_state));
   }
}

/**
 * @private       sv_OnSelfTestRx
 * @brief         can_rx_callback_t of the self-test: keep the frame and wake the
 *                test.
 * @param[in]     stpt_dev Controller.
 * @param[in]     stpt_frame Frame.
 * @param[in]     vpt_user Unused.
 * @return        None.
 */
static void sv_OnSelfTestRx(const struct device *stpt_dev, struct can_frame *stpt_frame,
   void *vpt_user)
{
   ARG_UNUSED(stpt_dev);
   ARG_UNUSED(vpt_user);

   sst_selfTestRx = *stpt_frame;
   k_sem_give(&sst_selfTestSem);
}

/**
 * @private       si_SelfTestFrame
 * @brief         Send one frame in loopback mode and check it comes back
 *                unchanged.
 * @param[in]     stpt_tx Frame.
 * @return        0; the error from can_send(); -ETIMEDOUT if it did not come
 *                back; -EIO if it came back changed.
 */
static int si_SelfTestFrame(const struct can_frame *stpt_tx)
{
   const uint8_t u8_flagMask = (uint8_t)(CAN_FRAME_IDE | CAN_FRAME_FDF | CAN_FRAME_BRS);
   uint8_t u8_len = can_dlc_to_bytes(stpt_tx->dlc);
   int i_ret;

   k_sem_reset(&sst_selfTestSem);
   memset(&sst_selfTestRx, 0, sizeof(sst_selfTestRx));

   i_ret = can_send(sstpt_dev, stpt_tx, K_MSEC(CANIF_SELFTEST_TIMEOUT_MS), NULL, NULL);
   if (i_ret != 0)
   {
      return i_ret;
   }

   // Check if the frame came back in time
   if (k_sem_take(&sst_selfTestSem, K_MSEC(CANIF_SELFTEST_TIMEOUT_MS)) != 0)
   {
      return -ETIMEDOUT;
   }

   // Check if it came back unchanged
   if ((sst_selfTestRx.id != stpt_tx->id) || (sst_selfTestRx.dlc != stpt_tx->dlc)
      || ((sst_selfTestRx.flags & u8_flagMask) != (stpt_tx->flags & u8_flagMask))
      || (memcmp(sst_selfTestRx.data, stpt_tx->data, u8_len) != 0))
   {
      return -EIO;
   }

   return 0;
}

/**
 * @private       si_SelfTest
 * @brief         Loopback self-test: a classic 8-byte frame and, with CAN FD, a
 *                64-byte FD frame with BRS, at the boot bitrates. The MCP2518FD's
 *                loopback is external: the frames also go out on the bus. Leaves
 *                the controller stopped.
 * @return        0, or the first error (logged by the caller).
 */
static int si_SelfTest(void)
{
   struct can_filter st_filter = { .id = CANIF_TEST_ID, .mask = CAN_STD_ID_MASK, .flags = 0U };
   struct can_frame st_tx;
   can_mode_t t_mode = CAN_MODE_LOOPBACK;
   int i_filterId = -1;
   int i_ret = 0;
   uint32_t i;

   if (sb_capFd)
   {
      t_mode |= CAN_MODE_FD;
   }

   i_ret = can_set_mode(sstpt_dev, t_mode);
   if (i_ret == 0)
   {
      i_ret = can_set_bitrate(sstpt_dev, CONFIG_CANIF_BITRATE);
   }
#if defined(CONFIG_CAN_FD_MODE)
   if ((i_ret == 0) && sb_capFd)
   {
      i_ret = can_set_bitrate_data(sstpt_dev, CANIF_BOOT_BITRATE_DATA);
   }
#endif // CONFIG_CAN_FD_MODE
   if (i_ret == 0)
   {
      i_filterId = can_add_rx_filter(sstpt_dev, sv_OnSelfTestRx, NULL, &st_filter);
      i_ret = (i_filterId < 0) ? i_filterId : 0;
   }
   if (i_ret == 0)
   {
      i_ret = can_start(sstpt_dev);
   }

   // A classic frame
   if (i_ret == 0)
   {
      memset(&st_tx, 0, sizeof(st_tx));
      st_tx.id = CANIF_TEST_ID;
      st_tx.dlc = 8U;
      for (i = 0U; i < 8U; i++)
      {
         st_tx.data[i] = (uint8_t)(0xA5U ^ i);
      }
      i_ret = si_SelfTestFrame(&st_tx);
   }

#if defined(CONFIG_CAN_FD_MODE)
   // A 64-byte FD frame with bit-rate switching
   if ((i_ret == 0) && sb_capFd)
   {
      memset(&st_tx, 0, sizeof(st_tx));
      st_tx.id = CANIF_TEST_ID;
      st_tx.flags = (uint8_t)(CAN_FRAME_FDF | CAN_FRAME_BRS);
      st_tx.dlc = can_bytes_to_dlc(CANIF_FD_TEST_LEN);
      for (i = 0U; i < CANIF_FD_TEST_LEN; i++)
      {
         st_tx.data[i] = (uint8_t)((i * 7U) + 1U);
      }
      i_ret = si_SelfTestFrame(&st_tx);
   }
#endif // CONFIG_CAN_FD_MODE

   (void)can_stop(sstpt_dev);
   if (i_filterId >= 0)
   {
      can_remove_rx_filter(sstpt_dev, i_filterId);
   }

   return i_ret;
}

/**
 * @private       si_Apply
 * @brief         Set the mode and bitrates of the stopped controller and start
 *                it.
 * @param[in]     stpt_config Configuration (checked).
 * @return        0, or the error of the step that failed (the controller then
 *                stays stopped).
 */
static int si_Apply(const CanIfConfig_T *stpt_config)
{
   can_mode_t t_mode = CAN_MODE_NORMAL;
   int i_ret;

   if (stpt_config->b_fd)
   {
      t_mode |= CAN_MODE_FD;
   }
   if (stpt_config->b_listenOnly)
   {
      t_mode |= CAN_MODE_LISTENONLY;
   }

   i_ret = can_set_mode(sstpt_dev, t_mode);
   if (i_ret == 0)
   {
      i_ret = can_set_bitrate(sstpt_dev, stpt_config->u32_bitrate);
   }
#if defined(CONFIG_CAN_FD_MODE)
   if ((i_ret == 0) && stpt_config->b_fd)
   {
      i_ret = can_set_bitrate_data(sstpt_dev, stpt_config->u32_bitrateData);
   }
#endif // CONFIG_CAN_FD_MODE
   if (i_ret == 0)
   {
      i_ret = can_start(sstpt_dev);
   }

   // Check if the controller runs
   if (i_ret == 0)
   {
      sb_started = true;
      se_state = CAN_STATE_ERROR_ACTIVE;
   }

   return i_ret;
}

/**
 * @private       si_Stop
 * @brief         Stop the controller (stopping a stopped one is fine).
 * @return        0, or the error from can_stop().
 */
static int si_Stop(void)
{
   int i_ret = can_stop(sstpt_dev);

   if (i_ret == -EALREADY)
   {
      i_ret = 0;
   }
   if (i_ret == 0)
   {
      sb_started = false;
      se_state = CAN_STATE_STOPPED;
   }

   return i_ret;
}

/**
 * @private       si_CheckConfig
 * @brief         Check a configuration against the controller.
 * @param[in]     stpt_config Configuration.
 * @return        0; -EINVAL for a zero bitrate; -ENOTSUP for CAN FD without
 *                support.
 */
static int si_CheckConfig(const CanIfConfig_T *stpt_config)
{
   if (stpt_config->u32_bitrate == 0U)
   {
      return -EINVAL;
   }

   // Check if CAN FD is asked for, and possible
   if (stpt_config->b_fd)
   {
      if (!sb_capFd)
      {
         return -ENOTSUP;
      }
      if (stpt_config->u32_bitrateData == 0U)
      {
         return -EINVAL;
      }
   }

   return 0;
}

/**
 * @private       si_CheckFrame
 * @brief         Check a frame before sending it.
 * @param[in]     stpt_frame Frame.
 * @return        0; -EINVAL for unknown flags, an ID out of range, a DLC too
 *                large, RTR on an FD frame or BRS on a classic one; -ENOTSUP for
 *                an FD frame in classic mode.
 */
static int si_CheckFrame(const struct can_frame *stpt_frame)
{
   uint8_t u8_flags = stpt_frame->flags;
   uint32_t u32_idMax = ((u8_flags & CAN_FRAME_IDE) != 0U) ? CAN_EXT_ID_MASK : CAN_STD_ID_MASK;

   if (((u8_flags & (uint8_t)~CANIF_TX_FLAGS) != 0U) || (stpt_frame->id > u32_idMax))
   {
      return -EINVAL;
   }

   // Check if this is an FD frame
   if ((u8_flags & CAN_FRAME_FDF) != 0U)
   {
      if (((u8_flags & CAN_FRAME_RTR) != 0U) || (stpt_frame->dlc > CANFD_MAX_DLC))
      {
         return -EINVAL;
      }
      if (!sst_config.b_fd)
      {
         return -ENOTSUP;
      }
   }
   else if (((u8_flags & CAN_FRAME_BRS) != 0U) || (stpt_frame->dlc > CAN_MAX_DLC))
   {
      return -EINVAL;
   }

   return 0;
}

/**
 * @private       si_MonitorOn
 * @brief         Install the traffic log's filters (all standard, all extended
 *                IDs). Caller holds sst_canIfMutex.
 * @return        0, or the error from can_add_rx_filter() (the filters already
 *                installed stay; sv_MonitorOff() removes them).
 */
static int si_MonitorOn(void)
{
   static const struct can_filter scstar_all[CANIF_MONITOR_FILTERS] =
   {
      { .id = 0U, .mask = 0U, .flags = 0U },
      { .id = 0U, .mask = 0U, .flags = CAN_FILTER_IDE },
   };
   uint32_t i;
   int i_id;

   for (i = 0U; i < CANIF_MONITOR_FILTERS; i++)
   {
      if (siar_monitorIds[i] < 0)
      {
         i_id = can_add_rx_filter(sstpt_dev, sv_OnDriverRx, NULL, &scstar_all[i]);
         if (i_id < 0)
         {
            return i_id;
         }
         siar_monitorIds[i] = i_id;
      }
   }

   sb_monitor = true;
   return 0;
}

/**
 * @private       sv_MonitorOff
 * @brief         Remove the traffic log's filters. Caller holds sst_canIfMutex.
 * @return        None.
 */
static void sv_MonitorOff(void)
{
   uint32_t i;

   for (i = 0U; i < CANIF_MONITOR_FILTERS; i++)
   {
      if (siar_monitorIds[i] >= 0)
      {
         can_remove_rx_filter(sstpt_dev, siar_monitorIds[i]);
         siar_monitorIds[i] = -1;
      }
   }

   sb_monitor = false;
}

/**
 * @private       sv_LogFrame
 * @brief         Log a received frame, at most CONFIG_CANIF_LOG_RX_MAX_PER_SEC a
 *                second; the frames left out are counted and reported with the
 *                first frame of the next window.
 * @param[in]     stpt_frame Frame.
 * @return        None.
 */
static void sv_LogFrame(const struct can_frame *stpt_frame)
{
   int64_t i64_now = k_uptime_get();
   uint8_t u8_flags = stpt_frame->flags;
   uint8_t u8_len;

   // Check if a new window starts
   if ((i64_now - si64_logWindowMs) >= CANIF_LOG_WINDOW_MS)
   {
      if (su32_logSuppressed > 0U)
      {
         APP_LOG_INF("%u frames not logged", su32_logSuppressed);
      }
      si64_logWindowMs = i64_now;
      su32_logCount = 0U;
      su32_logSuppressed = 0U;
   }

   // Check if the window's budget is spent
   if (su32_logCount >= CONFIG_CANIF_LOG_RX_MAX_PER_SEC)
   {
      su32_logSuppressed++;
      return;
   }
   su32_logCount++;

   u8_len = ((u8_flags & CAN_FRAME_RTR) != 0U) ? 0U : can_dlc_to_bytes(stpt_frame->dlc);
   if ((u8_flags & CAN_FRAME_IDE) != 0U)
   {
      APP_LOG_INF("RX 0x%08x [%u]%s%s%s", stpt_frame->id, u8_len,
         ((u8_flags & CAN_FRAME_FDF) != 0U) ? " FD" : "", ((u8_flags & CAN_FRAME_BRS) != 0U) ? " BRS" : "",
         ((u8_flags & CAN_FRAME_RTR) != 0U) ? " RTR" : "");
   }
   else
   {
      APP_LOG_INF("RX 0x%03x [%u]%s%s%s", stpt_frame->id, u8_len,
         ((u8_flags & CAN_FRAME_FDF) != 0U) ? " FD" : "", ((u8_flags & CAN_FRAME_BRS) != 0U) ? " BRS" : "",
         ((u8_flags & CAN_FRAME_RTR) != 0U) ? " RTR" : "");
   }
   if (u8_len > 0U)
   {
      LOG_HEXDUMP_INF(stpt_frame->data, u8_len, "RX data");
   }
}

/**
 * @private       sv_OnState
 * @brief         Record and log a state change, then call the listeners.
 * @param[in]     e_state New state.
 * @param[in]     stpt_errCnt Error counters.
 * @return        None.
 */
static void sv_OnState(enum can_state e_state, const struct can_bus_err_cnt *stpt_errCnt)
{
   CanIfListener_T star_listeners[CANIF_STATE_LISTENERS];
   uint32_t i;

   // Check if the controller just went bus-off
   if ((e_state == CAN_STATE_BUS_OFF) && (se_state != CAN_STATE_BUS_OFF))
   {
      su32_busOffCount++;
   }
   se_state = e_state;

   if ((e_state == CAN_STATE_ERROR_PASSIVE) || (e_state == CAN_STATE_BUS_OFF))
   {
      APP_LOG_WRN("state %s (tx err %u, rx err %u)", scpt_StateName(e_state),
         stpt_errCnt->tx_err_cnt, stpt_errCnt->rx_err_cnt);
   }
   else
   {
      APP_LOG_INF("state %s (tx err %u, rx err %u)", scpt_StateName(e_state),
         stpt_errCnt->tx_err_cnt, stpt_errCnt->rx_err_cnt);
   }

   // Call the listeners outside the lock: one may remove itself
   (void)k_mutex_lock(&sst_canIfMutex, K_FOREVER);
   memcpy(star_listeners, sstar_listeners, sizeof(star_listeners));
   (void)k_mutex_unlock(&sst_canIfMutex);
   for (i = 0U; i < CANIF_STATE_LISTENERS; i++)
   {
      if (star_listeners[i].fpt_cb != NULL)
      {
         star_listeners[i].fpt_cb(e_state, stpt_errCnt, star_listeners[i].vpt_user);
      }
   }
}

/**
 * @private       sv_HandleEvent
 * @brief         Hand a queue entry on: a frame to its filter's callback (unless
 *                the filter was removed since), a monitored frame to the log, a
 *                state change to sv_OnState().
 * @param[in]     stpt_event Event.
 * @return        None.
 */
static void sv_HandleEvent(const CanIfEvent_T *stpt_event)
{
   CanIfRx_F fpt_cb = NULL;
   void *vpt_user = NULL;
   CanIfSlot_T *stpt_slot;

   switch (stpt_event->u8_type)
   {
      case eCANIF_EVT_FRAME:
         (void)k_mutex_lock(&sst_canIfMutex, K_FOREVER);
         if (stpt_event->u8_slot < CONFIG_CANIF_MAX_FILTERS)
         {
            stpt_slot = &sstar_slots[stpt_event->u8_slot];
            if (stpt_slot->b_used && (stpt_slot->u16_gen == stpt_event->u16_gen))
            {
               fpt_cb = stpt_slot->fpt_cb;
               vpt_user = stpt_slot->vpt_user;
            }
         }
         (void)k_mutex_unlock(&sst_canIfMutex);

         // Check if the filter is still there
         if (fpt_cb != NULL)
         {
            fpt_cb(&stpt_event->st_frame, vpt_user);
         }
         break;

      case eCANIF_EVT_MONITOR:
         sv_LogFrame(&stpt_event->st_frame);
         break;

      case eCANIF_EVT_STATE:
         sv_OnState(stpt_event->e_state, &stpt_event->st_errCnt);
         break;

      default:
         break;
   }
}

/**
 * @private       sv_TestTx
 * @brief         Work handler: send a test frame (ID CANIF_TEST_ID, a 32-bit
 *                counter, then a byte pattern; in CAN FD mode every other one is a
 *                64-byte FD frame with BRS) and schedule the next. Skipped while
 *                stopped, listen-only or locked.
 * @param[in]     stpt_work Unused.
 * @return        None.
 */
static void sv_TestTx(struct k_work *stpt_work)
{
   struct can_frame st_frame;
   uint8_t u8_len;
   uint32_t i;
   int i_ret;

   ARG_UNUSED(stpt_work);

   // Check if the bus is free for test frames
   if (sb_started && !sst_config.b_listenOnly && (atomic_ptr_get(&st_owner) == NULL))
   {
      memset(&st_frame, 0, sizeof(st_frame));
      st_frame.id = CANIF_TEST_ID;
      st_frame.dlc = 8U;
#if defined(CONFIG_CAN_FD_MODE)
      if (sst_config.b_fd && ((su32_testCount & 1U) != 0U))
      {
         st_frame.flags = (uint8_t)(CAN_FRAME_FDF | CAN_FRAME_BRS);
         st_frame.dlc = can_bytes_to_dlc(CANIF_FD_TEST_LEN);
      }
#endif // CONFIG_CAN_FD_MODE
      u8_len = can_dlc_to_bytes(st_frame.dlc);
      sys_put_le32(su32_testCount, st_frame.data);
      for (i = 4U; i < u8_len; i++)
      {
         st_frame.data[i] = (uint8_t)i;
      }

      i_ret = gi_CanIf_Send(&st_frame, K_MSEC(CANIF_TEST_TX_TIMEOUT_MS));
      if (i_ret != 0)
      {
         APP_LOG_WRN("test frame %u not sent (%d)", su32_testCount, i_ret);
      }
      su32_testCount++;
   }

   (void)k_work_schedule(&sst_testTxWork, K_MSEC(CONFIG_CANIF_TEST_TX_PERIOD_MS));
}

/**
 * @private       sv_CanIfThread
 * @brief         Thread of the CAN interface: handle queued frames and state
 *                changes.
 * @param[in]     vpt_p1 Unused.
 * @param[in]     vpt_p2 Unused.
 * @param[in]     vpt_p3 Unused.
 * @return        None.
 */
static void sv_CanIfThread(void *vpt_p1, void *vpt_p2, void *vpt_p3)
{
   CanIfEvent_T st_event;

   ARG_UNUSED(vpt_p1);
   ARG_UNUSED(vpt_p2);
   ARG_UNUSED(vpt_p3);

   while (true)
   {
      // Check if an event arrived
      if (k_msgq_get(&sst_canIfMsgq, &st_event, K_FOREVER) == 0)
      {
         sv_HandleEvent(&st_event);
      }
   }
}

/******************************************************************************/
/*                                                                            */
/*                        PUBLIC FUNCTION DEFINITIONS                         */
/*                                                                            */
/******************************************************************************/
/**
 * @public        gi_CanIf_Init
 * @brief         Set up the CAN controller: initialise its driver (deferred, see
 *                the BUILD_ASSERT on zephyr,deferred-init), check it is there
 *                and supports the boot mode, run the loopback self-test
 *                (CONFIG_CANIF_SELFTEST), apply the boot configuration and start
 *                it, install the traffic log (CONFIG_CANIF_LOG_RX) and the test
 *                frames (CONFIG_CANIF_TEST_TX_PERIOD_MS). Call once, from main(),
 *                after dk_buttons_init() (gi_ProvButton_Init()).
 * @return        0; -EALREADY if called before; -ENODEV if the controller is not
 *                ready (no click, wiring, supply); -ENOTSUP if the boot mode is CAN
 *                FD and the controller lacks it; -EIO if the self-test failed (the
 *                interface then stays unusable); otherwise the driver's error. When
 *                only the start failed the interface is ready but stopped, and
 *                gi_CanIf_Configure() may try again.
 */
int gi_CanIf_Init(void)
{
   can_mode_t t_cap = 0;
   int i_ret;
   int i_monRet;

   if (sb_ready)
   {
      return -EALREADY;
   }

   // Initialise the driver now (zephyr,deferred-init); -EALREADY if it was at boot
   i_ret = device_init(sstpt_dev);
   if ((i_ret != 0) && (i_ret != -EALREADY))
   {
      APP_LOG_ERR("%s init failed (%d)", sstpt_dev->name, i_ret);
   }

   // Check if the driver found the controller
   if (!device_is_ready(sstpt_dev))
   {
      APP_LOG_ERR("%s not ready: check the click, its wiring and the DK's VDD (3.3 V)",
         sstpt_dev->name);
      return -ENODEV;
   }

   i_ret = can_get_capabilities(sstpt_dev, &t_cap);
   if (i_ret != 0)
   {
      APP_LOG_ERR("can_get_capabilities failed (%d)", i_ret);
      return i_ret;
   }
   sb_capFd = IS_ENABLED(CONFIG_CAN_FD_MODE) && ((t_cap & CAN_MODE_FD) != 0U);

   // Check if the boot mode is possible
   if (sst_config.b_fd && !sb_capFd)
   {
      APP_LOG_ERR("%s has no CAN FD", sstpt_dev->name);
      return -ENOTSUP;
   }

   can_set_state_change_callback(sstpt_dev, sv_OnDriverState, NULL);

   if (IS_ENABLED(CONFIG_CANIF_SELFTEST))
   {
      i_ret = si_SelfTest();
      if (i_ret != 0)
      {
         APP_LOG_ERR("loopback self-test failed (%d): check the wiring and the click's supply",
            i_ret);
         return -EIO;
      }
      APP_LOG_INF("loopback self-test passed (classic%s)", sb_capFd ? " and FD" : "");
   }

   sb_ready = true;

   (void)k_mutex_lock(&sst_canIfMutex, K_FOREVER);
   i_ret = si_Apply(&sst_config);
   if (i_ret != 0)
   {
      APP_LOG_ERR("%s not started (%d)", sstpt_dev->name, i_ret);
   }
   else
   {
      sv_LogConfig("started");
   }

   if (IS_ENABLED(CONFIG_CANIF_LOG_RX))
   {
      i_monRet = si_MonitorOn();
      if (i_monRet != 0)
      {
         sv_MonitorOff();
         APP_LOG_WRN("traffic log not installed (%d)", i_monRet);
      }
   }
   (void)k_mutex_unlock(&sst_canIfMutex);

   // Check if bench test frames are wanted
   if (CONFIG_CANIF_TEST_TX_PERIOD_MS > 0)
   {
      APP_LOG_WRN("test frame (ID 0x%03x) every %d ms: bench only", CANIF_TEST_ID,
         CONFIG_CANIF_TEST_TX_PERIOD_MS);
      (void)k_work_schedule(&sst_testTxWork, K_MSEC(CONFIG_CANIF_TEST_TX_PERIOD_MS));
   }

   return i_ret;
}

/**
 * @public        gi_CanIf_Configure
 * @brief         Change the mode and bitrates: stop the controller, apply the new
 *                configuration and start it again. If the new one is refused the
 *                previous one is restored. Filters and listeners are kept.
 * @param[in]     stpt_config Configuration (u32_bitrateData is used only with
 *                b_fd).
 * @param[in]     vpt_owner The caller's lock owner, or NULL.
 * @return        0; -EINVAL for NULL or a zero bitrate; -ENODEV if not ready;
 *                -ENOTSUP for CAN FD without support; -EBUSY while another owner
 *                holds the lock; otherwise the driver's error (the previous
 *                configuration is then back, unless restoring it failed too, which
 *                is logged and leaves the controller stopped).
 */
int gi_CanIf_Configure(const CanIfConfig_T *stpt_config, const void *vpt_owner)
{
   CanIfConfig_T st_old;
   void *vpt_holder;
   int i_ret;
   int i_restoreRet;

   if (stpt_config == NULL)
   {
      return -EINVAL;
   }
   if (!sb_ready)
   {
      return -ENODEV;
   }

   i_ret = si_CheckConfig(stpt_config);
   if (i_ret != 0)
   {
      return i_ret;
   }

   // Check if another session holds the bus
   vpt_holder = atomic_ptr_get(&st_owner);
   if ((vpt_holder != NULL) && (vpt_holder != vpt_owner))
   {
      return -EBUSY;
   }

   (void)k_mutex_lock(&sst_canIfMutex, K_FOREVER);
   st_old = sst_config;
   i_ret = si_Stop();
   if (i_ret != 0)
   {
      APP_LOG_WRN("can_stop failed (%d)", i_ret);
   }
   else
   {
      i_ret = si_Apply(stpt_config);
      if (i_ret == 0)
      {
         sst_config = *stpt_config;
         sv_LogConfig("reconfigured");
      }
      else
      {
         APP_LOG_WRN("configuration refused (%d): restoring the previous one", i_ret);
         i_restoreRet = si_Apply(&st_old);
         if (i_restoreRet != 0)
         {
            APP_LOG_ERR("%s left stopped (%d)", sstpt_dev->name, i_restoreRet);
         }
      }
   }
   (void)k_mutex_unlock(&sst_canIfMutex);

   return i_ret;
}

/**
 * @public        gi_CanIf_Lock
 * @brief         Reserve the bus for a session (a flash job): until it unlocks,
 *                gi_CanIf_Configure() from anyone else is refused and the test
 *                frames pause. gi_CanIf_Send() stays open to all.
 * @param[in]     vpt_owner Any pointer identifying the session.
 * @return        0; -EINVAL for NULL; -EALREADY if this owner holds it; -EBUSY if
 *                another does.
 */
int gi_CanIf_Lock(const void *vpt_owner)
{
   if (vpt_owner == NULL)
   {
      return -EINVAL;
   }
   if (atomic_ptr_get(&st_owner) == vpt_owner)
   {
      return -EALREADY;
   }
   if (!atomic_ptr_cas(&st_owner, NULL, (void *)vpt_owner))
   {
      return -EBUSY;
   }

   APP_LOG_INF("bus locked");
   return 0;
}

/**
 * @public        gi_CanIf_Unlock
 * @brief         Release the bus lock.
 * @param[in]     vpt_owner The owner that locked it.
 * @return        0; -EINVAL for NULL; -EPERM if this owner does not hold it.
 */
int gi_CanIf_Unlock(const void *vpt_owner)
{
   if (vpt_owner == NULL)
   {
      return -EINVAL;
   }
   if (!atomic_ptr_cas(&st_owner, (void *)vpt_owner, NULL))
   {
      return -EPERM;
   }

   APP_LOG_INF("bus unlocked");
   return 0;
}

/**
 * @public        gi_CanIf_Send
 * @brief         Send a frame and wait until it is on the bus. Any thread.
 * @param[in]     stpt_frame Frame (classic, or FD with CAN_FRAME_FDF and optional
 *                CAN_FRAME_BRS).
 * @param[in]     t_timeout Wait for a free transmit buffer.
 * @return        0; -EINVAL for NULL, unknown flags, an ID out of range, a DLC too
 *                large, RTR on an FD frame or BRS on a classic one; -ENODEV if not
 *                ready; -ENOTSUP for an FD frame in classic mode; -ENETDOWN if
 *                stopped; -EACCES in listen-only mode; otherwise can_send()'s
 *                error (-ENETUNREACH bus-off, -EAGAIN timeout, -EIO).
 */
int gi_CanIf_Send(const struct can_frame *stpt_frame, k_timeout_t t_timeout)
{
   int i_ret;

   if (stpt_frame == NULL)
   {
      return -EINVAL;
   }
   if (!sb_ready)
   {
      return -ENODEV;
   }

   i_ret = si_CheckFrame(stpt_frame);
   if (i_ret != 0)
   {
      return i_ret;
   }
   if (!sb_started)
   {
      return -ENETDOWN;
   }
   if (sst_config.b_listenOnly)
   {
      return -EACCES;
   }

   i_ret = can_send(sstpt_dev, stpt_frame, t_timeout, NULL, NULL);
   if (i_ret == 0)
   {
      (void)atomic_inc(&st_txFrames);
   }

   return i_ret;
}

/**
 * @public        gi_CanIf_AddRxFilter
 * @brief         Receive the frames that match a filter: fpt_cb is called with
 *                each on the CAN interface thread. A filter matches either
 *                standard IDs or (CAN_FILTER_IDE) extended IDs, classic and FD
 *                frames alike.
 * @param[in]     stpt_filter Filter (copied).
 * @param[in]     fpt_cb Callback.
 * @param[in]     vpt_user Passed to fpt_cb.
 * @return        The filter id (0..CONFIG_CANIF_MAX_FILTERS-1); -EINVAL for NULL;
 *                -ENODEV if not ready; -ENOSPC if all filters are in use;
 *                otherwise can_add_rx_filter()'s error.
 */
int gi_CanIf_AddRxFilter(const struct can_filter *stpt_filter, CanIfRx_F fpt_cb, void *vpt_user)
{
   CanIfSlot_T *stpt_slot = NULL;
   int i_ret = -ENOSPC;
   uint32_t i;

   if ((stpt_filter == NULL) || (fpt_cb == NULL))
   {
      return -EINVAL;
   }
   if (!sb_ready)
   {
      return -ENODEV;
   }

   (void)k_mutex_lock(&sst_canIfMutex, K_FOREVER);
   for (i = 0U; (i < CONFIG_CANIF_MAX_FILTERS) && (stpt_slot == NULL); i++)
   {
      if (!sstar_slots[i].b_used)
      {
         stpt_slot = &sstar_slots[i];
      }
   }

   // Check if a slot is free
   if (stpt_slot != NULL)
   {
      // Ready before the driver may call back
      stpt_slot->u16_gen++;
      stpt_slot->fpt_cb = fpt_cb;
      stpt_slot->vpt_user = vpt_user;
      stpt_slot->b_used = true;

      i_ret = can_add_rx_filter(sstpt_dev, sv_OnDriverRx, stpt_slot, stpt_filter);
      if (i_ret < 0)
      {
         stpt_slot->b_used = false;
         stpt_slot->fpt_cb = NULL;
      }
      else
      {
         stpt_slot->i_driverId = i_ret;
         i_ret = (int)(stpt_slot - sstar_slots);
      }
   }
   (void)k_mutex_unlock(&sst_canIfMutex);

   return i_ret;
}

/**
 * @public        gi_CanIf_RemoveRxFilter
 * @brief         Remove a filter. Frames already queued for it are dropped.
 * @param[in]     i_filterId Id from gi_CanIf_AddRxFilter().
 * @return        0; -EINVAL for an id not in use; -ENODEV if not ready.
 */
int gi_CanIf_RemoveRxFilter(int i_filterId)
{
   CanIfSlot_T *stpt_slot;
   int i_ret = -EINVAL;

   if ((i_filterId < 0) || (i_filterId >= (int)CONFIG_CANIF_MAX_FILTERS))
   {
      return -EINVAL;
   }
   if (!sb_ready)
   {
      return -ENODEV;
   }

   (void)k_mutex_lock(&sst_canIfMutex, K_FOREVER);
   stpt_slot = &sstar_slots[i_filterId];
   if (stpt_slot->b_used)
   {
      can_remove_rx_filter(sstpt_dev, stpt_slot->i_driverId);
      stpt_slot->b_used = false;
      stpt_slot->u16_gen++;
      stpt_slot->fpt_cb = NULL;
      i_ret = 0;
   }
   (void)k_mutex_unlock(&sst_canIfMutex);

   return i_ret;
}

/**
 * @public        gi_CanIf_AddStateListener
 * @brief         Be told of every error state change (on the CAN interface
 *                thread). Works before gi_CanIf_Init().
 * @param[in]     fpt_cb Callback.
 * @param[in]     vpt_user Passed to fpt_cb.
 * @return        0; -EINVAL for NULL; -EALREADY if this pair is registered;
 *                -ENOSPC if CANIF_STATE_LISTENERS are.
 */
int gi_CanIf_AddStateListener(CanIfState_F fpt_cb, void *vpt_user)
{
   CanIfListener_T *stpt_free = NULL;
   int i_ret = 0;
   uint32_t i;

   if (fpt_cb == NULL)
   {
      return -EINVAL;
   }

   (void)k_mutex_lock(&sst_canIfMutex, K_FOREVER);
   for (i = 0U; i < CANIF_STATE_LISTENERS; i++)
   {
      if ((sstar_listeners[i].fpt_cb == fpt_cb) && (sstar_listeners[i].vpt_user == vpt_user))
      {
         i_ret = -EALREADY;
      }
      else if ((sstar_listeners[i].fpt_cb == NULL) && (stpt_free == NULL))
      {
         stpt_free = &sstar_listeners[i];
      }
   }

   // Check if it can be added
   if (i_ret == 0)
   {
      if (stpt_free == NULL)
      {
         i_ret = -ENOSPC;
      }
      else
      {
         stpt_free->fpt_cb = fpt_cb;
         stpt_free->vpt_user = vpt_user;
      }
   }
   (void)k_mutex_unlock(&sst_canIfMutex);

   return i_ret;
}

/**
 * @public        gi_CanIf_RemoveStateListener
 * @brief         Remove a state listener.
 * @param[in]     fpt_cb Callback given to gi_CanIf_AddStateListener().
 * @param[in]     vpt_user User pointer given with it.
 * @return        0; -EINVAL for NULL; -ENOENT if the pair is not registered.
 */
int gi_CanIf_RemoveStateListener(CanIfState_F fpt_cb, void *vpt_user)
{
   int i_ret = -ENOENT;
   uint32_t i;

   if (fpt_cb == NULL)
   {
      return -EINVAL;
   }

   (void)k_mutex_lock(&sst_canIfMutex, K_FOREVER);
   for (i = 0U; i < CANIF_STATE_LISTENERS; i++)
   {
      if ((sstar_listeners[i].fpt_cb == fpt_cb) && (sstar_listeners[i].vpt_user == vpt_user))
      {
         sstar_listeners[i].fpt_cb = NULL;
         sstar_listeners[i].vpt_user = NULL;
         i_ret = 0;
      }
   }
   (void)k_mutex_unlock(&sst_canIfMutex);

   return i_ret;
}

/**
 * @public        gv_CanIf_SetMonitor
 * @brief         Turn the traffic log on or off. It sees every frame on the bus,
 *                which costs SPI and CPU time: turn it off while flashing.
 * @param[in]     b_on true to log received frames.
 * @return        None. Ignored (with a warning) if not ready.
 */
void gv_CanIf_SetMonitor(bool b_on)
{
   int i_ret;

   if (!sb_ready)
   {
      APP_LOG_WRN("CAN not ready");
      return;
   }

   (void)k_mutex_lock(&sst_canIfMutex, K_FOREVER);
   if (b_on)
   {
      i_ret = si_MonitorOn();
      if (i_ret != 0)
      {
         sv_MonitorOff();
         APP_LOG_WRN("traffic log not installed (%d)", i_ret);
      }
      else
      {
         APP_LOG_INF("traffic log on");
      }
   }
   else
   {
      sv_MonitorOff();
      APP_LOG_INF("traffic log off");
   }
   (void)k_mutex_unlock(&sst_canIfMutex);
}

/**
 * @public        gi_CanIf_GetStatus
 * @brief         Snapshot of the interface; the error state and counters are read
 *                from the controller when it is ready.
 * @param[out]    stpt_status Status.
 * @return        0, or -EINVAL for NULL.
 */
int gi_CanIf_GetStatus(CanIfStatus_T *stpt_status)
{
   enum can_state e_state;
   struct can_bus_err_cnt st_errCnt;

   if (stpt_status == NULL)
   {
      return -EINVAL;
   }

   memset(stpt_status, 0, sizeof(*stpt_status));
   stpt_status->b_ready = sb_ready;
   stpt_status->b_started = sb_started;
   stpt_status->b_locked = (atomic_ptr_get(&st_owner) != NULL);
   stpt_status->b_monitor = sb_monitor;
   stpt_status->st_config = sst_config;
   stpt_status->e_state = se_state;
   stpt_status->u32_txFrames = (uint32_t)atomic_get(&st_txFrames);
   stpt_status->u32_rxFrames = (uint32_t)atomic_get(&st_rxFrames);
   stpt_status->u32_rxDropped = (uint32_t)atomic_get(&st_rxDropped);
   stpt_status->u32_busOffCount = su32_busOffCount;

   // Check if the controller can report its live state
   if (sb_ready && (can_get_state(sstpt_dev, &e_state, &st_errCnt) == 0))
   {
      stpt_status->e_state = e_state;
      stpt_status->st_errCnt = st_errCnt;
   }

   return 0;
}

/**
 * @public        gstpt_CanIf_GetDevice
 * @brief         The controller, for a protocol that binds to it directly (Zephyr's
 *                ISO-TP). Such a user must leave the mode and bitrates to
 *                gi_CanIf_Configure().
 * @return        The device, or NULL if not ready.
 */
const struct device *gstpt_CanIf_GetDevice(void)
{
   return sb_ready ? sstpt_dev : NULL;
}

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shivam Chudasama [SC]
 */
