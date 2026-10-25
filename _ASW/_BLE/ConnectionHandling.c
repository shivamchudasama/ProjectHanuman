/**
 * @file          ConnectionHandling.c
 * @brief         Source file containing all the connection handling related functions.
 *
 *                The device keeps up to two links at once:
 *                  - the host link: the PC (GUI or CLI) that uploads, provisions
 *                    or orchestrates pairing. It is the first connection that
 *                    the pairing module does not claim; the SETU Server binds
 *                    to it. A second unclaimed connection is refused.
 *                  - the peer link: another device during and after pairing,
 *                    owned by _PAIR (gb_Pair_ClaimConn()).
 *                Each link negotiates PHY, data length and MTU on its own; the
 *                peripheral side of a link also asks for a short connection
 *                interval.
 *
 *                Undirected advertising runs only while the host window of
 *                _HOST_AUTH is open (gb_HostAuth_WindowOpen(): the DK button,
 *                or a trusted host's grace period) and no host is connected. It
 *                carries the Pairing service UUID once the device is
 *                provisioned, the SETU service UUID before. Outside it, a
 *                bonded peripheral whose central is away
 *                (gb_Pair_AwaitsBondedPeer()) advertises directed to that
 *                central only. _PAIR's own directed advertising (a run) has the
 *                advertiser to itself. The host link's SMP, disconnects and
 *                security changes also go to _HOST_AUTH.
 * @date          21/02/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include "ConnectionHandling.h"
#include <errno.h>
#include <zephyr/settings/settings.h>
#include "SETU.h"
#include "Pair.h"
#include "PairSvc.h"
#include "Prov.h"
#include "HostAuth.h"

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
/**
 * @def           TARGET_PHY
 * @brief         Target PHY for connection.
 */
#define TARGET_PHY                           (BT_GAP_LE_PHY_2M)

/**
 * @def           TARGET_DLE
 * @brief         Target DLE value.
 */
#define TARGET_DLE                           (251)

/**
 * @def           TARGET_MTU
 * @brief         Target MTU value.
 */
#define TARGET_MTU                           (247)

/**
 * @def           TARGET_CONN_INTERVAL_MIN
 * @brief         Minimum requested connection interval (units of 1.25 ms): 7.5 ms.
 */
#define TARGET_CONN_INTERVAL_MIN             (6)

/**
 * @def           TARGET_CONN_INTERVAL_MAX
 * @brief         Maximum requested connection interval (units of 1.25 ms): 15 ms.
 *                A shorter interval gives more connection events per second, which
 *                is what limits the upload throughput.
 */
#define TARGET_CONN_INTERVAL_MAX             (12)

/**
 * @def           TARGET_CONN_LATENCY
 * @brief         Requested peripheral latency (connection events).
 */
#define TARGET_CONN_LATENCY                  (0)

/**
 * @def           TARGET_CONN_TIMEOUT
 * @brief         Requested supervision timeout (units of 10 ms): 4 s.
 */
#define TARGET_CONN_TIMEOUT                  (400)

/**
 * @def           NEGOTIATION_DELAY_S
 * @brief         Delay between a connection and the start of its negotiation,
 *                to let the link settle.
 */
#define NEGOTIATION_DELAY_S                  (2)

/**
 * @def           NEGOTIATION_RETRY_DELAY_MS
 * @brief         Delay for retrying a busy negotiation procedure.
 */
#define NEGOTIATION_RETRY_DELAY_MS           (200)

/**
 * @def           MAX_NEGOTIATION_RETRY_CNT
 * @brief         Maximum number of retries for a negotiation procedure.
 */
#define MAX_NEGOTIATION_RETRY_CNT            (3)

/******************************************************************************/
/*                                                                            */
/*                                   ENUMS                                    */
/*                                                                            */
/******************************************************************************/
/**
 * @enum          ConnNegotiationStep_E
 * @brief         Enums to track which link-layer optimization is currently being
 *                negotiated.
 */
typedef enum
{
   eCNS_PHY = 0,                             /**< PHY update */
   eCNS_DLE,                                 /**< Data Length Extention */
   eCNS_MTU,                                 /**< MTU exchange */
   eCNS_CONN_PARAM,                          /**< Connection parameter update */
   eCNS_COMPLETE,                            /**< Negotiation complete */
} ConnNegotiationStep_E;

/******************************************************************************/
/*                                                                            */
/*                                 STRUCTURES                                 */
/*                                                                            */
/******************************************************************************/
/**
 * @struct        LinkCtx_T
 * @brief         Negotiation state of one link, indexed by bt_conn_index().
 */
typedef struct
{
   struct bt_conn *stpt_conn;                /**< Link (referenced), NULL if unused   */
   bool b_isSelfNegotiation;                 /**< Negotiation has started             */
   bool b_waitingForProcedure;               /**< A local procedure is pending        */
   ConnNegotiationStep_E e_step;             /**< Current negotiation step            */
   uint8_t u8_retryCnt;                      /**< Retries of the current step         */
   struct k_work_delayable st_work;          /**< Negotiation work item               */
   struct bt_gatt_exchange_params st_mtuParams; /**< MTU exchange parameters          */
} LinkCtx_T;

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
static LinkCtx_T *sstpt_FindLink(struct bt_conn *stpt_conn);
static void sv_OpenLink(struct bt_conn *stpt_conn);
static void sv_CloseLink(struct bt_conn *stpt_conn);
static void sv_ConnParamNegotiation(struct k_work *stpt_work);
static void sv_MTUExchangeCallback(struct bt_conn *stpt_conn, uint8_t u8_err,
   struct bt_gatt_exchange_params *stpt_exchangeParams);
static void sv_StartAdvIfAllowed(void);
static void sv_Connected(struct bt_conn *stpt_conn, uint8_t u8_err);
static void sv_Disconnected(struct bt_conn *stpt_conn, uint8_t reason);
static void sv_Recycled(void);
static void sv_SecurityChanged(struct bt_conn *stpt_conn, bt_security_t e_level,
   enum bt_security_err e_err);
static void sv_PHYUpdated(struct bt_conn *stpt_conn, struct bt_conn_le_phy_info *stpt_PHYInfo);
static void sv_DataLengthUpdated(struct bt_conn *stpt_conn,
   struct bt_conn_le_data_len_info *stpt_dataLenInfo);
static void sv_ConnParamUpdated(struct bt_conn *stpt_conn, uint16_t u16_interval,
   uint16_t u16_latency, uint16_t u16_timeout);

/******************************************************************************/
/*                                                                            */
/*                              EXTERN VARIABLES                              */
/*                                                                            */
/******************************************************************************/

/******************************************************************************/
/*                                                                            */
/*                              PUBLIC VARIABLES                              */
/*                                                                            */
/******************************************************************************/

/******************************************************************************/
/*                                                                            */
/*                             PRIVATE VARIABLES                              */
/*                                                                            */
/******************************************************************************/
/**
 * @var           sstar_links
 * @brief         Negotiation state per link.
 */
static LinkCtx_T sstar_links[CONFIG_BT_MAX_CONN];

/**
 * @var           sstpt_hostConn
 * @brief         Host link (referenced), NULL if none. Guarded by sst_hostLock.
 */
static struct bt_conn *sstpt_hostConn = NULL;

/**
 * @var           sst_hostLock
 * @brief         Guards sstpt_hostConn (BT callbacks and other threads).
 */
static struct k_spinlock sst_hostLock;

/**
 * @var           sb_btReady
 * @brief         Set once the stack is enabled and its settings are loaded.
 */
static bool sb_btReady = false;

/**
 * @var           sstar_advDataProv
 * @brief         Advertising data of a device to provision: flags and the
 *                SETU service, which lets the PC filter its scans. The name
 *                stays in the scan response (both don't fit in 31 B).
 */
static struct bt_data sstar_advDataProv[] =
{
   // AD Type: Flags - general discoverable and no BR/EDR support
   BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
   // AD Type: Complete list of 128-bit service UUIDs - SETU service
   BT_DATA_BYTES(BT_DATA_UUID128_ALL, BT_UUID_SETU_SVC_VAL),
};

/**
 * @var           sstar_advDataPair
 * @brief         Advertising data of a provisioned device: flags and the
 *                Pairing service, which the GUI's pairing page scans for.
 *                SETU stays available over GATT.
 */
static struct bt_data sstar_advDataPair[] =
{
   // AD Type: Flags - general discoverable and no BR/EDR support
   BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
   // AD Type: Incomplete list of 128-bit service UUIDs - Pairing service
   BT_DATA_BYTES(BT_DATA_UUID128_SOME, BT_UUID_PAIR_SVC_VAL),
};

/**
 * @var           sstar_scanRespData
 * @brief         Create scan response data structure array.
 */
static struct bt_data sstar_scanRespData[] =
{
   // AD Type: Complete local name
   BT_DATA(BT_DATA_NAME_COMPLETE, CONFIG_BT_DEVICE_NAME,
      sizeof(CONFIG_BT_DEVICE_NAME) - 1),
};

/**
 * @var           sst_connCallbacks
 * @brief         Connection callbacks.
 */
BT_CONN_CB_DEFINE(sst_connCallbacks) = {
	.connected = sv_Connected,                // Callback for handling new connections
	.disconnected = sv_Disconnected,          // Callback for handling disconnections
   .recycled = sv_Recycled,                  // Callback for handling recycled connections
   .security_changed = sv_SecurityChanged,   // Callback for handling security changes
   .le_phy_updated = sv_PHYUpdated,          // Callback to be called upon PHY updated
   .le_data_len_updated = sv_DataLengthUpdated,
                                             // Callback to be called upon data length updated
   .le_param_updated = sv_ConnParamUpdated,  // Callback to be called upon connection parameters updated
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
 * @private       sstpt_FindLink
 * @brief         Negotiation state of an open link.
 * @param[in]     stpt_conn Connection.
 * @return        Its context, or NULL if the link is not open here.
 */
static LinkCtx_T *sstpt_FindLink(struct bt_conn *stpt_conn)
{
   LinkCtx_T *stpt_link = &sstar_links[bt_conn_index(stpt_conn)];

   return (stpt_link->stpt_conn == stpt_conn) ? stpt_link : NULL;
}

/**
 * @private       sv_OpenLink
 * @brief         Take a reference on a new link and schedule its negotiation.
 * @param[in]     stpt_conn Connection.
 * @return        None.
 */
static void sv_OpenLink(struct bt_conn *stpt_conn)
{
   LinkCtx_T *stpt_link = &sstar_links[bt_conn_index(stpt_conn)];
   int i_err;

   // Check if a stale context is left (it should be closed at disconnect)
   if (stpt_link->stpt_conn != NULL)
   {
      (void)k_work_cancel_delayable(&stpt_link->st_work);
      bt_conn_unref(stpt_link->stpt_conn);
   }

   stpt_link->stpt_conn = bt_conn_ref(stpt_conn);
   stpt_link->b_isSelfNegotiation = false;
   stpt_link->b_waitingForProcedure = false;
   stpt_link->e_step = eCNS_PHY;
   stpt_link->u8_retryCnt = 0U;
   k_work_init_delayable(&stpt_link->st_work, sv_ConnParamNegotiation);

   // Negotiate PHY, DLE, MTU and the interval after a short delay, to allow
   // the connection to stabilize
   i_err = k_work_schedule(&stpt_link->st_work, K_SECONDS(NEGOTIATION_DELAY_S));

   // Check if scheduling the negotiation work failed
   if (i_err < 0)
   {
      LOG_WRN("Failed to schedule negotiation work (err %x)", i_err);
   }
}

/**
 * @private       sv_CloseLink
 * @brief         Stop a link's negotiation and drop its reference.
 * @param[in]     stpt_conn Connection.
 * @return        None.
 */
static void sv_CloseLink(struct bt_conn *stpt_conn)
{
   LinkCtx_T *stpt_link = sstpt_FindLink(stpt_conn);

   // Check if the link was open here
   if (stpt_link != NULL)
   {
      (void)k_work_cancel_delayable(&stpt_link->st_work);
      bt_conn_unref(stpt_link->stpt_conn);
      stpt_link->stpt_conn = NULL;
   }
}

/**
 * @private       sv_ConnParamNegotiation
 * @brief         Negotiation for PHY update, data length update, MTU exchange
 *                and (as peripheral) connection parameter update, one link at a
 *                time per work item.
 * @param[in]     stpt_work Work item of the link.
 * @return        None.
 */
static void sv_ConnParamNegotiation(struct k_work *stpt_work)
{
   struct k_work_delayable *stpt_dwork = k_work_delayable_from_work(stpt_work);
   LinkCtx_T *stpt_link = CONTAINER_OF(stpt_dwork, LinkCtx_T, st_work);
   struct bt_conn *stpt_conn = stpt_link->stpt_conn;
   struct bt_conn_le_phy_param st_PHYParam = {
      .options = BT_CONN_LE_PHY_OPT_NONE,
      .pref_tx_phy = TARGET_PHY,
      .pref_rx_phy = TARGET_PHY,
   };
   struct bt_conn_info st_connInfo;
   int i_err;
   uint16_t u16_MTU;

   // Check if the link is still open
   if (stpt_conn == NULL)
   {
      return;
   }

   // Track first entry after the delay to mark start of self negotiation.
   if (!stpt_link->b_isSelfNegotiation)
   {
      stpt_link->b_isSelfNegotiation = true;
      LOG_INF("Starting self negotiation after a delay...");
   }

   // Loop through negotiation steps until complete, handling busy responses with retries
   while (stpt_link->e_step != eCNS_COMPLETE)
   {
      // Get the current connection info for the connection handle
      i_err = bt_conn_get_info(stpt_conn, &st_connInfo);

      // Check if getting connection info failed
      if (i_err)
      {
         LOG_ERR("Failed to get connection info (err %x)", i_err);
         return;
      }

      // Switch through negotiation steps and perform necessary actions for each step
      switch (stpt_link->e_step)
      {
         case eCNS_PHY:
         {
            // Check if PHY is already at target for both TX and RX
            if ((st_connInfo.le.phy->tx_phy == TARGET_PHY) &&
               (st_connInfo.le.phy->rx_phy == TARGET_PHY))
            {
               LOG_INF("PHY already at target (TX:%d RX:%d), skipping PHY request",
                  st_connInfo.le.phy->tx_phy, st_connInfo.le.phy->rx_phy);
               stpt_link->e_step = eCNS_DLE;
               stpt_link->b_waitingForProcedure = false;
               continue;
            }

            // Check if we are already waiting for a procedure to complete
            if (stpt_link->b_waitingForProcedure)
            {
               return;
            }

            LOG_INF("Requesting PHY 2M...");
            i_err = bt_conn_le_phy_update(stpt_conn, &st_PHYParam);

            // Check if there was an error initiating PHY update
            if (i_err)
            {
               // Check if we haven't exceeded max retry count
               if (stpt_link->u8_retryCnt < MAX_NEGOTIATION_RETRY_CNT)
               {
                  stpt_link->u8_retryCnt++;
                  LOG_WRN("PHY update request failed (err %d), retrying...", i_err);
                  k_work_schedule(&stpt_link->st_work, K_MSEC(NEGOTIATION_RETRY_DELAY_MS));
                  return;
               }
               else
               {
                  LOG_WRN("PHY update request failed, proceeding without it...");
                  stpt_link->e_step = eCNS_DLE;
                  continue;
               }
            }

            stpt_link->b_waitingForProcedure = true;
            return;
         }

         case eCNS_DLE:
         {
            // Check if DLE is already at target for both TX and RX
            if ((st_connInfo.le.data_len->tx_max_len >= TARGET_DLE) &&
               (st_connInfo.le.data_len->rx_max_len >= TARGET_DLE))
            {
               LOG_INF("DLE already at target (TX:%d RX:%d), skipping DLE request",
                  st_connInfo.le.data_len->tx_max_len, st_connInfo.le.data_len->rx_max_len);
               stpt_link->e_step = eCNS_MTU;
               stpt_link->b_waitingForProcedure = false;
               continue;
            }

            // Check if we are already waiting for a procedure to complete
            if (stpt_link->b_waitingForProcedure)
            {
               return;
            }

            LOG_INF("Requesting DLE 251...");
            // Zephyr reads the parameters without a NULL check: a NULL here
            // sends the controller whatever lies at address 0
            i_err = bt_conn_le_data_len_update(stpt_conn, BT_LE_DATA_LEN_PARAM_MAX);

            // Check if the controller already uses these parameters
            if (i_err == -EALREADY)
            {
               stpt_link->e_step = eCNS_MTU;
               continue;
            }

            // Check if there was an error initiating DLE update
            if (i_err)
            {
               // Check if we haven't exceeded max retry count
               if (stpt_link->u8_retryCnt < MAX_NEGOTIATION_RETRY_CNT)
               {
                  stpt_link->u8_retryCnt++;
                  LOG_WRN("DLE update request failed (err %d), retrying...", i_err);
                  k_work_schedule(&stpt_link->st_work, K_MSEC(NEGOTIATION_RETRY_DELAY_MS));
                  return;
               }
               else
               {
                  LOG_WRN("DLE update request failed, proceeding without it...");
                  stpt_link->e_step = eCNS_MTU;
                  continue;
               }
            }

            stpt_link->b_waitingForProcedure = true;
            return;
         }

         case eCNS_MTU:
         {
            u16_MTU = bt_gatt_get_mtu(stpt_conn);

            // Check if MTU is already at target
            if (u16_MTU >= TARGET_MTU)
            {
               LOG_INF("MTU already at target (%d bytes), skipping MTU request", u16_MTU);
               stpt_link->e_step = eCNS_CONN_PARAM;
               stpt_link->b_waitingForProcedure = false;
               continue;
            }

            // Check if we are already waiting for a procedure to complete
            if (stpt_link->b_waitingForProcedure)
            {
               return;
            }

            LOG_INF("Requesting MTU %d...", TARGET_MTU);
            stpt_link->st_mtuParams.func = sv_MTUExchangeCallback;
            i_err = bt_gatt_exchange_mtu(stpt_conn, &stpt_link->st_mtuParams);

            // Check if there was an error initiating the MTU exchange
            if (i_err)
            {
               // Check if we haven't exceeded max retry count
               if (stpt_link->u8_retryCnt < MAX_NEGOTIATION_RETRY_CNT)
               {
                  stpt_link->u8_retryCnt++;
                  LOG_WRN("MTU exchange request failed (err %d), retrying...", i_err);
                  k_work_schedule(&stpt_link->st_work, K_MSEC(NEGOTIATION_RETRY_DELAY_MS));
                  return;
               }
               else
               {
                  LOG_WRN("MTU exchange request failed, proceeding without it...");
                  stpt_link->e_step = eCNS_CONN_PARAM;
                  continue;
               }
            }

            stpt_link->b_waitingForProcedure = true;
            return;
         }

         case eCNS_CONN_PARAM:
         {
            // Check if this side is the central: it chose the interval when
            // it connected
            if (st_connInfo.role != BT_CONN_ROLE_PERIPHERAL)
            {
               stpt_link->e_step = eCNS_COMPLETE;
               continue;
            }

            // Check if the connection interval is already at target
            if (st_connInfo.le.interval_us <= BT_CONN_INTERVAL_TO_US(TARGET_CONN_INTERVAL_MAX))
            {
               LOG_INF("Connection interval already at target (%u us), skipping request",
                  st_connInfo.le.interval_us);
               stpt_link->e_step = eCNS_COMPLETE;
               stpt_link->b_waitingForProcedure = false;
               continue;
            }

            LOG_INF("Requesting connection interval %u-%u us (current %u us)...",
               BT_CONN_INTERVAL_TO_US(TARGET_CONN_INTERVAL_MIN),
               BT_CONN_INTERVAL_TO_US(TARGET_CONN_INTERVAL_MAX), st_connInfo.le.interval_us);
            i_err = bt_conn_le_param_update(stpt_conn,
               BT_LE_CONN_PARAM(TARGET_CONN_INTERVAL_MIN, TARGET_CONN_INTERVAL_MAX,
                  TARGET_CONN_LATENCY, TARGET_CONN_TIMEOUT));

            // Check if there was an error initiating the connection parameter update
            if (i_err)
            {
               // Check if we haven't exceeded max retry count
               if (stpt_link->u8_retryCnt < MAX_NEGOTIATION_RETRY_CNT)
               {
                  stpt_link->u8_retryCnt++;
                  LOG_WRN("Connection parameter update request failed (err %d), retrying...",
                     i_err);
                  k_work_schedule(&stpt_link->st_work, K_MSEC(NEGOTIATION_RETRY_DELAY_MS));
                  return;
               }
               else
               {
                  LOG_WRN("Connection parameter update request failed, proceeding without it...");
               }
            }

            // Not waited for: the central may reject the request without any callback.
            // Zephyr sends it once CONFIG_BT_CONN_PARAM_UPDATE_TIMEOUT has passed since the
            // connection; the result is logged by sv_ConnParamUpdated().
            stpt_link->e_step = eCNS_COMPLETE;
            continue;
         }

         case eCNS_COMPLETE:
         default:
            break;
      }
   }

   LOG_INF("Negotiation complete.");
}

/**
 * @private       sv_MTUExchangeCallback
 * @brief         Callback function to be called after exchanging MTU
 * @param[in]     stpt_conn Connection handle
 * @param[in]     u8_err Error code of the MTU exchange procedure
 * @param[in]     stpt_exchangeParams Pointer to the exchange parameters structure
 * @return        None.
 */
static void sv_MTUExchangeCallback(struct bt_conn *stpt_conn, uint8_t u8_err,
   struct bt_gatt_exchange_params *stpt_exchangeParams)
{
   LinkCtx_T *stpt_link = sstpt_FindLink(stpt_conn);

   ARG_UNUSED(stpt_exchangeParams);

   // Check if the callback is for an open link
   if (stpt_link == NULL)
   {
      return;
   }

   LOG_INF("MTU exchange %s", (u8_err == 0 ? "successful" : "failed"));

   // Check if no error
   if (!u8_err)
   {
      // Get the current MTU size
      uint16_t u16_payloadMTU = bt_gatt_get_mtu(stpt_conn) - 3;  /* 3 bytes ATT header */
      LOG_INF("New MTU payload: %d bytes", u16_payloadMTU);
   }

   if ((stpt_link->b_isSelfNegotiation) && (stpt_link->e_step == eCNS_MTU))
   {
      stpt_link->b_waitingForProcedure = false;
      stpt_link->e_step = eCNS_CONN_PARAM;
      k_work_schedule(&stpt_link->st_work, K_NO_WAIT);
   }
}

/**
 * @private       sv_StartAdvIfAllowed
 * @brief         Start the advertising that is wanted now, if _PAIR does not
 *                use the advertiser:
 *                - the host window is open and no host is connected: connectable
 *                  undirected advertising, its data following the provisioning
 *                  state (a bonded central can connect to it too);
 *                - otherwise, a bonded peripheral whose central is away:
 *                  connectable directed advertising to that central only;
 *                - otherwise none.
 * @return        None.
 */
static void sv_StartAdvIfAllowed(void)
{
   bool b_hasHost;
   bool b_isProvisioned = (ge_Prov_GetState() == ePS_PROVISIONED);
   bt_addr_le_t st_peer;
   k_spinlock_key_t t_key;
   int i_err;

   t_key = k_spin_lock(&sst_hostLock);
   b_hasHost = (sstpt_hostConn != NULL);
   k_spin_unlock(&sst_hostLock, t_key);

   // Check if the stack runs and the advertiser is free
   if (!sb_btReady || gb_Pair_IsAdvertising())
   {
      return;
   }

   // Check if only the bonded central may connect (no window, or a host is here)
   if (!gb_HostAuth_WindowOpen() || b_hasHost)
   {
      // Check if a bonded peripheral awaits its central
      if (gb_Pair_AwaitsBondedPeer() && gb_Pair_GetBondedPeer(&st_peer))
      {
         i_err = bt_le_adv_start(BT_LE_ADV_CONN_DIR_LOW_DUTY(&st_peer), NULL, 0U, NULL, 0U);

         // Check if directed advertising did not start (already running is fine)
         if ((i_err != 0) && (i_err != -EALREADY))
         {
            LOG_ERR("Directed advertising failed to start (err %d)", i_err);
         }
         else
         {
            LOG_INF("Advertising for the bonded central");
         }
      }
      return;
   }

   // Start advertising by setting advertisement data, scan response data,
   // and advertisement parameters.
   i_err = bt_le_adv_start(
      BT_LE_ADV_CONN_FAST_1,                 // Advertising parameters: Connectable undirected advertising
      b_isProvisioned ? sstar_advDataPair : sstar_advDataProv,
                                             // Advertising data
      b_isProvisioned ? ARRAY_SIZE(sstar_advDataPair) : ARRAY_SIZE(sstar_advDataProv),
                                             // Length of advertising data
      sstar_scanRespData,                    // Scan response data
      ARRAY_SIZE(sstar_scanRespData)         // Length of scan response data
   );

   // Check if advertising start wasn't successful (already running is fine)
   if ((i_err != 0) && (i_err != -EALREADY))
   {
      LOG_ERR("Advertising failed to start (err %d)", i_err);
      return;
   }

   LOG_INF("Advertising for a host (%s)", b_isProvisioned ? "provisioned" : "unprovisioned");
}

/**
 * @private       sv_Connected
 * @brief         Callback for handling new connections. The pairing module
 *                claims its peer link; the first other connection becomes the
 *                host link; a second host is refused.
 * @param[in]     stpt_conn Connection handle.
 * @param[in]     u8_err Error code of the connection attempt.
 * @return        None.
 */
static void sv_Connected(struct bt_conn *stpt_conn, uint8_t u8_err)
{
   k_spinlock_key_t t_key;
   bool b_isHost = false;

   // Check if it is the pairing peer (up, or a failed attempt to reach it)
   if (gb_Pair_ClaimConn(stpt_conn, u8_err))
   {
      // Check if the peer link came up
      if (u8_err == 0U)
      {
         LOG_INF("Peer link connected");
         sv_OpenLink(stpt_conn);

         // The connection ended advertising: resume it for a host if wanted
         sv_StartAdvIfAllowed();
      }
      return;
   }

   // Check if the connection attempt failed
   if (u8_err)
   {
      LOG_ERR("Connection failed (err %u)", u8_err);
      return;
   }

   t_key = k_spin_lock(&sst_hostLock);
   // Check if there is no host yet: this one is it
   if (sstpt_hostConn == NULL)
   {
      sstpt_hostConn = bt_conn_ref(stpt_conn);
      b_isHost = true;
   }
   k_spin_unlock(&sst_hostLock, t_key);

   // Check if a second host tries to connect
   if (!b_isHost)
   {
      LOG_WRN("Second host connection refused");
      (void)bt_conn_disconnect(stpt_conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
      return;
   }

   LOG_INF("Host connected");

   // Host authentication takes the link's SMP callbacks before any pairing
   gv_HostAuth_OnHostConnected(stpt_conn);

   // Bind the SETU Server to the host (unless pairing holds it)
   gv_SETUS_OnConnected(stpt_conn);

   sv_OpenLink(stpt_conn);

   // The connection ended advertising: resume it if the bonded central is
   // still awaited
   sv_StartAdvIfAllowed();
}

/**
 * @private       sv_Disconnected
 * @brief         Callback for handling disconnections.
 * @param[in]     stpt_conn Connection handle.
 * @param[in]     reason Reason for disconnection.
 * @return        None.
 */
static void sv_Disconnected(struct bt_conn *stpt_conn, uint8_t reason)
{
   struct bt_conn *stpt_oldHost = NULL;
   k_spinlock_key_t t_key;

	LOG_INF("Disconnected (reason 0x%x)", reason);

   // Release SETU's binding; a running transfer ends with eBS_DISCONNECTED
   gv_SETU_OnDisconnected(stpt_conn);

   // The pairing module releases its peer link, host authentication its host link
   gv_Pair_OnDisconnected(stpt_conn, reason);
   gv_HostAuth_OnHostDisconnected(stpt_conn);

   sv_CloseLink(stpt_conn);

   t_key = k_spin_lock(&sst_hostLock);
   // Check if the host left
   if (sstpt_hostConn == stpt_conn)
   {
      stpt_oldHost = sstpt_hostConn;
      sstpt_hostConn = NULL;
   }
   k_spin_unlock(&sst_hostLock, t_key);

   // Check if a host reference is to be dropped
   if (stpt_oldHost != NULL)
   {
      bt_conn_unref(stpt_oldHost);
   }
}

/**
 * @private       sv_Recycled
 * @brief         Callback for handling recycled connections: a connection
 *                object is free again, so advertising may resume.
 * @return        None.
 */
static void sv_Recycled(void)
{
   sv_StartAdvIfAllowed();
}

/**
 * @private       sv_SecurityChanged
 * @brief         Callback for handling security level changes: logged, and
 *                passed to the pairing module, which follows the encryption of
 *                a bonded peer link (a pairing run follows the SMP callbacks).
 * @param[in]     stpt_conn Connection handle.
 * @param[in]     e_level New security level.
 * @param[in]     e_err Security error.
 * @return        None.
 */
static void sv_SecurityChanged(struct bt_conn *stpt_conn, bt_security_t e_level,
   enum bt_security_err e_err)
{
   LOG_INF("Security level %d (err %d)", (int)e_level, (int)e_err);

   gv_Pair_OnSecurityChanged(stpt_conn, (uint8_t)e_level, (uint8_t)e_err);
   gv_HostAuth_OnSecurityChanged(stpt_conn, (uint8_t)e_level, (uint8_t)e_err);
}

/**
 * @private       sv_PHYUpdated
 * @brief         Callback to be called upon PHY updated.
 * @param[in]     stpt_conn Connection handle.
 * @param[in]     stpt_PHYInfo PHY information.
 * @return        None.
 */
static void sv_PHYUpdated(struct bt_conn *stpt_conn, struct bt_conn_le_phy_info *stpt_PHYInfo)
{
   LinkCtx_T *stpt_link = sstpt_FindLink(stpt_conn);

   // Check if the callback is for an open link
   if (stpt_link == NULL)
   {
      return;
   }

   LOG_INF("PHY updated TX:%d RX:%d", stpt_PHYInfo->tx_phy, stpt_PHYInfo->rx_phy);

   // Check if we have initiated the negotiation
   if (stpt_link->b_isSelfNegotiation)
   {
      // Check if we were waiting for PHY update to complete
      if ((stpt_link->e_step == eCNS_PHY) && (stpt_link->b_waitingForProcedure))
      {
         stpt_link->b_waitingForProcedure = false;
         stpt_link->e_step = eCNS_DLE;
      }

      LOG_INF("Running next negotiation step after PHY update...");
      k_work_schedule(&stpt_link->st_work, K_NO_WAIT);
   }
}

/**
 * @private       sv_DataLengthUpdated
 * @brief         Callback to be called upon data length updated.
 * @param[in]     stpt_conn Connection handle.
 * @param[in]     stpt_dataLenInfo Data length information.
 * @return        None.
 */
static void sv_DataLengthUpdated(struct bt_conn *stpt_conn,
   struct bt_conn_le_data_len_info *stpt_dataLenInfo)
{
   LinkCtx_T *stpt_link = sstpt_FindLink(stpt_conn);

   // Check if the callback is for an open link
   if (stpt_link == NULL)
   {
      return;
   }

   LOG_INF("Data length updated. Len TX/ RX: %d/ %d bytes, time TX/ RX: %d/ %d us",
      stpt_dataLenInfo->tx_max_len, stpt_dataLenInfo->rx_max_len,
      stpt_dataLenInfo->tx_max_time, stpt_dataLenInfo->rx_max_time);

   // Check if we have initiated the negotiation
   if (stpt_link->b_isSelfNegotiation)
   {
      // Check if we were waiting for DLE update to complete
      if ((stpt_link->e_step == eCNS_DLE) && (stpt_link->b_waitingForProcedure))
      {
         stpt_link->b_waitingForProcedure = false;
         stpt_link->e_step = eCNS_MTU;
      }

      LOG_INF("Running next negotiation step after DLE update...");
      k_work_schedule(&stpt_link->st_work, K_NO_WAIT);
   }
}

/**
 * @private       sv_ConnParamUpdated
 * @brief         Callback to be called upon connection parameters updated, whether
 *                requested by us or changed by the central.
 * @param[in]     stpt_conn Connection handle.
 * @param[in]     u16_interval Connection interval (units of 1.25 ms).
 * @param[in]     u16_latency Peripheral latency (connection events).
 * @param[in]     u16_timeout Supervision timeout (units of 10 ms).
 * @return        None.
 */
static void sv_ConnParamUpdated(struct bt_conn *stpt_conn, uint16_t u16_interval,
   uint16_t u16_latency, uint16_t u16_timeout)
{
   // Check if the callback is for an open link
   if (sstpt_FindLink(stpt_conn) == NULL)
   {
      return;
   }

   LOG_INF("Connection parameters updated: interval %u us, latency %u, timeout %u ms",
      BT_CONN_INTERVAL_TO_US(u16_interval), u16_latency, u16_timeout * 10U);
}

/******************************************************************************/
/*                                                                            */
/*                        PUBLIC FUNCTION DEFINITIONS                         */
/*                                                                            */
/******************************************************************************/
/**
 * @public        gv_BLEInitStartAdv
 * @brief         Initialize BLE module, load the stored bonds and start
 *                advertising.
 * @return        None.
 */
void gv_BLEInitStartAdv(void)
{
   int i_err;

   LOG_INF("Initializing Bluetooth...");

   // Enable Bluetooth
   i_err = bt_enable(NULL);

   // Check if Bluetooth initialization wasn't successful
	if (i_err)
   {
		LOG_ERR("Bluetooth init failed (err %x)", i_err);
      return;
	}

   LOG_INF("Bluetooth initialized");

   // Load the stack's settings (identity, bonds) after bt_enable(). The
   // settings subsystem itself was initialised by the provisioning start-up.
   i_err = settings_load();

   // Check if the settings could not be loaded (bonds are then unavailable)
   if (i_err)
   {
      LOG_ERR("Settings load failed (err %d)", i_err);
   }

   // The pairing module learns this device's address and restores its bond;
   // host authentication keeps its host record only with its bond
   gv_HostAuth_OnBtReady();
   gv_Pair_OnBtReady();

   sb_btReady = true;
   LOG_INF("Starting BLE advertising...");
   sv_StartAdvIfAllowed();
}

/**
 * @public        gstpt_BLE_GetHostConn
 * @brief         Host link. Any thread.
 * @return        A new reference to the host link (the caller drops it with
 *                bt_conn_unref()), or NULL if no host is connected.
 */
struct bt_conn *gstpt_BLE_GetHostConn(void)
{
   struct bt_conn *stpt_host = NULL;
   k_spinlock_key_t t_key;

   t_key = k_spin_lock(&sst_hostLock);
   // Check if a host is connected
   if (sstpt_hostConn != NULL)
   {
      stpt_host = bt_conn_ref(sstpt_hostConn);
   }
   k_spin_unlock(&sst_hostLock, t_key);

   return stpt_host;
}

/**
 * @public        gv_BLE_RefreshAdv
 * @brief         Re-evaluate advertising after a provisioning or pairing
 *                change: undirected advertising restarts with data for the new
 *                provisioning state, or stays off (host connected and no
 *                bonded central awaited, or _PAIR uses the advertiser). Any
 *                thread.
 * @return        None.
 */
void gv_BLE_RefreshAdv(void)
{
   // Check if the stack runs and the advertiser is not _PAIR's
   if (!sb_btReady || gb_Pair_IsAdvertising())
   {
      return;
   }

   (void)bt_le_adv_stop();
   sv_StartAdvIfAllowed();
}

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shviam Chudasama [SC]
 */
