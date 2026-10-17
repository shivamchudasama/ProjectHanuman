/**
 * @file          Pair.c
 * @brief         Source file containing certificate-based OOB pairing between two
 *                provisioned devices (CBAP phase 2, AN1396 §4.2). A host (the PC
 *                GUI) tells each device its role and its peer's address over the
 *                Pairing service (PairSvc.c), then:
 *
 *                  1. the peripheral advertises directed to the central, the
 *                     central scans for the peer and connects (open link);
 *                  2. both move their SETU Server and Client to the peer
 *                     link, the router admits only the pairing range there, and
 *                     each sends its device certificate (0x30);
 *                  3. each verifies the peer's certificate against the CA it was
 *                     provisioned with (ge_VerifyRemoteDeviceCertificate()),
 *                     which also gives the peer's public key;
 *                  4. each makes fresh LE Secure Connections OOB data (r, c),
 *                     signs it with its device key (PairOob.c) and sends it
 *                     (0x31); the peer verifies the signature;
 *                  5. the central starts pairing (level 4); SMP asks both for
 *                     OOB data, which each answers once the peer's is verified;
 *                  6. once bonded, the central writes SECURED on the peer, which
 *                     only a level-4 link may write; the peripheral lights its
 *                     LED (DK_LED1, LED0 on the board). The role and the peer
 *                     address are saved in settings with the bond.
 *
 *                A bonded pair reconnects by itself, after a reset or a lost
 *                link: the peripheral advertises (undirected, also while a host
 *                is connected), the central scans for the peer and connects,
 *                then encrypts with the stored keys. Once the link is at level
 *                4 again, both blink their LED for as long as it stays up. A
 *                link that does not reach level 4 is dropped and retried.
 *
 *                Every step is reported to the host in STATUS. Callbacks (BT
 *                stack, SETU engine, GATT writes) only check, copy and post
 *                an event; the pairing thread does the work, as in Prov.c.
 *                Wire contract: _DOC/Pairing/PROTOCOL.md.
 *
 *                The flow follows the BG22/BG24 reference (PairingFSM.c in
 *                Sample Code Device Cert Verification): host-chosen roles,
 *                directed advertising, signed r || c, central-initiated
 *                security. Its transport (GATT reads of certificate blocks and
 *                of an OOB characteristic) is replaced by SETU pushes,
 *                which removes its race on OOB data read before it was written.
 * @date          06/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include "Pair.h"
#include <errno.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/settings/settings.h>
#include <dk_buttons_and_leds.h>
#include <psa/crypto.h>
#include "PairOob.h"
#include "PairSvc.h"
#include "Prov.h"
#include "SETU.h"
#include "SETURouter.h"
#include "CSR_Generator.h"
#include "DeviceCert.h"
#include "DeviceCert_Verify.h"
#include "AppLog.h"

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
#ifndef CONFIG_PAIR_TIMEOUT_MS
#define CONFIG_PAIR_TIMEOUT_MS               (60000)
#endif // CONFIG_PAIR_TIMEOUT_MS

#ifndef CONFIG_PAIR_CONNECT_TIMEOUT_MS
#define CONFIG_PAIR_CONNECT_TIMEOUT_MS       (30000)
#endif // CONFIG_PAIR_CONNECT_TIMEOUT_MS

/**
 * @def           PAIR_EVENT_QUEUE_LEN
 * @brief         Depth of the event queue to the pairing thread.
 */
#define PAIR_EVENT_QUEUE_LEN                 (12U)

/**
 * @def           PAIR_STACK_SIZE
 * @brief         Stack size of the pairing thread: mbedTLS X.509 parsing and
 *                ECDSA verification of the peer certificate run on it, as on
 *                the provisioning thread. Its deepest static path (X.509 parse
 *                -> key import -> secure storage) takes about 6.3 KiB (audit F4).
 */
#define PAIR_STACK_SIZE                      (10240)

/**
 * @def           PAIR_PRIORITY
 * @brief         Priority of the pairing thread, below the SETU engine.
 */
#define PAIR_PRIORITY                        (10)

/**
 * @def           PAIR_CONN_INTERVAL
 * @brief         Connection interval the central asks for (units of 1.25 ms):
 *                15 ms, as the host link.
 */
#define PAIR_CONN_INTERVAL                   (12U)

/**
 * @def           PAIR_CONN_TIMEOUT
 * @brief         Supervision timeout of the peer link (units of 10 ms): 4 s.
 */
#define PAIR_CONN_TIMEOUT                    (400U)

/**
 * @def           PAIR_SECURED_VALUE
 * @brief         Byte the central writes to SECURED.
 */
#define PAIR_SECURED_VALUE                   (0x01U)

/**
 * @def           PAIR_LED
 * @brief         DK LED (LED0 on the board): steady on the peripheral when the
 *                paired central has written SECURED; blinking on both devices
 *                while a bonded reconnection is up at level 4.
 */
#define PAIR_LED                             (DK_LED1)

/**
 * @def           PAIR_LED_BLINK_MS
 * @brief         Half period of the LED blink.
 */
#define PAIR_LED_BLINK_MS                    (500)

/**
 * @def           PAIR_RECONNECT_DELAY_MS
 * @brief         Central: wait before scanning for the bonded peer again after
 *                the link dropped or an attempt failed.
 */
#define PAIR_RECONNECT_DELAY_MS              (1000)

/**
 * @def           PAIR_RECONNECT_SECURE_MS
 * @brief         A bonded peer link must reach level 4 within this time, or it
 *                is dropped.
 */
#define PAIR_RECONNECT_SECURE_MS             (10000)

/**
 * @def           PAIR_SETTINGS_SUBTREE
 * @brief         Settings subtree of this module.
 */
#define PAIR_SETTINGS_SUBTREE                "pair"

/**
 * @def           PAIR_SETTINGS_BOND_KEY
 * @brief         Settings key (in PAIR_SETTINGS_SUBTREE) of the bond record.
 */
#define PAIR_SETTINGS_BOND_KEY               "peer"

/**
 * @def           PAIR_BOND_RECORD_LEN
 * @brief         Bond record in settings: [u8 role][7 B peer address].
 */
#define PAIR_BOND_RECORD_LEN                 (1U + PAIR_ADDR_LEN)

/**
 * @def           PAIR_RX_CERT
 * @brief         st_rxHave bit: the peer certificate is in su8ar_rxCert.
 */
#define PAIR_RX_CERT                         (0)

/**
 * @def           PAIR_RX_OOB
 * @brief         st_rxHave bit: the peer OOB frame is in su8ar_rxOob.
 */
#define PAIR_RX_OOB                          (1)

/**
 * @def           PAIR_ADDR_BYTES
 * @brief         An address as its PAIR_ADDR_LEN wire bytes [type][6 B LE]:
 *                bt_addr_le_t has exactly that layout (checked below).
 */
#define PAIR_ADDR_BYTES(stpt_addr)           ((const uint8_t *)(stpt_addr))

BUILD_ASSERT(sizeof(bt_addr_le_t) == PAIR_ADDR_LEN, "bt_addr_le_t is not [type][6 B]");

/******************************************************************************/
/*                                                                            */
/*                                   ENUMS                                    */
/*                                                                            */
/******************************************************************************/
/**
 * @enum          PairEventType_E
 * @brief         Events posted to the pairing thread.
 */
typedef enum
{
   ePEV_BT_READY = 0,                        /**< Stack and bonds loaded              */
   ePEV_START,                               /**< START from the host                 */
   ePEV_CANCEL,                              /**< CANCEL from the host                */
   ePEV_UNPAIR,                              /**< UNPAIR from the host                */
   ePEV_FORGET,                              /**< Provisioning wipe: drop every bond  */
   ePEV_SCAN_MATCH,                          /**< Central: peer advertising seen      */
   ePEV_CONNECTED,                           /**< Peer link up (i32 0) or failed      */
   ePEV_DISCONNECTED,                        /**< Peer link down (i32 = reason)       */
   ePEV_CLI_READY,                           /**< Client attach result (i32)          */
   ePEV_TX_DONE,                             /**< Own transfer ended (u8_status)      */
   ePEV_RX_DONE,                             /**< Peer transfer ended (u8_status)     */
   ePEV_OOB_REQUEST,                         /**< SMP wants OOB data (i32 = config)   */
   ePEV_PAIRING_DONE,                        /**< SMP done (i32 = level, u8 = bonded) */
   ePEV_PAIRING_FAILED,                      /**< SMP failed (i32 = reason)           */
   ePEV_SECURED_RX,                          /**< Peripheral: peer wrote SECURED      */
   ePEV_SECURED_TX,                          /**< Central: SECURED written (i32 err)  */
   ePEV_TIMEOUT,                             /**< Run timer (i32 = run id)            */
   ePEV_RECONNECT,                           /**< Central: look for the bonded peer   */
   ePEV_RECONNECTED,                         /**< Bonded peer link up (i32 0) or not  */
   ePEV_SECURITY,                            /**< Peer link level (i32), u8 = error   */
   ePEV_SECURE_TIMEOUT,                      /**< Bonded link not at level 4 in time  */
} PairEventType_E;

/**
 * @enum          PairLed_E
 * @brief         What PAIR_LED shows.
 */
typedef enum
{
   ePLD_OFF = 0,                             /**< No proven link                       */
   ePLD_ON,                                  /**< Peripheral: pairing proven (SECURED) */
   ePLD_BLINK,                               /**< Bonded reconnection up at level 4    */
} PairLed_E;

/******************************************************************************/
/*                                                                            */
/*                                 STRUCTURES                                 */
/*                                                                            */
/******************************************************************************/
/**
 * @struct        PairEvent_T
 * @brief         One queued event.
 */
typedef struct
{
   uint8_t u8_type;                          /**< PairEventType_E                     */
   uint8_t u8_appType;                       /**< appType of a SETU event         */
   uint8_t u8_status;                        /**< SETUStatus_E, or bonded              */
   uint8_t u8_role;                          /**< START: PairRole_E                   */
   int32_t i32_value;                        /**< Error, reason, level, config or id  */
   bt_addr_le_t st_addr;                     /**< START: peer address                 */
   struct bt_conn *stpt_conn;                /**< DISCONNECTED: the link (its ref)    */
} PairEvent_T;

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
static void sv_Post(const PairEvent_T *stpt_event);
static void sv_PostSimple(uint8_t u8_type, int32_t i32_value);
static void sv_SetLed(PairLed_E e_mode);
static void sv_SaveBond(void);
static void sv_ForgetBond(void);
static void sv_ScheduleReconnect(void);
static void sv_StopReconnect(void);
static void sv_ReconnectStart(void);
static void sv_HandleReconnected(int32_t i32_err);
static void sv_HandleSecurity(int32_t i32_level, uint8_t u8_err);
static void sv_HandleSecureTimeout(void);
static void sv_LedWork(struct k_work *stpt_work);
static void sv_ReconnectWork(struct k_work *stpt_work);
static void sv_SecureTimeout(struct k_work *stpt_work);
static int si_SettingsSet(const char *cpt_key, size_t t_len, settings_read_cb fpt_read,
   void *vpt_arg);
static bool sb_IsRunningState(PairState_E e_state);
static struct bt_conn *sstpt_PeerConnRef(void);
static void sv_Publish(void);
static void sv_SetState(PairState_E e_state);
static void sv_ResetRun(void);
static void sv_StopRadio(void);
static void sv_ReturnRoles(void);
static void sv_EndRun(void);
static void sv_Fail(PairError_E e_error, int32_t i32_detail);
static void sv_Succeed(void);
static void sv_DropPeerLink(void);
static void sv_ReleaseOldLink(void);
static void sv_ForgetPeer(bool b_allBonds);
static void sv_TrySendOob(void);
static void sv_TryVerifyOob(void);
static void sv_TryAnswerOob(void);
static void sv_WriteSecured(void);
static void sv_HandleBtReady(void);
static void sv_HandleStart(const PairEvent_T *stpt_event);
static void sv_HandleScanMatch(void);
static void sv_HandleConnected(int32_t i32_err);
static void sv_HandleDisconnected(struct bt_conn *stpt_conn, int32_t i32_reason);
static void sv_HandleCliReady(int32_t i32_status);
static void sv_HandleTxDone(uint8_t u8_appType, uint8_t u8_status);
static void sv_HandleRxDone(uint8_t u8_appType, uint8_t u8_status);
static void sv_HandleCertReceived(void);
static void sv_HandleOobRequest(int32_t i32_config);
static void sv_HandlePairingDone(int32_t i32_level, bool b_bonded);
static void sv_HandleEvent(const PairEvent_T *stpt_event);
static void sv_PairThread(void *vpt_p1, void *vpt_p2, void *vpt_p3);
static void sv_ConnectTimeout(struct k_work *stpt_work);
static void sv_RunTimeout(struct k_work *stpt_work);
static void sv_ScanCb(const bt_addr_le_t *stpt_addr, int8_t i8_rssi, uint8_t u8_advType,
   struct net_buf_simple *stpt_ad);
static int si_PairRxStart(uint8_t u8_appType, uint32_t u32_totalLen);
static int si_PairRxData(uint8_t u8_appType, uint32_t u32_offset,
   const uint8_t *u8pt_data, uint16_t u16_len);
static void sv_PairRxDone(uint8_t u8_appType, SETUStatus_E e_status, uint32_t u32_totalLen);
static void sv_PairTxDone(uint8_t u8_appType, SETUStatus_E e_status);
static void sv_PairCliReady(struct bt_conn *stpt_conn, int i_status);
static enum bt_security_err se_PairingAccept(struct bt_conn *stpt_conn,
   const struct bt_conn_pairing_feat *const stpt_feat);
static void sv_OobDataRequest(struct bt_conn *stpt_conn, struct bt_conn_oob_info *stpt_info);
static void sv_PairingComplete(struct bt_conn *stpt_conn, bool b_bonded);
static void sv_PairingFailed(struct bt_conn *stpt_conn, enum bt_security_err e_reason);
static uint8_t su8_SecuredDiscovered(struct bt_conn *stpt_conn,
   const struct bt_gatt_attr *stpt_attr, struct bt_gatt_discover_params *stpt_params);
static void sv_SecuredWritten(struct bt_conn *stpt_conn, uint8_t u8_err,
   struct bt_gatt_write_params *stpt_params);
static void sv_BondFound(const struct bt_bond_info *stpt_info, void *vpt_user);

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
 * @var           st_state
 * @brief         PairState_E. Written by the pairing thread; read by callbacks.
 */
static atomic_t st_state = ATOMIC_INIT(ePST_IDLE);

/**
 * @var           st_dirAdv
 * @brief         Set while this module uses the advertiser (directed to the
 *                peer); ConnectionHandling.c then starts no advertising.
 */
static atomic_t st_dirAdv = ATOMIC_INIT(0);

/**
 * @var           st_scanMatched
 * @brief         Set by the scan callback once the peer is seen, so only one
 *                SCAN_MATCH is posted per scan.
 */
static atomic_t st_scanMatched = ATOMIC_INIT(0);

/**
 * @var           st_peerConn
 * @brief         Peer link (referenced; the reference is dropped when it goes
 *                down). Set in BT context by gb_Pair_ClaimConn().
 */
static atomic_ptr_t st_peerConn = ATOMIC_PTR_INIT(NULL);

/**
 * @var           st_rxType
 * @brief         appType of the peer transfer being received, 0 if none.
 */
static atomic_t st_rxType = ATOMIC_INIT(0);

/**
 * @var           st_rxHave
 * @brief         PAIR_RX_CERT / PAIR_RX_OOB: what the peer has delivered in
 *                this run (each is accepted once).
 */
static atomic_t st_rxHave = ATOMIC_INIT(0);

/**
 * @var           se_error
 * @brief         Error of the last failed run. Pairing thread.
 */
static PairError_E se_error = ePER_NONE;

/**
 * @var           su8_detail
 * @brief         Code that goes with se_error. Pairing thread.
 */
static uint8_t su8_detail = 0U;

/**
 * @var           se_role
 * @brief         Role of the current or last run. Pairing thread.
 */
static PairRole_E se_role = ePRL_NONE;

/**
 * @var           sst_ownAddr
 * @brief         This device's identity address.
 */
static bt_addr_le_t sst_ownAddr;

/**
 * @var           sst_peerAddr
 * @brief         Peer identity address of the current run or of the bond. Set
 *                by the pairing thread before the state leaves IDLE/FAILED.
 */
static bt_addr_le_t sst_peerAddr;

/**
 * @var           su32_runId
 * @brief         Number of the current run; a timer of an older run is ignored.
 */
static uint32_t su32_runId = 0U;

/**
 * @var           sstpt_createConn
 * @brief         Central: the connection object bt_conn_le_create() returned,
 *                until the link is up or the attempt is abandoned.
 */
static struct bt_conn *sstpt_createConn = NULL;

/**
 * @var           sb_scanning
 * @brief         Central: a scan for the peer runs. Pairing thread.
 */
static bool sb_scanning = false;

/**
 * @var           sb_runHasLink
 * @brief         The current run's peer link came up (a link of an earlier
 *                run going down later is not this run's loss).
 */
static bool sb_runHasLink = false;

/**
 * @var           sb_ownCertSent
 * @brief         The peer has acknowledged this device's certificate.
 */
static bool sb_ownCertSent = false;

/**
 * @var           sb_peerCertOk
 * @brief         The peer certificate verified; st_peerKey holds its key.
 */
static bool sb_peerCertOk = false;

/**
 * @var           sb_oobTxStarted
 * @brief         This device's OOB frame transfer has started.
 */
static bool sb_oobTxStarted = false;

/**
 * @var           sb_peerOobOk
 * @brief         The peer OOB frame verified; sst_remoteOob holds it.
 */
static bool sb_peerOobOk = false;

/**
 * @var           sb_oobRequested
 * @brief         SMP has asked for OOB data and is waiting for the answer.
 */
static bool sb_oobRequested = false;

/**
 * @var           sb_oobAnswered
 * @brief         bt_le_oob_set_sc_data() has been called in this run.
 */
static bool sb_oobAnswered = false;

/**
 * @var           sb_securedSent
 * @brief         Central: SECURED discovery or write started.
 */
static bool sb_securedSent = false;

/**
 * @var           st_bondRole
 * @brief         PairRole_E this device has towards its bonded peer
 *                (sst_peerAddr), whom it reconnects to; ePRL_NONE if there is
 *                none to reconnect to. Written by the pairing thread; read by
 *                callbacks.
 */
static atomic_t st_bondRole = ATOMIC_INIT(ePRL_NONE);

/**
 * @var           sb_bondLink
 * @brief         The peer link is a bonded reconnection (not a pairing run's).
 *                Pairing thread.
 */
static bool sb_bondLink = false;

/**
 * @var           sb_rolesMoved
 * @brief         SETU is on the peer link (a run's link came up) and not
 *                returned to the host yet. Pairing thread.
 */
static bool sb_rolesMoved = false;

/**
 * @var           sb_bondSecured
 * @brief         The bonded reconnection reached level 4. Pairing thread.
 */
static bool sb_bondSecured = false;

/**
 * @var           su8ar_savedBond
 * @brief         Bond record read from settings at start-up
 *                ([u8 role][7 B peer address]).
 */
static uint8_t su8ar_savedBond[PAIR_BOND_RECORD_LEN];

/**
 * @var           sb_savedBondValid
 * @brief         su8ar_savedBond holds a valid record.
 */
static bool sb_savedBondValid = false;

/**
 * @var           st_ledMode
 * @brief         PairLed_E to show; applied by sv_LedWork(), the only writer of
 *                the LED.
 */
static atomic_t st_ledMode = ATOMIC_INIT(ePLD_OFF);

/**
 * @var           sb_ledLit
 * @brief         The LED is on. System work queue.
 */
static bool sb_ledLit = false;

/**
 * @var           st_peerKey
 * @brief         Peer public key (volatile PSA key) from its certificate, 0 if
 *                none.
 */
static psa_key_id_t st_peerKey = 0U;

/**
 * @var           su8ar_rxCert
 * @brief         Peer device certificate being received or received.
 */
static uint8_t su8ar_rxCert[DEVICE_CERT_MAX_DER_LEN];

/**
 * @var           su32_rxCertLen
 * @brief         Length of the peer certificate announced at START.
 */
static uint32_t su32_rxCertLen = 0U;

/**
 * @var           su8ar_rxOob
 * @brief         Peer OOB frame [r][c][signature].
 */
static uint8_t su8ar_rxOob[PAIR_OOB_FRAME_LEN];

/**
 * @var           su8ar_txOob
 * @brief         This device's OOB frame; unchanged until its transfer ends, as
 *                SETU requires.
 */
static uint8_t su8ar_txOob[PAIR_OOB_FRAME_LEN];

/**
 * @var           sst_localOob
 * @brief         This device's OOB data for this run (bt_le_oob_get_local()).
 *                The stack keeps a pointer to le_sc_data until pairing ends.
 */
static struct bt_le_oob sst_localOob;

/**
 * @var           sst_remoteOob
 * @brief         The peer's verified OOB data. The stack keeps a pointer to it
 *                until pairing ends.
 */
static struct bt_le_oob_sc_data sst_remoteOob;

/**
 * @var           sst_securedUuid
 * @brief         SECURED UUID for the central's discovery (static: the stack
 *                keeps the pointer).
 */
static const struct bt_uuid_128 sst_securedUuid = BT_UUID_INIT_128(PAIR_UUID_VAL(0x0003));

/**
 * @var           sst_discoverParams
 * @brief         Central: discovery of SECURED on the peer.
 */
static struct bt_gatt_discover_params sst_discoverParams;

/**
 * @var           sst_writeParams
 * @brief         Central: the SECURED write.
 */
static struct bt_gatt_write_params sst_writeParams;

/**
 * @var           scu8_securedValue
 * @brief         Value written to SECURED.
 */
static const uint8_t scu8_securedValue = PAIR_SECURED_VALUE;

/**
 * @var           sst_statusLock
 * @brief         Guards the STATUS fields read by gv_Pair_GetStatus() in BT
 *                context.
 */
K_MUTEX_DEFINE(sst_statusLock);

/**
 * @var           sst_authCb
 * @brief         SMP callbacks: pairing is allowed only on the peer link during
 *                a run, and only with OOB data.
 */
static struct bt_conn_auth_cb sst_authCb = {
   .pairing_accept = se_PairingAccept,
   .oob_data_request = sv_OobDataRequest,
};

/**
 * @var           sst_authInfoCb
 * @brief         SMP result callbacks.
 */
static struct bt_conn_auth_info_cb sst_authInfoCb = {
   .pairing_complete = sv_PairingComplete,
   .pairing_failed = sv_PairingFailed,
};

/**
 * @var           sst_connectTimeout
 * @brief         Run timer: the peer link must be up in
 *                CONFIG_PAIR_CONNECT_TIMEOUT_MS.
 */
K_WORK_DELAYABLE_DEFINE(sst_connectTimeout, sv_ConnectTimeout);

/**
 * @var           sst_runTimeout
 * @brief         Run timer: the whole pairing must end in CONFIG_PAIR_TIMEOUT_MS.
 */
K_WORK_DELAYABLE_DEFINE(sst_runTimeout, sv_RunTimeout);

/**
 * @var           sst_reconnectWork
 * @brief         Central: look for the bonded peer again after a delay.
 */
K_WORK_DELAYABLE_DEFINE(sst_reconnectWork, sv_ReconnectWork);

/**
 * @var           sst_secureTimeout
 * @brief         A bonded peer link must reach level 4 in
 *                PAIR_RECONNECT_SECURE_MS.
 */
K_WORK_DELAYABLE_DEFINE(sst_secureTimeout, sv_SecureTimeout);

/**
 * @var           sst_ledWork
 * @brief         Applies st_ledMode to the LED, and blinks it.
 */
K_WORK_DELAYABLE_DEFINE(sst_ledWork, sv_LedWork);

/**
 * @var           settings_handler_pair
 * @brief         Loads the bond record (settings_load(), before BT_READY).
 */
SETTINGS_STATIC_HANDLER_DEFINE(pair, PAIR_SETTINGS_SUBTREE, NULL, si_SettingsSet, NULL, NULL);

/**
 * @var           sst_pairMsgq
 * @brief         Events to the pairing thread.
 */
K_MSGQ_DEFINE(sst_pairMsgq, sizeof(PairEvent_T), PAIR_EVENT_QUEUE_LEN, 4);

/**
 * @var           sst_pairThread
 * @brief         Pairing thread.
 */
K_THREAD_DEFINE(sst_pairThread, PAIR_STACK_SIZE, sv_PairThread, NULL, NULL, NULL,
   PAIR_PRIORITY, 0, 0);

/******************************************************************************/
/*                                                                            */
/*                              EXTERN FUNCTIONS                              */
/*                                                                            */
/******************************************************************************/
/**
 * @extern        gstpt_BLE_GetHostConn
 * @brief         Host link, owned by ConnectionHandling.c: a new reference, or
 *                NULL if there is no host.
 */
extern struct bt_conn *gstpt_BLE_GetHostConn(void);

/**
 * @extern        gv_BLE_RefreshAdv
 * @brief         Re-evaluate advertising (ConnectionHandling.c).
 */
extern void gv_BLE_RefreshAdv(void);

/******************************************************************************/
/*                                                                            */
/*                        PRIVATE FUNCTION DEFINITIONS                        */
/*                                                                            */
/******************************************************************************/
/**
 * @private       sv_Post
 * @brief         Queue an event for the pairing thread (never blocks).
 * @param[in]     stpt_event Event (copied).
 * @return        None.
 */
static void sv_Post(const PairEvent_T *stpt_event)
{
   // Check if the queue is full
   if (k_msgq_put(&sst_pairMsgq, stpt_event, K_NO_WAIT) != 0)
   {
      APP_LOG_WRN("event %u dropped: queue full", stpt_event->u8_type);
   }
}

/**
 * @private       sv_PostSimple
 * @brief         Queue an event that carries one value.
 * @param[in]     u8_type PairEventType_E.
 * @param[in]     i32_value Value.
 * @return        None.
 */
static void sv_PostSimple(uint8_t u8_type, int32_t i32_value)
{
   PairEvent_T st_event;

   (void)memset(&st_event, 0, sizeof(st_event));
   st_event.u8_type = u8_type;
   st_event.i32_value = i32_value;
   sv_Post(&st_event);
}

/**
 * @private       sv_SetLed
 * @brief         Show something else on the LED (sv_LedWork() applies it).
 * @param[in]     e_mode PairLed_E.
 * @return        None.
 */
static void sv_SetLed(PairLed_E e_mode)
{
   (void)atomic_set(&st_ledMode, (atomic_val_t)e_mode);
   (void)k_work_reschedule(&sst_ledWork, K_NO_WAIT);
}

/**
 * @private       sv_SaveBond
 * @brief         Paired: remember the role and the peer, in RAM for the
 *                reconnection and in settings for the next start-up.
 * @return        None.
 */
static void sv_SaveBond(void)
{
   uint8_t u8ar_record[PAIR_BOND_RECORD_LEN];
   int i_ret;

   u8ar_record[0] = (uint8_t)se_role;
   (void)memcpy(&u8ar_record[1], PAIR_ADDR_BYTES(&sst_peerAddr), PAIR_ADDR_LEN);
   (void)atomic_set(&st_bondRole, (atomic_val_t)se_role);

   i_ret = settings_save_one(PAIR_SETTINGS_SUBTREE "/" PAIR_SETTINGS_BOND_KEY, u8ar_record,
      sizeof(u8ar_record));

   // Check if the record was stored (the bond itself is the stack's)
   if (i_ret != 0)
   {
      APP_LOG_WRN("bond record not saved (%d): no reconnection after a reset", i_ret);
   }
}

/**
 * @private       sv_ForgetBond
 * @brief         No bonded peer to reconnect to any more (START, UNPAIR, wipe).
 * @return        None.
 */
static void sv_ForgetBond(void)
{
   (void)atomic_set(&st_bondRole, ePRL_NONE);
   sb_savedBondValid = false;
   (void)settings_delete(PAIR_SETTINGS_SUBTREE "/" PAIR_SETTINGS_BOND_KEY);
}

/**
 * @private       sv_ScheduleReconnect
 * @brief         Central: look for the bonded peer again in
 *                PAIR_RECONNECT_DELAY_MS.
 * @return        None.
 */
static void sv_ScheduleReconnect(void)
{
   // Check if this device is the one that connects
   if (atomic_get(&st_bondRole) == ePRL_CENTRAL)
   {
      (void)k_work_schedule(&sst_reconnectWork, K_MSEC(PAIR_RECONNECT_DELAY_MS));
   }
}

/**
 * @private       sv_StopReconnect
 * @brief         Stop reconnecting: the timers, and the central's scan or
 *                connection attempt. Outside a run.
 * @return        None.
 */
static void sv_StopReconnect(void)
{
   (void)k_work_cancel_delayable(&sst_reconnectWork);
   (void)k_work_cancel_delayable(&sst_secureTimeout);
   sv_StopRadio();
}

/**
 * @private       sv_ReconnectStart
 * @brief         Central: scan for the bonded peer, unless it is connected or
 *                being reached already.
 * @return        None.
 */
static void sv_ReconnectStart(void)
{
   int i_ret;

   // Check if this central has a bonded peer to reach, and nothing under way
   if ((atomic_get(&st_state) != ePST_PAIRED) || (atomic_get(&st_bondRole) != ePRL_CENTRAL) ||
      (sstpt_PeerConnRef() != NULL) || sb_scanning || (sstpt_createConn != NULL))
   {
      return;
   }

   (void)atomic_set(&st_scanMatched, 0);
   i_ret = bt_le_scan_start(BT_LE_SCAN_PASSIVE, sv_ScanCb);

   // Check if the scan runs
   if (i_ret != 0)
   {
      APP_LOG_WRN("scan for the bonded peer not started (%d)", i_ret);
      sv_ScheduleReconnect();
      return;
   }

   sb_scanning = true;
   APP_LOG_INF("looking for the bonded peer");
}

/**
 * @private       sb_IsRunningState
 * @brief         Whether a state belongs to a run in progress.
 * @param[in]     e_state State.
 * @return        true from ARMED to PAIRING.
 */
static bool sb_IsRunningState(PairState_E e_state)
{
   return (e_state >= ePST_ARMED) && (e_state <= ePST_PAIRING);
}

/**
 * @private       sstpt_PeerConnRef
 * @brief         Peer link without a new reference (pairing thread: the
 *                reference it holds is dropped only by this thread).
 * @return        The peer link, or NULL.
 */
static struct bt_conn *sstpt_PeerConnRef(void)
{
   return (struct bt_conn *)atomic_ptr_get(&st_peerConn);
}

/**
 * @private       sv_Publish
 * @brief         Notify STATUS to the host (best effort).
 * @return        None.
 */
static void sv_Publish(void)
{
   uint8_t u8ar_status[PAIR_STATUS_LEN];
   struct bt_conn *stpt_host = gstpt_BLE_GetHostConn();

   gv_Pair_GetStatus(u8ar_status);

   // Check if a host is connected to hear it
   if (stpt_host != NULL)
   {
      (void)gi_PairSvc_NotifyStatus(stpt_host, u8ar_status, sizeof(u8ar_status));
      bt_conn_unref(stpt_host);
   }
}

/**
 * @private       sv_SetState
 * @brief         Enter a state and tell the host.
 * @param[in]     e_state New state.
 * @return        None.
 */
static void sv_SetState(PairState_E e_state)
{
   (void)k_mutex_lock(&sst_statusLock, K_FOREVER);
   (void)atomic_set(&st_state, (atomic_val_t)e_state);
   k_mutex_unlock(&sst_statusLock);

   APP_LOG_INF("state %d", (int)e_state);
   sv_Publish();
}

/**
 * @private       sv_ResetRun
 * @brief         Forget everything a run accumulated (not the addresses).
 * @return        None.
 */
static void sv_ResetRun(void)
{
   sb_bondLink = false;
   sb_bondSecured = false;
   sb_runHasLink = false;
   sb_ownCertSent = false;
   sb_peerCertOk = false;
   sb_oobTxStarted = false;
   sb_peerOobOk = false;
   sb_oobRequested = false;
   sb_oobAnswered = false;
   sb_securedSent = false;
   su32_rxCertLen = 0U;
   (void)atomic_set(&st_rxType, 0);
   (void)atomic_set(&st_rxHave, 0);
   (void)memset(&sst_localOob, 0, sizeof(sst_localOob));
   (void)memset(&sst_remoteOob, 0, sizeof(sst_remoteOob));

   // Check if a peer key is left over
   if (st_peerKey != 0U)
   {
      (void)psa_destroy_key(st_peerKey);
      st_peerKey = 0U;
   }
}

/**
 * @private       sv_StopRadio
 * @brief         Stop what a run started on the radio and has not finished:
 *                the scan, the directed advertising, a pending connection.
 * @return        None.
 */
static void sv_StopRadio(void)
{
   // Check if the central still scans for the peer
   if (sb_scanning)
   {
      (void)bt_le_scan_stop();
      sb_scanning = false;
   }

   // Check if the peripheral still advertises to the peer
   if (atomic_get(&st_dirAdv) != 0)
   {
      (void)bt_le_adv_stop();
      (void)atomic_set(&st_dirAdv, 0);
   }

   // Check if the central's connection attempt is still pending
   if (sstpt_createConn != NULL)
   {
      (void)bt_conn_disconnect(sstpt_createConn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
      bt_conn_unref(sstpt_createConn);
      sstpt_createConn = NULL;
   }
}

/**
 * @private       sv_ReturnRoles
 * @brief         Give SETU back to the host link: no appType filter, the
 *                Server bound to the host link (or released), the Client
 *                released. Called when no peer transfer runs any more.
 * @return        None.
 */
static void sv_ReturnRoles(void)
{
   struct bt_conn *stpt_host = gstpt_BLE_GetHostConn();
   int i_ret;

   sb_rolesMoved = false;
   gv_SETURouter_ClearFilter();

   i_ret = gi_SETUS_Rebind(stpt_host);

   // Check if the Server could not move (a peer transfer still ends)
   if (i_ret != 0)
   {
      APP_LOG_WRN("Server not returned to the host (%d)", i_ret);
   }

   // Check if the Client is on the peer link
   (void)gi_SETUC_Detach();

   // Check if a host reference was taken
   if (stpt_host != NULL)
   {
      bt_conn_unref(stpt_host);
   }
}

/**
 * @private       sv_EndRun
 * @brief         Clean up after a run, successful or not: timers, radio, OOB
 *                flag, peer key, advertising.
 * @return        None.
 */
static void sv_EndRun(void)
{
   (void)k_work_cancel_delayable(&sst_connectTimeout);
   (void)k_work_cancel_delayable(&sst_runTimeout);
   sv_StopRadio();
   bt_le_oob_set_sc_flag(false);

   // Check if the peer key is still imported
   if (st_peerKey != 0U)
   {
      (void)psa_destroy_key(st_peerKey);
      st_peerKey = 0U;
   }

   // The advertiser is free again: let ConnectionHandling.c decide
   gv_BLE_RefreshAdv();
}

/**
 * @private       sv_DropPeerLink
 * @brief         Disconnect the peer link if it is up. Its SETU bindings
 *                (if SETU is on it) are released by the disconnect;
 *                sv_HandleDisconnected() then returns the roles to the host.
 *                SETU on the host link (a bonded link) is left alone.
 * @return        None.
 */
static void sv_DropPeerLink(void)
{
   struct bt_conn *stpt_peer = sstpt_PeerConnRef();

   // Check if the peer link is up
   if (stpt_peer != NULL)
   {
      // Check if SETU serves the peer link (its transfers end now)
      if (sb_rolesMoved)
      {
         gv_SETUS_AbortRx();
         gv_SETUC_AbortTx();
      }
      (void)bt_conn_disconnect(stpt_peer, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
   }
   else if (sb_rolesMoved)
   {
      sv_ReturnRoles();
   }
}

/**
 * @private       sv_ReleaseOldLink
 * @brief         Disconnect the link of an earlier pairing and release it now.
 * @return        None.
 */
static void sv_ReleaseOldLink(void)
{
   struct bt_conn *stpt_old = (struct bt_conn *)atomic_ptr_set(&st_peerConn, NULL);

   // Check if an earlier link is still up
   if (stpt_old != NULL)
   {
      (void)bt_conn_disconnect(stpt_old, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
      bt_conn_unref(stpt_old);
   }
}

/**
 * @private       sv_Fail
 * @brief         End the run with an error: STATUS FAILED, peer link dropped.
 *                Ignored outside a run.
 * @param[in]     e_error Error.
 * @param[in]     i32_detail Code that goes with it (its low byte is reported).
 * @return        None.
 */
static void sv_Fail(PairError_E e_error, int32_t i32_detail)
{
   (void)k_mutex_lock(&sst_statusLock, K_FOREVER);
   se_error = e_error;
   su8_detail = (uint8_t)i32_detail;
   k_mutex_unlock(&sst_statusLock);

   APP_LOG_WRN("pairing failed: error %d, detail %d", (int)e_error, (int)i32_detail);

   sv_EndRun();
   sv_DropPeerLink();
   sv_SetState(ePST_FAILED);
}

/**
 * @private       sv_Succeed
 * @brief         End the run paired: the peer link stays up, encrypted and
 *                bonded; SETU goes back to the host; the bond is saved for
 *                the reconnections.
 * @return        None.
 */
static void sv_Succeed(void)
{
   APP_LOG_INF("paired at level 4, bonded");

   sv_EndRun();
   sv_ReturnRoles();
   sv_SaveBond();
   sv_SetState(ePST_PAIRED);
}

/**
 * @private       sv_ForgetPeer
 * @brief         UNPAIR / wipe: end any run, drop the peer link, delete the
 *                bond (or all bonds), turn the LED off, back to IDLE.
 * @param[in]     b_allBonds Delete every bond, not only the peer's.
 * @return        None.
 */
static void sv_ForgetPeer(bool b_allBonds)
{
   bt_addr_le_t st_peer = sst_peerAddr;

   // Check if a run is in progress
   if (sb_IsRunningState((PairState_E)atomic_get(&st_state)))
   {
      sv_EndRun();
   }

   sv_StopReconnect();
   sv_ForgetBond();
   sv_DropPeerLink();
   // NULL, like an all-zero address (BT_ADDR_LE_ANY), deletes every bond
   (void)bt_unpair(BT_ID_DEFAULT, b_allBonds ? NULL : &st_peer);
   sv_SetLed(ePLD_OFF);

   (void)k_mutex_lock(&sst_statusLock, K_FOREVER);
   se_error = ePER_NONE;
   su8_detail = 0U;
   se_role = ePRL_NONE;
   (void)memset(&sst_peerAddr, 0, sizeof(sst_peerAddr));
   k_mutex_unlock(&sst_statusLock);

   sv_ResetRun();
   APP_LOG_INF("bond%s deleted", b_allBonds ? "s" : "");
   sv_SetState(ePST_IDLE);
}

/**
 * @private       sv_TrySendOob
 * @brief         Send this device's OOB frame once the peer has its
 *                certificate and its certificate has verified (the Client
 *                runs one transfer at a time).
 * @return        None.
 */
static void sv_TrySendOob(void)
{
   int i_ret;

   // Check if it is time and not done yet
   if (!sb_ownCertSent || !sb_peerCertOk || sb_oobTxStarted)
   {
      return;
   }

   sb_oobTxStarted = true;
   i_ret = gi_SETUC_SendBuffer(PAIR_APP_TYPE_OOB, su8ar_txOob, sizeof(su8ar_txOob));

   // Check if the transfer could not start
   if (i_ret != 0)
   {
      sv_Fail(ePER_TRANSFER, i_ret);
   }
}

/**
 * @private       sv_TryVerifyOob
 * @brief         Verify the peer OOB frame once it and the peer key are there;
 *                then pairing may start (central) and SMP may be answered.
 * @return        None.
 */
static void sv_TryVerifyOob(void)
{
   struct bt_conn *stpt_peer = sstpt_PeerConnRef();
   psa_status_t t_status;
   int i_ret;

   // Check if it is time and not done yet
   if (!sb_peerCertOk || sb_peerOobOk || !atomic_test_bit(&st_rxHave, PAIR_RX_OOB))
   {
      return;
   }

   t_status = gt_PairOob_Verify(st_peerKey, su8ar_rxOob, PAIR_ADDR_BYTES(&sst_peerAddr),
      PAIR_ADDR_BYTES(&sst_ownAddr));

   // Check if the peer signed the OOB data it sent, for this device
   if (t_status != PSA_SUCCESS)
   {
      sv_Fail(ePER_OOB_SIG, t_status);
      return;
   }

   (void)memcpy(sst_remoteOob.r, &su8ar_rxOob[0], PAIR_OOB_VALUE_LEN);
   (void)memcpy(sst_remoteOob.c, &su8ar_rxOob[PAIR_OOB_VALUE_LEN], PAIR_OOB_VALUE_LEN);
   sb_peerOobOk = true;
   APP_LOG_INF("peer OOB data verified");
   sv_SetState(ePST_PAIRING);

   sv_TryAnswerOob();

   // Check if this device starts pairing (and SMP is not running already)
   if ((se_role == ePRL_CENTRAL) && (stpt_peer != NULL))
   {
      i_ret = bt_conn_set_security(stpt_peer, BT_SECURITY_L4);

      // Check if pairing could not start
      if (i_ret != 0)
      {
         sv_Fail(ePER_SMP, i_ret);
      }
   }
}

/**
 * @private       sv_TryAnswerOob
 * @brief         Give SMP both OOB data once it has asked and the peer's has
 *                verified.
 * @return        None.
 */
static void sv_TryAnswerOob(void)
{
   struct bt_conn *stpt_peer = sstpt_PeerConnRef();
   int i_ret;

   // Check if SMP waits and the data is ready
   if (!sb_oobRequested || !sb_peerOobOk || sb_oobAnswered || (stpt_peer == NULL))
   {
      return;
   }

   sb_oobAnswered = true;
   i_ret = bt_le_oob_set_sc_data(stpt_peer, &sst_localOob.le_sc_data, &sst_remoteOob);

   // Check if SMP took the data
   if (i_ret != 0)
   {
      sv_Fail(ePER_SMP, i_ret);
   }
}

/**
 * @private       sv_WriteSecured
 * @brief         Central: find SECURED on the peer, then write it. The write
 *                succeeds only on a level-4 link.
 * @return        None.
 */
static void sv_WriteSecured(void)
{
   struct bt_conn *stpt_peer = sstpt_PeerConnRef();
   int i_ret;

   // Check if it was started already, or the link is gone
   if (sb_securedSent || (stpt_peer == NULL))
   {
      return;
   }

   sb_securedSent = true;
   (void)memset(&sst_discoverParams, 0, sizeof(sst_discoverParams));
   sst_discoverParams.uuid = &sst_securedUuid.uuid;
   sst_discoverParams.func = su8_SecuredDiscovered;
   sst_discoverParams.start_handle = BT_ATT_FIRST_ATTRIBUTE_HANDLE;
   sst_discoverParams.end_handle = BT_ATT_LAST_ATTRIBUTE_HANDLE;
   sst_discoverParams.type = BT_GATT_DISCOVER_CHARACTERISTIC;

   i_ret = bt_gatt_discover(stpt_peer, &sst_discoverParams);

   // Check if the discovery started
   if (i_ret != 0)
   {
      sv_Fail(ePER_SECURED, i_ret);
   }
}

/**
 * @private       sv_HandleBtReady
 * @brief         The stack is up and its settings (bonds, the bond record) are
 *                loaded: learn this device's address; keep a bond only while
 *                provisioned; reconnect to the bonded peer.
 * @return        None.
 */
static void sv_HandleBtReady(void)
{
   bt_addr_le_t star_ids[CONFIG_BT_ID_MAX];
   size_t t_count = ARRAY_SIZE(star_ids);

   bt_id_get(star_ids, &t_count);

   // Check if the stack has an identity
   if (t_count > 0U)
   {
      (void)k_mutex_lock(&sst_statusLock, K_FOREVER);
      sst_ownAddr = star_ids[0];
      k_mutex_unlock(&sst_statusLock);
   }

   // Check if this device may keep a bond at all
   if (ge_Prov_GetState() != ePS_PROVISIONED)
   {
      (void)bt_unpair(BT_ID_DEFAULT, NULL);
   }
   else
   {
      // A bond that survived the reset makes the device PAIRED again
      bt_foreach_bond(BT_ID_DEFAULT, sv_BondFound, NULL);
   }

   // Check if the bond record has no bond (any more): it is stale
   if (sb_savedBondValid && (atomic_get(&st_bondRole) == ePRL_NONE))
   {
      sv_ForgetBond();
   }

   sv_Publish();

   // Check if this device has a bonded peer to reconnect to
   if (atomic_get(&st_bondRole) == ePRL_CENTRAL)
   {
      sv_ReconnectStart();
   }
   else if (atomic_get(&st_bondRole) == ePRL_PERIPHERAL)
   {
      gv_BLE_RefreshAdv();
   }
}

/**
 * @private       sv_BondFound
 * @brief         bt_foreach_bond() callback: the bond of the saved record is
 *                the paired peer, reconnected to in the saved role; without a
 *                record, the first bond is (and is not reconnected to).
 * @param[in]     stpt_info Bond.
 * @param[in]     vpt_user Unused.
 * @return        None.
 */
static void sv_BondFound(const struct bt_bond_info *stpt_info, void *vpt_user)
{
   bool b_saved = sb_savedBondValid &&
      (memcmp(&stpt_info->addr, &su8ar_savedBond[1], PAIR_ADDR_LEN) == 0);
   PairRole_E e_role = b_saved ? (PairRole_E)su8ar_savedBond[0] : ePRL_NONE;

   ARG_UNUSED(vpt_user);

   // Check if a peer is known already (the record's bond, else the first one)
   if ((atomic_get(&st_state) == ePST_PAIRED) && !b_saved)
   {
      return;
   }

   (void)k_mutex_lock(&sst_statusLock, K_FOREVER);
   sst_peerAddr = stpt_info->addr;
   se_role = e_role;
   (void)atomic_set(&st_state, ePST_PAIRED);
   k_mutex_unlock(&sst_statusLock);
   (void)atomic_set(&st_bondRole, (atomic_val_t)e_role);

   APP_LOG_INF("bonded peer restored%s", b_saved ? "" : " (no record: not reconnected)");
}

/**
 * @private       sv_HandleStart
 * @brief         START: check, then advertise to the peer (peripheral) or scan
 *                for it (central).
 * @param[in]     stpt_event START event (role, peer address).
 * @return        None.
 */
static void sv_HandleStart(const PairEvent_T *stpt_event)
{
   int i_ret;

   // Check if a run is in progress (a second START queued behind the first)
   if (sb_IsRunningState((PairState_E)atomic_get(&st_state)))
   {
      APP_LOG_WRN("START ignored: pairing in progress");
      return;
   }

   // A previous pairing goes first: no more reconnecting to it, and its link
   // is released here, so its disconnect is not taken for this run's
   // (SETU is already the host's).
   sv_StopReconnect();
   sv_ForgetBond();
   sv_ReleaseOldLink();
   sv_SetLed(ePLD_OFF);
   sv_ResetRun();
   su32_runId++;

   (void)k_mutex_lock(&sst_statusLock, K_FOREVER);
   se_role = (PairRole_E)stpt_event->u8_role;
   sst_peerAddr = stpt_event->st_addr;
   se_error = ePER_NONE;
   su8_detail = 0U;
   (void)atomic_set(&st_state, ePST_ARMED);
   k_mutex_unlock(&sst_statusLock);

   APP_LOG_INF("pairing as %s", (se_role == ePRL_CENTRAL) ? "central" : "peripheral");

   // Check if this device has an identity to pair with
   if ((ge_Prov_GetState() != ePS_PROVISIONED) || !gb_IsTrustAnchorSet())
   {
      sv_Fail(ePER_NOT_PROVISIONED, 0);
      return;
   }

   // Check if the peer is another device
   if (bt_addr_le_cmp(&sst_peerAddr, &sst_ownAddr) == 0)
   {
      sv_Fail(ePER_BAD_ARG, 0);
      return;
   }

   // Check if SETU is free to move to the peer
   if (gb_SETUS_IsRxBusy() || gb_SETUC_IsTxBusy())
   {
      sv_Fail(ePER_BUSY, 0);
      return;
   }

   // A fresh pairing: an older bond with this peer would be reused instead
   (void)bt_unpair(BT_ID_DEFAULT, &sst_peerAddr);

   (void)k_work_schedule(&sst_connectTimeout, K_MSEC(CONFIG_PAIR_CONNECT_TIMEOUT_MS));
   (void)k_work_schedule(&sst_runTimeout, K_MSEC(CONFIG_PAIR_TIMEOUT_MS));

   // Check if this device advertises to the peer
   if (se_role == ePRL_PERIPHERAL)
   {
      // Taken before the stop, so ConnectionHandling.c does not restart
      // undirected advertising in between
      (void)atomic_set(&st_dirAdv, 1);
      (void)bt_le_adv_stop();
      i_ret = bt_le_adv_start(BT_LE_ADV_CONN_DIR_LOW_DUTY(&sst_peerAddr), NULL, 0U,
         NULL, 0U);

      // Check if directed advertising runs
      if (i_ret != 0)
      {
         (void)atomic_set(&st_dirAdv, 0);
         sv_Fail(ePER_INTERNAL, i_ret);
         return;
      }
   }
   else
   {
      (void)atomic_set(&st_scanMatched, 0);
      i_ret = bt_le_scan_start(BT_LE_SCAN_PASSIVE, sv_ScanCb);

      // Check if the scan runs
      if (i_ret != 0)
      {
         sv_Fail(ePER_INTERNAL, i_ret);
         return;
      }

      sb_scanning = true;
   }

   sv_Publish();
}

/**
 * @private       sv_HandleScanMatch
 * @brief         Central: the peer advertises (to a run, or as the bonded
 *                peer); stop scanning and connect.
 * @return        None.
 */
static void sv_HandleScanMatch(void)
{
   bool b_run = (atomic_get(&st_state) == ePST_ARMED);
   int i_ret;

   // Check if a run, or the reconnection, still waits for the peer
   if ((!b_run && ((atomic_get(&st_state) != ePST_PAIRED) ||
         (atomic_get(&st_bondRole) != ePRL_CENTRAL))) || !sb_scanning)
   {
      return;
   }

   (void)bt_le_scan_stop();
   sb_scanning = false;

   i_ret = bt_conn_le_create(&sst_peerAddr, BT_CONN_LE_CREATE_CONN,
      BT_LE_CONN_PARAM(PAIR_CONN_INTERVAL, PAIR_CONN_INTERVAL, 0, PAIR_CONN_TIMEOUT),
      &sstpt_createConn);

   // Check if the connection attempt started
   if (i_ret != 0)
   {
      sstpt_createConn = NULL;

      // Check if a run made it, or the reconnection (which tries again)
      if (b_run)
      {
         sv_Fail(ePER_CONNECT, i_ret);
      }
      else
      {
         APP_LOG_WRN("bonded peer not connected (%d)", i_ret);
         sv_ScheduleReconnect();
      }
   }
}

/**
 * @private       sv_HandleConnected
 * @brief         The peer link is up (or the attempt failed): move SETU to
 *                it and attach the Client to the peer's service.
 * @param[in]     i32_err 0, or the HCI error of a failed attempt.
 * @return        None.
 */
static void sv_HandleConnected(int32_t i32_err)
{
   struct bt_conn *stpt_peer = sstpt_PeerConnRef();
   int i_ret;

   // Check if it is the end of an attempt this run did not make: a
   // reconnection's, cancelled when START came
   if ((i32_err != 0) && (se_role == ePRL_CENTRAL) && (sstpt_createConn == NULL))
   {
      return;
   }

   // The connection object from bt_conn_le_create() is not needed any more
   if (sstpt_createConn != NULL)
   {
      bt_conn_unref(sstpt_createConn);
      sstpt_createConn = NULL;
   }
   (void)atomic_set(&st_dirAdv, 0);

   // Check if the run still waits for the link (it may have ended meanwhile)
   if (atomic_get(&st_state) != ePST_ARMED)
   {
      // Check if a late link came up: it has no run any more
      if ((i32_err == 0) && (stpt_peer != NULL))
      {
         sv_DropPeerLink();
      }
      return;
   }

   // Check if the link came up
   if ((i32_err != 0) || (stpt_peer == NULL))
   {
      sv_Fail(ePER_CONNECT, i32_err);
      return;
   }

   sb_runHasLink = true;
   (void)k_work_cancel_delayable(&sst_connectTimeout);
   APP_LOG_INF("peer link up");
   sv_SetState(ePST_CONNECTED);

   // From now on only the pairing range is reachable, on whatever link
   sb_rolesMoved = true;
   gv_SETURouter_SetFilter(PAIR_APP_TYPE_FIRST, PAIR_APP_TYPE_LAST);
   i_ret = gi_SETUS_Rebind(stpt_peer);

   // Check if the Server moved to the peer
   if (i_ret != 0)
   {
      sv_Fail(ePER_BUSY, i_ret);
      return;
   }

   i_ret = gi_SETURouter_ClientAttach(stpt_peer, PAIR_APP_TYPE_FIRST);

   // Check if the attach started (-EALREADY: ready at once)
   if (i_ret == -EALREADY)
   {
      sv_HandleCliReady(0);
   }
   else if (i_ret != 0)
   {
      sv_Fail(ePER_NO_PEER_SVC, i_ret);
   }
}

/**
 * @private       sv_HandleDisconnected
 * @brief         The peer link is down (gv_Pair_OnDisconnected() has already
 *                cleared st_peerConn): drop its reference, give SETU back
 *                to the host if it was moved. The run that had it fails; a
 *                pairing stays paired (bonded), its LED goes off and the
 *                reconnection starts.
 * @param[in]     stpt_conn The link (its reference is dropped here).
 * @param[in]     i32_reason HCI reason.
 * @return        None.
 */
static void sv_HandleDisconnected(struct bt_conn *stpt_conn, int32_t i32_reason)
{
   // Check if a reference was held
   if (stpt_conn != NULL)
   {
      bt_conn_unref(stpt_conn);
   }

   APP_LOG_INF("peer link down (reason 0x%02x)", (unsigned int)i32_reason);

   // Check if SETU is still on the peer link
   if (sb_rolesMoved)
   {
      sv_ReturnRoles();
   }

   // Check if the running pairing lost its link
   if (sb_runHasLink && sb_IsRunningState((PairState_E)atomic_get(&st_state)))
   {
      sv_Fail(ePER_LINK_LOST, i32_reason);
   }
   // Check if the bonded peer is gone: reach it again
   else if (atomic_get(&st_state) == ePST_PAIRED)
   {
      sb_bondLink = false;
      sb_bondSecured = false;
      (void)k_work_cancel_delayable(&sst_secureTimeout);
      sv_SetLed(ePLD_OFF);

      // Check if this device connects, or waits for the peer to
      if (atomic_get(&st_bondRole) == ePRL_CENTRAL)
      {
         sv_ScheduleReconnect();
      }
      else if (atomic_get(&st_bondRole) == ePRL_PERIPHERAL)
      {
         gv_BLE_RefreshAdv();
      }
   }
}

/**
 * @private       sv_HandleReconnected
 * @brief         A bonded peer link is up (or the central's attempt failed):
 *                the central encrypts it with the stored keys; both give it
 *                PAIR_RECONNECT_SECURE_MS to reach level 4.
 * @param[in]     i32_err 0, or the HCI error of a failed attempt.
 * @return        None.
 */
static void sv_HandleReconnected(int32_t i32_err)
{
   struct bt_conn *stpt_peer = sstpt_PeerConnRef();
   int i_ret;

   // The connection object from bt_conn_le_create() is not needed any more
   if (sstpt_createConn != NULL)
   {
      bt_conn_unref(sstpt_createConn);
      sstpt_createConn = NULL;
   }

   // Check if the bond is still the one to reach (START or UNPAIR came first)
   if ((atomic_get(&st_state) != ePST_PAIRED) || (atomic_get(&st_bondRole) == ePRL_NONE))
   {
      // Check if a link of no use came up (not a run's, which is up to the run)
      if ((i32_err == 0) && (stpt_peer != NULL) &&
         !sb_IsRunningState((PairState_E)atomic_get(&st_state)))
      {
         sv_DropPeerLink();
      }
      return;
   }

   // Check if the link came up
   if ((i32_err != 0) || (stpt_peer == NULL))
   {
      APP_LOG_WRN("bonded peer not reached (0x%02x)", (unsigned int)i32_err);
      sv_ScheduleReconnect();
      return;
   }

   sb_bondLink = true;
   sb_bondSecured = false;
   APP_LOG_INF("bonded peer link up");
   (void)k_work_schedule(&sst_secureTimeout, K_MSEC(PAIR_RECONNECT_SECURE_MS));

   // Check if this device starts encryption
   if (atomic_get(&st_bondRole) == ePRL_CENTRAL)
   {
      i_ret = bt_conn_set_security(stpt_peer, BT_SECURITY_L4);

      // Check if encryption could not start
      if (i_ret != 0)
      {
         APP_LOG_WRN("bonded link not encrypted (%d)", i_ret);
         sv_DropPeerLink();
      }
   }
}

/**
 * @private       sv_HandleSecurity
 * @brief         The peer link's security changed: a bonded reconnection at
 *                level 4 blinks the LED; anything less drops the link.
 * @param[in]     i32_level Security level.
 * @param[in]     u8_err bt_security_err, 0 on success.
 * @return        None.
 */
static void sv_HandleSecurity(int32_t i32_level, uint8_t u8_err)
{
   // Check if a bonded reconnection waits for it (a run follows SMP instead)
   if (!sb_bondLink || sb_bondSecured || (atomic_get(&st_state) != ePST_PAIRED))
   {
      return;
   }

   // Check if the stored keys gave the level of the pairing
   if ((u8_err != 0U) || (i32_level < (int32_t)BT_SECURITY_L4))
   {
      APP_LOG_WRN("bonded link not secured: level %d, error %u", (int)i32_level,
         (unsigned int)u8_err);
      sv_DropPeerLink();
      return;
   }

   sb_bondSecured = true;
   (void)k_work_cancel_delayable(&sst_secureTimeout);
   APP_LOG_INF("bonded peer reconnected at level 4");
   sv_SetLed(ePLD_BLINK);
}

/**
 * @private       sv_HandleSecureTimeout
 * @brief         The bonded link did not reach level 4 in time: drop it.
 * @return        None.
 */
static void sv_HandleSecureTimeout(void)
{
   // Check if the bonded link still waits for encryption
   if (sb_bondLink && !sb_bondSecured && (atomic_get(&st_state) == ePST_PAIRED))
   {
      APP_LOG_WRN("bonded link not secured in time");
      sv_DropPeerLink();
   }
}

/**
 * @private       sv_HandleCliReady
 * @brief         Client attached to the peer's service: send the certificate.
 * @param[in]     i32_status 0, or the attach error.
 * @return        None.
 */
static void sv_HandleCliReady(int32_t i32_status)
{
   int i_ret;

   // Check if the run waits for it
   if (atomic_get(&st_state) != ePST_CONNECTED)
   {
      return;
   }

   // Check if the peer hosts a SETU service
   if (i32_status != 0)
   {
      sv_Fail(ePER_NO_PEER_SVC, i32_status);
      return;
   }

   sv_SetState(ePST_CERT_EXCHANGE);
   i_ret = gi_SETUC_SendBuffer(PAIR_APP_TYPE_PEER_CERT, gst_deviceCertData.u8ar_DeviceCert,
      gst_deviceCertData.u16_deviceCertLen);

   // Check if the transfer started
   if (i_ret != 0)
   {
      sv_Fail(ePER_TRANSFER, i_ret);
   }
}

/**
 * @private       sv_HandleTxDone
 * @brief         One of this device's transfers ended.
 * @param[in]     u8_appType PAIR_APP_TYPE_PEER_CERT or PAIR_APP_TYPE_OOB.
 * @param[in]     u8_status SETUStatus_E.
 * @return        None.
 */
static void sv_HandleTxDone(uint8_t u8_appType, uint8_t u8_status)
{
   // Check if a run waits for it
   if (!sb_IsRunningState((PairState_E)atomic_get(&st_state)))
   {
      return;
   }

   // Check if the peer got it intact
   if (u8_status != (uint8_t)eBS_OK)
   {
      sv_Fail(ePER_TRANSFER, u8_status);
      return;
   }

   // Check if it was the certificate: the OOB frame may follow
   if (u8_appType == PAIR_APP_TYPE_PEER_CERT)
   {
      sb_ownCertSent = true;
      sv_TrySendOob();
   }
}

/**
 * @private       sv_HandleCertReceived
 * @brief         Verify the peer certificate, then make, sign and send this
 *                device's OOB data.
 * @return        None.
 */
static void sv_HandleCertReceived(void)
{
   DeviceCertStatus_E e_status;
   psa_status_t t_status;
   int i_ret;

   e_status = ge_VerifyRemoteDeviceCertificate(su8ar_rxCert, su32_rxCertLen, &st_peerKey);

   // Check if the peer is a device of the same CA, within the profile
   if (e_status != eDCS_OK)
   {
      st_peerKey = 0U;
      sv_Fail(ePER_PEER_CERT, (int32_t)e_status);
      return;
   }

   sb_peerCertOk = true;
   APP_LOG_INF("peer certificate verified");
   sv_SetState(ePST_CERT_VERIFIED);

   // Fresh LE Secure Connections OOB data for this run
   i_ret = bt_le_oob_get_local(BT_ID_DEFAULT, &sst_localOob);

   // Check if the stack made it
   if (i_ret != 0)
   {
      sv_Fail(ePER_INTERNAL, i_ret);
      return;
   }

   t_status = gt_PairOob_Sign(CSR_DEVICE_SIGNING_KEY_ID, sst_localOob.le_sc_data.r,
      sst_localOob.le_sc_data.c, PAIR_ADDR_BYTES(&sst_ownAddr), PAIR_ADDR_BYTES(&sst_peerAddr),
      su8ar_txOob);

   // Check if it was signed with the device key
   if (t_status != PSA_SUCCESS)
   {
      sv_Fail(ePER_INTERNAL, t_status);
      return;
   }

   // Both OOB flags must be set before the central sends its pairing request
   bt_le_oob_set_sc_flag(true);
   sv_SetState(ePST_OOB_EXCHANGE);

   sv_TrySendOob();
   sv_TryVerifyOob();
}

/**
 * @private       sv_HandleRxDone
 * @brief         A peer transfer ended.
 * @param[in]     u8_appType PAIR_APP_TYPE_PEER_CERT or PAIR_APP_TYPE_OOB.
 * @param[in]     u8_status SETUStatus_E.
 * @return        None.
 */
static void sv_HandleRxDone(uint8_t u8_appType, uint8_t u8_status)
{
   // Check if a run waits for it
   if (!sb_IsRunningState((PairState_E)atomic_get(&st_state)))
   {
      return;
   }

   // Check if it arrived intact
   if (u8_status != (uint8_t)eBS_OK)
   {
      sv_Fail(ePER_TRANSFER, u8_status);
      return;
   }

   // Check which object it was
   if (u8_appType == PAIR_APP_TYPE_PEER_CERT)
   {
      sv_HandleCertReceived();
   }
   else
   {
      sv_TryVerifyOob();
   }
}

/**
 * @private       sv_HandleOobRequest
 * @brief         SMP asks for OOB data: answer now or once the peer's verifies.
 * @param[in]     i32_config bt_conn_oob_info lesc.oob_config, or -1 for legacy.
 * @return        None.
 */
static void sv_HandleOobRequest(int32_t i32_config)
{
   struct bt_conn *stpt_peer = sstpt_PeerConnRef();

   // Check if a run expects it
   if (!sb_IsRunningState((PairState_E)atomic_get(&st_state)) || (stpt_peer == NULL))
   {
      return;
   }

   // Check if both devices use OOB data (both flags set)
   if (i32_config != (int32_t)BT_CONN_OOB_BOTH_PEERS)
   {
      (void)bt_conn_auth_cancel(stpt_peer);
      sv_Fail(ePER_SMP, 0x80 | (i32_config & 0x7F));
      return;
   }

   sb_oobRequested = true;
   sv_TryAnswerOob();
}

/**
 * @private       sv_HandlePairingDone
 * @brief         SMP finished: require level 4 and a bond, then prove the link
 *                (the central writes SECURED; the peripheral waits for it).
 * @param[in]     i32_level Security level of the peer link.
 * @param[in]     b_bonded Keys were distributed and stored.
 * @return        None.
 */
static void sv_HandlePairingDone(int32_t i32_level, bool b_bonded)
{
   // Check if a run expects it
   if (atomic_get(&st_state) != ePST_PAIRING)
   {
      return;
   }

   // Check if the link is authenticated LE Secure Connections and bonded
   if ((i32_level < (int32_t)BT_SECURITY_L4) || !b_bonded)
   {
      sv_Fail(ePER_SMP, b_bonded ? i32_level : 0xFF);
      return;
   }

   APP_LOG_INF("SMP done, level %d", (int)i32_level);

   // Check if this device proves the link
   if (se_role == ePRL_CENTRAL)
   {
      sv_WriteSecured();
   }
}

/**
 * @private       sv_HandleEvent
 * @brief         Dispatch one event (pairing thread).
 * @param[in]     stpt_event Event.
 * @return        None.
 */
static void sv_HandleEvent(const PairEvent_T *stpt_event)
{
   switch (stpt_event->u8_type)
   {
      case ePEV_BT_READY:
         sv_HandleBtReady();
         break;

      case ePEV_START:
         sv_HandleStart(stpt_event);
         break;

      case ePEV_CANCEL:
         // Check if there is a run to cancel
         if (sb_IsRunningState((PairState_E)atomic_get(&st_state)))
         {
            sv_Fail(ePER_CANCELLED, 0);
         }
         break;

      case ePEV_UNPAIR:
         sv_ForgetPeer(false);
         break;

      case ePEV_FORGET:
         sv_ForgetPeer(true);
         break;

      case ePEV_SCAN_MATCH:
         sv_HandleScanMatch();
         break;

      case ePEV_CONNECTED:
         sv_HandleConnected(stpt_event->i32_value);
         break;

      case ePEV_DISCONNECTED:
         sv_HandleDisconnected(stpt_event->stpt_conn, stpt_event->i32_value);
         break;

      case ePEV_CLI_READY:
         sv_HandleCliReady(stpt_event->i32_value);
         break;

      case ePEV_TX_DONE:
         sv_HandleTxDone(stpt_event->u8_appType, stpt_event->u8_status);
         break;

      case ePEV_RX_DONE:
         sv_HandleRxDone(stpt_event->u8_appType, stpt_event->u8_status);
         break;

      case ePEV_OOB_REQUEST:
         sv_HandleOobRequest(stpt_event->i32_value);
         break;

      case ePEV_PAIRING_DONE:
         sv_HandlePairingDone(stpt_event->i32_value, stpt_event->u8_status != 0U);
         break;

      case ePEV_PAIRING_FAILED:
         // Check if a run was pairing
         if (sb_IsRunningState((PairState_E)atomic_get(&st_state)))
         {
            sv_Fail(ePER_SMP, stpt_event->i32_value);
         }
         break;

      case ePEV_SECURED_RX:
         // Check if this peripheral waits for the proof
         if ((atomic_get(&st_state) == ePST_PAIRING) && (se_role == ePRL_PERIPHERAL))
         {
            sv_SetLed(ePLD_ON);
            sv_Succeed();
         }
         break;

      case ePEV_SECURED_TX:
         // Check if this central waits for the write
         if (atomic_get(&st_state) == ePST_PAIRING)
         {
            // Check if the peer accepted it (only a level-4 link may write)
            if (stpt_event->i32_value != 0)
            {
               sv_Fail(ePER_SECURED, stpt_event->i32_value);
            }
            else
            {
               sv_Succeed();
            }
         }
         break;

      case ePEV_TIMEOUT:
         // Check if the timer belongs to this run, which still runs
         if (((uint32_t)stpt_event->i32_value == su32_runId) &&
            sb_IsRunningState((PairState_E)atomic_get(&st_state)))
         {
            sv_Fail(ePER_TIMEOUT, (int32_t)atomic_get(&st_state));
         }
         break;

      case ePEV_RECONNECT:
         sv_ReconnectStart();
         break;

      case ePEV_RECONNECTED:
         sv_HandleReconnected(stpt_event->i32_value);
         break;

      case ePEV_SECURITY:
         sv_HandleSecurity(stpt_event->i32_value, stpt_event->u8_status);
         break;

      case ePEV_SECURE_TIMEOUT:
         sv_HandleSecureTimeout();
         break;

      default:
         break;
   }
}

/**
 * @private       sv_PairThread
 * @brief         Pairing thread: serve events one at a time.
 * @param[in]     vpt_p1 Unused.
 * @param[in]     vpt_p2 Unused.
 * @param[in]     vpt_p3 Unused.
 * @return        None.
 */
static void sv_PairThread(void *vpt_p1, void *vpt_p2, void *vpt_p3)
{
   PairEvent_T st_event;

   ARG_UNUSED(vpt_p1);
   ARG_UNUSED(vpt_p2);
   ARG_UNUSED(vpt_p3);

   while (k_msgq_get(&sst_pairMsgq, &st_event, K_FOREVER) == 0)
   {
      sv_HandleEvent(&st_event);
   }
}

/**
 * @private       sv_ConnectTimeout
 * @brief         The peer link did not come up in time (work queue).
 * @param[in]     stpt_work Unused.
 * @return        None.
 */
static void sv_ConnectTimeout(struct k_work *stpt_work)
{
   ARG_UNUSED(stpt_work);

   // Check if the run still waits for the link
   if (atomic_get(&st_state) == ePST_ARMED)
   {
      sv_PostSimple(ePEV_TIMEOUT, (int32_t)su32_runId);
   }
}

/**
 * @private       sv_RunTimeout
 * @brief         The pairing did not end in time (work queue).
 * @param[in]     stpt_work Unused.
 * @return        None.
 */
static void sv_RunTimeout(struct k_work *stpt_work)
{
   ARG_UNUSED(stpt_work);

   sv_PostSimple(ePEV_TIMEOUT, (int32_t)su32_runId);
}

/**
 * @private       sv_ReconnectWork
 * @brief         Central: time to look for the bonded peer again (work queue).
 * @param[in]     stpt_work Unused.
 * @return        None.
 */
static void sv_ReconnectWork(struct k_work *stpt_work)
{
   ARG_UNUSED(stpt_work);

   sv_PostSimple(ePEV_RECONNECT, 0);
}

/**
 * @private       sv_SecureTimeout
 * @brief         The bonded link had its time to reach level 4 (work queue).
 * @param[in]     stpt_work Unused.
 * @return        None.
 */
static void sv_SecureTimeout(struct k_work *stpt_work)
{
   ARG_UNUSED(stpt_work);

   sv_PostSimple(ePEV_SECURE_TIMEOUT, 0);
}

/**
 * @private       sv_LedWork
 * @brief         Show st_ledMode on the LED; while it is ePLD_BLINK, toggle it
 *                every PAIR_LED_BLINK_MS (work queue).
 * @param[in]     stpt_work Unused.
 * @return        None.
 */
static void sv_LedWork(struct k_work *stpt_work)
{
   ARG_UNUSED(stpt_work);

   switch ((PairLed_E)atomic_get(&st_ledMode))
   {
      case ePLD_BLINK:
         sb_ledLit = !sb_ledLit;
         (void)k_work_schedule(&sst_ledWork, K_MSEC(PAIR_LED_BLINK_MS));
         break;

      case ePLD_ON:
         sb_ledLit = true;
         break;

      default:
         sb_ledLit = false;
         break;
   }

   (void)dk_set_led(PAIR_LED, sb_ledLit ? 1U : 0U);
}

/**
 * @private       si_SettingsSet
 * @brief         Settings handler (settings_load()): read the bond record.
 * @param[in]     cpt_key Key below PAIR_SETTINGS_SUBTREE.
 * @param[in]     t_len Stored length.
 * @param[in]     fpt_read Reads the value.
 * @param[in]     vpt_arg Argument of fpt_read.
 * @return        0, -ENOENT for an unknown key, -EINVAL for a wrong length or
 *                role, or the read error.
 */
static int si_SettingsSet(const char *cpt_key, size_t t_len, settings_read_cb fpt_read,
   void *vpt_arg)
{
   ssize_t t_read;

   // Check if it is the bond record, with its size
   if (strcmp(cpt_key, PAIR_SETTINGS_BOND_KEY) != 0)
   {
      return -ENOENT;
   }
   if (t_len != sizeof(su8ar_savedBond))
   {
      return -EINVAL;
   }

   t_read = fpt_read(vpt_arg, su8ar_savedBond, sizeof(su8ar_savedBond));

   // Check if the record was read whole
   if (t_read != (ssize_t)sizeof(su8ar_savedBond))
   {
      return (t_read < 0) ? (int)t_read : -EINVAL;
   }

   // Check if the role is one a pairing gives
   if ((su8ar_savedBond[0] != (uint8_t)ePRL_CENTRAL) &&
      (su8ar_savedBond[0] != (uint8_t)ePRL_PERIPHERAL))
   {
      return -EINVAL;
   }

   sb_savedBondValid = true;

   return 0;
}

/**
 * @private       sv_ScanCb
 * @brief         Central: an advertising report (BT RX context). The peer's
 *                connectable advertising (directed to this device) is posted
 *                once.
 * @param[in]     stpt_addr Advertiser address.
 * @param[in]     i8_rssi Unused.
 * @param[in]     u8_advType Advertising PDU type.
 * @param[in]     stpt_ad Unused.
 * @return        None.
 */
static void sv_ScanCb(const bt_addr_le_t *stpt_addr, int8_t i8_rssi, uint8_t u8_advType,
   struct net_buf_simple *stpt_ad)
{
   ARG_UNUSED(i8_rssi);
   ARG_UNUSED(stpt_ad);

   // Check if it is the peer, connectable, and the first report
   if ((bt_addr_le_cmp(stpt_addr, &sst_peerAddr) == 0) &&
      ((u8_advType == BT_GAP_ADV_TYPE_ADV_DIRECT_IND) ||
         (u8_advType == BT_GAP_ADV_TYPE_ADV_IND)) &&
      atomic_cas(&st_scanMatched, 0, 1))
   {
      sv_PostSimple(ePEV_SCAN_MATCH, 0);
   }
}

/**
 * @private       si_PairRxStart
 * @brief         SETURxStart_F: accept the peer certificate (1..1024 bytes) and
 *                the OOB frame (PAIR_OOB_FRAME_LEN bytes), each once per run,
 *                while a run has the peer link.
 * @param[in]     u8_appType appType announced by the peer.
 * @param[in]     u32_totalLen Object size.
 * @return        0 to accept, -EPERM / -EINVAL / -EALREADY / -EBUSY to reject.
 */
static int si_PairRxStart(uint8_t u8_appType, uint32_t u32_totalLen)
{
   PairState_E e_state = (PairState_E)atomic_get(&st_state);

   // Check if a run has the peer link
   if ((e_state < ePST_CONNECTED) || (e_state > ePST_OOB_EXCHANGE))
   {
      return -EPERM;
   }

   // Check if the object is one this device receives, with its size
   if (u8_appType == PAIR_APP_TYPE_PEER_CERT)
   {
      if ((u32_totalLen == 0U) || (u32_totalLen > DEVICE_CERT_MAX_DER_LEN))
      {
         return -EINVAL;
      }
      if (atomic_test_bit(&st_rxHave, PAIR_RX_CERT))
      {
         return -EALREADY;
      }
      su32_rxCertLen = u32_totalLen;
   }
   else if (u8_appType == PAIR_APP_TYPE_OOB)
   {
      if (u32_totalLen != PAIR_OOB_FRAME_LEN)
      {
         return -EINVAL;
      }
      if (atomic_test_bit(&st_rxHave, PAIR_RX_OOB))
      {
         return -EALREADY;
      }
   }
   else
   {
      return -EINVAL;
   }

   // Check if the other object is not being received at the same time
   if (!atomic_cas(&st_rxType, 0, (atomic_val_t)u8_appType))
   {
      return -EBUSY;
   }

   return 0;
}

/**
 * @private       si_PairRxData
 * @brief         SETURxData_F: copy an in-order chunk.
 * @param[in]     u8_appType appType of the transfer.
 * @param[in]     u32_offset Offset of the chunk.
 * @param[in]     u8pt_data Chunk.
 * @param[in]     u16_len Chunk length.
 * @return        0, or -EIO if the chunk does not fit (aborts the transfer).
 */
static int si_PairRxData(uint8_t u8_appType, uint32_t u32_offset,
   const uint8_t *u8pt_data, uint16_t u16_len)
{
   uint8_t *u8pt_dst = (u8_appType == PAIR_APP_TYPE_PEER_CERT) ? su8ar_rxCert : su8ar_rxOob;
   uint32_t u32_size = (u8_appType == PAIR_APP_TYPE_PEER_CERT) ?
      sizeof(su8ar_rxCert) : sizeof(su8ar_rxOob);

   // Check if this is the accepted transfer and the chunk fits
   if ((atomic_get(&st_rxType) != (atomic_val_t)u8_appType) ||
      (u32_offset > u32_size) || (u16_len > (u32_size - u32_offset)))
   {
      return -EIO;
   }

   (void)memcpy(&u8pt_dst[u32_offset], u8pt_data, u16_len);

   return 0;
}

/**
 * @private       sv_PairRxDone
 * @brief         SETURxDone_F: record the object and post the result.
 * @param[in]     u8_appType appType of the transfer.
 * @param[in]     e_status Result.
 * @param[in]     u32_totalLen Unused.
 * @return        None.
 */
static void sv_PairRxDone(uint8_t u8_appType, SETUStatus_E e_status, uint32_t u32_totalLen)
{
   PairEvent_T st_event;

   ARG_UNUSED(u32_totalLen);

   // Check if this is the transfer that was accepted
   if (!atomic_cas(&st_rxType, (atomic_val_t)u8_appType, 0))
   {
      return;
   }

   // Check if it arrived intact: it counts as received
   if (e_status == eBS_OK)
   {
      atomic_set_bit(&st_rxHave,
         (u8_appType == PAIR_APP_TYPE_PEER_CERT) ? PAIR_RX_CERT : PAIR_RX_OOB);
   }

   (void)memset(&st_event, 0, sizeof(st_event));
   st_event.u8_type = ePEV_RX_DONE;
   st_event.u8_appType = u8_appType;
   st_event.u8_status = (uint8_t)e_status;
   sv_Post(&st_event);
}

/**
 * @private       sv_PairTxDone
 * @brief         SETUTxDone_F (routed by appType): post the result.
 * @param[in]     u8_appType appType of the transfer.
 * @param[in]     e_status Result.
 * @return        None.
 */
static void sv_PairTxDone(uint8_t u8_appType, SETUStatus_E e_status)
{
   PairEvent_T st_event;

   (void)memset(&st_event, 0, sizeof(st_event));
   st_event.u8_type = ePEV_TX_DONE;
   st_event.u8_appType = u8_appType;
   st_event.u8_status = (uint8_t)e_status;
   sv_Post(&st_event);
}

/**
 * @private       sv_PairCliReady
 * @brief         SETUCliReady_F: the attach this module asked for ended.
 * @param[in]     stpt_conn Unused.
 * @param[in]     i_status 0 or negative errno.
 * @return        None.
 */
static void sv_PairCliReady(struct bt_conn *stpt_conn, int i_status)
{
   ARG_UNUSED(stpt_conn);

   sv_PostSimple(ePEV_CLI_READY, i_status);
}

/**
 * @private       se_PairingAccept
 * @brief         SMP pairing_accept (BT context): pairing is allowed only on
 *                the peer link, once its certificate has verified.
 * @param[in]     stpt_conn Link that pairs.
 * @param[in]     stpt_feat Unused.
 * @return        BT_SECURITY_ERR_SUCCESS, or BT_SECURITY_ERR_PAIR_NOT_ALLOWED.
 */
static enum bt_security_err se_PairingAccept(struct bt_conn *stpt_conn,
   const struct bt_conn_pairing_feat *const stpt_feat)
{
   PairState_E e_state = (PairState_E)atomic_get(&st_state);

   ARG_UNUSED(stpt_feat);

   // Check if it is the peer link of a run past certificate verification
   if ((stpt_conn == atomic_ptr_get(&st_peerConn)) &&
      (e_state >= ePST_CERT_VERIFIED) && (e_state <= ePST_PAIRING))
   {
      return BT_SECURITY_ERR_SUCCESS;
   }

   APP_LOG_WRN("pairing refused on this link");
   return BT_SECURITY_ERR_PAIR_NOT_ALLOWED;
}

/**
 * @private       sv_OobDataRequest
 * @brief         SMP oob_data_request (BT context): post it; the answer comes
 *                from the pairing thread.
 * @param[in]     stpt_conn Link that pairs.
 * @param[in]     stpt_info OOB method and which data is needed.
 * @return        None.
 */
static void sv_OobDataRequest(struct bt_conn *stpt_conn, struct bt_conn_oob_info *stpt_info)
{
   // Check if it is the peer link
   if (stpt_conn != atomic_ptr_get(&st_peerConn))
   {
      (void)bt_conn_auth_cancel(stpt_conn);
      return;
   }

   sv_PostSimple(ePEV_OOB_REQUEST, (stpt_info->type == BT_CONN_OOB_LE_SC) ?
      (int32_t)stpt_info->lesc.oob_config : -1);
}

/**
 * @private       sv_PairingComplete
 * @brief         SMP pairing_complete (BT context).
 * @param[in]     stpt_conn Link that paired.
 * @param[in]     b_bonded Keys were stored.
 * @return        None.
 */
static void sv_PairingComplete(struct bt_conn *stpt_conn, bool b_bonded)
{
   PairEvent_T st_event;

   // Check if it is the peer link
   if (stpt_conn != atomic_ptr_get(&st_peerConn))
   {
      return;
   }

   (void)memset(&st_event, 0, sizeof(st_event));
   st_event.u8_type = ePEV_PAIRING_DONE;
   st_event.u8_status = b_bonded ? 1U : 0U;
   st_event.i32_value = (int32_t)bt_conn_get_security(stpt_conn);
   sv_Post(&st_event);
}

/**
 * @private       sv_PairingFailed
 * @brief         SMP pairing_failed (BT context).
 * @param[in]     stpt_conn Link that failed.
 * @param[in]     e_reason Reason.
 * @return        None.
 */
static void sv_PairingFailed(struct bt_conn *stpt_conn, enum bt_security_err e_reason)
{
   // Check if it is the peer link
   if (stpt_conn == atomic_ptr_get(&st_peerConn))
   {
      sv_PostSimple(ePEV_PAIRING_FAILED, (int32_t)e_reason);
   }
}

/**
 * @private       su8_SecuredDiscovered
 * @brief         Central: SECURED found (or not) on the peer; write it.
 * @param[in]     stpt_conn Peer link.
 * @param[in]     stpt_attr Characteristic declaration, or NULL at the end.
 * @param[in]     stpt_params Discovery parameters.
 * @return        BT_GATT_ITER_STOP.
 */
static uint8_t su8_SecuredDiscovered(struct bt_conn *stpt_conn,
   const struct bt_gatt_attr *stpt_attr, struct bt_gatt_discover_params *stpt_params)
{
   const struct bt_gatt_chrc *stpt_chrc = NULL;
   int i_ret;

   ARG_UNUSED(stpt_params);

   // Check if the peer has the characteristic
   if (stpt_attr == NULL)
   {
      sv_PostSimple(ePEV_SECURED_TX, -ENOENT);
      return BT_GATT_ITER_STOP;
   }

   stpt_chrc = (const struct bt_gatt_chrc *)stpt_attr->user_data;
   (void)memset(&sst_writeParams, 0, sizeof(sst_writeParams));
   sst_writeParams.func = sv_SecuredWritten;
   sst_writeParams.handle = stpt_chrc->value_handle;
   sst_writeParams.offset = 0U;
   sst_writeParams.data = &scu8_securedValue;
   sst_writeParams.length = sizeof(scu8_securedValue);

   i_ret = bt_gatt_write(stpt_conn, &sst_writeParams);

   // Check if the write was sent
   if (i_ret != 0)
   {
      sv_PostSimple(ePEV_SECURED_TX, i_ret);
   }

   return BT_GATT_ITER_STOP;
}

/**
 * @private       sv_SecuredWritten
 * @brief         Central: the peer answered the SECURED write.
 * @param[in]     stpt_conn Unused.
 * @param[in]     u8_err ATT error, 0 on success.
 * @param[in]     stpt_params Unused.
 * @return        None.
 */
static void sv_SecuredWritten(struct bt_conn *stpt_conn, uint8_t u8_err,
   struct bt_gatt_write_params *stpt_params)
{
   ARG_UNUSED(stpt_conn);
   ARG_UNUSED(stpt_params);

   sv_PostSimple(ePEV_SECURED_TX, (int32_t)u8_err);
}

/******************************************************************************/
/*                                                                            */
/*                        PUBLIC FUNCTION DEFINITIONS                         */
/*                                                                            */
/******************************************************************************/
/**
 * @public        gi_Pair_Init
 * @brief         Register the pairing appType range (with its Client callbacks)
 *                with the SETU router and the SMP callbacks with the stack,
 *                and set up the DK LEDs.
 *                Call once from main(), before gi_SETURouter_Start() and
 *                before advertising.
 * @return        0 on success, otherwise the error of gi_SETURouter_Register(),
 *                bt_conn_auth_cb_register() or bt_conn_auth_info_cb_register().
 */
int gi_Pair_Init(void)
{
   SETURoute_T st_route = { 0 };
   int i_ret;

   st_route.u8_firstAppType = PAIR_APP_TYPE_FIRST;
   st_route.u8_lastAppType = PAIR_APP_TYPE_LAST;
   st_route.fpt_onRxStart = si_PairRxStart;
   st_route.fpt_onRxData = si_PairRxData;
   st_route.fpt_onRxDone = sv_PairRxDone;
   st_route.fpt_onTxDone = sv_PairTxDone;
   st_route.fpt_onCliReady = sv_PairCliReady;

   i_ret = gi_SETURouter_Register(&st_route);

   // Check if the pairing range was registered
   if (i_ret != 0)
   {
      APP_LOG_ERR("gi_SETURouter_Register failed (%d)", i_ret);
      return i_ret;
   }

   // The LED shows a proven link; without it pairing still works
   if (dk_leds_init() != 0)
   {
      APP_LOG_WRN("DK LEDs not available");
   }

   i_ret = bt_conn_auth_cb_register(&sst_authCb);

   // Check if the SMP callbacks were taken
   if (i_ret != 0)
   {
      APP_LOG_ERR("bt_conn_auth_cb_register failed (%d)", i_ret);
      return i_ret;
   }

   i_ret = bt_conn_auth_info_cb_register(&sst_authInfoCb);

   // Check if the SMP result callbacks were taken
   if (i_ret != 0)
   {
      APP_LOG_ERR("bt_conn_auth_info_cb_register failed (%d)", i_ret);
   }

   return i_ret;
}

/**
 * @public        gv_Pair_OnBtReady
 * @brief         The stack is enabled and its settings (bonds) loaded. Call
 *                from _BLE once, after settings_load() and before advertising.
 * @return        None.
 */
void gv_Pair_OnBtReady(void)
{
   sv_PostSimple(ePEV_BT_READY, 0);
}

/**
 * @public        gb_Pair_ClaimConn
 * @brief         Whether a new connection is the peer link this module waits
 *                for: a run's, or the bonded peer's while it is not connected
 *                (BT context, from bt_conn_cb.connected, also for a failed
 *                connection). A claimed link is not a host link.
 * @param[in]     stpt_conn New connection.
 * @param[in]     u8_err HCI error of the connection (0 when it is up).
 * @return        true if it belongs to the pairing run or the bond.
 */
bool gb_Pair_ClaimConn(struct bt_conn *stpt_conn, uint8_t u8_err)
{
   const bt_addr_le_t *stpt_dst = bt_conn_get_dst(stpt_conn);
   PairState_E e_state = (PairState_E)atomic_get(&st_state);
   bool b_run = (e_state == ePST_ARMED);
   bool b_bond = (e_state == ePST_PAIRED) && (atomic_get(&st_bondRole) != ePRL_NONE) &&
      (atomic_ptr_get(&st_peerConn) == NULL);

   // Check if a run or the bond waits for a link from (or to) its peer
   if ((!b_run && !b_bond) || (stpt_dst == NULL) ||
      (bt_addr_le_cmp(stpt_dst, &sst_peerAddr) != 0))
   {
      return false;
   }

   // Check if the link came up: hold it for the run or the bond
   if (u8_err == 0U)
   {
      (void)atomic_ptr_set(&st_peerConn, bt_conn_ref(stpt_conn));
   }

   sv_PostSimple(b_run ? ePEV_CONNECTED : ePEV_RECONNECTED, (int32_t)u8_err);

   return true;
}

/**
 * @public        gv_Pair_OnDisconnected
 * @brief         A connection went down (BT context, from
 *                bt_conn_cb.disconnected). Only the peer link matters here.
 * @param[in]     stpt_conn Connection.
 * @param[in]     u8_reason HCI reason.
 * @return        None.
 */
void gv_Pair_OnDisconnected(struct bt_conn *stpt_conn, uint8_t u8_reason)
{
   PairEvent_T st_event;

   // Check if it is the peer link; it is released now, its reference by the
   // pairing thread
   if ((stpt_conn != NULL) && atomic_ptr_cas(&st_peerConn, stpt_conn, NULL))
   {
      (void)memset(&st_event, 0, sizeof(st_event));
      st_event.u8_type = ePEV_DISCONNECTED;
      st_event.i32_value = (int32_t)u8_reason;
      st_event.stpt_conn = stpt_conn;
      sv_Post(&st_event);
   }
}

/**
 * @public        gv_Pair_OnSecurityChanged
 * @brief         A connection's security changed (BT context, from
 *                bt_conn_cb.security_changed). Only the peer link matters here.
 * @param[in]     stpt_conn Connection.
 * @param[in]     u8_level New security level (bt_security_t).
 * @param[in]     u8_err bt_security_err, 0 on success.
 * @return        None.
 */
void gv_Pair_OnSecurityChanged(struct bt_conn *stpt_conn, uint8_t u8_level, uint8_t u8_err)
{
   PairEvent_T st_event;

   // Check if it is the peer link
   if ((stpt_conn == NULL) || (stpt_conn != atomic_ptr_get(&st_peerConn)))
   {
      return;
   }

   (void)memset(&st_event, 0, sizeof(st_event));
   st_event.u8_type = ePEV_SECURITY;
   st_event.i32_value = (int32_t)u8_level;
   st_event.u8_status = u8_err;
   sv_Post(&st_event);
}

/**
 * @public        gb_Pair_AwaitsBondedPeer
 * @brief         Whether this device is a bonded peripheral whose central is
 *                not connected: ConnectionHandling.c then advertises even with
 *                a host connected, so the central can reconnect. Any thread.
 * @return        true while the bonded central is awaited.
 */
bool gb_Pair_AwaitsBondedPeer(void)
{
   return (atomic_get(&st_state) == ePST_PAIRED) &&
      (atomic_get(&st_bondRole) == ePRL_PERIPHERAL) &&
      (atomic_ptr_get(&st_peerConn) == NULL);
}

/**
 * @public        gb_Pair_IsAdvertising
 * @brief         Whether this module uses the advertiser (directed to the
 *                peer); ConnectionHandling.c then leaves it alone.
 * @return        true while directed advertising runs or is being started.
 */
bool gb_Pair_IsAdvertising(void)
{
   return atomic_get(&st_dirAdv) != 0;
}

/**
 * @public        gt_Pair_OnControlWrite
 * @brief         CONTROL write from the host (BT context). Malformed commands
 *                and a START during a run are refused with an ATT error; every
 *                other outcome is reported in STATUS.
 * @param[in]     stpt_conn Link that wrote.
 * @param[in]     u8pt_data Command.
 * @param[in]     u16_len Command length.
 * @return        0 to accept; BT_GATT_ERR(): WRITE_NOT_PERMITTED from the peer
 *                link, INVALID_ATTRIBUTE_LEN for a wrong length,
 *                VALUE_NOT_ALLOWED for an unknown opcode, role or address type,
 *                PROCEDURE_IN_PROGRESS for START during a run,
 *                INSUFFICIENT_RESOURCES if the event queue is full.
 */
ssize_t gt_Pair_OnControlWrite(struct bt_conn *stpt_conn, const uint8_t *u8pt_data,
   uint16_t u16_len)
{
   PairEvent_T st_event;

   // Check if the peer device tries to drive this device
   if ((stpt_conn != NULL) && (stpt_conn == atomic_ptr_get(&st_peerConn)))
   {
      return BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED);
   }

   // Check if there is an opcode
   if ((u8pt_data == NULL) || (u16_len == 0U))
   {
      return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
   }

   (void)memset(&st_event, 0, sizeof(st_event));

   switch (u8pt_data[0])
   {
      case PAIR_OP_START:
         // Check if the command is complete and valid
         if (u16_len != PAIR_START_LEN)
         {
            return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
         }
         if (((u8pt_data[1] != (uint8_t)ePRL_CENTRAL) &&
               (u8pt_data[1] != (uint8_t)ePRL_PERIPHERAL)) ||
            ((u8pt_data[2] != BT_ADDR_LE_PUBLIC) && (u8pt_data[2] != BT_ADDR_LE_RANDOM)))
         {
            return BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED);
         }
         // Check if a run is in progress
         if (gb_Pair_IsRunning())
         {
            return BT_GATT_ERR(BT_ATT_ERR_PROCEDURE_IN_PROGRESS);
         }
         st_event.u8_type = ePEV_START;
         st_event.u8_role = u8pt_data[1];
         st_event.st_addr.type = u8pt_data[2];
         (void)memcpy(st_event.st_addr.a.val, &u8pt_data[3], sizeof(st_event.st_addr.a.val));
         break;

      case PAIR_OP_CANCEL:
      case PAIR_OP_UNPAIR:
         // Check if the command has no payload
         if (u16_len != 1U)
         {
            return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
         }
         st_event.u8_type = (u8pt_data[0] == PAIR_OP_CANCEL) ? ePEV_CANCEL : ePEV_UNPAIR;
         break;

      default:
         return BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED);
   }

   // Check if the pairing thread can take it
   if (k_msgq_put(&sst_pairMsgq, &st_event, K_NO_WAIT) != 0)
   {
      return BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES);
   }

   return 0;
}

/**
 * @public        gt_Pair_OnSecuredWrite
 * @brief         SECURED write (BT context). The stack has already refused it on
 *                a link below level 4; here it must come from the peer link,
 *                to a peripheral that is pairing, with PAIR_SECURED_VALUE.
 * @param[in]     stpt_conn Link that wrote.
 * @param[in]     u8pt_data Written bytes.
 * @param[in]     u16_len Number of bytes.
 * @return        0 to accept; BT_GATT_ERR(WRITE_NOT_PERMITTED) or
 *                BT_GATT_ERR(VALUE_NOT_ALLOWED) otherwise.
 */
ssize_t gt_Pair_OnSecuredWrite(struct bt_conn *stpt_conn, const uint8_t *u8pt_data,
   uint16_t u16_len)
{
   // Check if the paired peer writes it during the run
   if ((stpt_conn == NULL) || (stpt_conn != atomic_ptr_get(&st_peerConn)) ||
      (atomic_get(&st_state) != ePST_PAIRING))
   {
      return BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED);
   }

   // Check if the value is the one expected
   if ((u8pt_data == NULL) || (u16_len != 1U) || (u8pt_data[0] != PAIR_SECURED_VALUE))
   {
      return BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED);
   }

   sv_PostSimple(ePEV_SECURED_RX, 0);

   return 0;
}

/**
 * @public        gv_Pair_GetStatus
 * @brief         Current STATUS: [u8 state][u8 error][u8 detail][u8 provState]
 *                [u8 role][7 B own address][7 B peer address]. Any thread.
 * @param[out]    u8pt_status PAIR_STATUS_LEN bytes.
 * @return        None.
 */
void gv_Pair_GetStatus(uint8_t *u8pt_status)
{
   (void)k_mutex_lock(&sst_statusLock, K_FOREVER);
   u8pt_status[0] = (uint8_t)atomic_get(&st_state);
   u8pt_status[1] = (uint8_t)se_error;
   u8pt_status[2] = su8_detail;
   u8pt_status[3] = (uint8_t)ge_Prov_GetState();
   u8pt_status[4] = (uint8_t)se_role;
   u8pt_status[5] = sst_ownAddr.type;
   (void)memcpy(&u8pt_status[6], sst_ownAddr.a.val, 6U);
   u8pt_status[12] = sst_peerAddr.type;
   (void)memcpy(&u8pt_status[13], sst_peerAddr.a.val, 6U);
   k_mutex_unlock(&sst_statusLock);
}

/**
 * @public        gb_Pair_IsRunning
 * @brief         Whether a pairing run is in progress (any thread).
 * @return        true from START until PAIRED or FAILED.
 */
bool gb_Pair_IsRunning(void)
{
   return sb_IsRunningState((PairState_E)atomic_get(&st_state));
}

/**
 * @public        gv_Pair_ForgetBonds
 * @brief         Provisioning wipe: drop the peer link and every bond (the
 *                identity they were made with is gone). Any thread; done by
 *                the pairing thread.
 * @return        None.
 */
void gv_Pair_ForgetBonds(void)
{
   sv_PostSimple(ePEV_FORGET, 0);
}

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shivam Chudasama [SC]
 */
