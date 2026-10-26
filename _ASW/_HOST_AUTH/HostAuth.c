/**
 * @file          HostAuth.c
 * @brief         Source file containing host authentication.
 *
 *                The host (the PC GUI) holds a host certificate of this
 *                device's CA (EKU clientAuth). On the host link it runs, in the
 *                appType range HOST_AUTH_APP_TYPE_FIRST..LAST:
 *                - HELLO [ver][Nh][Qh][host cert] -> the device verifies the
 *                  certificate against its CA (ge_VerifyHostCertificate()),
 *                  makes Nd and an ephemeral key, and sends CHALLENGE
 *                  [ver][Nd][Qd][SigD][device cert] with its SETU Client to the
 *                  host's SETU service;
 *                - FINISH [SigH] -> the device checks the host's signature over
 *                  the transcript (RESULT OK), and both now know the passkey
 *                  derived from the ECDH secret (HostAuthCrypto.c);
 *                - the host pairs (LE Secure Connections, passkey entry with
 *                  that passkey). This link's SMP callbacks are this module's
 *                  (bt_conn_auth_cb_overlay()): pairing is accepted only after
 *                  FINISH on this link, and the passkey is the derived one
 *                  (app_passkey: the device acts as DisplayOnly). A bonded,
 *                  level 4 result makes the host the one trusted host; an
 *                  older host bond is deleted.
 *                A bonded host that reconnects is asked for security (level 4)
 *                and trusted once the link is encrypted with its keys.
 *
 *                The router's gate (gb_HostAuth_Admits()) lets the host link
 *                reach only this range and provisioning's GET_STATUS until the
 *                host is trusted; an unprovisioned device admits provisioning
 *                too. Pairing CONTROL asks gb_HostAuth_IsTrustedConn().
 *
 *                Advertising for a host runs only while the host window is
 *                open: HostAuthButton.c opens it (and, held, forgets the host
 *                first); it closes when a host connects or after
 *                CONFIG_HOST_AUTH_WINDOW_MS. A trusted host's link loss opens
 *                it for CONFIG_HOST_AUTH_GRACE_MS. LED1 (DK_LED2) blinks while
 *                it is open and is lit while a trusted host is connected.
 *
 *                SETU and BT callbacks only check, copy and post; everything
 *                else runs on this module's low-priority thread.
 * @date          25/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include "HostAuth.h"
#include <errno.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/settings/settings.h>
#include <dk_buttons_and_leds.h>
#include <psa/crypto.h>
#include "SETU.h"
#include "SETURouter.h"
#include "HostAuthCrypto.h"
#include "CSR_Generator.h"
#include "DeviceCert.h"
#include "DeviceCert_Verify.h"
#include "Prov.h"
#include "AppLog.h"

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
#ifndef CONFIG_HOST_AUTH_WINDOW_MS
#define CONFIG_HOST_AUTH_WINDOW_MS           (120000)
#endif // CONFIG_HOST_AUTH_WINDOW_MS

#ifndef CONFIG_HOST_AUTH_GRACE_MS
#define CONFIG_HOST_AUTH_GRACE_MS            (60000)
#endif // CONFIG_HOST_AUTH_GRACE_MS

#ifndef CONFIG_HOST_AUTH_TIMEOUT_MS
#define CONFIG_HOST_AUTH_TIMEOUT_MS          (30000)
#endif // CONFIG_HOST_AUTH_TIMEOUT_MS

#ifndef CONFIG_HOST_AUTH_STACK_SIZE
#define CONFIG_HOST_AUTH_STACK_SIZE          (6144)
#endif // CONFIG_HOST_AUTH_STACK_SIZE

/**
 * @def           HOST_AUTH_PRIORITY
 * @brief         Thread priority: below the SETU engine and the BT stack, as
 *                provisioning.
 */
#define HOST_AUTH_PRIORITY                   (10)

/**
 * @def           HOST_AUTH_EVENT_QUEUE_LEN
 * @brief         Events the thread can hold.
 */
#define HOST_AUTH_EVENT_QUEUE_LEN            (8U)

/**
 * @def           HOST_AUTH_SHORT_TIMEOUT_MS
 * @brief         How long a reply waits for an ATT credit.
 */
#define HOST_AUTH_SHORT_TIMEOUT_MS           (100)

/**
 * @def           HOST_AUTH_LED
 * @brief         DK LED of the host window and the trusted host (LED1).
 */
#define HOST_AUTH_LED                        (DK_LED2)

/**
 * @def           HOST_AUTH_BLINK_MS
 * @brief         Half period of the LED while the window is open.
 */
#define HOST_AUTH_BLINK_MS                   (250)

/**
 * @def           HOST_AUTH_HELLO_HDR_LEN
 * @brief         HELLO bytes before the certificate: [ver][Nh][Qh].
 */
#define HOST_AUTH_HELLO_HDR_LEN              (1U + HOST_AUTH_NONCE_LEN + HOST_AUTH_POINT_LEN)

/**
 * @def           HOST_AUTH_HELLO_MAX_LEN
 * @brief         Longest HELLO (certificate of DEVICE_CERT_MAX_DER_LEN bytes).
 */
#define HOST_AUTH_HELLO_MAX_LEN              (HOST_AUTH_HELLO_HDR_LEN + DEVICE_CERT_MAX_DER_LEN)

/**
 * @def           HOST_AUTH_CHALLENGE_HDR_LEN
 * @brief         CHALLENGE bytes before the certificate: [ver][Nd][Qd][SigD].
 */
#define HOST_AUTH_CHALLENGE_HDR_LEN          (1U + HOST_AUTH_NONCE_LEN + HOST_AUTH_POINT_LEN + \
                                              HOST_AUTH_SIG_LEN)

/**
 * @def           HOST_AUTH_SETTINGS_SUBTREE
 * @brief         Settings subtree of the host bond record.
 */
#define HOST_AUTH_SETTINGS_SUBTREE           "hauth"

/**
 * @def           HOST_AUTH_SETTINGS_KEY
 * @brief         Key of the record: [u8 address type][6 B address].
 */
#define HOST_AUTH_SETTINGS_KEY               "host"

/**
 * @def           HOST_AUTH_RECORD_LEN
 * @brief         Length of the host bond record.
 */
#define HOST_AUTH_RECORD_LEN                 (7U)

/******************************************************************************/
/*                                                                            */
/*                                   ENUMS                                    */
/*                                                                            */
/******************************************************************************/
/**
 * @enum          HostAuthPhase_E
 * @brief         Where the host link is.
 */
typedef enum
{
   eHAP_NONE = 0,                            /**< No host link                      */
   eHAP_LINK,                                /**< Host link up, not authenticated   */
   eHAP_AWAIT_FINISH,                        /**< CHALLENGE being sent or sent      */
   eHAP_AWAIT_PAIRING,                       /**< FINISH verified                   */
   eHAP_TRUSTED,                             /**< The bonded host at level 4        */
} HostAuthPhase_E;

/**
 * @enum          HostAuthEventType_E
 * @brief         Events posted to the thread.
 */
typedef enum
{
   eHAE_STATUS_REQ = 0,                      /**< STATUS_REQ received                 */
   eHAE_HELLO,                               /**< HELLO in staging (i32 = length)     */
   eHAE_REJECTED,                            /**< Transfer refused at START (status)  */
   eHAE_FINISH,                              /**< FINISH (u8ar_data, i32 = length)    */
   eHAE_CLI_READY,                           /**< Client attach result (i32)          */
   eHAE_TX_DONE,                             /**< CHALLENGE transfer result (status)  */
   eHAE_REFUSED,                             /**< Gate refused appType                */
   eHAE_CONNECTED,                           /**< Host link up (conn)                 */
   eHAE_DISCONNECTED,                        /**< Host link down (conn)               */
   eHAE_SECURITY,                            /**< Security changed (i32 level, status)*/
   eHAE_PAIRED,                              /**< Pairing complete (i32 bonded)       */
   eHAE_PAIR_FAILED,                         /**< Pairing failed (i32 reason)         */
   eHAE_TIMEOUT,                             /**< Handshake took too long             */
   eHAE_WINDOW_OPEN,                         /**< Button: open the window             */
   eHAE_FORGET_OPEN,                         /**< Button held: forget host, open      */
   eHAE_WINDOW_CLOSED,                       /**< Window timer ran out                */
   eHAE_FORGET,                              /**< Provisioning wipe                   */
   eHAE_BT_READY,                            /**< Stack up, settings loaded           */
} HostAuthEventType_E;

/******************************************************************************/
/*                                                                            */
/*                                 STRUCTURES                                 */
/*                                                                            */
/******************************************************************************/
/**
 * @struct        HostAuthEvent_T
 * @brief         One queued event.
 */
typedef struct
{
   uint8_t u8_type;                          /**< HostAuthEventType_E                 */
   uint8_t u8_appType;                       /**< appType the event refers to         */
   uint8_t u8_status;                        /**< Status carried                      */
   int32_t i32_value;                        /**< Length, level, reason or error      */
   struct bt_conn *stpt_conn;                /**< Connection (compared only)          */
   uint8_t u8ar_data[HOST_AUTH_SIG_LEN];     /**< FINISH signature                    */
} HostAuthEvent_T;

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
static void sv_Post(const HostAuthEvent_T *stpt_event);
static void sv_PostSimple(uint8_t u8_type, uint8_t u8_appType, uint8_t u8_status, int32_t i32_value,
   struct bt_conn *stpt_conn);
static bool sb_IsProvisioned(void);
static bool sb_LinkIsBondedHost(struct bt_conn *stpt_conn);
static int si_HauthRxStart(uint8_t u8_appType, uint32_t u32_totalLen);
static int si_HauthRxData(uint8_t u8_appType, uint32_t u32_offset,
   const uint8_t *u8pt_data, uint16_t u16_len);
static void sv_HauthRxDone(uint8_t u8_appType, SETUStatus_E e_status, uint32_t u32_totalLen);
static void sv_HauthRxShort(uint8_t u8_appType, const uint8_t *u8pt_data, uint8_t u8_len);
static void sv_HauthCliReady(struct bt_conn *stpt_conn, int i_status);
static void sv_HauthTxDone(uint8_t u8_appType, SETUStatus_E e_status);
static void sv_GateRefused(uint8_t u8_appType);
static enum bt_security_err se_PairingAccept(struct bt_conn *stpt_conn,
   const struct bt_conn_pairing_feat *const stpt_feat);
static uint32_t su32_AppPasskey(struct bt_conn *stpt_conn);
static void sv_AuthCancel(struct bt_conn *stpt_conn);
static void sv_PairingComplete(struct bt_conn *stpt_conn, bool b_bonded);
static void sv_PairingFailed(struct bt_conn *stpt_conn, enum bt_security_err e_reason);
static void sv_SendShort(uint8_t u8_appType, const uint8_t *u8pt_payload, uint8_t u8_len);
static void sv_SendResult(uint8_t u8_refAppType, HostAuthResult_E e_status, uint8_t u8_detail);
static void sv_SendStatus(void);
static void sv_EndSession(void);
static void sv_FailSession(uint8_t u8_refAppType, HostAuthResult_E e_status, uint8_t u8_detail);
static void sv_HandleHello(uint32_t u32_len);
static void sv_SendChallenge(void);
static void sv_HandleFinish(const HostAuthEvent_T *stpt_event);
static void sv_EvaluateTrust(void);
static void sv_HandlePaired(bool b_bonded);
static void sv_SaveHost(const bt_addr_le_t *stpt_addr);
static void sv_ForgetHost(void);
static void sv_SetWindow(bool b_open, int32_t i32_ms);
static void sv_UpdateLed(void);
static void sv_HandleBtReady(void);
static void sv_BondCheck(const struct bt_bond_info *stpt_info, void *vpt_user);
static void sv_HandleEvent(const HostAuthEvent_T *stpt_event);
static void sv_WindowWork(struct k_work *stpt_work);
static void sv_TimeoutWork(struct k_work *stpt_work);
static void sv_LedWork(struct k_work *stpt_work);
static int si_SettingsSet(const char *cpt_key, size_t t_len, settings_read_cb fpt_read,
   void *vpt_arg);
static void sv_HostAuthThread(void *vpt_p1, void *vpt_p2, void *vpt_p3);

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
 * @var           st_phase
 * @brief         HostAuthPhase_E. Written by the thread (and set to NONE by
 *                the disconnect hook), read by the gate and the BT callbacks.
 */
static atomic_t st_phase = ATOMIC_INIT(eHAP_NONE);

/**
 * @var           st_hostConn
 * @brief         The host link (a reference held from OnHostConnected until
 *                the thread handles the disconnect), or NULL.
 */
static atomic_ptr_t st_hostConn = ATOMIC_PTR_INIT(NULL);

/**
 * @var           st_hostBonded
 * @brief         1 while a host bond record is held (sst_hostAddr is valid).
 */
static atomic_t st_hostBonded = ATOMIC_INIT(0);

/**
 * @var           sst_hostAddr
 * @brief         Identity address of the bonded host. Written by the thread
 *                and by settings_load(), read from BT contexts under
 *                sst_addrLock.
 */
static bt_addr_le_t sst_hostAddr;

/**
 * @var           st_window
 * @brief         1 while the host window is open (undirected advertising).
 */
static atomic_t st_window = ATOMIC_INIT(0);

/**
 * @var           si64_windowEndMs
 * @brief         Uptime at which the last opened window ends; kept when a host
 *                connection closes the window early, so an untrusted host's
 *                loss gives back the rest of it (0: none). Thread only.
 */
static int64_t si64_windowEndMs;

/**
 * @var           st_bufBusy
 * @brief         1 from an accepted HELLO START until su8ar_buf is free again:
 *                HELLO refused or failed, or the CHALLENGE transfer ended (or
 *                never started).
 */
static atomic_t st_bufBusy = ATOMIC_INIT(0);

/**
 * @var           st_passkey
 * @brief         Passkey of the pairing that FINISH allows (app_passkey).
 */
static atomic_t st_passkey = ATOMIC_INIT(0);

/**
 * @var           sb_challengePending
 * @brief         CHALLENGE is built and waits for the Client (thread only).
 */
static bool sb_challengePending = false;

/**
 * @var           st_hostKey
 * @brief         The host's public key from its verified certificate, until
 *                FINISH is checked (0: none). Thread only.
 */
static psa_key_id_t st_hostKey = 0;

/**
 * @var           su8ar_buf
 * @brief         HELLO being received, then (once the transcript is made) the
 *                CHALLENGE being sent, unchanged until its transfer ends. One
 *                buffer for both: HELLO is not needed any more by then.
 */
static uint8_t su8ar_buf[HOST_AUTH_CHALLENGE_HDR_LEN + DEVICE_CERT_MAX_DER_LEN];

/**
 * @var           su16_challengeLen
 * @brief         Length of the CHALLENGE in su8ar_buf.
 */
static uint16_t su16_challengeLen = 0U;

/**
 * @var           sb_challengeTx
 * @brief         The CHALLENGE transfer runs (su8ar_buf is SETU's until
 *                TX_DONE). Thread only.
 */
static bool sb_challengeTx = false;

/**
 * @var           su8ar_transcript
 * @brief         T of the running handshake.
 */
static uint8_t su8ar_transcript[HOST_AUTH_HASH_LEN];

/**
 * @var           sb_bondSeen
 * @brief         The record's bond was found at BT_READY (thread only).
 */
static bool sb_bondSeen = false;

/**
 * @var           sb_ledOn
 * @brief         Blink phase of the LED (LED work item only).
 */
static bool sb_ledOn = false;

/**
 * @var           sst_addrLock
 * @brief         Guards sst_hostAddr.
 */
static K_MUTEX_DEFINE(sst_addrLock);

/**
 * @var           sst_hostAuthCb
 * @brief         SMP callbacks of the host link (bt_conn_auth_cb_overlay()):
 *                app_passkey alone makes the device DisplayOnly, so the host
 *                enters the passkey, the one derived from the handshake.
 */
static const struct bt_conn_auth_cb sst_hostAuthCb = {
   .pairing_accept = se_PairingAccept,
   .app_passkey = su32_AppPasskey,
   .cancel = sv_AuthCancel,
};

/**
 * @var           sst_authInfoCb
 * @brief         SMP result callbacks (only the host link matters here).
 */
static struct bt_conn_auth_info_cb sst_authInfoCb = {
   .pairing_complete = sv_PairingComplete,
   .pairing_failed = sv_PairingFailed,
};

/**
 * @var           sst_windowWork
 * @brief         Closes the host window.
 */
static K_WORK_DELAYABLE_DEFINE(sst_windowWork, sv_WindowWork);

/**
 * @var           sst_timeoutWork
 * @brief         The handshake and pairing must end in CONFIG_HOST_AUTH_TIMEOUT_MS.
 */
static K_WORK_DELAYABLE_DEFINE(sst_timeoutWork, sv_TimeoutWork);

/**
 * @var           sst_ledWork
 * @brief         Drives (and blinks) the LED.
 */
static K_WORK_DELAYABLE_DEFINE(sst_ledWork, sv_LedWork);

/**
 * @var           settings_handler_hauth
 * @brief         Loads the host bond record (settings_load(), before BT_READY).
 */
SETTINGS_STATIC_HANDLER_DEFINE(hauth, HOST_AUTH_SETTINGS_SUBTREE, NULL, si_SettingsSet, NULL, NULL);

/**
 * @var           sst_hostAuthMsgq
 * @brief         Events to the thread.
 */
K_MSGQ_DEFINE(sst_hostAuthMsgq, sizeof(HostAuthEvent_T), HOST_AUTH_EVENT_QUEUE_LEN, 4);

/**
 * @var           sst_hostAuthThread
 * @brief         Host authentication thread.
 */
K_THREAD_DEFINE(sst_hostAuthThread, CONFIG_HOST_AUTH_STACK_SIZE, sv_HostAuthThread, NULL, NULL,
   NULL, HOST_AUTH_PRIORITY, 0, 0);

/******************************************************************************/
/*                                                                            */
/*                              EXTERN FUNCTIONS                              */
/*                                                                            */
/******************************************************************************/
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
 * @brief         Queue an event for the thread (never blocks).
 * @param[in]     stpt_event Event (copied).
 * @return        None.
 */
static void sv_Post(const HostAuthEvent_T *stpt_event)
{
   // Check if the queue is full
   if (k_msgq_put(&sst_hostAuthMsgq, stpt_event, K_NO_WAIT) != 0)
   {
      APP_LOG_WRN("event %u dropped: queue full", stpt_event->u8_type);
   }
}

/**
 * @private       sv_PostSimple
 * @brief         Queue an event without data.
 * @param[in]     u8_type HostAuthEventType_E.
 * @param[in]     u8_appType appType it refers to.
 * @param[in]     u8_status Status carried.
 * @param[in]     i32_value Value carried.
 * @param[in]     stpt_conn Connection carried (may be NULL).
 * @return        None.
 */
static void sv_PostSimple(uint8_t u8_type, uint8_t u8_appType, uint8_t u8_status, int32_t i32_value,
   struct bt_conn *stpt_conn)
{
   HostAuthEvent_T st_event;

   (void)memset(&st_event, 0, sizeof(st_event));
   st_event.u8_type = u8_type;
   st_event.u8_appType = u8_appType;
   st_event.u8_status = u8_status;
   st_event.i32_value = i32_value;
   st_event.stpt_conn = stpt_conn;
   sv_Post(&st_event);
}

/**
 * @private       sb_IsProvisioned
 * @brief         Whether the device holds its certificates (and so can
 *                authenticate a host).
 * @return        true when provisioned.
 */
static bool sb_IsProvisioned(void)
{
   return ge_Prov_GetState() == ePS_PROVISIONED;
}

/**
 * @private       sb_LinkIsBondedHost
 * @brief         Whether a link comes from the bonded host's address.
 * @param[in]     stpt_conn Link (may be NULL).
 * @return        true if a host is bonded and the link is from it.
 */
static bool sb_LinkIsBondedHost(struct bt_conn *stpt_conn)
{
   const bt_addr_le_t *stpt_dst;

   // Check if there is a link and a bonded host
   if ((stpt_conn == NULL) || (atomic_get(&st_hostBonded) == 0))
   {
      return false;
   }

   stpt_dst = bt_conn_get_dst(stpt_conn);

   return (stpt_dst != NULL) && gb_HostAuth_IsHostAddr(stpt_dst);
}

/**
 * @private       si_HauthRxStart
 * @brief         SETURxStart_F: accept a HELLO of HOST_AUTH_HELLO_HDR_LEN + 1 ..
 *                HOST_AUTH_HELLO_MAX_LEN bytes from a host link that is not
 *                authenticated, on a provisioned device, when no other host is
 *                bonded. A refusal is also reported with RESULT.
 * @param[in]     u8_appType Application type.
 * @param[in]     u32_totalLen Object size.
 * @return        0 to accept, -EPERM to reject.
 */
static int si_HauthRxStart(uint8_t u8_appType, uint32_t u32_totalLen)
{
   HostAuthResult_E e_reject = eHRS_OK;
   struct bt_conn *stpt_host = (struct bt_conn *)atomic_ptr_get(&st_hostConn);

   // Check if the type is the one transfer the device receives
   if (u8_appType != HOST_AUTH_APP_TYPE_HELLO)
   {
      e_reject = eHRS_BAD_STATE;
   }
   // Check if the device can authenticate (it needs its certificate)
   else if (!sb_IsProvisioned())
   {
      e_reject = eHRS_BAD_STATE;
   }
   // Check if there is a host link that is not trusted already
   else if ((stpt_host == NULL) || (atomic_get(&st_phase) == eHAP_NONE) ||
      (atomic_get(&st_phase) == eHAP_TRUSTED))
   {
      e_reject = eHRS_BAD_STATE;
   }
   // Check if a handshake is running on it
   else if (atomic_get(&st_phase) != eHAP_LINK)
   {
      e_reject = eHRS_BUSY;
   }
   // Check if another host holds the one bond
   else if ((atomic_get(&st_hostBonded) != 0) && !sb_LinkIsBondedHost(stpt_host))
   {
      e_reject = eHRS_HOST_BONDED;
   }
   // Check if the length can be a HELLO
   else if ((u32_totalLen <= HOST_AUTH_HELLO_HDR_LEN) || (u32_totalLen > HOST_AUTH_HELLO_MAX_LEN))
   {
      e_reject = eHRS_PARSE;
   }
   // Check if the staging buffer is free
   else if (!atomic_cas(&st_bufBusy, 0, 1))
   {
      e_reject = eHRS_BUSY;
   }

   // Check if the transfer is refused
   if (e_reject != eHRS_OK)
   {
      APP_LOG_WRN("rejected: type 0x%02x, %u bytes, status %u", u8_appType, u32_totalLen,
         (unsigned int)e_reject);
      sv_PostSimple(eHAE_REJECTED, u8_appType, (uint8_t)e_reject, 0, NULL);
      return -EPERM;
   }

   return 0;
}

/**
 * @private       si_HauthRxData
 * @brief         SETURxData_F: copy an in-order chunk of HELLO.
 * @param[in]     u8_appType Application type (checked at START).
 * @param[in]     u32_offset Object offset of the chunk.
 * @param[in]     u8pt_data Chunk data.
 * @param[in]     u16_len Chunk length.
 * @return        0, or -ENOSPC past the buffer (not reachable after START).
 */
static int si_HauthRxData(uint8_t u8_appType, uint32_t u32_offset,
   const uint8_t *u8pt_data, uint16_t u16_len)
{
   ARG_UNUSED(u8_appType);

   // Check if the chunk fits
   if ((u32_offset > HOST_AUTH_HELLO_MAX_LEN) ||
      ((uint32_t)u16_len > (HOST_AUTH_HELLO_MAX_LEN - u32_offset)))
   {
      return -ENOSPC;
   }

   (void)memcpy(&su8ar_buf[u32_offset], u8pt_data, u16_len);

   return 0;
}

/**
 * @private       sv_HauthRxDone
 * @brief         SETURxDone_F: hand a complete HELLO to the thread.
 * @param[in]     u8_appType Application type.
 * @param[in]     e_status Result of the transfer.
 * @param[in]     u32_totalLen Object size.
 * @return        None.
 */
static void sv_HauthRxDone(uint8_t u8_appType, SETUStatus_E e_status, uint32_t u32_totalLen)
{
   // Check if HELLO arrived complete
   if (e_status == eBS_OK)
   {
      sv_PostSimple(eHAE_HELLO, u8_appType, 0U, (int32_t)u32_totalLen, NULL);
   }
   else
   {
      APP_LOG_WRN("HELLO transfer failed, status %u", (unsigned int)e_status);
      (void)atomic_set(&st_bufBusy, 0);
   }
}

/**
 * @private       sv_HauthRxShort
 * @brief         SETURxShort_F: STATUS_REQ and FINISH; others are ignored.
 * @param[in]     u8_appType Application type.
 * @param[in]     u8pt_data Payload.
 * @param[in]     u8_len Payload length.
 * @return        None.
 */
static void sv_HauthRxShort(uint8_t u8_appType, const uint8_t *u8pt_data, uint8_t u8_len)
{
   HostAuthEvent_T st_event;

   // Check which message this is
   if (u8_appType == HOST_AUTH_APP_TYPE_STATUS_REQ)
   {
      sv_PostSimple(eHAE_STATUS_REQ, u8_appType, 0U, 0, NULL);
   }
   else if (u8_appType == HOST_AUTH_APP_TYPE_FINISH)
   {
      (void)memset(&st_event, 0, sizeof(st_event));
      st_event.u8_type = eHAE_FINISH;
      st_event.u8_appType = u8_appType;
      st_event.i32_value = (int32_t)u8_len;

      // Check if the payload has the signature's length (else PARSE on the thread)
      if ((u8pt_data != NULL) && (u8_len == HOST_AUTH_SIG_LEN))
      {
         (void)memcpy(st_event.u8ar_data, u8pt_data, HOST_AUTH_SIG_LEN);
      }
      sv_Post(&st_event);
   }
   else
   {
      APP_LOG_INF("short message type 0x%02x, %u bytes ignored", u8_appType, u8_len);
   }
}

/**
 * @private       sv_HauthCliReady
 * @brief         SETUCliReady_F: the Client attach for CHALLENGE ended.
 * @param[in]     stpt_conn Connection (unused).
 * @param[in]     i_status 0 when ready, negative errno otherwise.
 * @return        None.
 */
static void sv_HauthCliReady(struct bt_conn *stpt_conn, int i_status)
{
   ARG_UNUSED(stpt_conn);

   sv_PostSimple(eHAE_CLI_READY, HOST_AUTH_APP_TYPE_CHALLENGE, 0U, (int32_t)i_status, NULL);
}

/**
 * @private       sv_HauthTxDone
 * @brief         SETUTxDone_F: the CHALLENGE transfer ended.
 * @param[in]     u8_appType Application type.
 * @param[in]     e_status Result.
 * @return        None.
 */
static void sv_HauthTxDone(uint8_t u8_appType, SETUStatus_E e_status)
{
   sv_PostSimple(eHAE_TX_DONE, u8_appType, (uint8_t)e_status, 0, NULL);
}

/**
 * @private       sv_GateRefused
 * @brief         SETURouterRefused_F: tell the host what the gate refused.
 * @param[in]     u8_appType Refused appType.
 * @return        None.
 */
static void sv_GateRefused(uint8_t u8_appType)
{
   sv_PostSimple(eHAE_REFUSED, u8_appType, 0U, 0, NULL);
}

/**
 * @private       se_PairingAccept
 * @brief         SMP pairing_accept of the host link: only once FINISH has
 *                verified on this link (BT context).
 * @param[in]     stpt_conn Link.
 * @param[in]     stpt_feat Peer's pairing features (unused).
 * @return        BT_SECURITY_ERR_SUCCESS, or BT_SECURITY_ERR_PAIR_NOT_ALLOWED.
 */
static enum bt_security_err se_PairingAccept(struct bt_conn *stpt_conn,
   const struct bt_conn_pairing_feat *const stpt_feat)
{
   ARG_UNUSED(stpt_feat);

   // Check if this link has just authenticated
   if ((stpt_conn != NULL) && (stpt_conn == atomic_ptr_get(&st_hostConn)) &&
      (atomic_get(&st_phase) == eHAP_AWAIT_PAIRING))
   {
      return BT_SECURITY_ERR_SUCCESS;
   }

   APP_LOG_WRN("pairing refused: host not authenticated");
   return BT_SECURITY_ERR_PAIR_NOT_ALLOWED;
}

/**
 * @private       su32_AppPasskey
 * @brief         SMP app_passkey: the passkey derived from the handshake (BT
 *                context). Outside an authenticated pairing a random one (the
 *                pairing is refused anyway).
 * @param[in]     stpt_conn Link.
 * @return        Passkey, or BT_PASSKEY_RAND.
 */
static uint32_t su32_AppPasskey(struct bt_conn *stpt_conn)
{
   // Check if this link is the one that authenticated
   if ((stpt_conn != NULL) && (stpt_conn == atomic_ptr_get(&st_hostConn)) &&
      (atomic_get(&st_phase) == eHAP_AWAIT_PAIRING))
   {
      return (uint32_t)atomic_get(&st_passkey);
   }

   return BT_PASSKEY_RAND;
}

/**
 * @private       sv_AuthCancel
 * @brief         SMP cancel: the host gave up the pairing (BT context).
 * @param[in]     stpt_conn Link.
 * @return        None.
 */
static void sv_AuthCancel(struct bt_conn *stpt_conn)
{
   ARG_UNUSED(stpt_conn);

   APP_LOG_INF("host pairing cancelled");
}

/**
 * @private       sv_PairingComplete
 * @brief         SMP pairing_complete (BT context): the host link's result.
 * @param[in]     stpt_conn Link.
 * @param[in]     b_bonded Whether keys were stored.
 * @return        None.
 */
static void sv_PairingComplete(struct bt_conn *stpt_conn, bool b_bonded)
{
   // Check if it is the host link
   if ((stpt_conn != NULL) && (stpt_conn == atomic_ptr_get(&st_hostConn)))
   {
      sv_PostSimple(eHAE_PAIRED, 0U, 0U, b_bonded ? 1 : 0, stpt_conn);
   }
}

/**
 * @private       sv_PairingFailed
 * @brief         SMP pairing_failed (BT context): the host link's result.
 * @param[in]     stpt_conn Link.
 * @param[in]     e_reason Reason.
 * @return        None.
 */
static void sv_PairingFailed(struct bt_conn *stpt_conn, enum bt_security_err e_reason)
{
   // Check if it is the host link
   if ((stpt_conn != NULL) && (stpt_conn == atomic_ptr_get(&st_hostConn)))
   {
      sv_PostSimple(eHAE_PAIR_FAILED, 0U, 0U, (int32_t)e_reason, stpt_conn);
   }
}

/**
 * @private       sv_SendShort
 * @brief         Send a short message to the host (best effort).
 * @param[in]     u8_appType appType.
 * @param[in]     u8pt_payload Payload.
 * @param[in]     u8_len Payload length.
 * @return        None.
 */
static void sv_SendShort(uint8_t u8_appType, const uint8_t *u8pt_payload, uint8_t u8_len)
{
   int i_ret;

   i_ret = gi_SETUS_SendShort(u8_appType, u8pt_payload, u8_len,
      K_MSEC(HOST_AUTH_SHORT_TIMEOUT_MS));

   // Check if it could not be sent (no link, not subscribed, no credit)
   if (i_ret != 0)
   {
      APP_LOG_DBG("short 0x%02x not sent (%d)", u8_appType, i_ret);
   }
}

/**
 * @private       sv_SendResult
 * @brief         Send RESULT [refAppType][status][detail].
 * @param[in]     u8_refAppType appType the result refers to.
 * @param[in]     e_status Result.
 * @param[in]     u8_detail Detail (certificate status, SMP reason) or 0.
 * @return        None.
 */
static void sv_SendResult(uint8_t u8_refAppType, HostAuthResult_E e_status, uint8_t u8_detail)
{
   uint8_t u8ar_payload[HOST_AUTH_RESULT_LEN];

   u8ar_payload[0] = u8_refAppType;
   u8ar_payload[1] = (uint8_t)e_status;
   u8ar_payload[2] = u8_detail;
   sv_SendShort(HOST_AUTH_APP_TYPE_RESULT, u8ar_payload, sizeof(u8ar_payload));
}

/**
 * @private       sv_SendStatus
 * @brief         Send STATUS [state][flags] (only with a host link).
 * @return        None.
 */
static void sv_SendStatus(void)
{
   uint8_t u8ar_payload[HOST_AUTH_STATUS_LEN];

   // Check if there is a host to tell
   if (atomic_ptr_get(&st_hostConn) == NULL)
   {
      return;
   }

   u8ar_payload[0] = (uint8_t)ge_HostAuth_GetState();
   u8ar_payload[1] = (uint8_t)(((atomic_get(&st_window) != 0) ? HOST_AUTH_FLAG_WINDOW_OPEN : 0U) |
      ((atomic_get(&st_hostBonded) != 0) ? HOST_AUTH_FLAG_HOST_BOND : 0U));
   sv_SendShort(HOST_AUTH_APP_TYPE_STATUS, u8ar_payload, sizeof(u8ar_payload));
}

/**
 * @private       sv_EndSession
 * @brief         Drop the handshake's keys and values (thread).
 * @return        None.
 */
static void sv_EndSession(void)
{
   // Check if a host key is held
   if (st_hostKey != 0)
   {
      (void)psa_destroy_key(st_hostKey);
      st_hostKey = 0;
   }

   (void)k_work_cancel_delayable(&sst_timeoutWork);
   (void)memset(su8ar_transcript, 0, sizeof(su8ar_transcript));
   (void)atomic_set(&st_passkey, 0);
   sb_challengePending = false;

   // Check if the buffer is not SETU's (a running CHALLENGE transfer keeps it
   // until TX_DONE)
   if (!sb_challengeTx)
   {
      (void)atomic_set(&st_bufBusy, 0);
   }
}

/**
 * @private       sv_FailSession
 * @brief         A handshake step failed: answer, and go back to a plain link.
 * @param[in]     u8_refAppType appType the result refers to.
 * @param[in]     e_status Result.
 * @param[in]     u8_detail Detail.
 * @return        None.
 */
static void sv_FailSession(uint8_t u8_refAppType, HostAuthResult_E e_status, uint8_t u8_detail)
{
   sv_EndSession();

   // Check if the host link is still up
   if (atomic_get(&st_phase) != eHAP_NONE)
   {
      (void)atomic_set(&st_phase, eHAP_LINK);
   }

   APP_LOG_WRN("handshake failed at 0x%02x: status %u, detail %u", u8_refAppType,
      (unsigned int)e_status, u8_detail);
   sv_SendResult(u8_refAppType, e_status, u8_detail);
   sv_SendStatus();
}

/**
 * @private       sv_HandleHello
 * @brief         Verify HELLO's certificate, make Nd and the ephemeral key, the
 *                transcript, the device signature and the passkey, then send
 *                CHALLENGE.
 * @param[in]     u32_len HELLO length (checked at START).
 * @return        None.
 */
static void sv_HandleHello(uint32_t u32_len)
{
   const uint8_t *u8pt_certHost = &su8ar_buf[HOST_AUTH_HELLO_HDR_LEN];
   size_t t_certLen = (size_t)u32_len - HOST_AUTH_HELLO_HDR_LEN;
   uint8_t u8ar_nonceHost[HOST_AUTH_NONCE_LEN];
   uint8_t u8ar_pointHost[HOST_AUTH_POINT_LEN];
   uint8_t u8ar_nonceDev[HOST_AUTH_NONCE_LEN];
   uint8_t u8ar_pointDev[HOST_AUTH_POINT_LEN];
   uint8_t u8ar_sigDev[HOST_AUTH_SIG_LEN];
   uint8_t u8ar_secret[HOST_AUTH_HASH_LEN];
   HostAuthTranscript_T st_in;
   DeviceCertStatus_E e_cert;
   psa_key_id_t t_eph = 0;
   psa_status_t t_status;
   uint32_t u32_passkey = 0U;
   struct bt_conn *stpt_host;
   int i_ret;

   // Check if the link is still waiting for this HELLO (it may have dropped)
   if (atomic_get(&st_phase) != eHAP_LINK)
   {
      (void)atomic_set(&st_bufBusy, 0);
      return;
   }

   // Check the version
   if (su8ar_buf[0] != HOST_AUTH_VERSION)
   {
      sv_FailSession(HOST_AUTH_APP_TYPE_HELLO, eHRS_PARSE, su8ar_buf[0]);
      return;
   }

   e_cert = ge_VerifyHostCertificate(u8pt_certHost, t_certLen, &st_hostKey);

   // Check if the host certificate is one of this CA's host certificates
   if (e_cert != eDCS_OK)
   {
      st_hostKey = 0;
      sv_FailSession(HOST_AUTH_APP_TYPE_HELLO, eHRS_BAD_CERT, (uint8_t)e_cert);
      return;
   }

   // The host's values move out: the buffer becomes the CHALLENGE
   (void)memcpy(u8ar_nonceHost, &su8ar_buf[1], sizeof(u8ar_nonceHost));
   (void)memcpy(u8ar_pointHost, &su8ar_buf[1U + HOST_AUTH_NONCE_LEN], sizeof(u8ar_pointHost));
   t_status = gt_HostAuthCrypto_Random(u8ar_nonceDev, HOST_AUTH_NONCE_LEN);

   // Make the ephemeral key, then the shared secret
   if (t_status == PSA_SUCCESS)
   {
      t_status = gt_HostAuthCrypto_NewEphemeral(&t_eph, u8ar_pointDev);
   }
   if (t_status == PSA_SUCCESS)
   {
      t_status = gt_HostAuthCrypto_Agree(t_eph, u8ar_pointHost, u8ar_secret);
      (void)psa_destroy_key(t_eph);
   }

   // The transcript over both sides' values and certificates
   if (t_status == PSA_SUCCESS)
   {
      st_in.u8pt_nonceHost = u8ar_nonceHost;
      st_in.u8pt_nonceDev = u8ar_nonceDev;
      st_in.u8pt_pointHost = u8ar_pointHost;
      st_in.u8pt_pointDev = u8ar_pointDev;
      st_in.u8pt_certHost = u8pt_certHost;
      st_in.t_certHostLen = t_certLen;
      st_in.u8pt_certDev = gst_deviceCertData.u8ar_DeviceCert;
      st_in.t_certDevLen = gst_deviceCertData.u16_deviceCertLen;
      t_status = gt_HostAuthCrypto_Transcript(&st_in, su8ar_transcript);
   }
   if (t_status == PSA_SUCCESS)
   {
      t_status = gt_HostAuthCrypto_Sign(CSR_DEVICE_SIGNING_KEY_ID, eHAR_DEVICE, su8ar_transcript,
         u8ar_sigDev);
   }
   if (t_status == PSA_SUCCESS)
   {
      t_status = gt_HostAuthCrypto_Passkey(u8ar_secret, u8ar_nonceHost, u8ar_nonceDev,
         su8ar_transcript, &u32_passkey);
   }

   (void)memset(u8ar_secret, 0, sizeof(u8ar_secret));

   // Check if a cryptographic step failed
   if (t_status != PSA_SUCCESS)
   {
      APP_LOG_ERR("handshake crypto failed (%d)", t_status);
      sv_FailSession(HOST_AUTH_APP_TYPE_HELLO, eHRS_INTERNAL, 0U);
      return;
   }

   // [ver][Nd][Qd][SigD][device certificate], over HELLO (no longer needed)
   su8ar_buf[0] = HOST_AUTH_VERSION;
   (void)memcpy(&su8ar_buf[1], u8ar_nonceDev, sizeof(u8ar_nonceDev));
   (void)memcpy(&su8ar_buf[1U + HOST_AUTH_NONCE_LEN], u8ar_pointDev, sizeof(u8ar_pointDev));
   (void)memcpy(&su8ar_buf[1U + HOST_AUTH_NONCE_LEN + HOST_AUTH_POINT_LEN], u8ar_sigDev,
      sizeof(u8ar_sigDev));
   (void)memcpy(&su8ar_buf[HOST_AUTH_CHALLENGE_HDR_LEN], gst_deviceCertData.u8ar_DeviceCert,
      gst_deviceCertData.u16_deviceCertLen);
   su16_challengeLen = (uint16_t)(HOST_AUTH_CHALLENGE_HDR_LEN + gst_deviceCertData.u16_deviceCertLen);
   (void)atomic_set(&st_passkey, (atomic_val_t)u32_passkey);
   (void)atomic_set(&st_phase, eHAP_AWAIT_FINISH);
   (void)k_work_reschedule(&sst_timeoutWork, K_MSEC(CONFIG_HOST_AUTH_TIMEOUT_MS));
   APP_LOG_INF("host certificate verified, sending CHALLENGE");

   // The Client attaches to the host's SETU service, moved off another link if needed
   stpt_host = (struct bt_conn *)atomic_ptr_get(&st_hostConn);
   i_ret = gi_SETURouter_ClientAttach(stpt_host, HOST_AUTH_APP_TYPE_CHALLENGE);

   // Check if the Client is attached already
   if (i_ret == -EALREADY)
   {
      sv_SendChallenge();
   }
   // Check if the attach started
   else if (i_ret == 0)
   {
      sb_challengePending = true;
   }
   else
   {
      APP_LOG_WRN("Client attach failed (%d)", i_ret);
      sv_FailSession(HOST_AUTH_APP_TYPE_HELLO, eHRS_NO_PC_SVC, 0U);
   }
}

/**
 * @private       sv_SendChallenge
 * @brief         Start the CHALLENGE transfer on the attached Client.
 * @return        None.
 */
static void sv_SendChallenge(void)
{
   int i_ret;

   sb_challengePending = false;
   i_ret = gi_SETUC_SendBuffer(HOST_AUTH_APP_TYPE_CHALLENGE, su8ar_buf, su16_challengeLen);

   // Check if the transfer could not start
   if (i_ret != 0)
   {
      APP_LOG_ERR("CHALLENGE not sent (%d)", i_ret);
      sv_FailSession(HOST_AUTH_APP_TYPE_HELLO, eHRS_TRANSFER, 0U);
   }
   else
   {
      // The buffer is SETU's until TX_DONE
      sb_challengeTx = true;
   }
}

/**
 * @private       sv_HandleFinish
 * @brief         Check FINISH: the host's signature over its role and T. On
 *                success the derived passkey is armed for pairing.
 * @param[in]     stpt_event FINISH event.
 * @return        None.
 */
static void sv_HandleFinish(const HostAuthEvent_T *stpt_event)
{
   psa_status_t t_status;

   // Check if a CHALLENGE was sent on this link
   if (atomic_get(&st_phase) != eHAP_AWAIT_FINISH)
   {
      sv_SendResult(HOST_AUTH_APP_TYPE_FINISH, eHRS_BAD_STATE, 0U);
      return;
   }

   // Check if the payload is a signature
   if (stpt_event->i32_value != (int32_t)HOST_AUTH_SIG_LEN)
   {
      sv_FailSession(HOST_AUTH_APP_TYPE_FINISH, eHRS_PARSE, 0U);
      return;
   }

   t_status = gt_HostAuthCrypto_Verify(st_hostKey, eHAR_HOST, su8ar_transcript,
      stpt_event->u8ar_data);

   // Check if the host holds the certificate's key
   if (t_status != PSA_SUCCESS)
   {
      sv_FailSession(HOST_AUTH_APP_TYPE_FINISH, eHRS_BAD_SIG, 0U);
      return;
   }

   (void)psa_destroy_key(st_hostKey);
   st_hostKey = 0;
   (void)atomic_set(&st_phase, eHAP_AWAIT_PAIRING);
   APP_LOG_INF("host authenticated: pairing allowed");
   sv_SendResult(HOST_AUTH_APP_TYPE_FINISH, eHRS_OK, 0U);
   sv_SendStatus();
}

/**
 * @private       sv_EvaluateTrust
 * @brief         Trust the host link once it is the bonded host at level 4.
 * @return        None.
 */
static void sv_EvaluateTrust(void)
{
   struct bt_conn *stpt_host = (struct bt_conn *)atomic_ptr_get(&st_hostConn);

   // Check if the link is the bonded host, encrypted and authenticated
   if ((atomic_get(&st_phase) == eHAP_TRUSTED) || !sb_LinkIsBondedHost(stpt_host) ||
      (bt_conn_get_security(stpt_host) < BT_SECURITY_L4))
   {
      return;
   }

   sv_EndSession();
   (void)atomic_set(&st_phase, eHAP_TRUSTED);
   APP_LOG_INF("trusted host connected");
   sv_UpdateLed();
   sv_SendStatus();
}

/**
 * @private       sv_HandlePaired
 * @brief         The host link's pairing ended: a bond after FINISH makes it
 *                the one host (an older host bond is deleted).
 * @param[in]     b_bonded Whether keys were stored.
 * @return        None.
 */
static void sv_HandlePaired(bool b_bonded)
{
   struct bt_conn *stpt_host = (struct bt_conn *)atomic_ptr_get(&st_hostConn);
   const bt_addr_le_t *stpt_dst;

   // Check if this pairing is the authenticated one
   if (atomic_get(&st_phase) != eHAP_AWAIT_PAIRING)
   {
      return;
   }

   stpt_dst = (stpt_host != NULL) ? bt_conn_get_dst(stpt_host) : NULL;

   // Check if the host bonded (a pairing without a bond cannot be trusted later)
   if (!b_bonded || (stpt_dst == NULL))
   {
      sv_FailSession(HOST_AUTH_APP_TYPE_FINISH, eHRS_PAIRING, 0xFFU);
      return;
   }

   sv_SaveHost(stpt_dst);
   sv_EvaluateTrust();
}

/**
 * @private       sv_SaveHost
 * @brief         Make an address the bonded host: an older host's bond goes.
 * @param[in]     stpt_addr Identity address of the new host.
 * @return        None.
 */
static void sv_SaveHost(const bt_addr_le_t *stpt_addr)
{
   uint8_t u8ar_record[HOST_AUTH_RECORD_LEN];
   bt_addr_le_t st_old;
   bool b_hadOther;
   int i_ret;

   (void)k_mutex_lock(&sst_addrLock, K_FOREVER);
   st_old = sst_hostAddr;
   b_hadOther = (atomic_get(&st_hostBonded) != 0) && (bt_addr_le_cmp(&st_old, stpt_addr) != 0);
   sst_hostAddr = *stpt_addr;
   k_mutex_unlock(&sst_addrLock);
   (void)atomic_set(&st_hostBonded, 1);

   // Check if another host was bonded: only one is kept
   if (b_hadOther)
   {
      (void)bt_unpair(BT_ID_DEFAULT, &st_old);
      APP_LOG_INF("previous host bond deleted");
   }

   u8ar_record[0] = stpt_addr->type;
   (void)memcpy(&u8ar_record[1], stpt_addr->a.val, sizeof(stpt_addr->a.val));
   i_ret = settings_save_one(HOST_AUTH_SETTINGS_SUBTREE "/" HOST_AUTH_SETTINGS_KEY, u8ar_record,
      sizeof(u8ar_record));

   // Check if the record was stored (the bond itself is the stack's)
   if (i_ret != 0)
   {
      APP_LOG_WRN("host record not saved (%d): host not trusted after a reset", i_ret);
   }

   APP_LOG_INF("host bonded");
}

/**
 * @private       sv_ForgetHost
 * @brief         Delete the host bond and its record; a connected host is
 *                dropped.
 * @return        None.
 */
static void sv_ForgetHost(void)
{
   struct bt_conn *stpt_host = (struct bt_conn *)atomic_ptr_get(&st_hostConn);
   bt_addr_le_t st_old;

   // Check if a host is bonded
   if (atomic_get(&st_hostBonded) != 0)
   {
      (void)k_mutex_lock(&sst_addrLock, K_FOREVER);
      st_old = sst_hostAddr;
      k_mutex_unlock(&sst_addrLock);
      (void)atomic_set(&st_hostBonded, 0);
      (void)bt_unpair(BT_ID_DEFAULT, &st_old);
      APP_LOG_INF("host bond forgotten");
   }
   (void)settings_delete(HOST_AUTH_SETTINGS_SUBTREE "/" HOST_AUTH_SETTINGS_KEY);

   // Check if a host is connected: it was (or may become) the forgotten one;
   // untrusted at once, so its loss opens no grace window
   if (stpt_host != NULL)
   {
      sv_EndSession();
      (void)atomic_set(&st_phase, eHAP_LINK);
      sv_UpdateLed();
      (void)bt_conn_disconnect(stpt_host, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
   }
}

/**
 * @private       sv_SetWindow
 * @brief         Open (for a time) or close the host window, and re-evaluate
 *                advertising.
 * @param[in]     b_open true to open.
 * @param[in]     i32_ms How long it stays open.
 * @return        None.
 */
static void sv_SetWindow(bool b_open, int32_t i32_ms)
{
   (void)atomic_set(&st_window, b_open ? 1 : 0);

   // Check if it opens: it closes again after i32_ms
   if (b_open)
   {
      si64_windowEndMs = k_uptime_get() + i32_ms;
      (void)k_work_reschedule(&sst_windowWork, K_MSEC(i32_ms));
      APP_LOG_INF("host window open for %d ms", (int)i32_ms);
   }
   else
   {
      (void)k_work_cancel_delayable(&sst_windowWork);
   }

   gv_BLE_RefreshAdv();
   sv_UpdateLed();
   sv_SendStatus();
}

/**
 * @private       sv_UpdateLed
 * @brief         Show the window (blinking) or the trusted host (lit).
 * @return        None.
 */
static void sv_UpdateLed(void)
{
   (void)k_work_reschedule(&sst_ledWork, K_NO_WAIT);
}

/**
 * @private       sv_HandleBtReady
 * @brief         The stack is up with its bonds loaded: keep the host record
 *                only on a provisioned device whose bond still exists.
 * @return        None.
 */
static void sv_HandleBtReady(void)
{
   sb_bondSeen = false;

   // Check if a record was loaded
   if (atomic_get(&st_hostBonded) != 0)
   {
      // Check if the device may keep it (an unprovisioned one has no bonds)
      if (sb_IsProvisioned())
      {
         bt_foreach_bond(BT_ID_DEFAULT, sv_BondCheck, NULL);
      }

      // Check if the record has no bond (any more): it is stale
      if (!sb_bondSeen)
      {
         APP_LOG_WRN("host record without bond: forgotten");
         (void)atomic_set(&st_hostBonded, 0);
         (void)settings_delete(HOST_AUTH_SETTINGS_SUBTREE "/" HOST_AUTH_SETTINGS_KEY);
         gv_BLE_RefreshAdv();
      }
      else
      {
         APP_LOG_INF("bonded host restored");
      }
   }

#if defined(CONFIG_HOST_AUTH_BOOT_WINDOW)
   // Bench and HIL images open the window once at boot
   sv_SetWindow(true, CONFIG_HOST_AUTH_WINDOW_MS);
#endif // CONFIG_HOST_AUTH_BOOT_WINDOW
}

/**
 * @private       sv_BondCheck
 * @brief         bt_foreach_bond() callback: notes the host record's bond.
 * @param[in]     stpt_info Bond.
 * @param[in]     vpt_user Unused.
 * @return        None.
 */
static void sv_BondCheck(const struct bt_bond_info *stpt_info, void *vpt_user)
{
   ARG_UNUSED(vpt_user);

   // Check if it is the host's bond
   if (gb_HostAuth_IsHostAddr(&stpt_info->addr))
   {
      sb_bondSeen = true;
   }
}

/**
 * @private       sv_HandleEvent
 * @brief         Serve one event on the thread.
 * @param[in]     stpt_event Event.
 * @return        None.
 */
static void sv_HandleEvent(const HostAuthEvent_T *stpt_event)
{
   struct bt_conn *stpt_host = (struct bt_conn *)atomic_ptr_get(&st_hostConn);
   uint8_t u8_type = stpt_event->u8_appType;
   HostAuthPhase_E e_phase;

   switch (stpt_event->u8_type)
   {
      case eHAE_STATUS_REQ:
         sv_SendStatus();
         break;

      case eHAE_HELLO:
         sv_HandleHello((uint32_t)stpt_event->i32_value);
         break;

      case eHAE_REJECTED:
         sv_SendResult(stpt_event->u8_appType, (HostAuthResult_E)stpt_event->u8_status, 0U);
         break;

      case eHAE_FINISH:
         sv_HandleFinish(stpt_event);
         break;

      case eHAE_CLI_READY:
         // Check if CHALLENGE waits for the Client
         if (!sb_challengePending || (atomic_get(&st_phase) != eHAP_AWAIT_FINISH))
         {
            break;
         }

         // Check if the Client is attached
         if (stpt_event->i32_value == 0)
         {
            sv_SendChallenge();
         }
         else
         {
            APP_LOG_WRN("no SETU service on the host (%d)", stpt_event->i32_value);
            sv_FailSession(HOST_AUTH_APP_TYPE_HELLO, eHRS_NO_PC_SVC, 0U);
         }
         break;

      case eHAE_TX_DONE:
         // The transfer is over: the buffer is free again
         sb_challengeTx = false;
         (void)atomic_set(&st_bufBusy, 0);

         // Check if CHALLENGE did not reach the host during its handshake
         if ((stpt_event->u8_status != (uint8_t)eBS_OK) &&
            (atomic_get(&st_phase) == eHAP_AWAIT_FINISH))
         {
            sv_FailSession(HOST_AUTH_APP_TYPE_HELLO, eHRS_TRANSFER, stpt_event->u8_status);
         }
         break;

      case eHAE_REFUSED:
         sv_SendShort(HOST_AUTH_APP_TYPE_REFUSED, &u8_type, 1U);
         break;

      case eHAE_CONNECTED:
         // Check if the link is still the host link (it may have dropped already)
         if ((stpt_host == NULL) || (stpt_host != stpt_event->stpt_conn))
         {
            break;
         }

         // A host connected: the window has served its purpose
         sv_EndSession();
         sv_SetWindow(false, 0);

         // Check if it is the bonded host: ask it to encrypt with its keys
         if (sb_LinkIsBondedHost(stpt_host))
         {
            (void)bt_conn_set_security(stpt_host, BT_SECURITY_L4);
         }
         break;

      case eHAE_DISCONNECTED:
         // The hook released the link; its handshake (if any) ends here
         sv_EndSession();
         bt_conn_unref(stpt_event->stpt_conn);

         // Check if the trusted host was lost: let it come back without the button
         if ((HostAuthPhase_E)stpt_event->i32_value == eHAP_TRUSTED)
         {
            sv_SetWindow(true, CONFIG_HOST_AUTH_GRACE_MS);
         }
         // Check if an untrusted host left (a failed attempt, Windows drops the
         // link): the window it closed reopens for the time it had left
         else if (si64_windowEndMs > k_uptime_get())
         {
            sv_SetWindow(true, (int32_t)(si64_windowEndMs - k_uptime_get()));
         }
         else
         {
            // No window left to give back
         }
         sv_UpdateLed();
         break;

      case eHAE_SECURITY:
         // Check if the host link is now encrypted
         if ((stpt_event->stpt_conn == stpt_host) && (stpt_event->u8_status == 0U))
         {
            sv_EvaluateTrust();
         }
         else if (stpt_event->stpt_conn == stpt_host)
         {
            APP_LOG_WRN("host link security failed (%u)", stpt_event->u8_status);
         }
         break;

      case eHAE_PAIRED:
         sv_HandlePaired(stpt_event->i32_value != 0);
         break;

      case eHAE_PAIR_FAILED:
         // Check if the authenticated pairing failed
         if (atomic_get(&st_phase) == eHAP_AWAIT_PAIRING)
         {
            sv_FailSession(HOST_AUTH_APP_TYPE_FINISH, eHRS_PAIRING, (uint8_t)stpt_event->i32_value);
         }
         break;

      case eHAE_TIMEOUT:
         // Check if a handshake or its pairing is still open
         e_phase = (HostAuthPhase_E)atomic_get(&st_phase);
         if ((e_phase == eHAP_AWAIT_FINISH) || (e_phase == eHAP_AWAIT_PAIRING))
         {
            sv_FailSession((e_phase == eHAP_AWAIT_FINISH) ? HOST_AUTH_APP_TYPE_HELLO :
               HOST_AUTH_APP_TYPE_FINISH, eHRS_TIMEOUT, 0U);

            // Check if the link is still there: a host that stalls is dropped
            if (stpt_host != NULL)
            {
               (void)bt_conn_disconnect(stpt_host, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
            }
         }
         break;

      case eHAE_WINDOW_OPEN:
         sv_SetWindow(true, CONFIG_HOST_AUTH_WINDOW_MS);
         break;

      case eHAE_FORGET_OPEN:
         sv_ForgetHost();
         sv_SetWindow(true, CONFIG_HOST_AUTH_WINDOW_MS);
         break;

      case eHAE_WINDOW_CLOSED:
         si64_windowEndMs = 0;
         sv_SetWindow(false, 0);
         APP_LOG_INF("host window closed");
         break;

      case eHAE_FORGET:
         // The wipe deleted every bond; the host link stays, untrusted
         (void)atomic_set(&st_hostBonded, 0);
         (void)settings_delete(HOST_AUTH_SETTINGS_SUBTREE "/" HOST_AUTH_SETTINGS_KEY);
         // The wipe's own refresh may have run before this: advertise no host bond
         gv_BLE_RefreshAdv();
         sv_EndSession();

         // Check if the host link is up: it is a plain link now
         if (atomic_get(&st_phase) != eHAP_NONE)
         {
            (void)atomic_set(&st_phase, eHAP_LINK);
         }
         sv_UpdateLed();
         sv_SendStatus();
         break;

      case eHAE_BT_READY:
         sv_HandleBtReady();
         break;

      default:
         APP_LOG_ERR("unknown event %u", stpt_event->u8_type);
         break;
   }
}

/**
 * @private       sv_WindowWork
 * @brief         The window timer ran out.
 * @param[in]     stpt_work Unused.
 * @return        None.
 */
static void sv_WindowWork(struct k_work *stpt_work)
{
   ARG_UNUSED(stpt_work);

   sv_PostSimple(eHAE_WINDOW_CLOSED, 0U, 0U, 0, NULL);
}

/**
 * @private       sv_TimeoutWork
 * @brief         The handshake timer ran out.
 * @param[in]     stpt_work Unused.
 * @return        None.
 */
static void sv_TimeoutWork(struct k_work *stpt_work)
{
   ARG_UNUSED(stpt_work);

   sv_PostSimple(eHAE_TIMEOUT, 0U, 0U, 0, NULL);
}

/**
 * @private       sv_LedWork
 * @brief         LED1: lit with a trusted host, blinking while the window is
 *                open, off otherwise.
 * @param[in]     stpt_work Unused.
 * @return        None.
 */
static void sv_LedWork(struct k_work *stpt_work)
{
   ARG_UNUSED(stpt_work);

   // Check what the LED shows
   if (atomic_get(&st_phase) == eHAP_TRUSTED)
   {
      sb_ledOn = false;
      (void)dk_set_led(HOST_AUTH_LED, 1U);
   }
   else if (atomic_get(&st_window) != 0)
   {
      sb_ledOn = !sb_ledOn;
      (void)dk_set_led(HOST_AUTH_LED, sb_ledOn ? 1U : 0U);
      (void)k_work_reschedule(&sst_ledWork, K_MSEC(HOST_AUTH_BLINK_MS));
   }
   else
   {
      sb_ledOn = false;
      (void)dk_set_led(HOST_AUTH_LED, 0U);
   }
}

/**
 * @private       si_SettingsSet
 * @brief         Settings handler (settings_load()): read the host record.
 * @param[in]     cpt_key Key below HOST_AUTH_SETTINGS_SUBTREE.
 * @param[in]     t_len Stored length.
 * @param[in]     fpt_read Reads the value.
 * @param[in]     vpt_arg Argument of fpt_read.
 * @return        0, -ENOENT for an unknown key, -EINVAL for a wrong length or
 *                address type, or the read error.
 */
static int si_SettingsSet(const char *cpt_key, size_t t_len, settings_read_cb fpt_read,
   void *vpt_arg)
{
   uint8_t u8ar_record[HOST_AUTH_RECORD_LEN];
   ssize_t t_read;

   // Check if it is the record, with its size
   if (strcmp(cpt_key, HOST_AUTH_SETTINGS_KEY) != 0)
   {
      return -ENOENT;
   }
   if (t_len != sizeof(u8ar_record))
   {
      return -EINVAL;
   }

   t_read = fpt_read(vpt_arg, u8ar_record, sizeof(u8ar_record));

   // Check if the record was read whole
   if (t_read != (ssize_t)sizeof(u8ar_record))
   {
      return (t_read < 0) ? (int)t_read : -EINVAL;
   }

   // Check if the address type is one LE uses
   if ((u8ar_record[0] != BT_ADDR_LE_PUBLIC) && (u8ar_record[0] != BT_ADDR_LE_RANDOM))
   {
      return -EINVAL;
   }

   (void)k_mutex_lock(&sst_addrLock, K_FOREVER);
   sst_hostAddr.type = u8ar_record[0];
   (void)memcpy(sst_hostAddr.a.val, &u8ar_record[1], sizeof(sst_hostAddr.a.val));
   k_mutex_unlock(&sst_addrLock);
   (void)atomic_set(&st_hostBonded, 1);

   return 0;
}

/**
 * @private       sv_HostAuthThread
 * @brief         Host authentication thread: serve events for ever.
 * @param[in]     vpt_p1 Unused.
 * @param[in]     vpt_p2 Unused.
 * @param[in]     vpt_p3 Unused.
 * @return        None.
 */
static void sv_HostAuthThread(void *vpt_p1, void *vpt_p2, void *vpt_p3)
{
   HostAuthEvent_T st_event;

   ARG_UNUSED(vpt_p1);
   ARG_UNUSED(vpt_p2);
   ARG_UNUSED(vpt_p3);

   while (true)
   {
      // Check if an event arrived
      if (k_msgq_get(&sst_hostAuthMsgq, &st_event, K_FOREVER) == 0)
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
 * @public        gi_HostAuth_Init
 * @brief         Register the host authentication range (with its Client
 *                callbacks), install the router gate and the SMP result
 *                callbacks. Call once from main(), after gi_Pair_Init() and
 *                before gi_SETURouter_Start().
 * @return        0 on success, otherwise the error of gi_SETURouter_Register(),
 *                gi_SETURouter_SetGate() or bt_conn_auth_info_cb_register().
 */
int gi_HostAuth_Init(void)
{
   SETURoute_T st_route = { 0 };
   int i_ret;

   st_route.u8_firstAppType = HOST_AUTH_APP_TYPE_FIRST;
   st_route.u8_lastAppType = HOST_AUTH_APP_TYPE_LAST;
   st_route.fpt_onRxStart = si_HauthRxStart;
   st_route.fpt_onRxData = si_HauthRxData;
   st_route.fpt_onRxDone = sv_HauthRxDone;
   st_route.fpt_onRxShort = sv_HauthRxShort;
   st_route.fpt_onTxDone = sv_HauthTxDone;
   st_route.fpt_onCliReady = sv_HauthCliReady;

   i_ret = gi_SETURouter_Register(&st_route);

   // Check if the range was registered
   if (i_ret != 0)
   {
      APP_LOG_ERR("gi_SETURouter_Register failed (%d)", i_ret);
      return i_ret;
   }

   i_ret = gi_SETURouter_SetGate(gb_HostAuth_Admits, sv_GateRefused);

   // Check if the gate was installed
   if (i_ret != 0)
   {
      APP_LOG_ERR("gi_SETURouter_SetGate failed (%d)", i_ret);
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
 * @public        gv_HostAuth_OnBtReady
 * @brief         The stack is enabled and its settings loaded. Call from _BLE
 *                once, after settings_load().
 * @return        None.
 */
void gv_HostAuth_OnBtReady(void)
{
   sv_PostSimple(eHAE_BT_READY, 0U, 0U, 0, NULL);
}

/**
 * @public        gv_HostAuth_OnHostConnected
 * @brief         A connection became the host link (BT context, from
 *                bt_conn_cb.connected). Its SMP callbacks become this module's
 *                before any pairing can start.
 * @param[in]     stpt_conn Host link.
 * @return        None.
 */
void gv_HostAuth_OnHostConnected(struct bt_conn *stpt_conn)
{
   int i_ret;

   // Check if there is a link, and no host link held already
   if ((stpt_conn == NULL) || !atomic_ptr_cas(&st_hostConn, NULL, bt_conn_ref(stpt_conn)))
   {
      if (stpt_conn != NULL)
      {
         bt_conn_unref(stpt_conn);
      }
      return;
   }

   (void)atomic_set(&st_phase, eHAP_LINK);
   i_ret = bt_conn_auth_cb_overlay(stpt_conn, &sst_hostAuthCb);

   // Check if the overlay was refused: SMP latched the global callbacks, which
   // refuse pairing on any link but the peer link
   if (i_ret != 0)
   {
      APP_LOG_WRN("host SMP callbacks not set (%d): host cannot pair", i_ret);
   }

   sv_PostSimple(eHAE_CONNECTED, 0U, 0U, 0, stpt_conn);
}

/**
 * @public        gv_HostAuth_OnHostDisconnected
 * @brief         A connection went down (BT context). Only the host link
 *                matters; it is untrusted at once, released by the thread.
 * @param[in]     stpt_conn Connection.
 * @return        None.
 */
void gv_HostAuth_OnHostDisconnected(struct bt_conn *stpt_conn)
{
   atomic_val_t t_phase;

   // Check if it is the host link: it is released now (a new host may follow at
   // once), its reference by the thread
   if ((stpt_conn == NULL) || !atomic_ptr_cas(&st_hostConn, stpt_conn, NULL))
   {
      return;
   }

   // The gate closes now; the thread learns whether the link was trusted
   t_phase = atomic_set(&st_phase, eHAP_NONE);
   sv_PostSimple(eHAE_DISCONNECTED, 0U, 0U, (int32_t)t_phase, stpt_conn);
}

/**
 * @public        gv_HostAuth_OnSecurityChanged
 * @brief         A connection's security changed (BT context). Only the host
 *                link matters.
 * @param[in]     stpt_conn Connection.
 * @param[in]     u8_level New level (bt_security_t).
 * @param[in]     u8_err bt_security_err, 0 on success.
 * @return        None.
 */
void gv_HostAuth_OnSecurityChanged(struct bt_conn *stpt_conn, uint8_t u8_level, uint8_t u8_err)
{
   // Check if it is the host link
   if ((stpt_conn != NULL) && (stpt_conn == atomic_ptr_get(&st_hostConn)))
   {
      sv_PostSimple(eHAE_SECURITY, 0U, u8_err, (int32_t)u8_level, stpt_conn);
   }
}

/**
 * @public        gb_HostAuth_Admits
 * @brief         The router's gate (SETU engine thread): the host link reaches
 *                host authentication and provisioning's GET_STATUS always,
 *                provisioning while the device is unprovisioned, and everything
 *                else only once trusted.
 * @param[in]     u8_appType Application type.
 * @return        true to admit.
 */
bool gb_HostAuth_Admits(uint8_t u8_appType)
{
   // Check if it is the handshake itself, or a status read
   if (((u8_appType >= HOST_AUTH_APP_TYPE_FIRST) && (u8_appType <= HOST_AUTH_APP_TYPE_LAST)) ||
      (u8_appType == PROV_APP_TYPE_GET_STATUS))
   {
      return true;
   }

   // Check if the device is unprovisioned: only provisioning is reachable
   if (!sb_IsProvisioned())
   {
      return (u8_appType >= PROV_APP_TYPE_FIRST) && (u8_appType <= PROV_APP_TYPE_LAST);
   }

   return atomic_get(&st_phase) == eHAP_TRUSTED;
}

/**
 * @public        gb_HostAuth_IsTrustedConn
 * @brief         Whether a connection is the trusted host's (any thread).
 * @param[in]     stpt_conn Connection.
 * @return        true for the trusted host link.
 */
bool gb_HostAuth_IsTrustedConn(const struct bt_conn *stpt_conn)
{
   return (stpt_conn != NULL) && (stpt_conn == atomic_ptr_get(&st_hostConn)) &&
      (atomic_get(&st_phase) == eHAP_TRUSTED);
}

/**
 * @public        gb_HostAuth_IsHostAddr
 * @brief         Whether an address is the bonded host's (any thread): its
 *                bond is not the pairing peer's.
 * @param[in]     stpt_addr Address.
 * @return        true if a host is bonded with that identity address.
 */
bool gb_HostAuth_IsHostAddr(const bt_addr_le_t *stpt_addr)
{
   bool b_match;

   // Check if a host is bonded
   if ((stpt_addr == NULL) || (atomic_get(&st_hostBonded) == 0))
   {
      return false;
   }

   (void)k_mutex_lock(&sst_addrLock, K_FOREVER);
   b_match = (bt_addr_le_cmp(stpt_addr, &sst_hostAddr) == 0);
   k_mutex_unlock(&sst_addrLock);

   return b_match;
}

/**
 * @public        gb_HostAuth_WindowOpen
 * @brief         Whether the host window is open: ConnectionHandling.c then
 *                advertises undirected while no host is connected.
 * @return        true while open.
 */
bool gb_HostAuth_WindowOpen(void)
{
   return atomic_get(&st_window) != 0;
}

/**
 * @public        gv_HostAuth_OpenWindow
 * @brief         Open the host window for CONFIG_HOST_AUTH_WINDOW_MS (the
 *                button's short press). Any thread.
 * @return        None.
 */
void gv_HostAuth_OpenWindow(void)
{
   sv_PostSimple(eHAE_WINDOW_OPEN, 0U, 0U, 0, NULL);
}

/**
 * @public        gv_HostAuth_ForgetHostAndOpen
 * @brief         Forget the bonded host (bond, record, link), then open the
 *                window (the button held). Any thread.
 * @return        None.
 */
void gv_HostAuth_ForgetHostAndOpen(void)
{
   sv_PostSimple(eHAE_FORGET_OPEN, 0U, 0U, 0, NULL);
}

/**
 * @public        gv_HostAuth_Forget
 * @brief         Provisioning wipe: the bonds are gone, forget the host
 *                record. Any thread.
 * @return        None.
 */
void gv_HostAuth_Forget(void)
{
   sv_PostSimple(eHAE_FORGET, 0U, 0U, 0, NULL);
}

/**
 * @public        ge_HostAuth_GetState
 * @brief         The host link's state as STATUS reports it.
 * @return        HostAuthState_E.
 */
HostAuthState_E ge_HostAuth_GetState(void)
{
   HostAuthPhase_E e_phase = (HostAuthPhase_E)atomic_get(&st_phase);

   // Check if the device can authenticate at all
   if (!sb_IsProvisioned())
   {
      return eHAS_UNPROVISIONED;
   }

   switch (e_phase)
   {
      case eHAP_TRUSTED:
         return eHAS_TRUSTED;
      case eHAP_AWAIT_FINISH:
         return eHAS_AWAIT_FINISH;
      case eHAP_AWAIT_PAIRING:
         return eHAS_AWAIT_PAIRING;
      default:
         return (atomic_get(&st_hostBonded) != 0) ? eHAS_HOST_BONDED : eHAS_OPEN;
   }
}

/**
 * @public        gv_HostAuth_GetAdvData
 * @brief         The manufacturer data ConnectionHandling.c advertises:
 *                [company ID u16 LE][format][flags], flags telling whether the
 *                device is provisioned and has a host bond. A PC that holds keys
 *                for a device without a host bond removes them before it
 *                connects (they are stale: the device was wiped or erased, or
 *                forgot its host). Any thread.
 * @param[out]    u8ar_out HOST_AUTH_ADV_LEN bytes.
 * @return        None.
 */
void gv_HostAuth_GetAdvData(uint8_t u8ar_out[HOST_AUTH_ADV_LEN])
{
   uint8_t u8_flags = 0U;

   // Check if the device is provisioned
   if (sb_IsProvisioned())
   {
      u8_flags |= HOST_AUTH_ADV_FLAG_PROVISIONED;
   }

   // Check if a host is bonded
   if (atomic_get(&st_hostBonded) != 0)
   {
      u8_flags |= HOST_AUTH_ADV_FLAG_HOST_BOND;
   }

   u8ar_out[0] = (uint8_t)(HOST_AUTH_ADV_COMPANY_ID & 0xFFU);
   u8ar_out[1] = (uint8_t)(HOST_AUTH_ADV_COMPANY_ID >> 8);
   u8ar_out[2] = HOST_AUTH_ADV_FORMAT;
   u8ar_out[3] = u8_flags;
}

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shivam Chudasama [SC]
 */
