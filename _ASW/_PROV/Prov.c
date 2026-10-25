/**
 * @file          Prov.c
 * @brief         Source file containing device provisioning over SETU.
 *
 *                The provisioner (the PC GUI, acting as the CA) drives the flow
 *                with short messages and transfers in the appType range
 *                PROV_APP_TYPE_FIRST..LAST, which this module registers with the
 *                SETU router:
 *                - GET_STATUS -> STATUS;
 *                - CSR_REQ -> this device attaches its SETU Client to the
 *                  provisioner's SETU service and sends the CSR;
 *                - CA_CERT, then DEV_CERT transfers -> each is verified
 *                  (DeviceCert_Verify.c) and answered with RESULT. The CA is held
 *                  in RAM; only once the device certificate verifies against it
 *                  are both stored in ITS (DeviceCert.c) and the CSR deleted;
 *                - DEPROVISION (or the DK button, ProvButton.c) -> wipe key, CSR
 *                  and certificates, generate a fresh key and CSR -> RESULT.
 *
 *                SETU callbacks run on the engine thread with the SETU
 *                lock held, so they only check, copy and post an event. Everything
 *                else (Client attach and send, certificate verification, PEM
 *                logging, replies) runs on the low-priority provisioning thread.
 *
 *                Provisioning is one-time: once PROVISIONED, CSR_REQ, CA_CERT and
 *                DEV_CERT are refused until a wipe. At boot a stored certificate
 *                pair is re-verified; if it fails, everything is wiped.
 * @date          01/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include "Prov.h"
#include <errno.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/base64.h>
#include <zephyr/logging/log_ctrl.h>
#include <psa/crypto.h>
#include "SETU.h"
#include "SETURouter.h"
#include "CSR_Generator.h"
#include "DeviceCert.h"
#include "DeviceCert_Verify.h"
#include "Pair.h"
#include "HostAuth.h"
#include "AppLog.h"

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
/**
 * @def           PROV_EVENT_QUEUE_LEN
 * @brief         Depth of the event queue between the SETU callbacks and the
 *                provisioning thread.
 */
#define PROV_EVENT_QUEUE_LEN                 (8U)

/**
 * @def           PROV_STACK_SIZE
 * @brief         Stack size of the provisioning thread. mbedTLS X.509 parsing,
 *                ECDSA verification, ITS writes (an entry-sized buffer on the
 *                stack) and, on a wipe, key generation and the CSR build run on
 *                it; main() needs CONFIG_MAIN_STACK_SIZE for the same work. The
 *                deepest static path (wipe -> CSR build -> PSA sign -> secure
 *                storage) takes about 7.5 KiB before interrupt frames and calls
 *                through function pointers; 10 KiB leaves a margin (audit F4).
 */
#define PROV_STACK_SIZE                      (10240)

/**
 * @def           PROV_PRIORITY
 * @brief         Priority of the provisioning thread. Below the SETU engine
 *                thread (SETU_THREAD_PRIORITY), like the data store dump thread.
 */
#define PROV_PRIORITY                        (10)

/**
 * @def           PROV_SHORT_TIMEOUT_MS
 * @brief         Maximum wait for a CTRL credit when sending STATUS or RESULT.
 */
#define PROV_SHORT_TIMEOUT_MS                (100)

/**
 * @def           PROV_PEM_LINE_BYTES
 * @brief         DER bytes per PEM line (48 bytes = 64 base64 characters).
 */
#define PROV_PEM_LINE_BYTES                  (48U)

/**
 * @def           PROV_LOG_BACKLOG_MAX
 * @brief         PEM logging waits while more log messages than this are pending,
 *                so the deferred log buffer never drops a line.
 */
#define PROV_LOG_BACKLOG_MAX                 (8U)

/**
 * @def           PROV_SHA256_LEN
 * @brief         Length of a SHA-256 digest.
 */
#define PROV_SHA256_LEN                      (32U)

/******************************************************************************/
/*                                                                            */
/*                                   ENUMS                                    */
/*                                                                            */
/******************************************************************************/
/**
 * @enum          ProvEventType_E
 * @brief         Events posted to the provisioning thread.
 */
typedef enum
{
   ePE_GET_STATUS = 0,                       /**< GET_STATUS received                 */
   ePE_CSR_REQ,                              /**< CSR_REQ received                    */
   ePE_CLI_READY,                            /**< Client attach result (i32_value)    */
   ePE_TX_DONE,                              /**< CSR transfer result (u8_status)     */
   ePE_CERT_RECEIVED,                        /**< Certificate in staging (i32 = len)  */
   ePE_REJECTED,                             /**< Transfer refused at START           */
   ePE_WIPE,                                 /**< Wipe (appType 0x27: RESULT; 0: none) */
} ProvEventType_E;

/******************************************************************************/
/*                                                                            */
/*                                 STRUCTURES                                 */
/*                                                                            */
/******************************************************************************/
/**
 * @struct        ProvEvent_T
 * @brief         One queued event.
 */
typedef struct
{
   uint8_t u8_type;                          /**< ProvEventType_E                     */
   uint8_t u8_appType;                       /**< appType the event refers to         */
   uint8_t u8_status;                        /**< ProvStatus_E or SETUStatus_E         */
   int32_t i32_value;                        /**< Length or error code                */
} ProvEvent_T;

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
static void sv_Post(uint8_t u8_type, uint8_t u8_appType, uint8_t u8_status, int32_t i32_value);
static int si_ProvRxStart(uint8_t u8_appType, uint32_t u32_totalLen);
static int si_ProvRxData(uint8_t u8_appType, uint32_t u32_offset,
   const uint8_t *u8pt_data, uint16_t u16_len);
static void sv_ProvRxDone(uint8_t u8_appType, SETUStatus_E e_status, uint32_t u32_totalLen);
static void sv_ProvRxShort(uint8_t u8_appType, const uint8_t *u8pt_data, uint8_t u8_len);
static void sv_ProvCliReady(struct bt_conn *stpt_conn, int i_status);
static void sv_ProvTxDone(uint8_t u8_appType, SETUStatus_E e_status);
static void sv_SendResult(uint8_t u8_refAppType, ProvStatus_E e_status);
static void sv_SendStatus(void);
static void sv_SendCsr(void);
static void sv_HandleCsrReq(void);
static void sv_HandleCertReceived(uint8_t u8_appType, uint32_t u32_len);
static void sv_LogPem(const char *cpt_label, const uint8_t *u8pt_der, uint32_t u32_len);
static void sv_ComputePubKeyHash(void);
static void sv_SetKeyState(void);
static bool sb_EraseAndRegenerate(void);
static void sv_HandleWipe(uint8_t u8_refAppType);
static void sv_RestoreAtBoot(void);
static void sv_HandleEvent(const ProvEvent_T *stpt_event);
static void sv_ProvThread(void *vpt_p1, void *vpt_p2, void *vpt_p3);

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
 * @brief         ProvState_E. Written by the provisioning thread, read by the
 *                SETU callbacks.
 */
static atomic_t st_state = ATOMIC_INIT(ePS_NO_KEY);

/**
 * @var           st_certBusy
 * @brief         Set from an accepted CA_CERT/DEV_CERT START until its RESULT: the
 *                staging buffer is in use and other certificates are refused.
 */
static atomic_t st_certBusy = ATOMIC_INIT(0);

/**
 * @var           sb_csrTxPending
 * @brief         A CSR request is being served (Client attach or transfer
 *                running). Provisioning thread only.
 */
static bool sb_csrTxPending = false;

/**
 * @var           su8ar_staging
 * @brief         Certificate being received. Copied to gst_CACertData or
 *                gst_deviceCertData only once it is verified.
 */
static uint8_t su8ar_staging[DEVICE_CERT_MAX_DER_LEN];

/**
 * @var           su8ar_pubKeyHash
 * @brief         SHA-256 of the device public key (uncompressed point), sent in
 *                STATUS so the provisioner can match the device to its CSR.
 */
static uint8_t su8ar_pubKeyHash[PROV_SHA256_LEN];

/**
 * @var           sst_provMsgq
 * @brief         Events from the SETU callbacks to the provisioning thread.
 */
K_MSGQ_DEFINE(sst_provMsgq, sizeof(ProvEvent_T), PROV_EVENT_QUEUE_LEN, 4);

/**
 * @var           sst_provThread
 * @brief         Provisioning thread.
 */
K_THREAD_DEFINE(sst_provThread, PROV_STACK_SIZE, sv_ProvThread, NULL, NULL, NULL,
   PROV_PRIORITY, 0, 0);

/******************************************************************************/
/*                                                                            */
/*                              EXTERN FUNCTIONS                              */
/*                                                                            */
/******************************************************************************/
/**
 * @extern        gstpt_BLE_GetHostConn
 * @brief         Host link (the provisioner's), owned by ConnectionHandling.c:
 *                a new reference, or NULL. The SETU Client attaches to it
 *                when the provisioner asks for the CSR.
 */
extern struct bt_conn *gstpt_BLE_GetHostConn(void);

/**
 * @extern        gv_BLE_RefreshAdv
 * @brief         Restart advertising with data for the new provisioning state
 *                (ConnectionHandling.c).
 */
extern void gv_BLE_RefreshAdv(void);

/******************************************************************************/
/*                                                                            */
/*                        PRIVATE FUNCTION DEFINITIONS                        */
/*                                                                            */
/******************************************************************************/
/**
 * @private       sv_Post
 * @brief         Queue an event for the provisioning thread (never blocks).
 * @param[in]     u8_type ProvEventType_E.
 * @param[in]     u8_appType appType the event refers to.
 * @param[in]     u8_status Status carried by the event.
 * @param[in]     i32_value Length or error code carried by the event.
 * @return        None.
 */
static void sv_Post(uint8_t u8_type, uint8_t u8_appType, uint8_t u8_status, int32_t i32_value)
{
   ProvEvent_T st_event;

   st_event.u8_type = u8_type;
   st_event.u8_appType = u8_appType;
   st_event.u8_status = u8_status;
   st_event.i32_value = i32_value;

   // Check if the queue is full (the provisioner sends faster than it is served)
   if (k_msgq_put(&sst_provMsgq, &st_event, K_NO_WAIT) != 0)
   {
      APP_LOG_WRN("event %u for 0x%02x dropped: queue full", u8_type, u8_appType);
   }
}

/**
 * @private       si_ProvRxStart
 * @brief         SETURxStart_F: accept a CA_CERT or DEV_CERT transfer when the
 *                state allows it, it is 1..DEVICE_CERT_MAX_DER_LEN bytes, and no
 *                other certificate is being handled. A refusal is also reported
 *                with RESULT.
 * @param[in]     u8_appType Application type announced by the provisioner.
 * @param[in]     u32_totalLen Object size.
 * @return        0 to accept, non-zero to reject (provisioner sees eBS_REJECTED).
 */
static int si_ProvRxStart(uint8_t u8_appType, uint32_t u32_totalLen)
{
   ProvState_E e_state = (ProvState_E)atomic_get(&st_state);
   ProvStatus_E e_reject = ePRS_OK;

   // Check if the type is a certificate the device receives
   if ((u8_appType != PROV_APP_TYPE_CA_CERT) && (u8_appType != PROV_APP_TYPE_DEV_CERT))
   {
      e_reject = ePRS_BAD_STATE;
   }
   // Check if the device has a key (and so a CSR the certificate must match),
   // and is not provisioned already (provisioning is one-time until a wipe)
   else if ((e_state == ePS_NO_KEY) || (e_state == ePS_PROVISIONED))
   {
      e_reject = ePRS_BAD_STATE;
   }
   // Check if a device certificate comes after a verified CA certificate
   else if ((u8_appType == PROV_APP_TYPE_DEV_CERT) && (e_state < ePS_CA_OK))
   {
      e_reject = ePRS_BAD_STATE;
   }
   // Check if the certificate fits
   else if ((u32_totalLen == 0U) || (u32_totalLen > DEVICE_CERT_MAX_DER_LEN))
   {
      e_reject = ePRS_TOO_LARGE;
   }
   // Check if the staging buffer is free
   else if (!atomic_cas(&st_certBusy, 0, 1))
   {
      e_reject = ePRS_BAD_STATE;
   }

   // Check if the transfer is refused
   if (e_reject != ePRS_OK)
   {
      APP_LOG_WRN("rejected: type 0x%02x, %u bytes, state %d, status %u", u8_appType,
         u32_totalLen, (int)e_state, (unsigned int)e_reject);
      sv_Post(ePE_REJECTED, u8_appType, (uint8_t)e_reject, 0);
      return -EPERM;
   }

   APP_LOG_INF("certificate 0x%02x announced: %u bytes", u8_appType, u32_totalLen);
   return 0;
}

/**
 * @private       si_ProvRxData
 * @brief         SETURxData_F: copy an in-order chunk into the staging buffer.
 * @param[in]     u8_appType Application type (checked at START).
 * @param[in]     u32_offset Object offset of the chunk.
 * @param[in]     u8pt_data Chunk data, valid only during the call.
 * @param[in]     u16_len Chunk length.
 * @return        0 to continue, -ENOSPC past the staging buffer (cannot happen
 *                after the START length check).
 */
static int si_ProvRxData(uint8_t u8_appType, uint32_t u32_offset,
   const uint8_t *u8pt_data, uint16_t u16_len)
{
   ARG_UNUSED(u8_appType);

   // Check if the chunk fits the staging buffer
   if ((u32_offset > sizeof(su8ar_staging)) ||
      ((uint32_t)u16_len > (sizeof(su8ar_staging) - u32_offset)))
   {
      APP_LOG_ERR("chunk at %u + %u overflows the staging buffer", u32_offset, u16_len);
      return -ENOSPC;
   }

   memcpy(&su8ar_staging[u32_offset], u8pt_data, u16_len);

   return 0;
}

/**
 * @private       sv_ProvRxDone
 * @brief         SETURxDone_F: hand a complete, CRC-verified certificate to the
 *                provisioning thread; release the staging buffer otherwise.
 * @param[in]     u8_appType Application type.
 * @param[in]     e_status Result of the transfer.
 * @param[in]     u32_totalLen Object size.
 * @return        None.
 */
static void sv_ProvRxDone(uint8_t u8_appType, SETUStatus_E e_status, uint32_t u32_totalLen)
{
   // Check if the certificate arrived complete
   if (e_status == eBS_OK)
   {
      sv_Post(ePE_CERT_RECEIVED, u8_appType, 0U, (int32_t)u32_totalLen);
   }
   else
   {
      APP_LOG_WRN("certificate 0x%02x transfer failed, status %u", u8_appType,
         (unsigned int)e_status);
      atomic_set(&st_certBusy, 0);
   }
}

/**
 * @private       sv_ProvRxShort
 * @brief         SETURxShort_F: GET_STATUS, CSR_REQ and DEPROVISION; other types
 *                are ignored.
 * @param[in]     u8_appType Application type.
 * @param[in]     u8pt_data Payload (unused: the messages are empty).
 * @param[in]     u8_len Payload length.
 * @return        None.
 */
static void sv_ProvRxShort(uint8_t u8_appType, const uint8_t *u8pt_data, uint8_t u8_len)
{
   ARG_UNUSED(u8pt_data);

   // Check which request this is
   if (u8_appType == PROV_APP_TYPE_GET_STATUS)
   {
      sv_Post(ePE_GET_STATUS, u8_appType, 0U, 0);
   }
   else if (u8_appType == PROV_APP_TYPE_CSR_REQ)
   {
      sv_Post(ePE_CSR_REQ, u8_appType, 0U, 0);
   }
   else if (u8_appType == PROV_APP_TYPE_DEPROVISION)
   {
      sv_Post(ePE_WIPE, u8_appType, 0U, 0);
   }
   else
   {
      APP_LOG_INF("short message type 0x%02x, %u bytes ignored", u8_appType, u8_len);
   }
}

/**
 * @private       sv_ProvCliReady
 * @brief         SETUCliReady_F: result of attaching the Client to the
 *                provisioner's SETU service.
 * @param[in]     stpt_conn Connection (unused).
 * @param[in]     i_status 0 when ready, negative errno otherwise.
 * @return        None.
 */
static void sv_ProvCliReady(struct bt_conn *stpt_conn, int i_status)
{
   ARG_UNUSED(stpt_conn);

   sv_Post(ePE_CLI_READY, PROV_APP_TYPE_CSR_REQ, 0U, (int32_t)i_status);
}

/**
 * @private       sv_ProvTxDone
 * @brief         SETUTxDone_F: result of the CSR transfer.
 * @param[in]     u8_appType Application type (PROV_APP_TYPE_CSR).
 * @param[in]     e_status Result reported by the provisioner, or a local error.
 * @return        None.
 */
static void sv_ProvTxDone(uint8_t u8_appType, SETUStatus_E e_status)
{
   sv_Post(ePE_TX_DONE, u8_appType, (uint8_t)e_status, 0);
}

/**
 * @private       sv_SendResult
 * @brief         Send RESULT [u8 refAppType][u8 status] (best effort).
 * @param[in]     u8_refAppType appType the result refers to.
 * @param[in]     e_status Result.
 * @return        None.
 */
static void sv_SendResult(uint8_t u8_refAppType, ProvStatus_E e_status)
{
   uint8_t u8ar_payload[PROV_RESULT_LEN];
   int i_ret;

   u8ar_payload[0] = u8_refAppType;
   u8ar_payload[1] = (uint8_t)e_status;

   i_ret = gi_SETUS_SendShort(PROV_APP_TYPE_RESULT, u8ar_payload, sizeof(u8ar_payload),
      K_MSEC(PROV_SHORT_TIMEOUT_MS));

   // Check if the result could not be sent (no link, not subscribed, no credit)
   if (i_ret != 0)
   {
      APP_LOG_DBG("RESULT 0x%02x not sent (%d)", u8_refAppType, i_ret);
   }
}

/**
 * @private       sv_SendStatus
 * @brief         Send STATUS [u8 state][u8 flags][u16 LE CSR length]
 *                [32 B SHA-256(public key)] (best effort).
 * @return        None.
 */
static void sv_SendStatus(void)
{
   uint8_t u8ar_payload[PROV_STATUS_LEN];
   uint16_t u16_csrLen = 0U;
   int i_ret;

   // Check if a CSR is available
   if (gst_CSRData.u8_isCSRGenerated == 1U)
   {
      u16_csrLen = gst_CSRData.u16_CSRLen;
   }

   u8ar_payload[0] = (uint8_t)atomic_get(&st_state);
   u8ar_payload[1] = sb_csrTxPending ? PROV_FLAG_CSR_TX_BUSY : 0U;
   sys_put_le16(u16_csrLen, &u8ar_payload[2]);
   memcpy(&u8ar_payload[4], su8ar_pubKeyHash, sizeof(su8ar_pubKeyHash));

   i_ret = gi_SETUS_SendShort(PROV_APP_TYPE_STATUS, u8ar_payload, sizeof(u8ar_payload),
      K_MSEC(PROV_SHORT_TIMEOUT_MS));

   // Check if the status could not be sent
   if (i_ret != 0)
   {
      APP_LOG_DBG("STATUS not sent (%d)", i_ret);
   }
}

/**
 * @private       sv_SendCsr
 * @brief         Start the CSR transfer on the attached Client. gst_CSRData stays
 *                unchanged until the transfer ends, as SETU requires.
 * @return        None.
 */
static void sv_SendCsr(void)
{
   int i_ret;

   i_ret = gi_SETUC_SendBuffer(PROV_APP_TYPE_CSR, gst_CSRData.u8ar_CSR, gst_CSRData.u16_CSRLen);

   // Check if the transfer could not start
   if (i_ret != 0)
   {
      APP_LOG_ERR("CSR transfer not started (%d)", i_ret);
      sb_csrTxPending = false;
      sv_SendResult(PROV_APP_TYPE_CSR_REQ, ePRS_INTERNAL);
   }
   else
   {
      sb_csrTxPending = true;
      APP_LOG_INF("sending CSR, %u bytes", gst_CSRData.u16_CSRLen);
   }
}

/**
 * @private       sv_HandleCsrReq
 * @brief         Serve CSR_REQ: send the CSR at once if the Client is attached
 *                to the host link, otherwise attach it to the provisioner's
 *                SETU service first (the transfer then starts on
 *                ePE_CLI_READY).
 * @return        None.
 */
static void sv_HandleCsrReq(void)
{
   struct bt_conn *stpt_host = NULL;
   int i_ret;

   // Check if there is a CSR to send (none without a key, none once provisioned)
   if ((atomic_get(&st_state) == ePS_NO_KEY) || (atomic_get(&st_state) == ePS_PROVISIONED))
   {
      sv_SendResult(PROV_APP_TYPE_CSR_REQ, ePRS_BAD_STATE);
   }
   // Check if a request is already being served
   else if (sb_csrTxPending)
   {
      sv_SendResult(PROV_APP_TYPE_CSR_REQ, ePRS_BAD_STATE);
   }
   else
   {
      // The Client attaches to the provisioner's (host link's) service, moved
      // off another link if needed
      stpt_host = gstpt_BLE_GetHostConn();
      i_ret = gi_SETURouter_ClientAttach(stpt_host, PROV_APP_TYPE_CSR_REQ);

      // Check if a host reference was taken
      if (stpt_host != NULL)
      {
         bt_conn_unref(stpt_host);
      }

      // Check if the Client is attached to it already
      if (i_ret == -EALREADY)
      {
         sv_SendCsr();
      }
      // Check if the attach started (or is already running)
      else if (i_ret == 0)
      {
         sb_csrTxPending = true;
         APP_LOG_INF("attaching to the provisioner's SETU service");
      }
      else
      {
         APP_LOG_WRN("Client attach failed (%d)", i_ret);
         sv_SendResult(PROV_APP_TYPE_CSR_REQ, ePRS_NO_PEER_SVC);
      }
   }
}

/**
 * @private       sv_HandleCertReceived
 * @brief         Verify the certificate in the staging buffer and answer with
 *                RESULT. A verified CA certificate becomes the trust anchor and is
 *                held in RAM only. A verified device certificate is stored in ITS
 *                together with the CA; once both are stored the CSR is deleted and
 *                the device is provisioned.
 * @param[in]     u8_appType PROV_APP_TYPE_CA_CERT or PROV_APP_TYPE_DEV_CERT.
 * @param[in]     u32_len Certificate length.
 * @return        None.
 */
static void sv_HandleCertReceived(uint8_t u8_appType, uint32_t u32_len)
{
   DeviceCertStatus_E e_status;
   ProvStatus_E e_result;
   psa_status_t t_status;

   // Check which certificate this is
   if (u8_appType == PROV_APP_TYPE_CA_CERT)
   {
      e_status = ge_VerifyCACertificate(su8ar_staging, u32_len);

      // Check if the CA certificate is the new trust anchor (held in RAM only)
      if (e_status == eDCS_OK)
      {
         memcpy(gst_CACertData.u8ar_CACert, su8ar_staging, u32_len);
         gst_CACertData.u16_CACertLen = (uint16_t)u32_len;
         gst_CACertData.u8_isCACertReceived = 1U;

         // A new CA invalidates a device certificate issued by the previous one
         gst_deviceCertData.u8_isDeviceCertGenerated = 0U;
         atomic_set(&st_state, ePS_CA_OK);

         sv_LogPem("CA certificate", gst_CACertData.u8ar_CACert, u32_len);
      }
   }
   else
   {
      e_status = ge_VerifyOwnDeviceCertificate(su8ar_staging, u32_len);
   }

   e_result = (ProvStatus_E)e_status;

   // Check if a verified device certificate completes the pair: store both
   if ((u8_appType == PROV_APP_TYPE_DEV_CERT) && (e_status == eDCS_OK))
   {
      memcpy(gst_deviceCertData.u8ar_DeviceCert, su8ar_staging, u32_len);
      gst_deviceCertData.u16_deviceCertLen = (uint16_t)u32_len;
      gst_deviceCertData.u8_isDeviceCertGenerated = 1U;

      t_status = gt_StoreCACert();

      // Check if the CA certificate was stored
      if (t_status == PSA_SUCCESS)
      {
         t_status = gt_StoreDeviceCert();
      }

      // Check if the pair could not be stored: keep neither, stay in CA_OK
      if (t_status != PSA_SUCCESS)
      {
         APP_LOG_ERR("certificates not stored (%d)", t_status);
         (void)gt_RemoveStoredCerts();
         gst_deviceCertData.u8_isDeviceCertGenerated = 0U;
         e_result = ePRS_INTERNAL;
      }
      else
      {
         sv_LogPem("Device certificate", gst_deviceCertData.u8ar_DeviceCert, u32_len);

         // The CSR is not needed any more. A failure here is only logged: the
         // next boot removes a leftover CSR.
         (void)gt_RemoveStoredCSR();
         atomic_set(&st_state, ePS_PROVISIONED);
         APP_LOG_INF("device provisioned");

         // Provisioned: advertise the pairing service from now on
         gv_BLE_RefreshAdv();
      }
   }

   // Check if verification failed: the previous certificates stay in force
   if (e_status != eDCS_OK)
   {
      APP_LOG_WRN("certificate 0x%02x rejected, status %u", u8_appType,
         (unsigned int)e_status);
   }

   atomic_set(&st_certBusy, 0);
   sv_SendResult(u8_appType, e_result);
}

/**
 * @private       sv_LogPem
 * @brief         Log a DER certificate as a standard PEM block ("CERTIFICATE"
 *                markers, 64 characters per line) after a title line, pacing the
 *                deferred log so no line is dropped. The block can be copied
 *                from the terminal into a .pem file as it is.
 * @param[in]     cpt_title Title line, e.g. "CA certificate".
 * @param[in]     u8pt_der DER data.
 * @param[in]     u32_len DER length.
 * @return        None.
 */
static void sv_LogPem(const char *cpt_title, const uint8_t *u8pt_der, uint32_t u32_len)
{
   char car_line[(((PROV_PEM_LINE_BYTES + 2U) / 3U) * 4U) + 1U];
   size_t t_lineLen = 0;
   uint32_t u32_pos;
   uint32_t u32_chunk;

   LOG_INF("%s (%u bytes):", cpt_title, u32_len);
   LOG_INF("-----BEGIN CERTIFICATE-----");

   for (u32_pos = 0U; u32_pos < u32_len; u32_pos += PROV_PEM_LINE_BYTES)
   {
      u32_chunk = MIN(PROV_PEM_LINE_BYTES, u32_len - u32_pos);

      // Check if the line could not be encoded (cannot happen: the buffer fits)
      if (base64_encode((uint8_t *)car_line, sizeof(car_line), &t_lineLen,
         &u8pt_der[u32_pos], u32_chunk) != 0)
      {
         APP_LOG_ERR("base64 encoding failed");
         return;
      }

      // Wait for the log thread to drain, so no line is dropped
      while (log_buffered_cnt() > PROV_LOG_BACKLOG_MAX)
      {
         k_msleep(1);
      }

      LOG_INF("%s", car_line);
   }

   LOG_INF("-----END CERTIFICATE-----");
}

/**
 * @private       sv_ComputePubKeyHash
 * @brief         Compute SHA-256 of the device public key for STATUS. Left all
 *                zero if the key cannot be exported.
 * @return        None.
 */
static void sv_ComputePubKeyHash(void)
{
   uint8_t u8ar_pubKey[DEVICE_CERT_P256_PUB_KEY_LEN];
   size_t t_len = 0;
   size_t t_hashLen = 0;
   psa_status_t t_status;

   memset(su8ar_pubKeyHash, 0, sizeof(su8ar_pubKeyHash));

   t_status = psa_export_public_key(CSR_DEVICE_SIGNING_KEY_ID, u8ar_pubKey,
      sizeof(u8ar_pubKey), &t_len);

   // Check if the public key was exported
   if (t_status == PSA_SUCCESS)
   {
      t_status = psa_hash_compute(PSA_ALG_SHA_256, u8ar_pubKey, t_len, su8ar_pubKeyHash,
         sizeof(su8ar_pubKeyHash), &t_hashLen);
   }

   // Check if the hash is unavailable
   if (t_status != PSA_SUCCESS)
   {
      memset(su8ar_pubKeyHash, 0, sizeof(su8ar_pubKeyHash));
      APP_LOG_ERR("public key hash failed: %d", t_status);
   }
}

/**
 * @private       sv_SetKeyState
 * @brief         Set the state from the CSR in RAM: KEY_READY with the public key
 *                hash when there is one, NO_KEY otherwise.
 * @return        None.
 */
static void sv_SetKeyState(void)
{
   // Check if the key and the CSR are ready
   if (gst_CSRData.u8_isCSRGenerated == 1U)
   {
      sv_ComputePubKeyHash();
      atomic_set(&st_state, ePS_KEY_READY);
      APP_LOG_INF("ready for provisioning, CSR %u bytes", gst_CSRData.u16_CSRLen);
   }
   else
   {
      memset(su8ar_pubKeyHash, 0, sizeof(su8ar_pubKeyHash));
      atomic_set(&st_state, ePS_NO_KEY);
      APP_LOG_ERR("no key/CSR: provisioning is not possible");
   }
}

/**
 * @private       sb_EraseAndRegenerate
 * @brief         Wipe every provisioning credential (trust anchor, both
 *                certificates in ITS and RAM, the device key and the CSR), then
 *                generate a fresh key and CSR as on a chip-erased device.
 * @return        true if everything was erased and a new key and CSR are ready.
 */
static bool sb_EraseAndRegenerate(void)
{
   bool b_isErased = true;

   APP_LOG_WRN("wiping provisioning credentials");

   gv_ClearTrustAnchor();
   gv_ClearCertData();

   // Check if the certificates could not be removed from storage
   if (gt_RemoveStoredCerts() != PSA_SUCCESS)
   {
      b_isErased = false;
   }

   // Check if the key or the CSR could not be removed
   if (gt_DestroyDeviceCredentials() != PSA_SUCCESS)
   {
      b_isErased = false;
   }

   gv_GenerateOrLoadCSR();
   sv_SetKeyState();

   return (b_isErased && (atomic_get(&st_state) == ePS_KEY_READY));
}

/**
 * @private       sv_HandleWipe
 * @brief         Serve a wipe request (DEPROVISION or the DK button). Refused
 *                while the CSR is being sent, a certificate is being received
 *                or verified, or a pairing runs. Holds the staging buffer
 *                meanwhile, so no certificate transfer starts during the wipe.
 *                A wipe also deletes every pairing bond: they were made with
 *                the identity it destroys.
 * @param[in]     u8_refAppType PROV_APP_TYPE_DEPROVISION to answer with RESULT,
 *                0 for no answer (button).
 * @return        None.
 */
static void sv_HandleWipe(uint8_t u8_refAppType)
{
   ProvStatus_E e_result = ePRS_OK;

   // Check if a pairing runs: it uses the identity the wipe destroys
   if (gb_Pair_IsRunning())
   {
      APP_LOG_WRN("wipe refused: pairing in progress");
      e_result = ePRS_BAD_STATE;
   }
   // Check if a CSR request or a certificate is in progress
   else if (sb_csrTxPending || !atomic_cas(&st_certBusy, 0, 1))
   {
      APP_LOG_WRN("wipe refused: provisioning in progress");
      e_result = ePRS_BAD_STATE;
   }
   else
   {
      // Check if the wipe or the regeneration failed
      if (!sb_EraseAndRegenerate())
      {
         e_result = ePRS_INTERNAL;
      }

      // The bonds go with the identity: the peer's and the host's
      gv_Pair_ForgetBonds();
      gv_HostAuth_Forget();
      atomic_set(&st_certBusy, 0);

      // Unprovisioned: advertise for provisioning, not for pairing
      gv_BLE_RefreshAdv();
   }

   // Check if the request came over BLE
   if (u8_refAppType != 0U)
   {
      sv_SendResult(u8_refAppType, e_result);
   }
}

/**
 * @private       sv_RestoreAtBoot
 * @brief         Set the boot state from storage. A stored certificate pair is
 *                re-verified (CA, then the device certificate against it and the
 *                device key); it passes -> PROVISIONED, and a leftover CSR is
 *                removed. A corrupt, incomplete or failing pair -> full wipe and
 *                a fresh key and CSR. No pair -> load or generate the key and CSR.
 *                Any other storage error -> NO_KEY, nothing erased.
 * @return        None.
 */
static void sv_RestoreAtBoot(void)
{
   psa_status_t t_status;
   bool b_isValid = false;

   t_status = gt_InitCryptoStorage();

   // Check if storage or crypto is unavailable: nothing can be loaded or made
   if (t_status != PSA_SUCCESS)
   {
      sv_SetKeyState();
      return;
   }

   t_status = gt_LoadStoredCerts();

   // Check if the device was never provisioned
   if (t_status == PSA_ERROR_DOES_NOT_EXIST)
   {
      gv_GenerateOrLoadCSR();
      sv_SetKeyState();
      return;
   }

   // Check if storage could not be read (not a sign of bad data): keep everything
   if ((t_status != PSA_SUCCESS) && (t_status != PSA_ERROR_DATA_CORRUPT) &&
      (t_status != PSA_ERROR_INVALID_SIGNATURE))
   {
      APP_LOG_ERR("stored certificates unreadable (%d)", t_status);
      sv_SetKeyState();
      return;
   }

   // Check if a stored pair re-verifies against the device key
   if ((t_status == PSA_SUCCESS) &&
      (gt_ProbeDeviceKey() == PSA_SUCCESS) &&
      (ge_VerifyCACertificate(gst_CACertData.u8ar_CACert,
         gst_CACertData.u16_CACertLen) == eDCS_OK) &&
      (ge_VerifyStoredDeviceCertificate(gst_deviceCertData.u8ar_DeviceCert,
         gst_deviceCertData.u16_deviceCertLen) == eDCS_OK))
   {
      b_isValid = true;
   }

   // Check if the stored provisioning is valid
   if (b_isValid)
   {
      // Removes a CSR left behind by a reset between storing and deleting it
      (void)gt_RemoveStoredCSR();
      sv_ComputePubKeyHash();
      atomic_set(&st_state, ePS_PROVISIONED);
      APP_LOG_INF("provisioned: stored certificates verified");
   }
   else
   {
      APP_LOG_ERR("stored provisioning is invalid (%d)", t_status);
      (void)sb_EraseAndRegenerate();
   }
}

/**
 * @private       sv_HandleEvent
 * @brief         Serve one event on the provisioning thread.
 * @param[in]     stpt_event Event.
 * @return        None.
 */
static void sv_HandleEvent(const ProvEvent_T *stpt_event)
{
   switch (stpt_event->u8_type)
   {
      case ePE_GET_STATUS:
      {
         sv_SendStatus();
      }
      break;

      case ePE_CSR_REQ:
      {
         sv_HandleCsrReq();
      }
      break;

      case ePE_CLI_READY:
      {
         // Check if the result belongs to a pending CSR request
         if (!sb_csrTxPending)
         {
            break;
         }

         // Check if the Client is attached
         if (stpt_event->i32_value == 0)
         {
            sv_SendCsr();
         }
         else
         {
            APP_LOG_WRN("no SETU service on the provisioner (%d)", stpt_event->i32_value);
            sb_csrTxPending = false;
            sv_SendResult(PROV_APP_TYPE_CSR_REQ, ePRS_NO_PEER_SVC);
         }
      }
      break;

      case ePE_TX_DONE:
      {
         sb_csrTxPending = false;

         // Check if the provisioner received the CSR
         if (stpt_event->u8_status == (uint8_t)eBS_OK)
         {
            APP_LOG_INF("CSR delivered");
            sv_SendResult(PROV_APP_TYPE_CSR, ePRS_OK);
         }
         else
         {
            APP_LOG_WRN("CSR transfer failed, status %u", stpt_event->u8_status);
            sv_SendResult(PROV_APP_TYPE_CSR, ePRS_TRANSFER);
         }
      }
      break;

      case ePE_CERT_RECEIVED:
      {
         sv_HandleCertReceived(stpt_event->u8_appType, (uint32_t)stpt_event->i32_value);
      }
      break;

      case ePE_REJECTED:
      {
         sv_SendResult(stpt_event->u8_appType, (ProvStatus_E)stpt_event->u8_status);
      }
      break;

      case ePE_WIPE:
      {
         sv_HandleWipe(stpt_event->u8_appType);
      }
      break;

      default:
      {
         APP_LOG_ERR("unknown event %u", stpt_event->u8_type);
      }
      break;
   }
}

/**
 * @private       sv_ProvThread
 * @brief         Provisioning thread: serve events for ever.
 * @param[in]     vpt_p1 Unused.
 * @param[in]     vpt_p2 Unused.
 * @param[in]     vpt_p3 Unused.
 * @return        None.
 */
static void sv_ProvThread(void *vpt_p1, void *vpt_p2, void *vpt_p3)
{
   ProvEvent_T st_event;

   ARG_UNUSED(vpt_p1);
   ARG_UNUSED(vpt_p2);
   ARG_UNUSED(vpt_p3);

   while (true)
   {
      // Check if an event arrived
      if (k_msgq_get(&sst_provMsgq, &st_event, K_FOREVER) == 0)
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
 * @public        gi_Prov_Init
 * @brief         Restore the provisioning state from storage (stored certificates
 *                re-verified, or the device key and CSR generated or loaded), register
 *                the provisioning appType range with the SETU router and
 *                with its Client callbacks (the router shares the SETU
 *                Client). Call once from main(), before gi_SETURouter_Start()
 *                and before advertising.
 * @return        0 on success (also when no key could be made: the device then
 *                stays in ePS_NO_KEY and refuses provisioning until a wipe),
 *                otherwise the error from gi_SETURouter_Register().
 */
int gi_Prov_Init(void)
{
   SETURoute_T st_route = { 0 };
   int i_ret;

   sv_RestoreAtBoot();

   st_route.u8_firstAppType = PROV_APP_TYPE_FIRST;
   st_route.u8_lastAppType = PROV_APP_TYPE_LAST;
   st_route.fpt_onRxStart = si_ProvRxStart;
   st_route.fpt_onRxData = si_ProvRxData;
   st_route.fpt_onRxDone = sv_ProvRxDone;
   st_route.fpt_onRxShort = sv_ProvRxShort;
   st_route.fpt_onTxDone = sv_ProvTxDone;
   st_route.fpt_onCliReady = sv_ProvCliReady;

   i_ret = gi_SETURouter_Register(&st_route);

   // Check if the provisioning range was registered
   if (i_ret != 0)
   {
      APP_LOG_ERR("gi_SETURouter_Register failed (%d)", i_ret);
   }

   return i_ret;
}

/**
 * @public        ge_Prov_GetState
 * @brief         Current provisioning state.
 * @return        ProvState_E.
 */
ProvState_E ge_Prov_GetState(void)
{
   return (ProvState_E)atomic_get(&st_state);
}

/**
 * @public        gv_Prov_RequestWipe
 * @brief         Ask the provisioning thread to wipe every provisioning credential
 *                and generate a fresh key and CSR (the DK button's action). Never
 *                blocks; no RESULT is sent. Safe from any thread or a work item.
 * @return        None.
 */
void gv_Prov_RequestWipe(void)
{
   sv_Post(ePE_WIPE, 0U, 0U, 0);
}

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shivam Chudasama [SC]
 */
