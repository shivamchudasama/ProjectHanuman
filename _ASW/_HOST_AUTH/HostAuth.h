/**
 * @file          HostAuth.h
 * @brief         Header file containing host authentication: the PC host proves
 *                a host certificate of this device's CA in a signed ECDH
 *                handshake over SETU, then bonds with LE Secure Connections
 *                passkey entry, the passkey derived from the handshake. The
 *                device keeps one host bond; only that host (on an encrypted,
 *                level 4 link) reaches the device's functions. Advertising for a
 *                host runs only in a window opened by the DK button.
 *                Wire contract: _DOC/HostAuth/PROTOCOL.md.
 * @date          25/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#ifndef _HOST_AUTH_H
#define _HOST_AUTH_H

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include <stdbool.h>
#include <stdint.h>
#include <zephyr/bluetooth/conn.h>

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
/**
 * @def           HOST_AUTH_APP_TYPE_FIRST
 * @brief         First SETU appType of the host authentication range.
 */
#define HOST_AUTH_APP_TYPE_FIRST             (0x60U)

/**
 * @def           HOST_AUTH_APP_TYPE_LAST
 * @brief         Last SETU appType of the range (inclusive).
 */
#define HOST_AUTH_APP_TYPE_LAST              (0x6FU)

/**
 * @def           HOST_AUTH_APP_TYPE_STATUS_REQ
 * @brief         Short message, host -> device, no payload: asks for STATUS.
 */
#define HOST_AUTH_APP_TYPE_STATUS_REQ        (0x60U)

/**
 * @def           HOST_AUTH_APP_TYPE_STATUS
 * @brief         Short message, device -> host: [u8 state][u8 flags].
 */
#define HOST_AUTH_APP_TYPE_STATUS            (0x61U)

/**
 * @def           HOST_AUTH_APP_TYPE_HELLO
 * @brief         Transfer, host -> device: [u8 version][Nh 16][Qh 65]
 *                [host certificate DER].
 */
#define HOST_AUTH_APP_TYPE_HELLO             (0x62U)

/**
 * @def           HOST_AUTH_APP_TYPE_CHALLENGE
 * @brief         Transfer, device -> host (to the host's SETU service):
 *                [u8 version][Nd 16][Qd 65][SigD 64][device certificate DER].
 */
#define HOST_AUTH_APP_TYPE_CHALLENGE         (0x63U)

/**
 * @def           HOST_AUTH_APP_TYPE_FINISH
 * @brief         Short message, host -> device: [SigH 64].
 */
#define HOST_AUTH_APP_TYPE_FINISH            (0x64U)

/**
 * @def           HOST_AUTH_APP_TYPE_RESULT
 * @brief         Short message, device -> host: [u8 refAppType][u8 status]
 *                [u8 detail].
 */
#define HOST_AUTH_APP_TYPE_RESULT            (0x65U)

/**
 * @def           HOST_AUTH_APP_TYPE_REFUSED
 * @brief         Short message, device -> host: [u8 appType] the gate refused.
 */
#define HOST_AUTH_APP_TYPE_REFUSED           (0x66U)

/**
 * @def           HOST_AUTH_VERSION
 * @brief         Handshake version in HELLO and CHALLENGE.
 */
#define HOST_AUTH_VERSION                    (1U)

/**
 * @def           HOST_AUTH_STATUS_LEN
 * @brief         Payload length of STATUS.
 */
#define HOST_AUTH_STATUS_LEN                 (2U)

/**
 * @def           HOST_AUTH_RESULT_LEN
 * @brief         Payload length of RESULT.
 */
#define HOST_AUTH_RESULT_LEN                 (3U)

/**
 * @def           HOST_AUTH_FLAG_WINDOW_OPEN
 * @brief         STATUS flags bit: the host window is open (advertising).
 */
#define HOST_AUTH_FLAG_WINDOW_OPEN           (0x01U)

/**
 * @def           HOST_AUTH_FLAG_HOST_BOND
 * @brief         STATUS flags bit: a host is bonded.
 */
#define HOST_AUTH_FLAG_HOST_BOND             (0x02U)

/******************************************************************************/
/*                                                                            */
/*                                   ENUMS                                    */
/*                                                                            */
/******************************************************************************/
/**
 * @enum          HostAuthState_E
 * @brief         State of the host link, sent in STATUS.
 */
typedef enum
{
   eHAS_UNPROVISIONED = 0,                   /**< No certificate yet: no handshake;
                                                  only provisioning is reachable   */
   eHAS_OPEN = 1,                            /**< No host bonded: HELLO accepted    */
   eHAS_HOST_BONDED = 2,                     /**< A host is bonded and this link is
                                                  not it (yet: not encrypted)      */
   eHAS_AWAIT_FINISH = 3,                    /**< CHALLENGE sent, FINISH awaited    */
   eHAS_AWAIT_PAIRING = 4,                   /**< Handshake done, pairing awaited   */
   eHAS_TRUSTED = 5,                         /**< The bonded host at level 4        */
} HostAuthState_E;

/**
 * @enum          HostAuthResult_E
 * @brief         RESULT status codes.
 */
typedef enum
{
   eHRS_OK = 0x00,                           /**< Done                                */
   eHRS_BAD_STATE = 0x01,                    /**< Not allowed in this state            */
   eHRS_PARSE = 0x02,                        /**< Wrong length or version              */
   eHRS_BAD_CERT = 0x03,                     /**< Host certificate refused (detail:
                                                  DeviceCertStatus_E)                  */
   eHRS_BAD_SIG = 0x04,                      /**< FINISH signature does not verify     */
   eHRS_HOST_BONDED = 0x05,                  /**< Another host is bonded: hold the
                                                  button to forget it                  */
   eHRS_NO_PC_SVC = 0x06,                    /**< Host hosts no SETU service           */
   eHRS_BUSY = 0x07,                         /**< A handshake is being served          */
   eHRS_TIMEOUT = 0x08,                      /**< Handshake or pairing took too long   */
   eHRS_PAIRING = 0x09,                      /**< Pairing failed (detail: SMP reason)  */
   eHRS_INTERNAL = 0x0A,                     /**< Crypto or memory failure             */
   eHRS_TRANSFER = 0x0B,                     /**< CHALLENGE transfer failed            */
} HostAuthResult_E;

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
/*                              EXTERN VARIABLES                              */
/*                                                                            */
/******************************************************************************/

/******************************************************************************/
/*                                                                            */
/*                              EXTERN FUNCTIONS                              */
/*                                                                            */
/******************************************************************************/
extern int gi_HostAuth_Init(void);
extern void gv_HostAuth_OnBtReady(void);
extern void gv_HostAuth_OnHostConnected(struct bt_conn *stpt_conn);
extern void gv_HostAuth_OnHostDisconnected(struct bt_conn *stpt_conn);
extern void gv_HostAuth_OnSecurityChanged(struct bt_conn *stpt_conn, uint8_t u8_level,
   uint8_t u8_err);
extern bool gb_HostAuth_Admits(uint8_t u8_appType);
extern bool gb_HostAuth_IsTrustedConn(const struct bt_conn *stpt_conn);
extern bool gb_HostAuth_IsHostAddr(const bt_addr_le_t *stpt_addr);
extern bool gb_HostAuth_WindowOpen(void);
extern void gv_HostAuth_OpenWindow(void);
extern void gv_HostAuth_ForgetHostAndOpen(void);
extern void gv_HostAuth_Forget(void);
extern HostAuthState_E ge_HostAuth_GetState(void);

#endif //!_HOST_AUTH_H

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shivam Chudasama [SC]
 */
