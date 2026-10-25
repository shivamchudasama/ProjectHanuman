/**
 * @file          Pair.h
 * @brief         Header file containing certificate-based OOB pairing between two
 *                provisioned devices (CBAP phase 2, AN1396 §4.2), orchestrated by
 *                a host (the PC GUI) over the Pairing GATT service. The two
 *                devices connect to each other, exchange and verify their device
 *                certificates over SETU, exchange their LE Secure Connections
 *                OOB data signed with their device keys, verify the signatures,
 *                and pair with the OOB method (LE Secure Connections, level 4,
 *                bonded). Once bonded, the two reconnect by themselves (after a
 *                reset or a lost link) and encrypt with the stored keys.
 *                Wire contract: _DOC/Pairing/PROTOCOL.md.
 * @date          06/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#ifndef _PAIR_H
#define _PAIR_H

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <zephyr/bluetooth/conn.h>

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
/**
 * @def           PAIR_APP_TYPE_FIRST
 * @brief         First SETU appType of the pairing range.
 */
#define PAIR_APP_TYPE_FIRST                  (0x30U)

/**
 * @def           PAIR_APP_TYPE_LAST
 * @brief         Last SETU appType of the pairing range (inclusive).
 */
#define PAIR_APP_TYPE_LAST                   (0x3FU)

/**
 * @def           PAIR_APP_TYPE_PEER_CERT
 * @brief         Transfer, device -> peer device: the sender's DER device
 *                certificate, 1..1024 bytes.
 */
#define PAIR_APP_TYPE_PEER_CERT              (0x30U)

/**
 * @def           PAIR_APP_TYPE_OOB
 * @brief         Transfer, device -> peer device: signed OOB data
 *                [16 B r][16 B c][64 B signature] (PAIR_OOB_FRAME_LEN).
 */
#define PAIR_APP_TYPE_OOB                    (0x31U)

/**
 * @def           PAIR_OP_START
 * @brief         CONTROL opcode: start pairing,
 *                [0x01][u8 role][7 B peer address].
 */
#define PAIR_OP_START                        (0x01U)

/**
 * @def           PAIR_OP_CANCEL
 * @brief         CONTROL opcode: abort a running pairing, [0x02].
 */
#define PAIR_OP_CANCEL                       (0x02U)

/**
 * @def           PAIR_OP_UNPAIR
 * @brief         CONTROL opcode: drop the peer link and delete the bond, [0x03].
 */
#define PAIR_OP_UNPAIR                       (0x03U)

/**
 * @def           PAIR_START_LEN
 * @brief         Length of a START write.
 */
#define PAIR_START_LEN                       (9U)

/**
 * @def           PAIR_STATUS_LEN
 * @brief         Length of STATUS: [u8 state][u8 error][u8 detail]
 *                [u8 provState][u8 role][7 B own address][7 B peer address].
 */
#define PAIR_STATUS_LEN                      (19U)

/******************************************************************************/
/*                                                                            */
/*                                   ENUMS                                    */
/*                                                                            */
/******************************************************************************/
/**
 * @enum          PairRole_E
 * @brief         Link role a device takes towards its peer, chosen by the host.
 */
typedef enum
{
   ePRL_NONE = 0,                            /**< No pairing yet                       */
   ePRL_CENTRAL = 1,                         /**< Scans, connects, starts pairing      */
   ePRL_PERIPHERAL = 2,                      /**< Advertises to the peer               */
} PairRole_E;

/**
 * @enum          PairState_E
 * @brief         Pairing state reported in STATUS.
 */
typedef enum
{
   ePST_IDLE = 0,                            /**< Nothing running, no bond             */
   ePST_ARMED = 1,                           /**< Advertising to / scanning for peer   */
   ePST_CONNECTED = 2,                       /**< Peer link up, SETU attaching     */
   ePST_CERT_EXCHANGE = 3,                   /**< Certificates being exchanged         */
   ePST_CERT_VERIFIED = 4,                   /**< Peer certificate verified            */
   ePST_OOB_EXCHANGE = 5,                    /**< Signed OOB data being exchanged      */
   ePST_PAIRING = 6,                         /**< Peer OOB verified, SMP running       */
   ePST_PAIRED = 7,                          /**< Bonded at level 4, link secured      */
   ePST_FAILED = 8,                          /**< Stopped; see error and detail        */
} PairState_E;

/**
 * @enum          PairError_E
 * @brief         Why a pairing failed (STATUS error; detail adds a code).
 */
typedef enum
{
   ePER_NONE = 0,                            /**< No error                             */
   ePER_NOT_PROVISIONED = 1,                 /**< This device is not provisioned       */
   ePER_BAD_ARG = 2,                         /**< Peer address is this device's own    */
   ePER_BUSY = 3,                            /**< A SETU transfer is running       */
   ePER_TIMEOUT = 4,                         /**< Detail: state when it expired        */
   ePER_CONNECT = 5,                         /**< Detail: HCI error or errno           */
   ePER_NO_PEER_SVC = 6,                     /**< Peer has no SETU service         */
   ePER_PEER_CERT = 7,                       /**< Detail: DeviceCertStatus_E           */
   ePER_OOB_SIG = 8,                         /**< Peer OOB signature does not verify   */
   ePER_SMP = 9,                             /**< Detail: bt_security_err or level     */
   ePER_TRANSFER = 10,                       /**< Detail: SETUStatus_E                  */
   ePER_SECURED = 11,                        /**< Detail: ATT error of the SECURED write */
   ePER_LINK_LOST = 12,                      /**< Detail: HCI disconnect reason        */
   ePER_CANCELLED = 13,                      /**< CANCEL from the host                 */
   ePER_INTERNAL = 14,                       /**< Detail: low byte of the error        */
} PairError_E;

/******************************************************************************/
/*                                                                            */
/*                                 STRUCTURES                                 */
/*                                                                            */
/******************************************************************************/
struct bt_conn;
struct bt_gatt_attr;

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
/* ---- Start-up (main(), _BLE) --------------------------------------------- */
extern int gi_Pair_Init(void);
extern void gv_Pair_OnBtReady(void);

/* ---- Link events (_BLE, BT context) -------------------------------------- */
extern bool gb_Pair_ClaimConn(struct bt_conn *stpt_conn, uint8_t u8_err);
extern void gv_Pair_OnDisconnected(struct bt_conn *stpt_conn, uint8_t u8_reason);
extern void gv_Pair_OnSecurityChanged(struct bt_conn *stpt_conn, uint8_t u8_level,
   uint8_t u8_err);
extern bool gb_Pair_IsAdvertising(void);
extern bool gb_Pair_AwaitsBondedPeer(void);
extern bool gb_Pair_GetBondedPeer(bt_addr_le_t *stpt_addr);

/* ---- Pairing service (PairSvc.c, BT context) ----------------------------- */
extern ssize_t gt_Pair_OnControlWrite(struct bt_conn *stpt_conn, const uint8_t *u8pt_data,
   uint16_t u16_len);
extern ssize_t gt_Pair_OnSecuredWrite(struct bt_conn *stpt_conn, const uint8_t *u8pt_data,
   uint16_t u16_len);
extern void gv_Pair_GetStatus(uint8_t *u8pt_status);

/* ---- Provisioning ------------------------------------------------------- */
extern bool gb_Pair_IsRunning(void);
extern void gv_Pair_ForgetBonds(void);

#endif //!_PAIR_H

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shivam Chudasama [SC]
 */
