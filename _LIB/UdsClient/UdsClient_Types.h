/**
 * @file          UdsClient_Types.h
 * @brief         Types of the UDS client (ISO 14229-1, tester side): the ECU target
 *                (CAN identifiers, frame format, timing), the transport interface
 *                the client sends requests through (UdsTp_T, implemented on
 *                Zephyr's ISO-TP by UdsTp_Isotp.c), the seed -> key callback, and
 *                the service and negative response codes it uses.
 *                See _DOC/UdsClient/API_REFERENCE.md.
 *
 * @date          12/10/2026
 * @author        Shivam Chudasama [SC]
 * @license       MIT
 */

/* SPDX-License-Identifier: MIT */

#ifndef _UDS_CLIENT_TYPES_H
#define _UDS_CLIENT_TYPES_H

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <zephyr/kernel.h>

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
/**
 * @def           UDS_TGT_EXT_ID
 * @brief         UdsTarget_T flag: 29-bit CAN identifiers (else 11-bit).
 */
#define UDS_TGT_EXT_ID                       (0x01U)

/**
 * @def           UDS_TGT_FD
 * @brief         UdsTarget_T flag: CAN FD frames (u8_txDl up to 64).
 */
#define UDS_TGT_FD                           (0x02U)

/**
 * @def           UDS_TGT_BRS
 * @brief         UdsTarget_T flag: bit-rate switching (needs UDS_TGT_FD).
 */
#define UDS_TGT_BRS                          (0x04U)

/**
 * @def           UDS_TGT_PAD
 * @brief         UdsTarget_T flag: pad frames (the transport decides the byte;
 *                Zephyr's ISO-TP pads with 0xCC when built with padding).
 */
#define UDS_TGT_PAD                          (0x08U)

/**
 * @def           UDS_TGT_EXT_ADDR
 * @brief         UdsTarget_T flag: ISO-TP extended addressing. Reserved: not
 *                supported (gi_UdsClient_SetTarget() returns -ENOTSUP).
 */
#define UDS_TGT_EXT_ADDR                     (0x10U)

/**
 * @def           UDS_TGT_FUNC
 * @brief         UdsTarget_T flag: u32_funcId is valid (functional requests).
 */
#define UDS_TGT_FUNC                         (0x20U)

/**
 * @def           UDS_TGT_FLAGS
 * @brief         Every UdsTarget_T flag.
 */
#define UDS_TGT_FLAGS                        (0x3FU)

/**
 * @def           UDS_SID_*
 * @brief         Service identifiers the client builds requests for.
 */
#define UDS_SID_SESSION                      (0x10U)
#define UDS_SID_ECU_RESET                    (0x11U)
#define UDS_SID_CLEAR_DTC                    (0x14U)
#define UDS_SID_READ_DTC                     (0x19U)
#define UDS_SID_READ_DID                     (0x22U)
#define UDS_SID_SECURITY                     (0x27U)
#define UDS_SID_COMM_CONTROL                 (0x28U)
#define UDS_SID_WRITE_DID                    (0x2EU)
#define UDS_SID_ROUTINE                      (0x31U)
#define UDS_SID_REQUEST_DOWNLOAD             (0x34U)
#define UDS_SID_TRANSFER_DATA                (0x36U)
#define UDS_SID_TRANSFER_EXIT                (0x37U)
#define UDS_SID_TESTER_PRESENT               (0x3EU)
#define UDS_SID_DTC_SETTING                  (0x85U)

/**
 * @def           UDS_NEGATIVE_RESPONSE
 * @brief         First byte of a negative response: 7F <SID> <NRC>.
 */
#define UDS_NEGATIVE_RESPONSE                (0x7FU)

/**
 * @def           UDS_POSITIVE_OFFSET
 * @brief         A positive response's SID is the request's plus this.
 */
#define UDS_POSITIVE_OFFSET                  (0x40U)

/**
 * @def           UDS_SUPPRESS_POS_RSP
 * @brief         Sub-function bit: the ECU sends no positive response.
 */
#define UDS_SUPPRESS_POS_RSP                 (0x80U)

/**
 * @def           UDS_NRC_BUSY_REPEAT
 * @brief         NRC busyRepeatRequest: the client sends the request again.
 */
#define UDS_NRC_BUSY_REPEAT                  (0x21U)

/**
 * @def           UDS_NRC_PENDING
 * @brief         NRC requestCorrectlyReceived-ResponsePending: the client waits
 *                P2* for the final response.
 */
#define UDS_NRC_PENDING                      (0x78U)

/**
 * @def           UDS_SESSION_DEFAULT
 * @brief         DiagnosticSessionControl: the default session (no keep-alive).
 */
#define UDS_SESSION_DEFAULT                  (0x01U)

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
 * @struct        UdsTarget_T
 * @brief         The ECU the client talks to.
 */
typedef struct
{
   uint32_t u32_txId;                        /**< Physical request CAN ID.             */
   uint32_t u32_rxId;                        /**< Response CAN ID.                     */
   uint32_t u32_funcId;                      /**< Functional request ID (UDS_TGT_FUNC).*/
   uint8_t u8_flags;                         /**< UDS_TGT_* flags.                     */
   uint8_t u8_txDl;                          /**< TX frame length: 8, or up to 64 (FD);
                                                  0 = 8 or 64.                         */
   uint16_t u16_p2Ms;                        /**< P2 override (ms), 0 = default/ECU's. */
   uint16_t u16_p2StarMs;                    /**< P2* override (ms), 0 = default/ECU's.*/
} UdsTarget_T;

/**
 * @struct        UdsTp_T
 * @brief         The transport the client sends requests through (ISO-TP). Every
 *                function returns 0 or a byte count, or a negative errno.
 */
typedef struct
{
   /** Listen for responses of the target (replacing any earlier binding). */
   int (*fpt_bind)(void *vpt_ctx, const UdsTarget_T *stpt_target);
   /** Stop listening. */
   void (*fpt_unbind)(void *vpt_ctx);
   /** Send one request, physically or functionally; blocks until it is sent. */
   int (*fpt_send)(void *vpt_ctx, const uint8_t *u8pt_data, size_t t_len, bool b_functional);
   /** Receive one whole message: its length; -EAGAIN on timeout; -EMSGSIZE if
       it did not fit (the rest is discarded). */
   int (*fpt_recv)(void *vpt_ctx, uint8_t *u8pt_buf, size_t t_max, k_timeout_t t_timeout);
   void *vpt_ctx;                            /**< Passed to every function.            */
} UdsTp_T;

/**
 * @typedef       UdsKey_F
 * @brief         Compute the key for a seed (SecurityAccess).
 * @param[in]     u8_level The requestSeed level (odd).
 * @param[in]     u8pt_seed Seed.
 * @param[in]     t_seedLen Seed length.
 * @param[out]    u8pt_key Key.
 * @param[in]     t_keyMax Size of u8pt_key.
 * @param[out]    tpt_keyLen Key length.
 * @param[in]     vpt_user The user pointer given to gi_UdsClient_SecurityAccess().
 * @return        0, or a negative errno (-ENOTSUP: no such algorithm).
 */
typedef int (*UdsKey_F)(uint8_t u8_level, const uint8_t *u8pt_seed, size_t t_seedLen, uint8_t *u8pt_key,
   size_t t_keyMax, size_t *tpt_keyLen, void *vpt_user);

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

#endif //!_UDS_CLIENT_TYPES_H
