/**
 * @file          HostAuthCrypto.h
 * @brief         Header file containing the cryptography of host authentication:
 *                the ephemeral ECDH key, the handshake transcript, the role
 *                signatures and the passkey derived for LE Secure Connections
 *                passkey entry. Wire contract: _DOC/HostAuth/PROTOCOL.md §4.
 * @date          25/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#ifndef _HOST_AUTH_CRYPTO_H
#define _HOST_AUTH_CRYPTO_H

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include <stddef.h>
#include <stdint.h>
#include <psa/crypto.h>

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
/**
 * @def           HOST_AUTH_NONCE_LEN
 * @brief         Length of the host nonce Nh and of the device nonce Nd.
 */
#define HOST_AUTH_NONCE_LEN                  (16U)

/**
 * @def           HOST_AUTH_POINT_LEN
 * @brief         Length of an ephemeral P-256 public key (uncompressed X9.62
 *                point 0x04 || X || Y).
 */
#define HOST_AUTH_POINT_LEN                  (65U)

/**
 * @def           HOST_AUTH_SIG_LEN
 * @brief         Length of an ECDSA P-256 signature, raw r || s.
 */
#define HOST_AUTH_SIG_LEN                    (64U)

/**
 * @def           HOST_AUTH_HASH_LEN
 * @brief         Length of a SHA-256 digest (the transcript T, a certificate
 *                hash) and of the ECDH shared secret Z.
 */
#define HOST_AUTH_HASH_LEN                   (32U)

/**
 * @def           HOST_AUTH_PASSKEY_MAX
 * @brief         Passkeys are 0 .. HOST_AUTH_PASSKEY_MAX (six decimal digits).
 */
#define HOST_AUTH_PASSKEY_MAX                (999999UL)

/******************************************************************************/
/*                                                                            */
/*                                   ENUMS                                    */
/*                                                                            */
/******************************************************************************/
/**
 * @enum          HostAuthRole_E
 * @brief         Who signs the transcript: the label put in front of T keeps a
 *                signature of one side from being replayed as the other's.
 */
typedef enum
{
   eHAR_DEVICE = 0,                          /**< Signs "dev" || T                 */
   eHAR_HOST = 1,                            /**< Signs "host" || T                */
} HostAuthRole_E;

/******************************************************************************/
/*                                                                            */
/*                                 STRUCTURES                                 */
/*                                                                            */
/******************************************************************************/
/**
 * @struct        HostAuthTranscript_T
 * @brief         The handshake values the transcript T covers.
 */
typedef struct
{
   const uint8_t *u8pt_nonceHost;            /**< Nh, HOST_AUTH_NONCE_LEN bytes        */
   const uint8_t *u8pt_nonceDev;             /**< Nd, HOST_AUTH_NONCE_LEN bytes        */
   const uint8_t *u8pt_pointHost;            /**< Qh, HOST_AUTH_POINT_LEN bytes        */
   const uint8_t *u8pt_pointDev;             /**< Qd, HOST_AUTH_POINT_LEN bytes        */
   const uint8_t *u8pt_certHost;             /**< Host certificate (DER)               */
   size_t t_certHostLen;                     /**< Its length                           */
   const uint8_t *u8pt_certDev;              /**< Device certificate (DER)             */
   size_t t_certDevLen;                      /**< Its length                           */
} HostAuthTranscript_T;

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
extern psa_status_t gt_HostAuthCrypto_Random(uint8_t *u8pt_buf, size_t t_len);
extern psa_status_t gt_HostAuthCrypto_NewEphemeral(psa_key_id_t *tpt_key, uint8_t *u8pt_point);
extern psa_status_t gt_HostAuthCrypto_Agree(psa_key_id_t t_key, const uint8_t *u8pt_peerPoint,
   uint8_t *u8pt_secret);
extern psa_status_t gt_HostAuthCrypto_Transcript(const HostAuthTranscript_T *stpt_in,
   uint8_t *u8pt_transcript);
extern psa_status_t gt_HostAuthCrypto_Sign(psa_key_id_t t_key, HostAuthRole_E e_role,
   const uint8_t *u8pt_transcript, uint8_t *u8pt_sig);
extern psa_status_t gt_HostAuthCrypto_Verify(psa_key_id_t t_key, HostAuthRole_E e_role,
   const uint8_t *u8pt_transcript, const uint8_t *u8pt_sig);
extern psa_status_t gt_HostAuthCrypto_Passkey(const uint8_t *u8pt_secret,
   const uint8_t *u8pt_nonceHost, const uint8_t *u8pt_nonceDev,
   const uint8_t *u8pt_transcript, uint32_t *u32pt_passkey);

#endif //!_HOST_AUTH_CRYPTO_H

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shivam Chudasama [SC]
 */
