/**
 * @file          HostAuthCrypto.c
 * @brief         Source file containing the cryptography of host authentication.
 *
 *                Both sides make a fresh P-256 key pair per handshake (the
 *                device key only signs: it has no derive usage). The transcript
 *
 *                   T = SHA-256("PH-HOSTAUTH-1" || Nh || Nd || Qh || Qd ||
 *                               SHA-256(host cert) || SHA-256(device cert))
 *
 *                binds the nonces, both ephemeral keys and both certificates.
 *                Each side signs its role label and T with its certificate key
 *                (ECDSA P-256, SHA-256, raw r || s), and both derive
 *
 *                   passkey = u32be(HKDF-SHA256(IKM = Z, salt = Nh || Nd,
 *                               info = "PH-HOSTAUTH-1 passkey" || T, L = 4))
 *                             mod 1 000 000
 *
 *                from the ECDH secret Z. Someone between the two cannot learn Z
 *                (the ephemeral keys are signed), so the passkey is secret and
 *                LE Secure Connections passkey entry with it is authenticated.
 * @date          25/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include "HostAuthCrypto.h"
#include <string.h>

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
/**
 * @def           HOST_AUTH_SIGN_ALG
 * @brief         Signature algorithm: ECDSA with SHA-256 over the message.
 */
#define HOST_AUTH_SIGN_ALG                   (PSA_ALG_ECDSA(PSA_ALG_SHA_256))

/**
 * @def           HOST_AUTH_LABEL
 * @brief         Protocol label at the start of the transcript.
 */
#define HOST_AUTH_LABEL                      "PH-HOSTAUTH-1"

/**
 * @def           HOST_AUTH_LABEL_LEN
 * @brief         Length of HOST_AUTH_LABEL, without the terminator.
 */
#define HOST_AUTH_LABEL_LEN                  (sizeof(HOST_AUTH_LABEL) - 1U)

/**
 * @def           HOST_AUTH_INFO
 * @brief         HKDF info prefix of the passkey (T follows).
 */
#define HOST_AUTH_INFO                       "PH-HOSTAUTH-1 passkey"

/**
 * @def           HOST_AUTH_INFO_LEN
 * @brief         Length of HOST_AUTH_INFO, without the terminator.
 */
#define HOST_AUTH_INFO_LEN                   (sizeof(HOST_AUTH_INFO) - 1U)

/**
 * @def           HOST_AUTH_TRANSCRIPT_IN_LEN
 * @brief         Length of the transcript's hashed input.
 */
#define HOST_AUTH_TRANSCRIPT_IN_LEN          (HOST_AUTH_LABEL_LEN + (2U * HOST_AUTH_NONCE_LEN) + \
                                              (2U * HOST_AUTH_POINT_LEN) + (2U * HOST_AUTH_HASH_LEN))

/**
 * @def           HOST_AUTH_ROLE_MAX_LEN
 * @brief         Longest role label ("host").
 */
#define HOST_AUTH_ROLE_MAX_LEN               (4U)

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
static size_t st_BuildSigned(HostAuthRole_E e_role, const uint8_t *u8pt_transcript,
   uint8_t *u8pt_msg);
static psa_status_t st_Hash(const uint8_t *u8pt_in, size_t t_len, uint8_t *u8pt_out);

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
 * @private       st_BuildSigned
 * @brief         Lay out the signed message: role label || T.
 * @param[in]     e_role Signing role.
 * @param[in]     u8pt_transcript T (HOST_AUTH_HASH_LEN bytes).
 * @param[out]    u8pt_msg Message, at least HOST_AUTH_ROLE_MAX_LEN +
 *                HOST_AUTH_HASH_LEN bytes.
 * @return        Message length.
 */
static size_t st_BuildSigned(HostAuthRole_E e_role, const uint8_t *u8pt_transcript,
   uint8_t *u8pt_msg)
{
   size_t t_labelLen = (e_role == eHAR_HOST) ? 4U : 3U;

   (void)memcpy(u8pt_msg, (e_role == eHAR_HOST) ? "host" : "dev", t_labelLen);
   (void)memcpy(&u8pt_msg[t_labelLen], u8pt_transcript, HOST_AUTH_HASH_LEN);

   return t_labelLen + HOST_AUTH_HASH_LEN;
}

/**
 * @private       st_Hash
 * @brief         SHA-256 of a buffer.
 * @param[in]     u8pt_in Input.
 * @param[in]     t_len Input length.
 * @param[out]    u8pt_out Digest, HOST_AUTH_HASH_LEN bytes.
 * @return        PSA_SUCCESS, or the error of psa_hash_compute().
 */
static psa_status_t st_Hash(const uint8_t *u8pt_in, size_t t_len, uint8_t *u8pt_out)
{
   size_t t_outLen = 0U;
   psa_status_t t_status;

   t_status = psa_hash_compute(PSA_ALG_SHA_256, u8pt_in, t_len, u8pt_out, HOST_AUTH_HASH_LEN,
      &t_outLen);

   // Check if a whole digest was made
   if ((t_status == PSA_SUCCESS) && (t_outLen != HOST_AUTH_HASH_LEN))
   {
      t_status = PSA_ERROR_CORRUPTION_DETECTED;
   }

   return t_status;
}

/******************************************************************************/
/*                                                                            */
/*                        PUBLIC FUNCTION DEFINITIONS                         */
/*                                                                            */
/******************************************************************************/
/**
 * @public        gt_HostAuthCrypto_Random
 * @brief         Fill a buffer with random bytes (the device nonce).
 * @param[out]    u8pt_buf Buffer.
 * @param[in]     t_len Buffer length.
 * @return        PSA_SUCCESS; PSA_ERROR_INVALID_ARGUMENT for NULL; otherwise the
 *                error of psa_generate_random().
 */
psa_status_t gt_HostAuthCrypto_Random(uint8_t *u8pt_buf, size_t t_len)
{
   // Check if the buffer is given
   if (u8pt_buf == NULL)
   {
      return PSA_ERROR_INVALID_ARGUMENT;
   }

   return psa_generate_random(u8pt_buf, t_len);
}

/**
 * @public        gt_HostAuthCrypto_NewEphemeral
 * @brief         Generate a volatile P-256 key pair for one ECDH and export its
 *                public point. The caller destroys the key (psa_destroy_key())
 *                once the handshake ends.
 * @param[out]    tpt_key Receives the key ID on success.
 * @param[out]    u8pt_point Public point, HOST_AUTH_POINT_LEN bytes.
 * @return        PSA_SUCCESS; PSA_ERROR_INVALID_ARGUMENT for NULL; otherwise the
 *                error of psa_generate_key() or psa_export_public_key() (the key
 *                is destroyed then), or PSA_ERROR_CORRUPTION_DETECTED if the
 *                point is not HOST_AUTH_POINT_LEN bytes.
 */
psa_status_t gt_HostAuthCrypto_NewEphemeral(psa_key_id_t *tpt_key, uint8_t *u8pt_point)
{
   psa_key_attributes_t st_attr = PSA_KEY_ATTRIBUTES_INIT;
   size_t t_pointLen = 0U;
   psa_status_t t_status;

   // Check if every buffer is given
   if ((tpt_key == NULL) || (u8pt_point == NULL))
   {
      return PSA_ERROR_INVALID_ARGUMENT;
   }

   psa_set_key_type(&st_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
   psa_set_key_bits(&st_attr, 256U);
   psa_set_key_usage_flags(&st_attr, PSA_KEY_USAGE_DERIVE);
   psa_set_key_algorithm(&st_attr, PSA_ALG_ECDH);
   psa_set_key_lifetime(&st_attr, PSA_KEY_LIFETIME_VOLATILE);

   t_status = psa_generate_key(&st_attr, tpt_key);
   psa_reset_key_attributes(&st_attr);

   // Check if the key pair was made
   if (t_status != PSA_SUCCESS)
   {
      return t_status;
   }

   t_status = psa_export_public_key(*tpt_key, u8pt_point, HOST_AUTH_POINT_LEN, &t_pointLen);

   // Check if a whole uncompressed point was exported
   if ((t_status == PSA_SUCCESS) && (t_pointLen != HOST_AUTH_POINT_LEN))
   {
      t_status = PSA_ERROR_CORRUPTION_DETECTED;
   }
   if (t_status != PSA_SUCCESS)
   {
      (void)psa_destroy_key(*tpt_key);
   }

   return t_status;
}

/**
 * @public        gt_HostAuthCrypto_Agree
 * @brief         ECDH of the own ephemeral key with the peer's point.
 * @param[in]     t_key Own ephemeral key (gt_HostAuthCrypto_NewEphemeral()).
 * @param[in]     u8pt_peerPoint Peer point, HOST_AUTH_POINT_LEN bytes.
 * @param[out]    u8pt_secret Shared secret Z (the X coordinate),
 *                HOST_AUTH_HASH_LEN bytes. The caller wipes it after use.
 * @return        PSA_SUCCESS; PSA_ERROR_INVALID_ARGUMENT for NULL or a point
 *                not on the curve; otherwise the error of
 *                psa_raw_key_agreement(), or PSA_ERROR_CORRUPTION_DETECTED if Z
 *                is not HOST_AUTH_HASH_LEN bytes.
 */
psa_status_t gt_HostAuthCrypto_Agree(psa_key_id_t t_key, const uint8_t *u8pt_peerPoint,
   uint8_t *u8pt_secret)
{
   size_t t_secretLen = 0U;
   psa_status_t t_status;

   // Check if every buffer is given
   if ((u8pt_peerPoint == NULL) || (u8pt_secret == NULL))
   {
      return PSA_ERROR_INVALID_ARGUMENT;
   }

   t_status = psa_raw_key_agreement(PSA_ALG_ECDH, t_key, u8pt_peerPoint, HOST_AUTH_POINT_LEN,
      u8pt_secret, HOST_AUTH_HASH_LEN, &t_secretLen);

   // Check if a whole P-256 secret was made
   if ((t_status == PSA_SUCCESS) && (t_secretLen != HOST_AUTH_HASH_LEN))
   {
      t_status = PSA_ERROR_CORRUPTION_DETECTED;
   }

   return t_status;
}

/**
 * @public        gt_HostAuthCrypto_Transcript
 * @brief         Compute the transcript T over the handshake values.
 * @param[in]     stpt_in Handshake values (every pointer set).
 * @param[out]    u8pt_transcript T, HOST_AUTH_HASH_LEN bytes.
 * @return        PSA_SUCCESS; PSA_ERROR_INVALID_ARGUMENT for a NULL argument;
 *                otherwise the error of psa_hash_compute().
 */
psa_status_t gt_HostAuthCrypto_Transcript(const HostAuthTranscript_T *stpt_in,
   uint8_t *u8pt_transcript)
{
   uint8_t u8ar_in[HOST_AUTH_TRANSCRIPT_IN_LEN];
   size_t t_off = 0U;
   psa_status_t t_status;

   // Check if every value is given
   if ((stpt_in == NULL) || (u8pt_transcript == NULL) || (stpt_in->u8pt_nonceHost == NULL) ||
      (stpt_in->u8pt_nonceDev == NULL) || (stpt_in->u8pt_pointHost == NULL) ||
      (stpt_in->u8pt_pointDev == NULL) || (stpt_in->u8pt_certHost == NULL) ||
      (stpt_in->u8pt_certDev == NULL))
   {
      return PSA_ERROR_INVALID_ARGUMENT;
   }

   (void)memcpy(&u8ar_in[t_off], HOST_AUTH_LABEL, HOST_AUTH_LABEL_LEN);
   t_off += HOST_AUTH_LABEL_LEN;
   (void)memcpy(&u8ar_in[t_off], stpt_in->u8pt_nonceHost, HOST_AUTH_NONCE_LEN);
   t_off += HOST_AUTH_NONCE_LEN;
   (void)memcpy(&u8ar_in[t_off], stpt_in->u8pt_nonceDev, HOST_AUTH_NONCE_LEN);
   t_off += HOST_AUTH_NONCE_LEN;
   (void)memcpy(&u8ar_in[t_off], stpt_in->u8pt_pointHost, HOST_AUTH_POINT_LEN);
   t_off += HOST_AUTH_POINT_LEN;
   (void)memcpy(&u8ar_in[t_off], stpt_in->u8pt_pointDev, HOST_AUTH_POINT_LEN);
   t_off += HOST_AUTH_POINT_LEN;

   t_status = st_Hash(stpt_in->u8pt_certHost, stpt_in->t_certHostLen, &u8ar_in[t_off]);
   t_off += HOST_AUTH_HASH_LEN;

   // Check if the host certificate was hashed
   if (t_status == PSA_SUCCESS)
   {
      t_status = st_Hash(stpt_in->u8pt_certDev, stpt_in->t_certDevLen, &u8ar_in[t_off]);
   }

   // Check if the device certificate was hashed
   if (t_status == PSA_SUCCESS)
   {
      t_status = st_Hash(u8ar_in, sizeof(u8ar_in), u8pt_transcript);
   }

   return t_status;
}

/**
 * @public        gt_HostAuthCrypto_Sign
 * @brief         Sign role label || T.
 * @param[in]     t_key Signing key (the device key, CSR_DEVICE_SIGNING_KEY_ID).
 * @param[in]     e_role Role of the signer (eHAR_DEVICE on the device).
 * @param[in]     u8pt_transcript T.
 * @param[out]    u8pt_sig Signature, HOST_AUTH_SIG_LEN bytes.
 * @return        PSA_SUCCESS; PSA_ERROR_INVALID_ARGUMENT for NULL; otherwise the
 *                error of psa_sign_message(), or PSA_ERROR_CORRUPTION_DETECTED
 *                if the signature is not HOST_AUTH_SIG_LEN bytes.
 */
psa_status_t gt_HostAuthCrypto_Sign(psa_key_id_t t_key, HostAuthRole_E e_role,
   const uint8_t *u8pt_transcript, uint8_t *u8pt_sig)
{
   uint8_t u8ar_msg[HOST_AUTH_ROLE_MAX_LEN + HOST_AUTH_HASH_LEN];
   size_t t_msgLen;
   size_t t_sigLen = 0U;
   psa_status_t t_status;

   // Check if every buffer is given
   if ((u8pt_transcript == NULL) || (u8pt_sig == NULL))
   {
      return PSA_ERROR_INVALID_ARGUMENT;
   }

   t_msgLen = st_BuildSigned(e_role, u8pt_transcript, u8ar_msg);
   t_status = psa_sign_message(t_key, HOST_AUTH_SIGN_ALG, u8ar_msg, t_msgLen, u8pt_sig,
      HOST_AUTH_SIG_LEN, &t_sigLen);

   // Check if a raw P-256 signature was made
   if ((t_status == PSA_SUCCESS) && (t_sigLen != HOST_AUTH_SIG_LEN))
   {
      t_status = PSA_ERROR_CORRUPTION_DETECTED;
   }

   return t_status;
}

/**
 * @public        gt_HostAuthCrypto_Verify
 * @brief         Check a peer's signature over its role label || T.
 * @param[in]     t_key Peer public key, from its verified certificate.
 * @param[in]     e_role Role of the peer (eHAR_HOST on the device).
 * @param[in]     u8pt_transcript T.
 * @param[in]     u8pt_sig Signature, HOST_AUTH_SIG_LEN bytes.
 * @return        PSA_SUCCESS if it verifies; PSA_ERROR_INVALID_ARGUMENT for NULL;
 *                PSA_ERROR_INVALID_SIGNATURE if it does not verify; otherwise the
 *                error of psa_verify_message().
 */
psa_status_t gt_HostAuthCrypto_Verify(psa_key_id_t t_key, HostAuthRole_E e_role,
   const uint8_t *u8pt_transcript, const uint8_t *u8pt_sig)
{
   uint8_t u8ar_msg[HOST_AUTH_ROLE_MAX_LEN + HOST_AUTH_HASH_LEN];
   size_t t_msgLen;

   // Check if every buffer is given
   if ((u8pt_transcript == NULL) || (u8pt_sig == NULL))
   {
      return PSA_ERROR_INVALID_ARGUMENT;
   }

   t_msgLen = st_BuildSigned(e_role, u8pt_transcript, u8ar_msg);

   return psa_verify_message(t_key, HOST_AUTH_SIGN_ALG, u8ar_msg, t_msgLen, u8pt_sig,
      HOST_AUTH_SIG_LEN);
}

/**
 * @public        gt_HostAuthCrypto_Passkey
 * @brief         Derive the six-digit passkey of the pairing that follows.
 * @param[in]     u8pt_secret ECDH secret Z, HOST_AUTH_HASH_LEN bytes.
 * @param[in]     u8pt_nonceHost Nh.
 * @param[in]     u8pt_nonceDev Nd.
 * @param[in]     u8pt_transcript T.
 * @param[out]    u32pt_passkey Passkey, 0 .. HOST_AUTH_PASSKEY_MAX.
 * @return        PSA_SUCCESS; PSA_ERROR_INVALID_ARGUMENT for NULL; otherwise the
 *                error of the PSA key derivation.
 */
psa_status_t gt_HostAuthCrypto_Passkey(const uint8_t *u8pt_secret,
   const uint8_t *u8pt_nonceHost, const uint8_t *u8pt_nonceDev,
   const uint8_t *u8pt_transcript, uint32_t *u32pt_passkey)
{
   psa_key_derivation_operation_t st_op = PSA_KEY_DERIVATION_OPERATION_INIT;
   uint8_t u8ar_salt[2U * HOST_AUTH_NONCE_LEN];
   uint8_t u8ar_info[HOST_AUTH_INFO_LEN + HOST_AUTH_HASH_LEN];
   uint8_t u8ar_out[4];
   psa_status_t t_status;

   // Check if every buffer is given
   if ((u8pt_secret == NULL) || (u8pt_nonceHost == NULL) || (u8pt_nonceDev == NULL) ||
      (u8pt_transcript == NULL) || (u32pt_passkey == NULL))
   {
      return PSA_ERROR_INVALID_ARGUMENT;
   }

   (void)memcpy(&u8ar_salt[0], u8pt_nonceHost, HOST_AUTH_NONCE_LEN);
   (void)memcpy(&u8ar_salt[HOST_AUTH_NONCE_LEN], u8pt_nonceDev, HOST_AUTH_NONCE_LEN);
   (void)memcpy(&u8ar_info[0], HOST_AUTH_INFO, HOST_AUTH_INFO_LEN);
   (void)memcpy(&u8ar_info[HOST_AUTH_INFO_LEN], u8pt_transcript, HOST_AUTH_HASH_LEN);

   t_status = psa_key_derivation_setup(&st_op, PSA_ALG_HKDF(PSA_ALG_SHA_256));

   // HKDF takes the salt, then the secret, then the info
   if (t_status == PSA_SUCCESS)
   {
      t_status = psa_key_derivation_input_bytes(&st_op, PSA_KEY_DERIVATION_INPUT_SALT,
         u8ar_salt, sizeof(u8ar_salt));
   }
   if (t_status == PSA_SUCCESS)
   {
      t_status = psa_key_derivation_input_bytes(&st_op, PSA_KEY_DERIVATION_INPUT_SECRET,
         u8pt_secret, HOST_AUTH_HASH_LEN);
   }
   if (t_status == PSA_SUCCESS)
   {
      t_status = psa_key_derivation_input_bytes(&st_op, PSA_KEY_DERIVATION_INPUT_INFO,
         u8ar_info, sizeof(u8ar_info));
   }
   if (t_status == PSA_SUCCESS)
   {
      t_status = psa_key_derivation_output_bytes(&st_op, u8ar_out, sizeof(u8ar_out));
   }

   (void)psa_key_derivation_abort(&st_op);

   // Check if the output was derived
   if (t_status == PSA_SUCCESS)
   {
      *u32pt_passkey = (((uint32_t)u8ar_out[0] << 24) | ((uint32_t)u8ar_out[1] << 16) |
         ((uint32_t)u8ar_out[2] << 8) | (uint32_t)u8ar_out[3]) % (HOST_AUTH_PASSKEY_MAX + 1UL);
   }

   return t_status;
}

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shivam Chudasama [SC]
 */
