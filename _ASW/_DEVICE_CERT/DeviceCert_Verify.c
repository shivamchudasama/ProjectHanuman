/**
 * @file          DeviceCert_Verify.c
 * @brief         Source file containing X.509 certificate verification for device
 *                provisioning.
 *
 *                Ported from the Silicon Labs BG22/BG24 reference
 *                (gt_VerifyOwnDeviceCertificate / gt_VerifyRemoteDeviceCertificate
 *                in its DeviceCert.c): parse with mbedtls_x509_crt_parse, verify
 *                the chain with mbedtls_x509_crt_verify against the CA, and import
 *                a remote device's public key into PSA from pk_raw. Differences:
 *                - the trust anchor is the CA certificate received from the
 *                  provisioner (DER), not a compiled-in PEM root, so the CA itself
 *                  is checked first (ge_VerifyCACertificate);
 *                - every failure returns its own status (the reference returned
 *                  OK when an mbedTLS call failed);
 *                - certificate contexts are freed on every path;
 *                - the profile is enforced: P-256 key, ecdsa-with-SHA256,
 *                  CA:FALSE and KeyUsage digitalSignature + keyAgreement on
 *                  device certificates, and
 *                  the own certificate must carry this device's key and the CSR
 *                  subject;
 *                - the 26-byte SPKI prefix is checked before the public key is
 *                  taken from pk_raw;
 *                - host certificates (extendedKeyUsage clientAuth) are a role of
 *                  their own: ge_VerifyHostCertificate() requires it, and a
 *                  device certificate must not carry it.
 * @date          01/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include <string.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/asn1.h>
#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#include "DeviceCert_Verify.h"
#include "CSR_Generator.h"
#include "AppLog.h"

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
/**
 * @def           DEVICE_CERT_P256_SPKI_PREFIX_LEN
 * @brief         Length of the DER prefix of a P-256 SubjectPublicKeyInfo, up to
 *                the public key point (the reference's PUB_KEY_OFFSET).
 */
#define DEVICE_CERT_P256_SPKI_PREFIX_LEN     (26)

/**
 * @def           DEVICE_CERT_P256_SPKI_LEN
 * @brief         Length of a P-256 SubjectPublicKeyInfo (prefix + 65-byte point).
 */
#define DEVICE_CERT_P256_SPKI_LEN            (DEVICE_CERT_P256_SPKI_PREFIX_LEN + \
                                              DEVICE_CERT_P256_PUB_KEY_LEN)

/**
 * @def           DEVICE_CERT_SHA256_LEN
 * @brief         Length of a SHA-256 digest.
 */
#define DEVICE_CERT_SHA256_LEN               (32)

/**
 * @def           DEVICE_CERT_TIME_FLAGS
 * @brief         Verification flags about the validity period. The device has no
 *                wall clock, so these are ignored.
 */
#define DEVICE_CERT_TIME_FLAGS               (MBEDTLS_X509_BADCERT_EXPIRED | \
                                              MBEDTLS_X509_BADCERT_FUTURE)

/**
 * @def           DEVICE_CERT_PROFILE_FLAGS
 * @brief         Verification flags meaning the certificate is signed correctly
 *                but falls outside the allowed profile.
 */
#define DEVICE_CERT_PROFILE_FLAGS            (MBEDTLS_X509_BADCERT_KEY_USAGE | \
                                              MBEDTLS_X509_BADCERT_EXT_KEY_USAGE | \
                                              MBEDTLS_X509_BADCERT_NS_CERT_TYPE | \
                                              MBEDTLS_X509_BADCERT_BAD_MD | \
                                              MBEDTLS_X509_BADCERT_BAD_PK | \
                                              MBEDTLS_X509_BADCERT_BAD_KEY)

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
static DeviceCertStatus_E se_Parse(mbedtls_x509_crt *stpt_crt, const uint8_t *u8pt_der,
   size_t t_len);
static DeviceCertStatus_E se_CheckAlgorithms(const mbedtls_x509_crt *stpt_crt);
static bool sb_IsCA(const mbedtls_x509_crt *stpt_crt);
static DeviceCertStatus_E se_VerifySelfSignature(mbedtls_x509_crt *stpt_crt);
static DeviceCertStatus_E se_VerifyChain(mbedtls_x509_crt *stpt_crt);
static DeviceCertStatus_E se_CheckLeafProfile(const mbedtls_x509_crt *stpt_crt);
static bool sb_IsHostCert(const mbedtls_x509_crt *stpt_crt);
static DeviceCertStatus_E se_CheckHostProfile(const mbedtls_x509_crt *stpt_crt);
static DeviceCertStatus_E se_ImportPublicKey(const mbedtls_x509_crt *stpt_crt,
   psa_key_id_t *tpt_keyID);
static DeviceCertStatus_E se_VerifyDeviceCert(mbedtls_x509_crt *stpt_crt,
   const uint8_t *u8pt_der, size_t t_len);
static DeviceCertStatus_E se_VerifyOwn(const uint8_t *u8pt_der, size_t t_len,
   bool b_checkSubject);

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
 * @var           su8ar_P256SPKIPrefix
 * @brief         DER prefix of a P-256 SubjectPublicKeyInfo:
 *                SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 }, BIT STRING }.
 */
static const uint8_t su8ar_P256SPKIPrefix[DEVICE_CERT_P256_SPKI_PREFIX_LEN] = {
   0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
   0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
};

/**
 * @var           su8ar_ecdsaWithSHA256OID
 * @brief         OID 1.2.840.10045.4.3.2 (ecdsa-with-SHA256), content bytes only.
 */
static const uint8_t su8ar_ecdsaWithSHA256OID[] = {
   0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
};

/**
 * @var           scu8ar_oidClientAuth
 * @brief         OID 1.3.6.1.5.5.7.3.2 (id-kp-clientAuth), content bytes only:
 *                the extendedKeyUsage that marks a host certificate.
 */
static const uint8_t scu8ar_oidClientAuth[] = {
   0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
};

/**
 * @var           sst_trustAnchor
 * @brief         The verified CA certificate, parsed. Every device certificate is
 *                verified against it.
 */
static mbedtls_x509_crt sst_trustAnchor;

/**
 * @var           sb_isTrustAnchorSet
 * @brief         True once sst_trustAnchor holds a verified CA certificate.
 */
static bool sb_isTrustAnchorSet = false;

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
 * @private       se_Parse
 * @brief         Initialize a certificate context and parse a DER certificate
 *                into it (copying the data). The caller frees the context on
 *                every path.
 * @param[out]    stpt_crt Certificate context.
 * @param[in]     u8pt_der DER certificate.
 * @param[in]     t_len Length of the DER certificate.
 * @return        eDCS_OK, or eDCS_PARSE.
 */
static DeviceCertStatus_E se_Parse(mbedtls_x509_crt *stpt_crt, const uint8_t *u8pt_der,
   size_t t_len)
{
   int i_ret;

   mbedtls_x509_crt_init(stpt_crt);

   // Check if there is anything to parse
   if ((u8pt_der == NULL) || (t_len == 0u))
   {
      return eDCS_PARSE;
   }

   i_ret = mbedtls_x509_crt_parse_der(stpt_crt, u8pt_der, t_len);

   // Check if the certificate could not be parsed
   if (i_ret != 0)
   {
      APP_LOG_WRN("Certificate parse failed: -0x%04x", (unsigned int)-i_ret);
      return eDCS_PARSE;
   }

   return eDCS_OK;
}

/**
 * @private       se_CheckAlgorithms
 * @brief         Check the certificate is X.509 v3, carries a P-256 public key and
 *                is signed with ecdsa-with-SHA256.
 * @param[in]     stpt_crt Parsed certificate.
 * @return        eDCS_OK, or eDCS_BAD_PROFILE.
 */
static DeviceCertStatus_E se_CheckAlgorithms(const mbedtls_x509_crt *stpt_crt)
{
   // Check the version (extensions need v3)
   if (stpt_crt->version != 3)
   {
      APP_LOG_WRN("Certificate is not X.509 v3 (v%d)", stpt_crt->version);
      return eDCS_BAD_PROFILE;
   }

   // Check the signature algorithm
   if ((stpt_crt->sig_oid.len != sizeof(su8ar_ecdsaWithSHA256OID)) ||
      (memcmp(stpt_crt->sig_oid.p, su8ar_ecdsaWithSHA256OID,
         sizeof(su8ar_ecdsaWithSHA256OID)) != 0))
   {
      APP_LOG_WRN("Certificate is not signed with ecdsa-with-SHA256");
      return eDCS_BAD_PROFILE;
   }

   // Check the public key is P-256 (named curve, uncompressed point)
   if ((stpt_crt->pk_raw.len != DEVICE_CERT_P256_SPKI_LEN) ||
      (memcmp(stpt_crt->pk_raw.p, su8ar_P256SPKIPrefix,
         DEVICE_CERT_P256_SPKI_PREFIX_LEN) != 0) ||
      (stpt_crt->pk_raw.p[DEVICE_CERT_P256_SPKI_PREFIX_LEN] != 0x04u))
   {
      APP_LOG_WRN("Certificate public key is not an uncompressed P-256 key");
      return eDCS_BAD_PROFILE;
   }

   return eDCS_OK;
}

/**
 * @private       sb_IsCA
 * @brief         Check the BasicConstraints extension says CA:TRUE.
 *                mbedTLS keeps the parsed flag private (MBEDTLS_PRIVATE): this is
 *                the only place it is read, so an mbedTLS update that renames it
 *                breaks the build here and nowhere else.
 * @param[in]     stpt_crt Parsed certificate.
 * @return        true if the certificate is a CA certificate.
 */
static bool sb_IsCA(const mbedtls_x509_crt *stpt_crt)
{
   return (mbedtls_x509_crt_has_ext_type(stpt_crt, MBEDTLS_X509_EXT_BASIC_CONSTRAINTS) &&
      (stpt_crt->MBEDTLS_PRIVATE(ca_istrue) != 0));
}

/**
 * @private       se_VerifySelfSignature
 * @brief         Verify a certificate's signature with its own public key.
 *                mbedtls_x509_crt_verify() accepts a self-signed certificate that
 *                is itself in the trusted list without checking its signature, so
 *                this is done explicitly: hash the TBS part, take the signature
 *                BIT STRING that follows the signature AlgorithmIdentifier, and
 *                verify it with mbedtls_pk_verify().
 * @param[in]     stpt_crt Parsed certificate.
 * @return        eDCS_OK, eDCS_PARSE, eDCS_BAD_SIG or eDCS_INTERNAL.
 */
static DeviceCertStatus_E se_VerifySelfSignature(mbedtls_x509_crt *stpt_crt)
{
   unsigned char *u8pt_cursor = stpt_crt->tbs.p + stpt_crt->tbs.len;
   const unsigned char *u8pt_end = stpt_crt->raw.p + stpt_crt->raw.len;
   uint8_t u8ar_hash[DEVICE_CERT_SHA256_LEN];
   size_t t_hashLen = 0;
   size_t t_len = 0;
   psa_status_t t_status;
   int i_ret;

   // Skip the signatureAlgorithm SEQUENCE
   i_ret = mbedtls_asn1_get_tag(&u8pt_cursor, u8pt_end, &t_len,
      (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

   // Check if the signature algorithm could not be read
   if (i_ret != 0)
   {
      return eDCS_PARSE;
   }

   u8pt_cursor += t_len;

   // Read the signatureValue BIT STRING (DER ECDSA-Sig-Value)
   i_ret = mbedtls_asn1_get_bitstring_null(&u8pt_cursor, u8pt_end, &t_len);

   // Check if the signature could not be read
   if (i_ret != 0)
   {
      return eDCS_PARSE;
   }

   t_status = psa_hash_compute(PSA_ALG_SHA_256, stpt_crt->tbs.p, stpt_crt->tbs.len,
      u8ar_hash, sizeof(u8ar_hash), &t_hashLen);

   // Check if the hash could not be computed
   if (t_status != PSA_SUCCESS)
   {
      APP_LOG_ERR("SHA-256 failed: %d", t_status);
      return eDCS_INTERNAL;
   }

   i_ret = mbedtls_pk_verify(&stpt_crt->pk, MBEDTLS_MD_SHA256, u8ar_hash, t_hashLen,
      u8pt_cursor, t_len);

   // Check if the self-signature does not verify
   if (i_ret != 0)
   {
      APP_LOG_WRN("Self-signature does not verify: -0x%04x", (unsigned int)-i_ret);
      return eDCS_BAD_SIG;
   }

   return eDCS_OK;
}

/**
 * @private       se_VerifyChain
 * @brief         Verify a certificate against the trust anchor with
 *                mbedtls_x509_crt_verify(), as the reference does. Validity
 *                period flags are ignored (no wall clock).
 * @param[in]     stpt_crt Parsed certificate.
 * @return        eDCS_OK, eDCS_NOT_CA (no CA set), eDCS_BAD_SIG,
 *                eDCS_BAD_PROFILE or eDCS_INTERNAL.
 */
static DeviceCertStatus_E se_VerifyChain(mbedtls_x509_crt *stpt_crt)
{
   uint32_t u32_flags = 0;
   int i_ret;

   // Check if there is a CA to verify against
   if (!sb_isTrustAnchorSet)
   {
      APP_LOG_WRN("No CA certificate set");
      return eDCS_NOT_CA;
   }

   i_ret = mbedtls_x509_crt_verify(
      stpt_crt,                              // Certificate to be verified
      &sst_trustAnchor,                      // Trusted CA
      NULL,                                  // List of CRL for the CA
      NULL,                                  // Expected common name (CN)
      &u32_flags,                            // Verification flags (result)
      NULL,                                  // Verification callback
      NULL                                   // Context for verification callback
   );

   u32_flags &= ~(uint32_t)DEVICE_CERT_TIME_FLAGS;

   // Check if the only reasons were about the validity period
   if (u32_flags == 0u)
   {
      // Check if verification failed for a reason other than the flags
      if ((i_ret != 0) && (i_ret != MBEDTLS_ERR_X509_CERT_VERIFY_FAILED))
      {
         APP_LOG_ERR("Chain verification error: -0x%04x", (unsigned int)-i_ret);
         return eDCS_INTERNAL;
      }

      return eDCS_OK;
   }

   APP_LOG_WRN("Chain verification failed, flags 0x%08x", u32_flags);

   // Check if the certificate is not signed by the CA (or the CA cannot sign)
   if ((u32_flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED) != 0u)
   {
      return eDCS_BAD_SIG;
   }

   return ((u32_flags & DEVICE_CERT_PROFILE_FLAGS) != 0u) ? eDCS_BAD_PROFILE : eDCS_BAD_SIG;
}

/**
 * @private       se_CheckLeafProfile
 * @brief         Check a device certificate is not a CA and allows both
 *                digitalSignature (pairing signs its OOB data with the key) and
 *                keyAgreement (the KeyUsage extension must be present; the CSR
 *                requests both).
 * @param[in]     stpt_crt Parsed certificate.
 * @return        eDCS_OK, or eDCS_BAD_PROFILE.
 */
static DeviceCertStatus_E se_CheckLeafProfile(const mbedtls_x509_crt *stpt_crt)
{
   // Check the certificate is not a CA
   if (sb_IsCA(stpt_crt))
   {
      APP_LOG_WRN("Device certificate is a CA certificate");
      return eDCS_BAD_PROFILE;
   }

   // Check the KeyUsage extension is present and allows signing and key agreement
   if ((!mbedtls_x509_crt_has_ext_type(stpt_crt, MBEDTLS_X509_EXT_KEY_USAGE)) ||
      (mbedtls_x509_crt_check_key_usage(stpt_crt,
         MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_AGREEMENT) != 0))
   {
      APP_LOG_WRN("Device certificate does not allow digitalSignature and keyAgreement");
      return eDCS_BAD_PROFILE;
   }

   // Check it is not a host certificate (a host must not pose as a device)
   if (sb_IsHostCert(stpt_crt))
   {
      APP_LOG_WRN("Device certificate is a host certificate (clientAuth)");
      return eDCS_BAD_PROFILE;
   }

   return eDCS_OK;
}

/**
 * @private       sb_IsHostCert
 * @brief         Whether a certificate carries the host role: an
 *                extendedKeyUsage extension that allows clientAuth.
 * @param[in]     stpt_crt Parsed certificate.
 * @return        true for a host certificate.
 */
static bool sb_IsHostCert(const mbedtls_x509_crt *stpt_crt)
{
   return mbedtls_x509_crt_has_ext_type(stpt_crt, MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE) &&
      (mbedtls_x509_crt_check_extended_key_usage(stpt_crt, (const char *)scu8ar_oidClientAuth,
         sizeof(scu8ar_oidClientAuth)) == 0);
}

/**
 * @private       se_CheckHostProfile
 * @brief         Check a host certificate is not a CA, allows digitalSignature
 *                (it signs the handshake; KeyUsage must be present) and carries
 *                the host role (extendedKeyUsage clientAuth).
 * @param[in]     stpt_crt Parsed certificate.
 * @return        eDCS_OK, or eDCS_BAD_PROFILE.
 */
static DeviceCertStatus_E se_CheckHostProfile(const mbedtls_x509_crt *stpt_crt)
{
   // Check the certificate is not a CA
   if (sb_IsCA(stpt_crt))
   {
      APP_LOG_WRN("Host certificate is a CA certificate");
      return eDCS_BAD_PROFILE;
   }

   // Check the KeyUsage extension is present and allows signing
   if ((!mbedtls_x509_crt_has_ext_type(stpt_crt, MBEDTLS_X509_EXT_KEY_USAGE)) ||
      (mbedtls_x509_crt_check_key_usage(stpt_crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE) != 0))
   {
      APP_LOG_WRN("Host certificate does not allow digitalSignature");
      return eDCS_BAD_PROFILE;
   }

   // Check it carries the host role
   if (!sb_IsHostCert(stpt_crt))
   {
      APP_LOG_WRN("Host certificate has no clientAuth extendedKeyUsage");
      return eDCS_BAD_PROFILE;
   }

   return eDCS_OK;
}

/**
 * @private       se_ImportPublicKey
 * @brief         Import a verified certificate's public key into PSA as a
 *                volatile ECDSA-SHA256 verify key.
 * @param[in]     stpt_crt Verified certificate (P-256 SPKI checked).
 * @param[out]    tpt_keyID Receives the key ID on eDCS_OK.
 * @return        eDCS_OK, or eDCS_INTERNAL.
 */
static DeviceCertStatus_E se_ImportPublicKey(const mbedtls_x509_crt *stpt_crt,
   psa_key_id_t *tpt_keyID)
{
   psa_key_attributes_t st_attr = PSA_KEY_ATTRIBUTES_INIT;
   psa_status_t t_status;

   psa_set_key_type(&st_attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
   psa_set_key_bits(&st_attr, 256);
   psa_set_key_usage_flags(&st_attr, (PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_VERIFY_HASH));
   psa_set_key_algorithm(&st_attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

   t_status = psa_import_key(&st_attr, &stpt_crt->pk_raw.p[DEVICE_CERT_P256_SPKI_PREFIX_LEN],
      DEVICE_CERT_P256_PUB_KEY_LEN, tpt_keyID);
   psa_reset_key_attributes(&st_attr);

   // Check if the public key could not be imported
   if (t_status != PSA_SUCCESS)
   {
      APP_LOG_ERR("Public key import failed: %d", t_status);
      return eDCS_INTERNAL;
   }

   return eDCS_OK;
}

/**
 * @private       se_VerifyDeviceCert
 * @brief         Checks shared by the own and the remote device certificate:
 *                parse, algorithms, chain to the CA, leaf profile. On eDCS_OK the
 *                caller still owns (and frees) the parsed context.
 * @param[out]    stpt_crt Certificate context, always initialized.
 * @param[in]     u8pt_der DER certificate.
 * @param[in]     t_len Length of the DER certificate.
 * @return        eDCS_OK or the first failing check's status.
 */
static DeviceCertStatus_E se_VerifyDeviceCert(mbedtls_x509_crt *stpt_crt,
   const uint8_t *u8pt_der, size_t t_len)
{
   DeviceCertStatus_E e_status;

   e_status = se_Parse(stpt_crt, u8pt_der, t_len);

   // Check if parsing succeeded
   if (e_status == eDCS_OK)
   {
      e_status = se_CheckAlgorithms(stpt_crt);
   }

   // Check if the algorithms are within the profile
   if (e_status == eDCS_OK)
   {
      e_status = se_VerifyChain(stpt_crt);
   }

   // Check if the certificate is signed by the CA
   if (e_status == eDCS_OK)
   {
      e_status = se_CheckLeafProfile(stpt_crt);
   }

   return e_status;
}

/**
 * @private       se_VerifyOwn
 * @brief         Verify this device's certificate: signed by the trust anchor,
 *                within the profile, carrying this device's public key and, when
 *                asked, the subject of this device's CSR (gst_CSRData).
 * @param[in]     u8pt_der DER certificate.
 * @param[in]     t_len Length of the DER certificate.
 * @param[in]     b_checkSubject true to compare the subject with the CSR's.
 * @return        eDCS_OK, eDCS_PARSE, eDCS_BAD_PROFILE, eDCS_NOT_CA (no CA set),
 *                eDCS_BAD_SIG, eDCS_KEY_MISMATCH, eDCS_SUBJECT_MISMATCH or
 *                eDCS_INTERNAL.
 */
static DeviceCertStatus_E se_VerifyOwn(const uint8_t *u8pt_der, size_t t_len,
   bool b_checkSubject)
{
   mbedtls_x509_crt st_crt;
   mbedtls_x509_csr st_csr;
   uint8_t u8ar_ownPubKey[DEVICE_CERT_P256_PUB_KEY_LEN];
   size_t t_ownPubKeyLen = 0;
   DeviceCertStatus_E e_status;
   psa_status_t t_status;

   e_status = se_VerifyDeviceCert(&st_crt, u8pt_der, t_len);

   // Check the certificate carries this device's public key
   if (e_status == eDCS_OK)
   {
      t_status = psa_export_public_key(CSR_DEVICE_SIGNING_KEY_ID, u8ar_ownPubKey,
         sizeof(u8ar_ownPubKey), &t_ownPubKeyLen);

      // Check if the own public key could not be exported
      if ((t_status != PSA_SUCCESS) || (t_ownPubKeyLen != DEVICE_CERT_P256_PUB_KEY_LEN))
      {
         APP_LOG_ERR("Own public key export failed: %d", t_status);
         e_status = eDCS_INTERNAL;
      }
      // Check if the certificate's key differs from the own key
      else if (memcmp(&st_crt.pk_raw.p[DEVICE_CERT_P256_SPKI_PREFIX_LEN], u8ar_ownPubKey,
         DEVICE_CERT_P256_PUB_KEY_LEN) != 0)
      {
         APP_LOG_WRN("Device certificate carries another public key");
         e_status = eDCS_KEY_MISMATCH;
      }
   }

   // Check the certificate subject is the CSR subject
   if ((e_status == eDCS_OK) && b_checkSubject)
   {
      mbedtls_x509_csr_init(&st_csr);

      // Check if this device's CSR cannot be parsed
      if ((gst_CSRData.u8_isCSRGenerated != 1u) ||
         (mbedtls_x509_csr_parse_der(&st_csr, gst_CSRData.u8ar_CSR,
            gst_CSRData.u16_CSRLen) != 0))
      {
         APP_LOG_ERR("Own CSR is not available or not parsable");
         e_status = eDCS_INTERNAL;
      }
      // Check if the subjects differ
      else if ((st_csr.subject_raw.len != st_crt.subject_raw.len) ||
         (memcmp(st_csr.subject_raw.p, st_crt.subject_raw.p, st_crt.subject_raw.len) != 0))
      {
         APP_LOG_WRN("Device certificate subject differs from the CSR subject");
         e_status = eDCS_SUBJECT_MISMATCH;
      }

      mbedtls_x509_csr_free(&st_csr);
   }

   mbedtls_x509_crt_free(&st_crt);

   // Check if the device certificate passed
   if (e_status == eDCS_OK)
   {
      APP_LOG_INF("Device certificate verified (%u bytes)", (unsigned int)t_len);
   }

   return e_status;
}

/******************************************************************************/
/*                                                                            */
/*                        PUBLIC FUNCTION DEFINITIONS                         */
/*                                                                            */
/******************************************************************************/
/**
 * @public        ge_VerifyCACertificate
 * @brief         Verify a CA certificate and, if it passes, make it the trust
 *                anchor (replacing any previous one). It must be X.509 v3, P-256,
 *                ecdsa-with-SHA256, CA:TRUE, self-issued (subject == issuer), allow
 *                keyCertSign when KeyUsage is present, and its self-signature must
 *                verify. On failure the previous trust anchor is kept.
 * @param[in]     u8pt_der DER certificate.
 * @param[in]     t_len Length of the DER certificate.
 * @return        eDCS_OK, eDCS_PARSE, eDCS_BAD_PROFILE, eDCS_NOT_CA,
 *                eDCS_BAD_SIG or eDCS_INTERNAL.
 */
DeviceCertStatus_E ge_VerifyCACertificate(const uint8_t *u8pt_der, size_t t_len)
{
   mbedtls_x509_crt st_crt;
   DeviceCertStatus_E e_status;

   e_status = se_Parse(&st_crt, u8pt_der, t_len);

   // Check if parsing succeeded
   if (e_status == eDCS_OK)
   {
      e_status = se_CheckAlgorithms(&st_crt);
   }

   // Check if it is a self-issued CA certificate
   if ((e_status == eDCS_OK) &&
      ((!sb_IsCA(&st_crt)) ||
      (st_crt.subject_raw.len != st_crt.issuer_raw.len) ||
      (memcmp(st_crt.subject_raw.p, st_crt.issuer_raw.p, st_crt.subject_raw.len) != 0)))
   {
      APP_LOG_WRN("Not a self-issued CA certificate");
      e_status = eDCS_NOT_CA;
   }

   // Check if KeyUsage, when present, allows certificate signing
   if ((e_status == eDCS_OK) &&
      (mbedtls_x509_crt_has_ext_type(&st_crt, MBEDTLS_X509_EXT_KEY_USAGE)) &&
      (mbedtls_x509_crt_check_key_usage(&st_crt, MBEDTLS_X509_KU_KEY_CERT_SIGN) != 0))
   {
      APP_LOG_WRN("CA certificate does not allow keyCertSign");
      e_status = eDCS_NOT_CA;
   }

   // Check the self-signature
   if (e_status == eDCS_OK)
   {
      e_status = se_VerifySelfSignature(&st_crt);
   }

   mbedtls_x509_crt_free(&st_crt);

   // Check if the CA passed: make it the trust anchor
   if (e_status == eDCS_OK)
   {
      gv_ClearTrustAnchor();

      // Check if the trust anchor cannot be parsed (out of mbedTLS heap)
      if (se_Parse(&sst_trustAnchor, u8pt_der, t_len) != eDCS_OK)
      {
         mbedtls_x509_crt_free(&sst_trustAnchor);
         e_status = eDCS_INTERNAL;
      }
      else
      {
         sb_isTrustAnchorSet = true;
         APP_LOG_INF("CA certificate verified (%u bytes)", (unsigned int)t_len);
      }
   }

   return e_status;
}

/**
 * @public        ge_VerifyOwnDeviceCertificate
 * @brief         Verify this device's certificate during provisioning: signed by
 *                the trust anchor, within the profile (P-256, ecdsa-with-SHA256,
 *                CA:FALSE, KeyUsage digitalSignature + keyAgreement), carrying
 *                this device's public
 *                key (CSR_DEVICE_SIGNING_KEY_ID) and the subject of this device's
 *                CSR (gst_CSRData).
 * @param[in]     u8pt_der DER certificate.
 * @param[in]     t_len Length of the DER certificate.
 * @return        eDCS_OK, eDCS_PARSE, eDCS_BAD_PROFILE, eDCS_NOT_CA (no CA set),
 *                eDCS_BAD_SIG, eDCS_KEY_MISMATCH, eDCS_SUBJECT_MISMATCH or
 *                eDCS_INTERNAL (also when no CSR is in RAM).
 */
DeviceCertStatus_E ge_VerifyOwnDeviceCertificate(const uint8_t *u8pt_der, size_t t_len)
{
   return se_VerifyOwn(u8pt_der, t_len, true);
}

/**
 * @public        ge_VerifyStoredDeviceCertificate
 * @brief         Re-verify this device's stored certificate at boot: as
 *                ge_VerifyOwnDeviceCertificate() but without the CSR subject check,
 *                because the CSR is deleted once the device is provisioned. The
 *                subject was checked before the certificate was stored, and ITS
 *                entries are authenticated.
 * @param[in]     u8pt_der DER certificate.
 * @param[in]     t_len Length of the DER certificate.
 * @return        eDCS_OK, eDCS_PARSE, eDCS_BAD_PROFILE, eDCS_NOT_CA (no CA set),
 *                eDCS_BAD_SIG, eDCS_KEY_MISMATCH or eDCS_INTERNAL.
 */
DeviceCertStatus_E ge_VerifyStoredDeviceCertificate(const uint8_t *u8pt_der, size_t t_len)
{
   return se_VerifyOwn(u8pt_der, t_len, false);
}

/**
 * @public        ge_VerifyRemoteDeviceCertificate
 * @brief         Verify a remote device's certificate (signed by the trust anchor,
 *                within the profile) and import its public key into PSA as a
 *                volatile ECDSA-SHA256 verify key, for checking the signed OOB data
 *                during pairing. The caller destroys the key with
 *                psa_destroy_key() when the connection ends.
 * @param[in]     u8pt_der DER certificate.
 * @param[in]     t_len Length of the DER certificate.
 * @param[out]    tpt_remotePubKeyID Receives the imported key ID on eDCS_OK.
 * @return        eDCS_OK, eDCS_PARSE, eDCS_BAD_PROFILE, eDCS_NOT_CA (no CA set),
 *                eDCS_BAD_SIG or eDCS_INTERNAL.
 */
DeviceCertStatus_E ge_VerifyRemoteDeviceCertificate(const uint8_t *u8pt_der, size_t t_len,
   psa_key_id_t *tpt_remotePubKeyID)
{
   mbedtls_x509_crt st_crt;
   DeviceCertStatus_E e_status;

   // Check if there is somewhere to return the key
   if (tpt_remotePubKeyID == NULL)
   {
      return eDCS_INTERNAL;
   }

   e_status = se_VerifyDeviceCert(&st_crt, u8pt_der, t_len);

   // Check if the certificate passed: import its public key
   if (e_status == eDCS_OK)
   {
      e_status = se_ImportPublicKey(&st_crt, tpt_remotePubKeyID);
   }

   mbedtls_x509_crt_free(&st_crt);

   return e_status;
}

/**
 * @public        ge_VerifyHostCertificate
 * @brief         Verify a host's certificate (signed by the trust anchor,
 *                P-256, ecdsa-with-SHA256, CA:FALSE, KeyUsage digitalSignature,
 *                extendedKeyUsage clientAuth: the host role) and import its
 *                public key into PSA as a volatile ECDSA-SHA256 verify key, for
 *                checking the host's handshake signature. The caller destroys
 *                the key with psa_destroy_key().
 * @param[in]     u8pt_der DER certificate.
 * @param[in]     t_len Length of the DER certificate.
 * @param[out]    tpt_hostPubKeyID Receives the imported key ID on eDCS_OK.
 * @return        eDCS_OK, eDCS_PARSE, eDCS_BAD_PROFILE (also a device
 *                certificate), eDCS_NOT_CA (no CA set), eDCS_BAD_SIG or
 *                eDCS_INTERNAL.
 */
DeviceCertStatus_E ge_VerifyHostCertificate(const uint8_t *u8pt_der, size_t t_len,
   psa_key_id_t *tpt_hostPubKeyID)
{
   mbedtls_x509_crt st_crt;
   DeviceCertStatus_E e_status;

   // Check if there is somewhere to return the key
   if (tpt_hostPubKeyID == NULL)
   {
      return eDCS_INTERNAL;
   }

   e_status = se_Parse(&st_crt, u8pt_der, t_len);

   // Check if parsing succeeded
   if (e_status == eDCS_OK)
   {
      e_status = se_CheckAlgorithms(&st_crt);
   }

   // Check if the algorithms are within the profile
   if (e_status == eDCS_OK)
   {
      e_status = se_VerifyChain(&st_crt);
   }

   // Check if the certificate is signed by the CA
   if (e_status == eDCS_OK)
   {
      e_status = se_CheckHostProfile(&st_crt);
   }

   // Check if the certificate passed: import its public key
   if (e_status == eDCS_OK)
   {
      e_status = se_ImportPublicKey(&st_crt, tpt_hostPubKeyID);
   }

   mbedtls_x509_crt_free(&st_crt);

   // Check if the host certificate passed
   if (e_status == eDCS_OK)
   {
      APP_LOG_INF("Host certificate verified (%u bytes)", (unsigned int)t_len);
   }

   return e_status;
}

/**
 * @public        gb_IsTrustAnchorSet
 * @brief         Tell whether a verified CA certificate is set.
 * @return        true if ge_VerifyCACertificate() has succeeded since the last
 *                gv_ClearTrustAnchor().
 */
bool gb_IsTrustAnchorSet(void)
{
   return sb_isTrustAnchorSet;
}

/**
 * @public        gv_ClearTrustAnchor
 * @brief         Forget the trust anchor and free its parsed context.
 * @return        None.
 */
void gv_ClearTrustAnchor(void)
{
   // Check if there is a parsed trust anchor to free
   if (sb_isTrustAnchorSet)
   {
      mbedtls_x509_crt_free(&sst_trustAnchor);
      sb_isTrustAnchorSet = false;
   }
}

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shivam Chudasama [SC]
 */
