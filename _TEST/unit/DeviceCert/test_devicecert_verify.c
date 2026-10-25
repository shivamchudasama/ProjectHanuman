/**
 * @file          test_devicecert_verify.c
 * @brief         Host unit tests for the X.509 verification in
 *                _ASW/_DEVICE_CERT/DeviceCert_Verify.c (ge_VerifyCACertificate,
 *                ge_VerifyOwnDeviceCertificate, ge_VerifyStoredDeviceCertificate,
 *                ge_VerifyRemoteDeviceCertificate, gb_IsTrustAnchorSet,
 *                gv_ClearTrustAnchor), with the REAL Mbed TLS 4 / TF-PSA-Crypto
 *                (the major version NCS v3.4.1 ships), built for the host by
 *                _TEST/CMakeLists.txt. Nothing cryptographic is stubbed.
 *
 *                The certificates come from gen/cert_vectors.h, generated on
 *                each fresh build by _TEST/tools/gen_cert_vectors.py with the PC
 *                tool's CA (blehost/pki/authority.py) and its negative set
 *                (blehost/pki/negative.py), so the device code is tested against
 *                what the PC sends, with the RESULT status each case expects.
 *                The device key of that set is imported as the persistent PSA
 *                key CSR_DEVICE_SIGNING_KEY_ID; its CSR stands in for
 *                gst_CSRData. Under ASan/LSan (CI) a certificate context left
 *                unfreed on any path fails the test.
 *                Contract: _DOC/Provisioning/PROTOCOL.md (certificate profile,
 *                RESULT statuses).
 *
 * @date          02/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#include "DeviceCert_Verify.c"
#include "unity.h"
#include "cert_vectors.h"

/******************************************************************************/
/*  What the rest of the firmware provides                                    */
/******************************************************************************/
CSRData_T gst_CSRData;

extern void gv_HostItsClear(void);           /* tfpsa_host_platform.c */

/******************************************************************************/
/*  Helpers                                                                   */
/******************************************************************************/
/** Import the vector's device key as the device's persistent signing key. */
static void sv_ImportDeviceKey(void)
{
   psa_key_attributes_t st_attr = PSA_KEY_ATTRIBUTES_INIT;
   psa_key_id_t t_id = 0;

   psa_set_key_type(&st_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
   psa_set_key_bits(&st_attr, 256);
   psa_set_key_usage_flags(&st_attr, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
   psa_set_key_algorithm(&st_attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
   psa_set_key_lifetime(&st_attr, PSA_KEY_LIFETIME_PERSISTENT);
   psa_set_key_id(&st_attr, CSR_DEVICE_SIGNING_KEY_ID);
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, psa_import_key(&st_attr, gu8ar_certDevKey,
      GU8AR_CERTDEVKEY_LEN, &t_id));
   TEST_ASSERT_EQUAL_UINT32(CSR_DEVICE_SIGNING_KEY_ID, t_id);
   psa_reset_key_attributes(&st_attr);
}

/** First test: the device key is in PSA (persistent, in the host ITS). */
static void test_ImportDeviceKey(void)
{
   sv_ImportDeviceKey();
}

static void sv_LoadCsr(void)
{
   memset(&gst_CSRData, 0, sizeof(gst_CSRData));
   TEST_ASSERT_TRUE(GU8AR_CERTDEVCSR_LEN <= sizeof(gst_CSRData.u8ar_CSR));
   memcpy(gst_CSRData.u8ar_CSR, gu8ar_certDevCsr, GU8AR_CERTDEVCSR_LEN);
   gst_CSRData.u16_CSRLen = (uint16_t)GU8AR_CERTDEVCSR_LEN;
   gst_CSRData.u8_isCSRGenerated = 1U;
}

static void sv_SetGoodCa(void)
{
   TEST_ASSERT_EQUAL_INT(eDCS_OK, ge_VerifyCACertificate(gu8ar_certCa, GU8AR_CERTCA_LEN));
   TEST_ASSERT_TRUE(gb_IsTrustAnchorSet());
}

static char scar_msg[96];

static const char *scpt_Case(const CertCase_T *stpt_case, const char *cpt_fn)
{
   (void)snprintf(scar_msg, sizeof(scar_msg), "%s: case %s", cpt_fn, stpt_case->cpt_name);
   return scar_msg;
}

void setUp(void)
{
   gv_ClearTrustAnchor();
   sv_LoadCsr();
   gv_SimLogClear();
}

void tearDown(void)
{
   gv_ClearTrustAnchor();
}

/******************************************************************************/
/*  CA certificate                                                            */
/******************************************************************************/
static void test_GoodCaBecomesTheTrustAnchor(void)
{
   TEST_ASSERT_FALSE(gb_IsTrustAnchorSet());
   sv_SetGoodCa();
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("CA certificate verified"));
}

static void test_CaCasesAreRejectedWithTheirStatus(void)
{
   uint32_t i;

   for (i = 0U; i < CERT_CASE_CNT; i++)
   {
      const CertCase_T *c = &gstar_certCases[i];

      if (c->u8_appType != CERT_APP_CA) { continue; }
      TEST_ASSERT_EQUAL_HEX8_MESSAGE(c->u8_expected,
         (uint8_t)ge_VerifyCACertificate(c->u8pt_der, c->t_len), scpt_Case(c, "CA"));
      TEST_ASSERT_FALSE_MESSAGE(gb_IsTrustAnchorSet(), scpt_Case(c, "no anchor"));
   }
}

static void test_RejectedCaKeepsThePreviousOne(void)
{
   uint32_t i;

   sv_SetGoodCa();
   for (i = 0U; i < CERT_CASE_CNT; i++)
   {
      const CertCase_T *c = &gstar_certCases[i];

      if (c->u8_appType != CERT_APP_CA) { continue; }
      TEST_ASSERT_NOT_EQUAL(eDCS_OK, ge_VerifyCACertificate(c->u8pt_der, c->t_len));
      TEST_ASSERT_TRUE_MESSAGE(gb_IsTrustAnchorSet(), scpt_Case(c, "anchor kept"));
   }
   // The good CA is still the one device certificates are checked against
   TEST_ASSERT_EQUAL_INT(eDCS_OK, ge_VerifyOwnDeviceCertificate(gu8ar_certDev, GU8AR_CERTDEV_LEN));
}

static void test_CaThatIsNotDerIsAParseError(void)
{
   static const uint8_t scu8ar_junk[4] = { 0xDE, 0xAD, 0xBE, 0xEF };

   TEST_ASSERT_EQUAL_INT(eDCS_PARSE, ge_VerifyCACertificate(NULL, 10U));
   TEST_ASSERT_EQUAL_INT(eDCS_PARSE, ge_VerifyCACertificate(gu8ar_certCa, 0U));
   TEST_ASSERT_EQUAL_INT(eDCS_PARSE, ge_VerifyCACertificate(scu8ar_junk, sizeof(scu8ar_junk)));
   TEST_ASSERT_EQUAL_INT(eDCS_PARSE, ge_VerifyCACertificate(gu8ar_certCa, GU8AR_CERTCA_LEN - 1U));
}

static void test_DeviceCertificateIsNotACa(void)
{
   TEST_ASSERT_EQUAL_INT(eDCS_NOT_CA, ge_VerifyCACertificate(gu8ar_certDev, GU8AR_CERTDEV_LEN));
   TEST_ASSERT_FALSE(gb_IsTrustAnchorSet());
}

static void test_NewCaReplacesTheAnchor(void)
{
   sv_SetGoodCa();
   TEST_ASSERT_EQUAL_INT(eDCS_OK, ge_VerifyCACertificate(gu8ar_certCa2, GU8AR_CERTCA2_LEN));
   TEST_ASSERT_EQUAL_INT(eDCS_BAD_SIG, ge_VerifyOwnDeviceCertificate(gu8ar_certDev, GU8AR_CERTDEV_LEN));
   TEST_ASSERT_EQUAL_INT(eDCS_OK, ge_VerifyOwnDeviceCertificate(gu8ar_certDevByCa2,
      GU8AR_CERTDEVBYCA2_LEN));
}

static void test_ClearTrustAnchor(void)
{
   sv_SetGoodCa();
   gv_ClearTrustAnchor();
   TEST_ASSERT_FALSE(gb_IsTrustAnchorSet());
   TEST_ASSERT_EQUAL_INT(eDCS_NOT_CA, ge_VerifyOwnDeviceCertificate(gu8ar_certDev, GU8AR_CERTDEV_LEN));
   gv_ClearTrustAnchor();                     // twice is harmless
   TEST_ASSERT_FALSE(gb_IsTrustAnchorSet());
}

/******************************************************************************/
/*  Own device certificate                                                    */
/******************************************************************************/
static void test_NoCaMeansNotCa(void)
{
   psa_key_id_t t_id = 0;

   TEST_ASSERT_EQUAL_INT(eDCS_NOT_CA, ge_VerifyOwnDeviceCertificate(gu8ar_certDev, GU8AR_CERTDEV_LEN));
   TEST_ASSERT_EQUAL_INT(eDCS_NOT_CA, ge_VerifyStoredDeviceCertificate(gu8ar_certDev, GU8AR_CERTDEV_LEN));
   TEST_ASSERT_EQUAL_INT(eDCS_NOT_CA, ge_VerifyRemoteDeviceCertificate(gu8ar_certRemote,
      GU8AR_CERTREMOTE_LEN, &t_id));
}

static void test_GoodDeviceCertificateVerifies(void)
{
   sv_SetGoodCa();
   TEST_ASSERT_EQUAL_INT(eDCS_OK, ge_VerifyOwnDeviceCertificate(gu8ar_certDev, GU8AR_CERTDEV_LEN));
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("Device certificate verified"));
}

static void test_DeviceCasesAreRejectedWithTheirStatus(void)
{
   uint32_t i;

   sv_SetGoodCa();
   for (i = 0U; i < CERT_CASE_CNT; i++)
   {
      const CertCase_T *c = &gstar_certCases[i];

      if (c->u8_appType != CERT_APP_DEV) { continue; }
      TEST_ASSERT_EQUAL_HEX8_MESSAGE(c->u8_expected,
         (uint8_t)ge_VerifyOwnDeviceCertificate(c->u8pt_der, c->t_len), scpt_Case(c, "own"));
   }
}

static void test_CaCertificateIsNotADeviceCertificate(void)
{
   sv_SetGoodCa();
   TEST_ASSERT_EQUAL_INT(eDCS_BAD_PROFILE, ge_VerifyOwnDeviceCertificate(gu8ar_certCa, GU8AR_CERTCA_LEN));
   TEST_ASSERT_EQUAL_INT(eDCS_PARSE, ge_VerifyOwnDeviceCertificate(gu8ar_certDev, 0U));
   TEST_ASSERT_EQUAL_INT(eDCS_PARSE, ge_VerifyOwnDeviceCertificate(NULL, GU8AR_CERTDEV_LEN));
}

static void test_OwnCheckNeedsTheCsr(void)
{
   sv_SetGoodCa();

   gst_CSRData.u8_isCSRGenerated = 0U;
   TEST_ASSERT_EQUAL_INT(eDCS_INTERNAL, ge_VerifyOwnDeviceCertificate(gu8ar_certDev, GU8AR_CERTDEV_LEN));

   sv_LoadCsr();
   gst_CSRData.u16_CSRLen = 10U;              // not a parsable CSR
   TEST_ASSERT_EQUAL_INT(eDCS_INTERNAL, ge_VerifyOwnDeviceCertificate(gu8ar_certDev, GU8AR_CERTDEV_LEN));
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("Own CSR is not available or not parsable"));
}

static void test_OwnCheckNeedsTheDeviceKey(void)
{
   sv_SetGoodCa();
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, psa_destroy_key(CSR_DEVICE_SIGNING_KEY_ID));

   TEST_ASSERT_EQUAL_INT(eDCS_INTERNAL, ge_VerifyOwnDeviceCertificate(gu8ar_certDev, GU8AR_CERTDEV_LEN));
   TEST_ASSERT_EQUAL_INT(eDCS_INTERNAL, ge_VerifyStoredDeviceCertificate(gu8ar_certDev, GU8AR_CERTDEV_LEN));
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("Own public key export failed"));

   sv_ImportDeviceKey();
   TEST_ASSERT_EQUAL_INT(eDCS_OK, ge_VerifyOwnDeviceCertificate(gu8ar_certDev, GU8AR_CERTDEV_LEN));
}

/******************************************************************************/
/*  Stored device certificate (boot)                                          */
/******************************************************************************/
static void test_StoredCheckSkipsOnlyTheSubject(void)
{
   uint32_t i;

   sv_SetGoodCa();
   memset(&gst_CSRData, 0, sizeof(gst_CSRData));       // deleted once provisioned
   TEST_ASSERT_EQUAL_INT(eDCS_OK, ge_VerifyStoredDeviceCertificate(gu8ar_certDev, GU8AR_CERTDEV_LEN));

   for (i = 0U; i < CERT_CASE_CNT; i++)
   {
      const CertCase_T *c = &gstar_certCases[i];
      uint8_t u8_expected = c->u8_expected;

      if (c->u8_appType != CERT_APP_DEV) { continue; }
      if (u8_expected == eDCS_SUBJECT_MISMATCH) { u8_expected = eDCS_OK; }
      TEST_ASSERT_EQUAL_HEX8_MESSAGE(u8_expected,
         (uint8_t)ge_VerifyStoredDeviceCertificate(c->u8pt_der, c->t_len), scpt_Case(c, "stored"));
   }
}

/******************************************************************************/
/*  Remote device certificate (phase 2)                                       */
/******************************************************************************/
static void test_RemoteCertificateImportsItsKey(void)
{
   psa_key_id_t t_id = 0;
   psa_key_attributes_t st_attr = PSA_KEY_ATTRIBUTES_INIT;
   uint8_t u8ar_pub[DEVICE_CERT_P256_PUB_KEY_LEN];
   size_t t_len = 0;

   sv_SetGoodCa();
   TEST_ASSERT_EQUAL_INT(eDCS_OK, ge_VerifyRemoteDeviceCertificate(gu8ar_certRemote,
      GU8AR_CERTREMOTE_LEN, &t_id));
   TEST_ASSERT_NOT_EQUAL(0U, t_id);

   // A volatile public key: the remote device's, for ECDSA-SHA256 verification
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, psa_export_public_key(t_id, u8ar_pub, sizeof(u8ar_pub), &t_len));
   TEST_ASSERT_EQUAL_UINT32(GU8AR_CERTREMOTEPUB_LEN, t_len);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(gu8ar_certRemotePub, u8ar_pub, t_len);
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, psa_get_key_attributes(t_id, &st_attr));
   TEST_ASSERT_EQUAL_HEX16(PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1), psa_get_key_type(&st_attr));
   TEST_ASSERT_EQUAL_HEX32(PSA_KEY_LIFETIME_VOLATILE, psa_get_key_lifetime(&st_attr));
   TEST_ASSERT_EQUAL_HEX32(PSA_ALG_ECDSA(PSA_ALG_SHA_256), psa_get_key_algorithm(&st_attr));
   psa_reset_key_attributes(&st_attr);
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, psa_destroy_key(t_id));

   // The device's own certificate is also a valid remote one
   TEST_ASSERT_EQUAL_INT(eDCS_OK, ge_VerifyRemoteDeviceCertificate(gu8ar_certDev, GU8AR_CERTDEV_LEN, &t_id));
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, psa_destroy_key(t_id));
}

static void test_RemoteNeedsAnOutputKey(void)
{
   sv_SetGoodCa();
   TEST_ASSERT_EQUAL_INT(eDCS_INTERNAL, ge_VerifyRemoteDeviceCertificate(gu8ar_certRemote,
      GU8AR_CERTREMOTE_LEN, NULL));
}

static void test_RemoteCasesAreRejectedWithoutTheOwnChecks(void)
{
   uint32_t i;

   sv_SetGoodCa();
   for (i = 0U; i < CERT_CASE_CNT; i++)
   {
      const CertCase_T *c = &gstar_certCases[i];
      uint8_t u8_expected = c->u8_expected;
      psa_key_id_t t_id = 0;
      DeviceCertStatus_E e_got;

      if (c->u8_appType != CERT_APP_DEV) { continue; }
      // Key and subject belong to the remote device: not compared
      if ((u8_expected == eDCS_KEY_MISMATCH) || (u8_expected == eDCS_SUBJECT_MISMATCH))
      {
         u8_expected = eDCS_OK;
      }
      e_got = ge_VerifyRemoteDeviceCertificate(c->u8pt_der, c->t_len, &t_id);
      TEST_ASSERT_EQUAL_HEX8_MESSAGE(u8_expected, (uint8_t)e_got, scpt_Case(c, "remote"));
      if (e_got == eDCS_OK) { TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, psa_destroy_key(t_id)); }
   }
}

/******************************************************************************/
/*  Host certificate (host authentication)                                    */
/******************************************************************************/
static void test_HostCertificateImportsItsKey(void)
{
   psa_key_id_t t_id = 0;
   uint8_t u8ar_pub[DEVICE_CERT_P256_PUB_KEY_LEN];
   size_t t_len = 0;

   sv_SetGoodCa();
   TEST_ASSERT_EQUAL_INT(eDCS_OK, ge_VerifyHostCertificate(gu8ar_certHost, GU8AR_CERTHOST_LEN, &t_id));
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, psa_export_public_key(t_id, u8ar_pub, sizeof(u8ar_pub), &t_len));
   TEST_ASSERT_EQUAL_HEX8_ARRAY(gu8ar_certHostPub, u8ar_pub, GU8AR_CERTHOSTPUB_LEN);
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, psa_destroy_key(t_id));
}

static void test_RolesDoNotMix(void)
{
   psa_key_id_t t_id = 0;

   sv_SetGoodCa();
   // A host certificate is no device certificate, in any check
   TEST_ASSERT_EQUAL_INT(eDCS_BAD_PROFILE, ge_VerifyRemoteDeviceCertificate(gu8ar_certHost,
      GU8AR_CERTHOST_LEN, &t_id));
   TEST_ASSERT_EQUAL_INT(eDCS_BAD_PROFILE, ge_VerifyStoredDeviceCertificate(gu8ar_certHost,
      GU8AR_CERTHOST_LEN));
   // A device certificate (no clientAuth) is no host certificate
   TEST_ASSERT_EQUAL_INT(eDCS_BAD_PROFILE, ge_VerifyHostCertificate(gu8ar_certDev, GU8AR_CERTDEV_LEN, &t_id));
   TEST_ASSERT_EQUAL_INT(eDCS_BAD_PROFILE, ge_VerifyHostCertificate(gu8ar_certRemote,
      GU8AR_CERTREMOTE_LEN, &t_id));
   // Nor is the CA
   TEST_ASSERT_EQUAL_INT(eDCS_BAD_PROFILE, ge_VerifyHostCertificate(gu8ar_certCa, GU8AR_CERTCA_LEN, &t_id));
}

static void test_HostOfAnotherCaIsRejected(void)
{
   psa_key_id_t t_id = 0;

   sv_SetGoodCa();
   TEST_ASSERT_EQUAL_INT(eDCS_BAD_SIG, ge_VerifyHostCertificate(gu8ar_certHostByCa2,
      GU8AR_CERTHOSTBYCA2_LEN, &t_id));
}

static void test_HostNeedsACaAndAnOutputKey(void)
{
   psa_key_id_t t_id = 0;

   gv_ClearTrustAnchor();
   TEST_ASSERT_EQUAL_INT(eDCS_NOT_CA, ge_VerifyHostCertificate(gu8ar_certHost, GU8AR_CERTHOST_LEN, &t_id));
   sv_SetGoodCa();
   TEST_ASSERT_EQUAL_INT(eDCS_INTERNAL, ge_VerifyHostCertificate(gu8ar_certHost, GU8AR_CERTHOST_LEN, NULL));
   TEST_ASSERT_EQUAL_INT(eDCS_PARSE, ge_VerifyHostCertificate(gu8ar_certHost, GU8AR_CERTHOST_LEN - 1U,
      &t_id));
}

static void test_DeviceCasesAreNoHosts(void)
{
   uint32_t i;

   sv_SetGoodCa();
   for (i = 0U; i < CERT_CASE_CNT; i++)
   {
      const CertCase_T *c = &gstar_certCases[i];
      uint8_t u8_expected = c->u8_expected;
      psa_key_id_t t_id = 0;
      DeviceCertStatus_E e_got;

      if (c->u8_appType != CERT_APP_DEV) { continue; }
      // Signed by the CA but without the host role: a profile failure
      if ((u8_expected == eDCS_KEY_MISMATCH) || (u8_expected == eDCS_SUBJECT_MISMATCH))
      {
         u8_expected = eDCS_BAD_PROFILE;
      }
      // The device certificate with the host role is a host certificate
      if (strcmp(c->cpt_name, "dev_host_role") == 0)
      {
         u8_expected = eDCS_OK;
      }
      e_got = ge_VerifyHostCertificate(c->u8pt_der, c->t_len, &t_id);
      TEST_ASSERT_EQUAL_HEX8_MESSAGE(u8_expected, (uint8_t)e_got, scpt_Case(c, "host"));
      if (e_got == eDCS_OK) { TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, psa_destroy_key(t_id)); }
   }
}

int main(void)
{
   int i_ret;

   (void)setvbuf(stdout, NULL, _IONBF, 0);
   gv_HostItsClear();
   if (psa_crypto_init() != PSA_SUCCESS)
   {
      printf("psa_crypto_init failed\n");
      return 1;
   }

   UNITY_BEGIN();
   RUN_TEST(test_ImportDeviceKey);
   RUN_TEST(test_GoodCaBecomesTheTrustAnchor);
   RUN_TEST(test_CaCasesAreRejectedWithTheirStatus);
   RUN_TEST(test_RejectedCaKeepsThePreviousOne);
   RUN_TEST(test_CaThatIsNotDerIsAParseError);
   RUN_TEST(test_DeviceCertificateIsNotACa);
   RUN_TEST(test_NewCaReplacesTheAnchor);
   RUN_TEST(test_ClearTrustAnchor);
   RUN_TEST(test_NoCaMeansNotCa);
   RUN_TEST(test_GoodDeviceCertificateVerifies);
   RUN_TEST(test_DeviceCasesAreRejectedWithTheirStatus);
   RUN_TEST(test_CaCertificateIsNotADeviceCertificate);
   RUN_TEST(test_OwnCheckNeedsTheCsr);
   RUN_TEST(test_OwnCheckNeedsTheDeviceKey);
   RUN_TEST(test_StoredCheckSkipsOnlyTheSubject);
   RUN_TEST(test_RemoteCertificateImportsItsKey);
   RUN_TEST(test_RemoteNeedsAnOutputKey);
   RUN_TEST(test_RemoteCasesAreRejectedWithoutTheOwnChecks);
   RUN_TEST(test_HostCertificateImportsItsKey);
   RUN_TEST(test_RolesDoNotMix);
   RUN_TEST(test_HostOfAnotherCaIsRejected);
   RUN_TEST(test_HostNeedsACaAndAnOutputKey);
   RUN_TEST(test_DeviceCasesAreNoHosts);
   i_ret = UNITY_END();

   (void)psa_destroy_key(CSR_DEVICE_SIGNING_KEY_ID);
   mbedtls_psa_crypto_free();
   return i_ret;
}
