/**
 * @file          test_host_auth_crypto.c
 * @brief         Host unit tests for the cryptography of host authentication
 *                (_ASW/_HOST_AUTH/HostAuthCrypto.c), with the REAL
 *                TF-PSA-Crypto. The handshake of wire.json "host_auth.handshake"
 *                (made by Python's cryptography) is recomputed here: the
 *                transcript, the ECDH secret and the passkey match, both
 *                signatures verify, and a signature altered in any byte, or
 *                checked under the other role, does not. Contract:
 *                _DOC/HostAuth/PROTOCOL.md §4.
 *
 * @date          25/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#include "HostAuthCrypto.c"
#include "unity.h"
#include "wire_vectors.h"

/******************************************************************************/
/*  Helpers                                                                   */
/******************************************************************************/
static psa_key_id_t st_devKey;
static psa_key_id_t st_devPub;
static psa_key_id_t st_hostPub;
static psa_key_id_t st_devEph;

static psa_key_id_t st_Import(psa_key_type_t t_type, psa_key_usage_t t_usage, psa_algorithm_t t_alg,
   const uint8_t *u8pt_key, size_t t_len)
{
   psa_key_attributes_t st_attr = PSA_KEY_ATTRIBUTES_INIT;
   psa_key_id_t t_id = 0;

   psa_set_key_type(&st_attr, t_type);
   psa_set_key_bits(&st_attr, 256);
   psa_set_key_usage_flags(&st_attr, t_usage);
   psa_set_key_algorithm(&st_attr, t_alg);
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, psa_import_key(&st_attr, u8pt_key, t_len, &t_id));
   psa_reset_key_attributes(&st_attr);
   return t_id;
}

static HostAuthTranscript_T st_VecTranscriptIn(void)
{
   HostAuthTranscript_T st_in;

   st_in.u8pt_nonceHost = gu8ar_vecHauthNonceHost;
   st_in.u8pt_nonceDev = gu8ar_vecHauthNonceDev;
   st_in.u8pt_pointHost = gu8ar_vecHauthPointHost;
   st_in.u8pt_pointDev = gu8ar_vecHauthPointDev;
   st_in.u8pt_certHost = gu8ar_vecHauthHostCert;
   st_in.t_certHostLen = VEC_HAUTH_HOSTCERT_LEN;
   st_in.u8pt_certDev = gu8ar_vecHauthDevCert;
   st_in.t_certDevLen = VEC_HAUTH_DEVCERT_LEN;
   return st_in;
}

void setUp(void)
{
   const psa_key_type_t t_pair = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
   const psa_key_type_t t_pub = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1);
   const psa_algorithm_t t_ecdsa = PSA_ALG_ECDSA(PSA_ALG_SHA_256);

   // The device key as CSR_Generator.c makes it, the host key as the device imports it
   st_devKey = st_Import(t_pair, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE,
      t_ecdsa, gu8ar_vecHauthDevPriv, VEC_HAUTH_DEVPRIV_LEN);
   st_devPub = st_Import(t_pub, PSA_KEY_USAGE_VERIFY_MESSAGE, t_ecdsa, gu8ar_vecHauthDevPub,
      VEC_HAUTH_DEVPUB_LEN);
   st_hostPub = st_Import(t_pub, PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_VERIFY_HASH, t_ecdsa,
      gu8ar_vecHauthHostPub, VEC_HAUTH_HOSTPUB_LEN);
   st_devEph = st_Import(t_pair, PSA_KEY_USAGE_DERIVE, PSA_ALG_ECDH, gu8ar_vecHauthDevEphPriv,
      VEC_HAUTH_DEVEPHPRIV_LEN);
}

void tearDown(void)
{
   (void)psa_destroy_key(st_devKey);
   (void)psa_destroy_key(st_devPub);
   (void)psa_destroy_key(st_hostPub);
   (void)psa_destroy_key(st_devEph);
}

/******************************************************************************/
/*  The vector handshake                                                      */
/******************************************************************************/
static void test_VectorLayout(void)
{
   TEST_ASSERT_EQUAL_UINT(HOST_AUTH_NONCE_LEN, VEC_HAUTH_NONCE_LEN);
   TEST_ASSERT_EQUAL_UINT(HOST_AUTH_POINT_LEN, VEC_HAUTH_POINT_LEN);
   TEST_ASSERT_EQUAL_UINT(HOST_AUTH_SIG_LEN, VEC_HAUTH_SIG_LEN);
   TEST_ASSERT_EQUAL_UINT(HOST_AUTH_HASH_LEN, VEC_HAUTH_HASH_LEN);
   // HELLO and CHALLENGE carry exactly the values the transcript covers
   TEST_ASSERT_EQUAL_UINT8_ARRAY(gu8ar_vecHauthNonceHost, &gu8ar_vecHauthHello[1], HOST_AUTH_NONCE_LEN);
   TEST_ASSERT_EQUAL_UINT8_ARRAY(gu8ar_vecHauthPointHost, &gu8ar_vecHauthHello[17], HOST_AUTH_POINT_LEN);
   TEST_ASSERT_EQUAL_UINT8_ARRAY(gu8ar_vecHauthHostCert, &gu8ar_vecHauthHello[82], VEC_HAUTH_HOSTCERT_LEN);
   TEST_ASSERT_EQUAL_UINT8_ARRAY(gu8ar_vecHauthSigDev, &gu8ar_vecHauthChallenge[82], HOST_AUTH_SIG_LEN);
}

static void test_TranscriptMatchesTheVector(void)
{
   HostAuthTranscript_T st_in = st_VecTranscriptIn();
   uint8_t u8ar_t[HOST_AUTH_HASH_LEN];

   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, gt_HostAuthCrypto_Transcript(&st_in, u8ar_t));
   TEST_ASSERT_EQUAL_UINT8_ARRAY(gu8ar_vecHauthTranscript, u8ar_t, HOST_AUTH_HASH_LEN);
}

static void test_TranscriptCoversEveryValue(void)
{
   HostAuthTranscript_T st_in = st_VecTranscriptIn();
   uint8_t u8ar_cert[VEC_HAUTH_DEVCERT_LEN];
   uint8_t u8ar_t[HOST_AUTH_HASH_LEN];

   // Another device certificate (one byte flipped) gives another T
   (void)memcpy(u8ar_cert, gu8ar_vecHauthDevCert, sizeof(u8ar_cert));
   u8ar_cert[sizeof(u8ar_cert) - 1U] ^= 0x01U;
   st_in.u8pt_certDev = u8ar_cert;
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, gt_HostAuthCrypto_Transcript(&st_in, u8ar_t));
   TEST_ASSERT_FALSE(memcmp(u8ar_t, gu8ar_vecHauthTranscript, HOST_AUTH_HASH_LEN) == 0);

   // The nonces swapped give another T
   st_in = st_VecTranscriptIn();
   st_in.u8pt_nonceHost = gu8ar_vecHauthNonceDev;
   st_in.u8pt_nonceDev = gu8ar_vecHauthNonceHost;
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, gt_HostAuthCrypto_Transcript(&st_in, u8ar_t));
   TEST_ASSERT_FALSE(memcmp(u8ar_t, gu8ar_vecHauthTranscript, HOST_AUTH_HASH_LEN) == 0);
}

static void test_AgreeMatchesTheVector(void)
{
   uint8_t u8ar_z[HOST_AUTH_HASH_LEN];

   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, gt_HostAuthCrypto_Agree(st_devEph, gu8ar_vecHauthPointHost, u8ar_z));
   TEST_ASSERT_EQUAL_UINT8_ARRAY(gu8ar_vecHauthSecret, u8ar_z, HOST_AUTH_HASH_LEN);
}

static void test_PasskeyMatchesTheVector(void)
{
   uint32_t u32_passkey = 0xFFFFFFFFUL;

   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, gt_HostAuthCrypto_Passkey(gu8ar_vecHauthSecret,
      gu8ar_vecHauthNonceHost, gu8ar_vecHauthNonceDev, gu8ar_vecHauthTranscript, &u32_passkey));
   TEST_ASSERT_EQUAL_UINT32(VEC_HAUTH_PASSKEY, u32_passkey);
   TEST_ASSERT_TRUE(u32_passkey <= HOST_AUTH_PASSKEY_MAX);
}

static void test_HostSignatureVerifies(void)
{
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, gt_HostAuthCrypto_Verify(st_hostPub, eHAR_HOST,
      gu8ar_vecHauthTranscript, gu8ar_vecHauthSigHost));
}

static void test_DeviceSignatureOfTheVectorVerifies(void)
{
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, gt_HostAuthCrypto_Verify(st_devPub, eHAR_DEVICE,
      gu8ar_vecHauthTranscript, gu8ar_vecHauthSigDev));
}

static void test_AlteredSignatureIsRejected(void)
{
   uint8_t u8ar_sig[HOST_AUTH_SIG_LEN];
   size_t t_i;

   for (t_i = 0U; t_i < HOST_AUTH_SIG_LEN; t_i++)
   {
      (void)memcpy(u8ar_sig, gu8ar_vecHauthSigHost, sizeof(u8ar_sig));
      u8ar_sig[t_i] ^= 0x01U;
      TEST_ASSERT_EQUAL_INT_MESSAGE(PSA_ERROR_INVALID_SIGNATURE, gt_HostAuthCrypto_Verify(st_hostPub,
         eHAR_HOST, gu8ar_vecHauthTranscript, u8ar_sig), "flipped signature byte accepted");
   }
}

static void test_RoleIsBoundIntoTheSignature(void)
{
   // The host's signature is no device signature, and the reverse
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_INVALID_SIGNATURE, gt_HostAuthCrypto_Verify(st_hostPub, eHAR_DEVICE,
      gu8ar_vecHauthTranscript, gu8ar_vecHauthSigHost));
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_INVALID_SIGNATURE, gt_HostAuthCrypto_Verify(st_devPub, eHAR_HOST,
      gu8ar_vecHauthTranscript, gu8ar_vecHauthSigDev));
}

static void test_AlteredTranscriptIsRejected(void)
{
   uint8_t u8ar_t[HOST_AUTH_HASH_LEN];

   (void)memcpy(u8ar_t, gu8ar_vecHauthTranscript, sizeof(u8ar_t));
   u8ar_t[5] ^= 0x80U;
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_INVALID_SIGNATURE, gt_HostAuthCrypto_Verify(st_hostPub, eHAR_HOST,
      u8ar_t, gu8ar_vecHauthSigHost));
}

static void test_DeviceSignsWhatThePeerVerifies(void)
{
   uint8_t u8ar_sig[HOST_AUTH_SIG_LEN];

   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, gt_HostAuthCrypto_Sign(st_devKey, eHAR_DEVICE,
      gu8ar_vecHauthTranscript, u8ar_sig));
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, gt_HostAuthCrypto_Verify(st_devPub, eHAR_DEVICE,
      gu8ar_vecHauthTranscript, u8ar_sig));
}

/******************************************************************************/
/*  Ephemeral keys                                                            */
/******************************************************************************/
static void test_EphemeralKeysAgree(void)
{
   psa_key_id_t t_a = 0;
   psa_key_id_t t_b = 0;
   uint8_t u8ar_pa[HOST_AUTH_POINT_LEN];
   uint8_t u8ar_pb[HOST_AUTH_POINT_LEN];
   uint8_t u8ar_za[HOST_AUTH_HASH_LEN];
   uint8_t u8ar_zb[HOST_AUTH_HASH_LEN];

   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, gt_HostAuthCrypto_NewEphemeral(&t_a, u8ar_pa));
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, gt_HostAuthCrypto_NewEphemeral(&t_b, u8ar_pb));
   TEST_ASSERT_EQUAL_HEX8(0x04U, u8ar_pa[0]);
   TEST_ASSERT_FALSE(memcmp(u8ar_pa, u8ar_pb, sizeof(u8ar_pa)) == 0);
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, gt_HostAuthCrypto_Agree(t_a, u8ar_pb, u8ar_za));
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, gt_HostAuthCrypto_Agree(t_b, u8ar_pa, u8ar_zb));
   TEST_ASSERT_EQUAL_UINT8_ARRAY(u8ar_za, u8ar_zb, HOST_AUTH_HASH_LEN);
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, psa_destroy_key(t_a));
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, psa_destroy_key(t_b));
}

static void test_EphemeralKeyCannotSign(void)
{
   psa_key_id_t t_a = 0;
   uint8_t u8ar_p[HOST_AUTH_POINT_LEN];
   uint8_t u8ar_sig[HOST_AUTH_SIG_LEN];

   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, gt_HostAuthCrypto_NewEphemeral(&t_a, u8ar_p));
   TEST_ASSERT_NOT_EQUAL_INT(PSA_SUCCESS, gt_HostAuthCrypto_Sign(t_a, eHAR_DEVICE,
      gu8ar_vecHauthTranscript, u8ar_sig));
   (void)psa_destroy_key(t_a);
}

static void test_PointOffTheCurveIsRejected(void)
{
   uint8_t u8ar_p[HOST_AUTH_POINT_LEN];
   uint8_t u8ar_z[HOST_AUTH_HASH_LEN];

   (void)memcpy(u8ar_p, gu8ar_vecHauthPointHost, sizeof(u8ar_p));
   u8ar_p[HOST_AUTH_POINT_LEN - 1U] ^= 0x01U;
   TEST_ASSERT_NOT_EQUAL_INT(PSA_SUCCESS, gt_HostAuthCrypto_Agree(st_devEph, u8ar_p, u8ar_z));
   u8ar_p[0] = 0x02U;
   TEST_ASSERT_NOT_EQUAL_INT(PSA_SUCCESS, gt_HostAuthCrypto_Agree(st_devEph, u8ar_p, u8ar_z));
}

static void test_RandomFillsTheBuffer(void)
{
   uint8_t u8ar_a[HOST_AUTH_NONCE_LEN] = { 0 };
   uint8_t u8ar_b[HOST_AUTH_NONCE_LEN] = { 0 };

   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, gt_HostAuthCrypto_Random(u8ar_a, sizeof(u8ar_a)));
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, gt_HostAuthCrypto_Random(u8ar_b, sizeof(u8ar_b)));
   TEST_ASSERT_FALSE(memcmp(u8ar_a, u8ar_b, sizeof(u8ar_a)) == 0);
}

/******************************************************************************/
/*  Arguments                                                                 */
/******************************************************************************/
static void test_NullArgumentsAreRejected(void)
{
   HostAuthTranscript_T st_in = st_VecTranscriptIn();
   psa_key_id_t t_k = 0;
   uint8_t u8ar_buf[HOST_AUTH_POINT_LEN];
   uint32_t u32_pk = 0;

   TEST_ASSERT_EQUAL_INT(PSA_ERROR_INVALID_ARGUMENT, gt_HostAuthCrypto_Random(NULL, 4U));
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_INVALID_ARGUMENT, gt_HostAuthCrypto_NewEphemeral(NULL, u8ar_buf));
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_INVALID_ARGUMENT, gt_HostAuthCrypto_NewEphemeral(&t_k, NULL));
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_INVALID_ARGUMENT, gt_HostAuthCrypto_Agree(st_devEph, NULL, u8ar_buf));
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_INVALID_ARGUMENT,
      gt_HostAuthCrypto_Agree(st_devEph, gu8ar_vecHauthPointHost, NULL));
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_INVALID_ARGUMENT, gt_HostAuthCrypto_Transcript(NULL, u8ar_buf));
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_INVALID_ARGUMENT, gt_HostAuthCrypto_Transcript(&st_in, NULL));
   st_in.u8pt_certHost = NULL;
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_INVALID_ARGUMENT, gt_HostAuthCrypto_Transcript(&st_in, u8ar_buf));
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_INVALID_ARGUMENT,
      gt_HostAuthCrypto_Sign(st_devKey, eHAR_DEVICE, NULL, u8ar_buf));
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_INVALID_ARGUMENT,
      gt_HostAuthCrypto_Sign(st_devKey, eHAR_DEVICE, gu8ar_vecHauthTranscript, NULL));
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_INVALID_ARGUMENT,
      gt_HostAuthCrypto_Verify(st_hostPub, eHAR_HOST, NULL, gu8ar_vecHauthSigHost));
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_INVALID_ARGUMENT,
      gt_HostAuthCrypto_Verify(st_hostPub, eHAR_HOST, gu8ar_vecHauthTranscript, NULL));
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_INVALID_ARGUMENT, gt_HostAuthCrypto_Passkey(NULL,
      gu8ar_vecHauthNonceHost, gu8ar_vecHauthNonceDev, gu8ar_vecHauthTranscript, &u32_pk));
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_INVALID_ARGUMENT, gt_HostAuthCrypto_Passkey(gu8ar_vecHauthSecret,
      gu8ar_vecHauthNonceHost, gu8ar_vecHauthNonceDev, gu8ar_vecHauthTranscript, NULL));
}

static void test_UnknownKeyIsAnError(void)
{
   uint8_t u8ar_sig[HOST_AUTH_SIG_LEN];

   TEST_ASSERT_NOT_EQUAL_INT(PSA_SUCCESS, gt_HostAuthCrypto_Sign((psa_key_id_t)0x7777U, eHAR_DEVICE,
      gu8ar_vecHauthTranscript, u8ar_sig));
   TEST_ASSERT_NOT_EQUAL_INT(PSA_SUCCESS, gt_HostAuthCrypto_Verify((psa_key_id_t)0x7777U, eHAR_HOST,
      gu8ar_vecHauthTranscript, gu8ar_vecHauthSigHost));
}

int main(void)
{
   (void)setvbuf(stdout, NULL, _IONBF, 0);
   if (psa_crypto_init() != PSA_SUCCESS)
   {
      return 1;
   }
   UNITY_BEGIN();
   RUN_TEST(test_VectorLayout);
   RUN_TEST(test_TranscriptMatchesTheVector);
   RUN_TEST(test_TranscriptCoversEveryValue);
   RUN_TEST(test_AgreeMatchesTheVector);
   RUN_TEST(test_PasskeyMatchesTheVector);
   RUN_TEST(test_HostSignatureVerifies);
   RUN_TEST(test_DeviceSignatureOfTheVectorVerifies);
   RUN_TEST(test_AlteredSignatureIsRejected);
   RUN_TEST(test_RoleIsBoundIntoTheSignature);
   RUN_TEST(test_AlteredTranscriptIsRejected);
   RUN_TEST(test_DeviceSignsWhatThePeerVerifies);
   RUN_TEST(test_EphemeralKeysAgree);
   RUN_TEST(test_EphemeralKeyCannotSign);
   RUN_TEST(test_PointOffTheCurveIsRejected);
   RUN_TEST(test_RandomFillsTheBuffer);
   RUN_TEST(test_NullArgumentsAreRejected);
   RUN_TEST(test_UnknownKeyIsAnError);
   return UNITY_END();
}
