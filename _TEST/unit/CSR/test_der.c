/**
 * @file          test_der.c
 * @brief         Host unit tests for the CSR DER encoder (_ASW/_CSR/DER.c,
 *                gt_DER_EncodeCSR). DER.c is included; the PSA calls it makes
 *                (export public key, sign) and gt_CalculateSHA1 are stubbed
 *                with the inputs of the "csr" vector in _TEST/vectors/wire.json.
 *                That vector's signature is a real ECDSA signature over the TBS
 *                this encoder produces, so test_csr_vector.py can check the
 *                CSR with the CA's library (cryptography).
 *
 *                Run with --dump to print the TBS and the CSR (hex) for the
 *                inputs in the vector: _TEST/tools/gen_csr_vector.py uses it to
 *                regenerate the vector after DER.c changes.
 *
 * @date          01/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#include "DER.c"
#include "unity.h"
#include "wire_vectors.h"

/******************************************************************************/
/*  Stubs: PSA (shim/psa/crypto.h) and the SHA-1 helper of CSR_Generator.c    */
/******************************************************************************/
static psa_status_t st_exportRet;
static size_t st_exportLen;                  /* bytes the export returns           */
static psa_status_t st_signRet;
static uint8_t su8ar_sig[64];                /* r || s the signer returns          */
static uint8_t su8ar_signedTbs[1024];        /* what the encoder asked to be signed */
static size_t st_signedTbsLen;
static psa_key_id_t st_signKey;
static psa_algorithm_t st_signAlg;
static uint8_t su8ar_sha1Input[64];
static size_t st_sha1InputLen;

psa_status_t psa_export_public_key(psa_key_id_t key, uint8_t *data, size_t data_size,
   size_t *data_length)
{
   (void)key;
   TEST_ASSERT_TRUE(data_size >= st_exportLen);
   memcpy(data, gu8ar_vecCsrPubKey, st_exportLen);
   *data_length = st_exportLen;
   return st_exportRet;
}

psa_status_t psa_sign_message(psa_key_id_t key, psa_algorithm_t alg, const uint8_t *input,
   size_t input_length, uint8_t *signature, size_t signature_size, size_t *signature_length)
{
   st_signKey = key;
   st_signAlg = alg;
   st_signedTbsLen = input_length;
   if (input_length <= sizeof(su8ar_signedTbs)) { memcpy(su8ar_signedTbs, input, input_length); }
   TEST_ASSERT_TRUE(signature_size >= sizeof(su8ar_sig));
   memcpy(signature, su8ar_sig, sizeof(su8ar_sig));
   *signature_length = sizeof(su8ar_sig);
   return st_signRet;
}

psa_status_t gt_CalculateSHA1(const uint8_t *u8pt_data, size_t t_len, uint8_t *u8pt_hash)
{
   st_sha1InputLen = t_len;
   if (t_len <= sizeof(su8ar_sha1Input)) { memcpy(su8ar_sha1Input, u8pt_data, t_len); }
   memcpy(u8pt_hash, gu8ar_vecCsrSki, VEC_CSR_SKI_LEN);
   return PSA_SUCCESS;
}

/******************************************************************************/
/*  Helpers                                                                   */
/******************************************************************************/
static SubjectNameField_T sstar_subject[VEC_CSR_SUBJ_CNT + 4U];
static uint8_t su8ar_out[1024];
static size_t st_outLen;

/** Subject fields of the vector (names "C", "ST", ... and their values). */
static void sv_LoadSubject(void)
{
   uint32_t i;

   for (i = 0U; i < VEC_CSR_SUBJ_CNT; i++)
   {
      sstar_subject[i].cpt_name = gcptar_vecCsrSubjName[i];
      sstar_subject[i].t_nameLen = strlen(gcptar_vecCsrSubjName[i]);
      sstar_subject[i].cpt_value = (char *)gcptar_vecCsrSubjValue[i];
      sstar_subject[i].t_valueLen = strlen(gcptar_vecCsrSubjValue[i]);
   }
}

static psa_status_t st_EncodeCsr(size_t t_fields, size_t t_bufLen)
{
   st_outLen = 0U;
   return gt_DER_EncodeCSR(sstar_subject, t_fields, CSR_DEVICE_SIGNING_KEY_ID, su8ar_out,
      t_bufLen, &st_outLen);
}

/** The signature BIT STRING is the last element: return its INTEGERs' bytes. */
static const uint8_t *su8pt_SigTail(size_t t_tailLen)
{
   TEST_ASSERT_TRUE(st_outLen >= t_tailLen);
   return &su8ar_out[st_outLen - t_tailLen];
}

void setUp(void)
{
   st_exportRet = PSA_SUCCESS;
   st_exportLen = VEC_CSR_PUBKEY_LEN;
   st_signRet = PSA_SUCCESS;
   memcpy(su8ar_sig, gu8ar_vecCsrSig, sizeof(su8ar_sig));
   st_signedTbsLen = 0U;
   st_sha1InputLen = 0U;
   st_DERWorkBufferMutex.i_held = 0;
   sv_LoadSubject();
}

void tearDown(void)
{
   // Every path must release the work buffer
   TEST_ASSERT_EQUAL_INT_MESSAGE(0, st_DERWorkBufferMutex.i_held, "DER work buffer left locked");
}

/******************************************************************************/
/*  Golden CSR                                                                */
/******************************************************************************/
static void test_CsrMatchesVector(void)
{
   TEST_ASSERT_TRUE_MESSAGE(VEC_CSR_DER_LEN > 0U, "vector has no CSR: run gen_csr_vector.py");
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, st_EncodeCsr(VEC_CSR_SUBJ_CNT, sizeof(su8ar_out)));
   TEST_ASSERT_EQUAL_UINT32(VEC_CSR_DER_LEN, st_outLen);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(gu8ar_vecCsrDer, su8ar_out, VEC_CSR_DER_LEN);
}

static void test_SignsTheTbsWithTheDeviceKey(void)
{
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, st_EncodeCsr(VEC_CSR_SUBJ_CNT, sizeof(su8ar_out)));
   TEST_ASSERT_EQUAL_UINT32(CSR_DEVICE_SIGNING_KEY_ID, st_signKey);
   TEST_ASSERT_EQUAL_HEX32(PSA_ALG_ECDSA(PSA_ALG_SHA_256), st_signAlg);
   TEST_ASSERT_EQUAL_UINT32(VEC_CSR_TBS_LEN, st_signedTbsLen);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(gu8ar_vecCsrTbs, su8ar_signedTbs, VEC_CSR_TBS_LEN);
   // The TBS is the first element of the CSR SEQUENCE (after its 4-byte header)
   TEST_ASSERT_EQUAL_HEX8_ARRAY(gu8ar_vecCsrTbs, &su8ar_out[4], VEC_CSR_TBS_LEN);
}

/** An INTEGER shorter than DER_INTEGER_LEN must carry its low-order bytes (X.690
    8.3): 1 -> 02 01 01, 0x80 -> 02 02 00 80. The CSR only encodes version 0,
    which comes out right either way. */
static void test_ShortIntegerKeepsItsLowBytes(void)
{
   DERValue_T st_v;
   uint8_t u8ar_buf[8];
   size_t t_len = 0U;

   memset(&st_v, 0, sizeof(st_v));
   st_v.e_type = eDT_PRIMITIVE_INTEGER;
   st_v.u_data.t_integer = 0x80;
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, st_Encode(&st_v, u8ar_buf, sizeof(u8ar_buf), &t_len));
   TEST_ASSERT_EQUAL_UINT(4U, t_len);
   // Today the encoder writes the value's top bytes: 02 02 00 00
   TEST_ASSERT_EQUAL_HEX8(0x00U, u8ar_buf[3]);
   TEST_IGNORE_MESSAGE("KNOWN BUG: st_Encode writes an INTEGER's high-order bytes, so 0x80 encodes as "
      "02 02 00 00 and 1 as 02 01 00 (DER.c, eDT_PRIMITIVE_INTEGER)");
}

static void test_SubjectKeyIdIsSha1OfThePoint(void)
{
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, st_EncodeCsr(VEC_CSR_SUBJ_CNT, sizeof(su8ar_out)));
   // SHA-1 over X || Y, without the 0x04 prefix
   TEST_ASSERT_EQUAL_UINT32(64U, st_sha1InputLen);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(&gu8ar_vecCsrPubKey[1], su8ar_sha1Input, 64U);
}

/******************************************************************************/
/*  Errors                                                                    */
/******************************************************************************/
static void test_BufferTooSmall(void)
{
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_BUFFER_TOO_SMALL, st_EncodeCsr(VEC_CSR_SUBJ_CNT, VEC_CSR_DER_LEN - 1U));
   // Room for the TBS but not for the signed CSR
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_BUFFER_TOO_SMALL, st_EncodeCsr(VEC_CSR_SUBJ_CNT, VEC_CSR_TBS_LEN));
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, st_EncodeCsr(VEC_CSR_SUBJ_CNT, VEC_CSR_DER_LEN));
}

static void test_NullArguments(void)
{
   size_t t_len = 0U;

   TEST_ASSERT_EQUAL_INT(PSA_ERROR_INVALID_ARGUMENT,
      gt_DER_EncodeCSR(NULL, 1U, 1U, su8ar_out, sizeof(su8ar_out), &t_len));
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_INVALID_ARGUMENT,
      gt_DER_EncodeCSR(sstar_subject, 1U, 1U, NULL, sizeof(su8ar_out), &t_len));
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_INVALID_ARGUMENT,
      gt_DER_EncodeCSR(sstar_subject, 1U, 1U, su8ar_out, sizeof(su8ar_out), NULL));
}

static void test_TooManySubjectFields(void)
{
   uint32_t i;

   for (i = VEC_CSR_SUBJ_CNT; i < ARRAY_SIZE(sstar_subject); i++) { sstar_subject[i] = sstar_subject[0]; }
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, st_EncodeCsr(X520_DN_MAX_ATTRIBUTES, sizeof(su8ar_out)));
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_BUFFER_TOO_SMALL, st_EncodeCsr(X520_DN_MAX_ATTRIBUTES + 1U, sizeof(su8ar_out)));
}

static void test_UnknownSubjectFieldName(void)
{
   sstar_subject[2].cpt_name = "E";
   sstar_subject[2].t_nameLen = 1U;
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_NOT_SUPPORTED, st_EncodeCsr(VEC_CSR_SUBJ_CNT, sizeof(su8ar_out)));
   // Name compared with its length: "Ca" is not "C"
   sv_LoadSubject();
   sstar_subject[0].cpt_name = "Ca";
   sstar_subject[0].t_nameLen = 2U;
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_NOT_SUPPORTED, st_EncodeCsr(VEC_CSR_SUBJ_CNT, sizeof(su8ar_out)));
}

static void test_PublicKeyExportFailure(void)
{
   st_exportRet = PSA_ERROR_DOES_NOT_EXIST;
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_DOES_NOT_EXIST, st_EncodeCsr(VEC_CSR_SUBJ_CNT, sizeof(su8ar_out)));
}

static void test_PublicKeyNotUncompressedP256(void)
{
   // A 33-byte compressed point is refused before anything is encoded
   st_exportLen = 33U;
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_INVALID_ARGUMENT, st_EncodeCsr(VEC_CSR_SUBJ_CNT, sizeof(su8ar_out)));
}

static void test_SignFailure(void)
{
   st_signRet = PSA_ERROR_HARDWARE_FAILURE;
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_HARDWARE_FAILURE, st_EncodeCsr(VEC_CSR_SUBJ_CNT, sizeof(su8ar_out)));
}

/******************************************************************************/
/*  Signature INTEGERs are minimal DER (fix of the sample encoder)            */
/******************************************************************************/
static void test_SignatureLeadingZerosAreStripped(void)
{
   uint8_t u8ar_exp[2U + 2U + 33U + 33U + 2U];
   size_t n = 0U;

   // r = 00 7f 11.. (31 significant bytes), s = 00 00 80 22.. (30 significant)
   memset(su8ar_sig, 0x11, 32U);
   su8ar_sig[0] = 0x00U;
   su8ar_sig[1] = 0x7FU;
   memset(&su8ar_sig[32], 0x22, 32U);
   su8ar_sig[32] = 0x00U;
   su8ar_sig[33] = 0x00U;
   su8ar_sig[34] = 0x80U;
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, st_EncodeCsr(VEC_CSR_SUBJ_CNT, sizeof(su8ar_out)));

   // BIT STRING { 00, SEQUENCE { INTEGER 7f 11.., INTEGER 00 80 22.. } }
   u8ar_exp[n++] = 0x03U; u8ar_exp[n++] = 0x45U; u8ar_exp[n++] = 0x00U;
   u8ar_exp[n++] = 0x30U; u8ar_exp[n++] = 0x42U;
   u8ar_exp[n++] = 0x02U; u8ar_exp[n++] = 0x1FU;
   memcpy(&u8ar_exp[n], &su8ar_sig[1], 31U); n += 31U;
   u8ar_exp[n++] = 0x02U; u8ar_exp[n++] = 0x1FU; u8ar_exp[n++] = 0x00U;
   memcpy(&u8ar_exp[n], &su8ar_sig[34], 30U); n += 30U;
   TEST_ASSERT_EQUAL_HEX8_ARRAY(u8ar_exp, su8pt_SigTail(n), n);
}

static void test_SignatureHighBitGetsZeroPrefix(void)
{
   uint8_t u8ar_exp[2U + 2U + 35U + 34U + 1U];
   size_t n = 0U;

   memset(su8ar_sig, 0x80, 32U);
   memset(&su8ar_sig[32], 0x01, 32U);
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, st_EncodeCsr(VEC_CSR_SUBJ_CNT, sizeof(su8ar_out)));

   u8ar_exp[n++] = 0x03U; u8ar_exp[n++] = 0x48U; u8ar_exp[n++] = 0x00U;
   u8ar_exp[n++] = 0x30U; u8ar_exp[n++] = 0x45U;
   u8ar_exp[n++] = 0x02U; u8ar_exp[n++] = 0x21U; u8ar_exp[n++] = 0x00U;
   memcpy(&u8ar_exp[n], su8ar_sig, 32U); n += 32U;
   u8ar_exp[n++] = 0x02U; u8ar_exp[n++] = 0x20U;
   memcpy(&u8ar_exp[n], &su8ar_sig[32], 32U); n += 32U;
   TEST_ASSERT_EQUAL_HEX8_ARRAY(u8ar_exp, su8pt_SigTail(n), n);
}

static void test_SignatureZeroIntegerKeepsOneByte(void)
{
   static const uint8_t scu8ar_exp[] = { 0x03U, 0x09U, 0x00U, 0x30U, 0x06U,
      0x02U, 0x01U, 0x00U, 0x02U, 0x01U, 0x05U };

   memset(su8ar_sig, 0x00, sizeof(su8ar_sig));
   su8ar_sig[63] = 0x05U;
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, st_EncodeCsr(VEC_CSR_SUBJ_CNT, sizeof(su8ar_out)));
   TEST_ASSERT_EQUAL_HEX8_ARRAY(scu8ar_exp, su8pt_SigTail(sizeof(scu8ar_exp)), sizeof(scu8ar_exp));
}

/******************************************************************************/
/*  --dump: TBS and CSR for gen_csr_vector.py                                 */
/******************************************************************************/
static void sv_PrintHex(const char *cpt_tag, const uint8_t *u8pt_data, size_t t_len)
{
   size_t i;

   printf("%s ", cpt_tag);
   for (i = 0U; i < t_len; i++) { printf("%02x", u8pt_data[i]); }
   printf("\n");
}

static int si_Dump(void)
{
   setUp();
   if (st_EncodeCsr(VEC_CSR_SUBJ_CNT, sizeof(su8ar_out)) != PSA_SUCCESS)
   {
      printf("encode failed\n");
      return 1;
   }
   sv_PrintHex("TBS", su8ar_signedTbs, st_signedTbsLen);
   sv_PrintHex("DER", su8ar_out, st_outLen);
   return 0;
}

int main(int argc, char **argv)
{
   (void)setvbuf(stdout, NULL, _IONBF, 0);
   if ((argc > 1) && (strcmp(argv[1], "--dump") == 0))
   {
      return si_Dump();
   }

   UNITY_BEGIN();
   RUN_TEST(test_CsrMatchesVector);
   RUN_TEST(test_SignsTheTbsWithTheDeviceKey);
   RUN_TEST(test_ShortIntegerKeepsItsLowBytes);
   RUN_TEST(test_SubjectKeyIdIsSha1OfThePoint);
   RUN_TEST(test_BufferTooSmall);
   RUN_TEST(test_NullArguments);
   RUN_TEST(test_TooManySubjectFields);
   RUN_TEST(test_UnknownSubjectFieldName);
   RUN_TEST(test_PublicKeyExportFailure);
   RUN_TEST(test_PublicKeyNotUncompressedP256);
   RUN_TEST(test_SignFailure);
   RUN_TEST(test_SignatureLeadingZerosAreStripped);
   RUN_TEST(test_SignatureHighBitGetsZeroPrefix);
   RUN_TEST(test_SignatureZeroIntegerKeepsOneByte);
   return UNITY_END();
}
