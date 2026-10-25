/**
 * @file          test_csr_generator.c
 * @brief         Host unit tests for the device key and CSR life cycle in
 *                _ASW/_CSR/CSR_Generator.c: gt_InitCryptoStorage,
 *                gv_GenerateOrLoadCSR, gt_ProbeDeviceKey, gt_RemoveStoredCSR,
 *                gt_DestroyDeviceCredentials and gt_CalculateSHA1.
 *                CSR_Generator.c is included to reach its static state. PSA
 *                (shim/psa_stub), the PSA ITS (in memory), the HUK and settings
 *                calls, the hardware ID and the DER encoder (tested on its own
 *                by test_der.c) are stubbed.
 *                Contract: _DOC/Provisioning/README.md (key and CSR).
 *
 *                gt_InitCryptoStorage() keeps its result in function-local
 *                statics, so one process can see only one initialization. The
 *                default run has a working init; the init failures run as
 *                separate CTest entries, selected by an argument:
 *                  --init=huk-present | huk-missing | settings-fail | crypto-fail
 *
 * @date          02/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

/* Kconfig values the module reads (prj.conf sets them on the device) */
#define CONFIG_CSR_SUBJ_C                    "IN"
#define CONFIG_CSR_SUBJ_ST                   "Maharashtra"
#define CONFIG_CSR_SUBJ_L                    "Pune"
#define CONFIG_CSR_SUBJ_O                    "Test Organisation"
#define CONFIG_CSR_SUBJ_OU                   "Test Unit"
/* The storage configuration of the firmware build (zephyr/.config): Zephyr's
   secure storage on settings, its key from the HUK library, the HUK written by
   NCS during psa_crypto_init() */
#define CONFIG_SECURE_STORAGE_ITS_STORE_IMPLEMENTATION_SETTINGS 1
#define CONFIG_SECURE_STORAGE_ITS_TRANSFORM_AEAD_KEY_PROVIDER_HUK_LIBRARY 1
#define CONFIG_HW_UNIQUE_KEY 1
#define CONFIG_HW_UNIQUE_KEY_WRITE_ON_CRYPTO_INIT 1

#include "CSR_Generator.c"
#include "unity.h"

/******************************************************************************/
/*  Stubs: HUK, settings, PSA crypto init                                     */
/******************************************************************************/
static bool sb_hukWritten;
static bool sb_cryptoWritesHuk;               /* NCS writes a missing HUK in crypto init */
static int si_settingsRet;
static uint32_t su32_settingsInits;
static psa_status_t st_cryptoInitRet;
static uint32_t su32_cryptoInits;

bool hw_unique_key_are_any_written(void) { return sb_hukWritten; }

int settings_subsys_init(void)
{
   su32_settingsInits++;
   return si_settingsRet;
}

psa_status_t psa_crypto_init(void)
{
   su32_cryptoInits++;
   if ((st_cryptoInitRet == PSA_SUCCESS) && sb_cryptoWritesHuk) { sb_hukWritten = true; }
   return st_cryptoInitRet;
}

/******************************************************************************/
/*  Stubs: the persistent key (one slot, ID CSR_DEVICE_SIGNING_KEY_ID)        */
/******************************************************************************/
static bool sb_keyExists;
static psa_status_t st_generateRet;          /* forced psa_generate_key() result */
static psa_status_t st_getAttrRet;           /* forced psa_get_key_attributes()  */
static psa_status_t st_destroyRet;           /* forced psa_destroy_key()         */
static psa_key_attributes_t st_genAttr;      /* policy of the last generate      */
static uint32_t su32_generates;
static uint32_t su32_probes;
static psa_key_id_t st_probedId;
static int32_t si_attrResets;                /* psa_reset_key_attributes() calls */

psa_status_t psa_generate_key(const psa_key_attributes_t *attributes, psa_key_id_t *key)
{
   su32_generates++;
   st_genAttr = *attributes;
   if (st_generateRet != PSA_SUCCESS) { return st_generateRet; }
   if (sb_keyExists) { return PSA_ERROR_ALREADY_EXISTS; }
   sb_keyExists = true;
   *key = attributes->id;
   return PSA_SUCCESS;
}

psa_status_t psa_get_key_attributes(psa_key_id_t key, psa_key_attributes_t *attributes)
{
   (void)attributes;
   su32_probes++;
   st_probedId = key;
   if (st_getAttrRet != PSA_SUCCESS) { return st_getAttrRet; }
   return sb_keyExists ? PSA_SUCCESS : PSA_ERROR_DOES_NOT_EXIST;
}

void psa_reset_key_attributes(psa_key_attributes_t *attributes)
{
   (void)attributes;
   si_attrResets++;
}

psa_status_t psa_destroy_key(psa_key_id_t key)
{
   TEST_ASSERT_EQUAL_UINT32(CSR_DEVICE_SIGNING_KEY_ID, key);
   if (st_destroyRet != PSA_SUCCESS) { return st_destroyRet; }
   if (!sb_keyExists) { return PSA_ERROR_INVALID_HANDLE; }
   sb_keyExists = false;
   return PSA_SUCCESS;
}

/******************************************************************************/
/*  Stubs: SHA-1, hardware ID, DER encoder                                    */
/******************************************************************************/
static psa_status_t st_hashRet;
static psa_algorithm_t st_hashAlg;
static uint8_t su8ar_hashInput[64];
static size_t st_hashInputLen;
static uint8_t su8ar_digest[CRYPTO_SHA_1_LEN];

static const uint8_t scu8ar_deviceId[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
static ssize_t st_hwinfoRet;

static psa_status_t st_derRet;
static size_t st_derLen;
static uint32_t su32_derCalls;
static const SubjectNameField_T *sstpt_derSubject;
static size_t st_derSubjectCnt;
static mbedtls_svc_key_id_t st_derKey;
static size_t st_derBufLen;

psa_status_t psa_hash_compute(psa_algorithm_t alg, const uint8_t *input, size_t input_length,
   uint8_t *hash, size_t hash_size, size_t *hash_length)
{
   st_hashAlg = alg;
   st_hashInputLen = input_length;
   if (input_length <= sizeof(su8ar_hashInput)) { memcpy(su8ar_hashInput, input, input_length); }
   if (st_hashRet != PSA_SUCCESS) { return st_hashRet; }
   TEST_ASSERT_TRUE(hash_size >= sizeof(su8ar_digest));
   memcpy(hash, su8ar_digest, sizeof(su8ar_digest));
   *hash_length = sizeof(su8ar_digest);
   return PSA_SUCCESS;
}

ssize_t hwinfo_get_device_id(uint8_t *buffer, size_t length)
{
   if (st_hwinfoRet < 0) { return st_hwinfoRet; }
   TEST_ASSERT_TRUE(length >= sizeof(scu8ar_deviceId));
   memcpy(buffer, scu8ar_deviceId, sizeof(scu8ar_deviceId));
   return (ssize_t)sizeof(scu8ar_deviceId);
}

psa_status_t gt_DER_EncodeCSR(const SubjectNameField_T *stpt_subjectName,
   size_t t_subjectNameLen, mbedtls_svc_key_id_t t_deviceKey, uint8_t *u8pt_buff,
   size_t t_buffLen, size_t *tpt_writeLen)
{
   size_t i;

   su32_derCalls++;
   sstpt_derSubject = stpt_subjectName;
   st_derSubjectCnt = t_subjectNameLen;
   st_derKey = t_deviceKey;
   st_derBufLen = t_buffLen;
   if (st_derRet != PSA_SUCCESS) { return st_derRet; }
   for (i = 0U; i < st_derLen; i++) { u8pt_buff[i] = (uint8_t)(0x30U + i); }
   *tpt_writeLen = st_derLen;
   return PSA_SUCCESS;
}

/******************************************************************************/
/*  Stubs: in-memory PSA ITS                                                  */
/******************************************************************************/
#define UID_CSR                              (0x4353520000000002ULL)   /* "CSR" | 2 */
#define ITS_MAX_ENTRY                        (sizeof(CSRData_T) + 16U)

static bool sb_itsUsed;
static psa_storage_uid_t st_itsUid;
static size_t st_itsLen;
static uint8_t su8ar_its[ITS_MAX_ENTRY];
static psa_status_t st_itsSetRet;
static psa_status_t st_itsGetRet;
static psa_status_t st_itsRemoveRet;
static size_t st_itsShort;                   /* bytes psa_its_get() leaves out */
static uint32_t su32_itsSets;
static uint32_t su32_itsRemoves;

psa_status_t psa_its_set(psa_storage_uid_t uid, size_t data_length, const void *p_data,
   psa_storage_create_flags_t create_flags)
{
   su32_itsSets++;
   TEST_ASSERT_EQUAL_UINT32(PSA_STORAGE_FLAG_NONE, create_flags);
   TEST_ASSERT_TRUE(data_length <= ITS_MAX_ENTRY);
   if (st_itsSetRet != PSA_SUCCESS) { return st_itsSetRet; }
   sb_itsUsed = true;
   st_itsUid = uid;
   st_itsLen = data_length;
   memcpy(su8ar_its, p_data, data_length);
   return PSA_SUCCESS;
}

psa_status_t psa_its_get(psa_storage_uid_t uid, size_t data_offset, size_t data_size,
   void *p_data, size_t *p_data_length)
{
   TEST_ASSERT_EQUAL_UINT32(0U, data_offset);
   if (st_itsGetRet != PSA_SUCCESS) { return st_itsGetRet; }
   if (!sb_itsUsed || (uid != st_itsUid)) { return PSA_ERROR_DOES_NOT_EXIST; }
   TEST_ASSERT_TRUE(data_size >= st_itsLen);
   memcpy(p_data, su8ar_its, st_itsLen - st_itsShort);
   *p_data_length = st_itsLen - st_itsShort;
   return PSA_SUCCESS;
}

psa_status_t psa_its_get_info(psa_storage_uid_t uid, struct psa_storage_info_t *p_info)
{
   if (!sb_itsUsed || (uid != st_itsUid)) { return PSA_ERROR_DOES_NOT_EXIST; }
   p_info->size = st_itsLen;
   p_info->flags = PSA_STORAGE_FLAG_NONE;
   return PSA_SUCCESS;
}

psa_status_t psa_its_remove(psa_storage_uid_t uid)
{
   su32_itsRemoves++;
   if (st_itsRemoveRet != PSA_SUCCESS) { return st_itsRemoveRet; }
   if (!sb_itsUsed || (uid != st_itsUid)) { return PSA_ERROR_DOES_NOT_EXIST; }
   sb_itsUsed = false;
   return PSA_SUCCESS;
}

/******************************************************************************/
/*  Helpers                                                                   */
/******************************************************************************/
#define DER_LEN                              (412U)

/** Bytes of the persisted record: header (flag, static auth, u16 len) + DER. */
static size_t st_RecordLen(size_t t_derLen)
{
   return offsetof(CSRData_T, u8ar_CSR) + t_derLen;
}

/** The device state after a first boot: key, CSR in RAM and in the ITS. */
static void sv_FirstBoot(void)
{
   gv_GenerateOrLoadCSR();
   TEST_ASSERT_EQUAL_UINT8(1U, gst_CSRData.u8_isCSRGenerated);
   TEST_ASSERT_TRUE(sb_itsUsed);
}

/** Put a record in the ITS as gv_GenerateOrLoadCSR() would have stored it. */
static void sv_StoreRecord(uint8_t u8_flag, uint16_t u16_len, size_t t_entryLen)
{
   CSRData_T st_rec;
   uint32_t i;

   memset(&st_rec, 0, sizeof(st_rec));
   st_rec.u8_isCSRGenerated = u8_flag;
   st_rec.u16_CSRLen = u16_len;
   for (i = 0U; (i < u16_len) && (i < CSR_MAX_DER_LEN); i++) { st_rec.u8ar_CSR[i] = (uint8_t)(0xA0U + i); }
   sb_itsUsed = true;
   st_itsUid = UID_CSR;
   st_itsLen = t_entryLen;
   memcpy(su8ar_its, &st_rec, MIN(t_entryLen, sizeof(st_rec)));
}

/** The CN the module must build: RFC 4122 version 5 and variant bits on the
    stub digest (version: high nibble of byte 6; variant: top bits of byte 8). */
static void sv_ExpectedCN(char *cpt_out)
{
   uint8_t u8ar_uuid[UUID_LEN];

   memcpy(u8ar_uuid, su8ar_digest, UUID_LEN);
   u8ar_uuid[6] = (uint8_t)((u8ar_uuid[6] & 0x0FU) | 0x50U);
   u8ar_uuid[8] = (uint8_t)((u8ar_uuid[8] & 0x3FU) | 0x80U);
   sv_FormatUUIDString(u8ar_uuid, cpt_out);
}

static void sv_ResetStubs(void)
{
   uint32_t i;

   sb_keyExists = false;
   st_generateRet = PSA_SUCCESS;
   st_getAttrRet = PSA_SUCCESS;
   st_destroyRet = PSA_SUCCESS;
   memset(&st_genAttr, 0, sizeof(st_genAttr));
   su32_generates = 0U;
   su32_probes = 0U;
   st_probedId = 0U;
   si_attrResets = 0;
   st_hashRet = PSA_SUCCESS;
   st_hashAlg = 0U;
   st_hashInputLen = 0U;
   for (i = 0U; i < sizeof(su8ar_digest); i++) { su8ar_digest[i] = (uint8_t)(0xF1U - (i * 13U)); }
   st_hwinfoRet = 0;
   st_derRet = PSA_SUCCESS;
   st_derLen = DER_LEN;
   su32_derCalls = 0U;
   sstpt_derSubject = NULL;
   sb_itsUsed = false;
   st_itsLen = 0U;
   st_itsSetRet = PSA_SUCCESS;
   st_itsGetRet = PSA_SUCCESS;
   st_itsRemoveRet = PSA_SUCCESS;
   st_itsShort = 0U;
   su32_itsSets = 0U;
   su32_itsRemoves = 0U;
   memset(&gst_CSRData, 0, sizeof(gst_CSRData));
   memset(sscar_commonNameUUID, 0, sizeof(sscar_commonNameUUID));
   gst_CSRConfig.stpt_subjectNameField = NULL;
   gv_SimLogClear();
}

void setUp(void)
{
   sv_ResetStubs();
}

void tearDown(void) {}

/******************************************************************************/
/*  Initialization (default run: first boot, crypto init writes the HUK)      */
/******************************************************************************/
static void test_InitRunsSettingsThenCryptoOnceAndFindsTheHuk(void)
{
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, gt_InitCryptoStorage());
   TEST_ASSERT_EQUAL_UINT32(1U, su32_settingsInits);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_cryptoInits);
   TEST_ASSERT_TRUE(sb_hukWritten);
   TEST_ASSERT_NULL(gcpt_SimLogFind("No hardware unique key"));

   // Later calls return the first result without running anything again
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, gt_InitCryptoStorage());
   gv_GenerateOrLoadCSR();
   TEST_ASSERT_EQUAL_UINT32(1U, su32_settingsInits);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_cryptoInits);
}

/******************************************************************************/
/*  First boot: new key and CSR                                               */
/******************************************************************************/
static void test_FirstBootGeneratesKeyWithTheDevicePolicy(void)
{
   gv_GenerateOrLoadCSR();

   TEST_ASSERT_EQUAL_UINT32(1U, su32_generates);
   TEST_ASSERT_EQUAL_HEX16(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), st_genAttr.type);
   TEST_ASSERT_EQUAL_UINT32(256U, st_genAttr.bits);
   TEST_ASSERT_EQUAL_HEX32(PSA_ALG_ECDSA(PSA_ALG_SHA_256), st_genAttr.alg);
   TEST_ASSERT_EQUAL_HEX32(PSA_KEY_LIFETIME_PERSISTENT, st_genAttr.lifetime);
   TEST_ASSERT_EQUAL_UINT32(CSR_DEVICE_SIGNING_KEY_ID, st_genAttr.id);
   TEST_ASSERT_EQUAL_HEX32(PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE |
      PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH, st_genAttr.usage);
   // The private key is never exportable
   TEST_ASSERT_EQUAL_HEX32(0U, st_genAttr.usage & PSA_KEY_USAGE_EXPORT);
   TEST_ASSERT_TRUE_MESSAGE(si_attrResets > 0, "key attributes are reset");
}

static void test_FirstBootBuildsAndStoresTheCsr(void)
{
   gv_GenerateOrLoadCSR();

   // DER encoder: the device key, the whole buffer
   TEST_ASSERT_EQUAL_UINT32(1U, su32_derCalls);
   TEST_ASSERT_EQUAL_UINT32(CSR_DEVICE_SIGNING_KEY_ID, st_derKey);
   TEST_ASSERT_EQUAL_UINT32(CSR_MAX_DER_LEN, st_derBufLen);

   // RAM copy
   TEST_ASSERT_EQUAL_UINT8(1U, gst_CSRData.u8_isCSRGenerated);
   TEST_ASSERT_EQUAL_UINT16(DER_LEN, gst_CSRData.u16_CSRLen);
   TEST_ASSERT_EQUAL_HEX8(0x30U, gst_CSRData.u8ar_CSR[0]);

   // ITS: UID "CSR" | 2, the record up to the DER length (packed header)
   TEST_ASSERT_TRUE(sb_itsUsed);
   TEST_ASSERT_TRUE(st_itsUid == UID_CSR);
   TEST_ASSERT_EQUAL_UINT32(st_RecordLen(DER_LEN), st_itsLen);
   TEST_ASSERT_EQUAL_UINT32(1U + CRYPTO_AUTH_256_LEN + 2U, offsetof(CSRData_T, u8ar_CSR));
   TEST_ASSERT_EQUAL_HEX8_ARRAY(&gst_CSRData, su8ar_its, st_itsLen);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("Generated CSR: "));
}

static void test_SubjectIsKconfigPlusUuidCommonName(void)
{
   static const char *const scptar_names[] = { "C", "ST", "L", "O", "OU", "CN" };
   const char *cptar_values[6] = { CONFIG_CSR_SUBJ_C, CONFIG_CSR_SUBJ_ST, CONFIG_CSR_SUBJ_L,
      CONFIG_CSR_SUBJ_O, CONFIG_CSR_SUBJ_OU, NULL };
   char car_cn[UUID_STRING_LEN + 1];
   uint32_t i;

   gv_GenerateOrLoadCSR();
   sv_ExpectedCN(car_cn);
   cptar_values[5] = car_cn;

   TEST_ASSERT_EQUAL_UINT32(6U, st_derSubjectCnt);
   TEST_ASSERT_NOT_NULL(sstpt_derSubject);
   for (i = 0U; i < 6U; i++)
   {
      TEST_ASSERT_EQUAL_STRING(scptar_names[i], sstpt_derSubject[i].cpt_name);
      TEST_ASSERT_EQUAL_UINT32(strlen(scptar_names[i]), sstpt_derSubject[i].t_nameLen);
      TEST_ASSERT_EQUAL_STRING(cptar_values[i], sstpt_derSubject[i].cpt_value);
      TEST_ASSERT_EQUAL_UINT32(strlen(cptar_values[i]), sstpt_derSubject[i].t_valueLen);
   }
}

static void test_CommonNameIsSha1OfNamespaceAndDeviceId(void)
{
   char car_cn[UUID_STRING_LEN + 1];

   gv_GenerateOrLoadCSR();

   // SHA-1 over the 16-byte namespace then the 8-byte hardware ID
   TEST_ASSERT_EQUAL_HEX32(PSA_ALG_SHA_1, st_hashAlg);
   TEST_ASSERT_EQUAL_UINT32(24U, st_hashInputLen);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(su8ar_namespace, su8ar_hashInput, 16U);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(scu8ar_deviceId, &su8ar_hashInput[16], 8U);

   // 8-4-4-4-12 lowercase hex, 36 characters
   sv_ExpectedCN(car_cn);
   TEST_ASSERT_EQUAL_STRING(car_cn, sscar_commonNameUUID);
   TEST_ASSERT_EQUAL_UINT32(UUID_STRING_LEN, strlen(sscar_commonNameUUID));
   TEST_ASSERT_EQUAL_CHAR('-', sscar_commonNameUUID[8]);
   TEST_ASSERT_EQUAL_CHAR('-', sscar_commonNameUUID[13]);
   TEST_ASSERT_EQUAL_CHAR('-', sscar_commonNameUUID[18]);
   TEST_ASSERT_EQUAL_CHAR('-', sscar_commonNameUUID[23]);
   // RFC 4122 variant: the 17th hex digit (byte 8, high bits 10) is 8..b
   TEST_ASSERT_NOT_NULL(strchr("89ab", sscar_commonNameUUID[19]));
}

static void test_CommonNameIsAnRfc4122Version5Uuid(void)
{
   gv_GenerateOrLoadCSR();

   // RFC 4122 section 4.3: the version is the high nibble of byte 6
   // (time_hi_and_version, big-endian), i.e. the first digit of the third
   // group: "xxxxxxxx-xxxx-5xxx-...". Byte 7 keeps the digest's bits.
   TEST_ASSERT_EQUAL_CHAR('5', sscar_commonNameUUID[14]);
   // The stub digest with those bits set, as Python's uuid.UUID(bytes=...)
   // prints it (version 5, RFC 4122 variant): worked out independently
   TEST_ASSERT_EQUAL_STRING("f1e4d7ca-bdb0-5396-897c-6f6255483b2e", sscar_commonNameUUID);
}

/******************************************************************************/
/*  Later boots: reuse, or repair                                             */
/******************************************************************************/
static void test_RebootReusesStoredCsrAndKey(void)
{
   sv_FirstBoot();
   su32_generates = 0U;
   su32_derCalls = 0U;
   su32_itsSets = 0U;
   memset(&gst_CSRData, 0, sizeof(gst_CSRData));

   gv_GenerateOrLoadCSR();

   TEST_ASSERT_EQUAL_UINT32(0U, su32_generates);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_derCalls);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_itsSets);
   TEST_ASSERT_EQUAL_UINT8(1U, gst_CSRData.u8_isCSRGenerated);
   TEST_ASSERT_EQUAL_UINT16(DER_LEN, gst_CSRData.u16_CSRLen);
   TEST_ASSERT_EQUAL_HEX8(0x30U, gst_CSRData.u8ar_CSR[0]);
   TEST_ASSERT_EQUAL_UINT32(CSR_DEVICE_SIGNING_KEY_ID, st_probedId);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("Reusing stored CSR across power cycle."));
}

static void test_StoredCsrWithoutKeyIsReplaced(void)
{
   sv_FirstBoot();
   sb_keyExists = false;                      // key gone, CSR still stored
   su32_generates = 0U;
   su32_derCalls = 0U;

   gv_GenerateOrLoadCSR();

   TEST_ASSERT_TRUE(su32_itsRemoves > 0U);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_generates);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_derCalls);
   TEST_ASSERT_TRUE(sb_keyExists);
   TEST_ASSERT_EQUAL_UINT8(1U, gst_CSRData.u8_isCSRGenerated);
   TEST_ASSERT_TRUE(sb_itsUsed);
}

static void test_StoredCsrWithUnreadableKeyIsNotReplaced(void)
{
   sv_FirstBoot();
   st_getAttrRet = PSA_ERROR_STORAGE_FAILURE;
   su32_derCalls = 0U;
   su32_itsRemoves = 0U;

   gv_GenerateOrLoadCSR();

   // The key exists but cannot be read: nothing is generated or deleted
   TEST_ASSERT_EQUAL_UINT32(0U, su32_derCalls);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_itsRemoves);
   TEST_ASSERT_TRUE(sb_itsUsed);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("Signing key exists but could not be opened"));
}

static void test_CorruptStoredCsrIsRemovedAndRegenerated(void)
{
   size_t t_rec = st_RecordLen(DER_LEN);

   // Flag not set; zero length; length above the buffer; length field
   // disagreeing with the entry size; entry no bigger than the header;
   // entry bigger than the record
   struct { uint8_t u8_flag; uint16_t u16_len; size_t t_entry; } star_cases[] = {
      { 0U, DER_LEN, t_rec },
      { 1U, 0U, st_RecordLen(0U) + 1U },
      { 1U, CSR_MAX_DER_LEN + 1U, sizeof(CSRData_T) },
      { 1U, DER_LEN + 1U, t_rec },
      { 1U, DER_LEN, offsetof(CSRData_T, u8ar_CSR) },
      { 1U, DER_LEN, sizeof(CSRData_T) + 1U },
   };
   uint32_t i;

   for (i = 0U; i < ARRAY_SIZE(star_cases); i++)
   {
      sv_ResetStubs();
      sb_keyExists = true;
      sv_StoreRecord(star_cases[i].u8_flag, star_cases[i].u16_len, star_cases[i].t_entry);

      gv_GenerateOrLoadCSR();

      TEST_ASSERT_TRUE_MESSAGE(su32_itsRemoves > 0U, "corrupt CSR removed");
      // The existing key is reused for the new CSR
      TEST_ASSERT_EQUAL_UINT32(1U, su32_generates);
      TEST_ASSERT_EQUAL_UINT32(1U, su32_derCalls);
      TEST_ASSERT_EQUAL_UINT16(DER_LEN, gst_CSRData.u16_CSRLen);
      TEST_ASSERT_EQUAL_UINT32(st_RecordLen(DER_LEN), st_itsLen);
      TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("Signing key already exists. Reusing key ID"));
   }
}

static void test_ShortReadOfStoredCsrIsCorrupt(void)
{
   sv_FirstBoot();
   st_itsShort = 1U;
   su32_itsRemoves = 0U;
   su32_derCalls = 0U;

   gv_GenerateOrLoadCSR();

   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("Stored CSR read length mismatch"));
   TEST_ASSERT_TRUE(su32_itsRemoves > 0U);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_derCalls);
}

static void test_StoredCsrReadErrors(void)
{
   // An authentication failure removes the entry; a plain storage error keeps it
   sv_FirstBoot();
   st_itsGetRet = PSA_ERROR_INVALID_SIGNATURE;
   su32_itsRemoves = 0U;
   gv_GenerateOrLoadCSR();
   TEST_ASSERT_TRUE(su32_itsRemoves > 0U);

   sv_ResetStubs();
   sv_FirstBoot();
   st_itsGetRet = PSA_ERROR_STORAGE_FAILURE;
   st_itsSetRet = PSA_ERROR_STORAGE_FAILURE;  // keep the entry as it was
   su32_itsRemoves = 0U;
   gv_GenerateOrLoadCSR();
   TEST_ASSERT_EQUAL_UINT32(0U, su32_itsRemoves);
   TEST_ASSERT_TRUE(sb_itsUsed);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("Stored CSR could not be reused. Generating a new CSR."));
}

/******************************************************************************/
/*  Failures while generating                                                 */
/******************************************************************************/
static void test_KeyGenerationFailureLeavesNoCsr(void)
{
   st_generateRet = PSA_ERROR_BAD_STATE;

   gv_GenerateOrLoadCSR();

   TEST_ASSERT_EQUAL_UINT8(0U, gst_CSRData.u8_isCSRGenerated);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_derCalls);
   TEST_ASSERT_FALSE(sb_itsUsed);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("Persistent key storage is not ready"));
}

static void test_ExistingKeyThatCannotBeOpenedLeavesNoCsr(void)
{
   sb_keyExists = true;
   st_getAttrRet = PSA_ERROR_STORAGE_FAILURE;

   gv_GenerateOrLoadCSR();

   TEST_ASSERT_EQUAL_UINT8(0U, gst_CSRData.u8_isCSRGenerated);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_derCalls);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("Failed to generate device signing key"));
}

static void test_HardwareIdFailureLeavesNoCsr(void)
{
   st_hwinfoRet = -EIO;

   gv_GenerateOrLoadCSR();

   TEST_ASSERT_EQUAL_UINT8(0U, gst_CSRData.u8_isCSRGenerated);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_derCalls);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("Failed to read device identifier"));
}

static void test_HashFailureLeavesNoCsr(void)
{
   st_hashRet = PSA_ERROR_HARDWARE_FAILURE;

   gv_GenerateOrLoadCSR();

   TEST_ASSERT_EQUAL_UINT8(0U, gst_CSRData.u8_isCSRGenerated);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_derCalls);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("Failed to generate UUID"));
}

static void test_EncoderFailureLeavesNoCsr(void)
{
   st_derRet = PSA_ERROR_BUFFER_TOO_SMALL;

   gv_GenerateOrLoadCSR();

   TEST_ASSERT_EQUAL_UINT8(0U, gst_CSRData.u8_isCSRGenerated);
   TEST_ASSERT_FALSE(sb_itsUsed);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("Failed to generate CSR"));
}

static void test_StoreFailureKeepsCsrInRam(void)
{
   st_itsSetRet = PSA_ERROR_INSUFFICIENT_STORAGE;

   gv_GenerateOrLoadCSR();

   // Usable this boot; a new CSR (same key) is made on the next one
   TEST_ASSERT_EQUAL_UINT8(1U, gst_CSRData.u8_isCSRGenerated);
   TEST_ASSERT_FALSE(sb_itsUsed);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("Failed to store generated CSR in trusted storage"));
}

/******************************************************************************/
/*  Public helpers                                                            */
/******************************************************************************/
static void test_ProbeDeviceKey(void)
{
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_DOES_NOT_EXIST, gt_ProbeDeviceKey());
   TEST_ASSERT_EQUAL_UINT32(CSR_DEVICE_SIGNING_KEY_ID, st_probedId);
   sb_keyExists = true;
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, gt_ProbeDeviceKey());
   st_getAttrRet = PSA_ERROR_STORAGE_FAILURE;
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_STORAGE_FAILURE, gt_ProbeDeviceKey());
}

static void test_RemoveStoredCsr(void)
{
   sv_FirstBoot();
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, gt_RemoveStoredCSR());
   TEST_ASSERT_FALSE(sb_itsUsed);
   TEST_ASSERT_EQUAL_UINT8(0U, gst_CSRData.u8_isCSRGenerated);
   TEST_ASSERT_EQUAL_UINT16(0U, gst_CSRData.u16_CSRLen);

   // Nothing stored is not an error; a storage error is returned
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, gt_RemoveStoredCSR());
   st_itsRemoveRet = PSA_ERROR_STORAGE_FAILURE;
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_STORAGE_FAILURE, gt_RemoveStoredCSR());
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(0U, gst_CSRData.u8_isCSRGenerated, "RAM is cleared anyway");
}

static void test_DestroyCredentials(void)
{
   sv_FirstBoot();
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, gt_DestroyDeviceCredentials());
   TEST_ASSERT_FALSE(sb_keyExists);
   TEST_ASSERT_FALSE(sb_itsUsed);
   TEST_ASSERT_EQUAL_UINT8(0U, gst_CSRData.u8_isCSRGenerated);

   // Nothing left (PSA reports a missing persistent key as an invalid handle)
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, gt_DestroyDeviceCredentials());
   st_destroyRet = PSA_ERROR_DOES_NOT_EXIST;
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, gt_DestroyDeviceCredentials());

   // After a wipe the next boot makes a fresh key and CSR
   st_destroyRet = PSA_SUCCESS;
   su32_generates = 0U;
   gv_GenerateOrLoadCSR();
   TEST_ASSERT_EQUAL_UINT32(1U, su32_generates);
   TEST_ASSERT_TRUE(sb_keyExists);
   TEST_ASSERT_EQUAL_UINT8(1U, gst_CSRData.u8_isCSRGenerated);
}

static void test_DestroyCredentialsErrors(void)
{
   // A key error wins, but the CSR is removed anyway
   sv_FirstBoot();
   st_destroyRet = PSA_ERROR_STORAGE_FAILURE;
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_STORAGE_FAILURE, gt_DestroyDeviceCredentials());
   TEST_ASSERT_FALSE(sb_itsUsed);

   // Key gone, CSR removal fails: that error is returned
   sv_ResetStubs();
   sv_FirstBoot();
   st_itsRemoveRet = PSA_ERROR_STORAGE_FAILURE;
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_STORAGE_FAILURE, gt_DestroyDeviceCredentials());
   TEST_ASSERT_FALSE(sb_keyExists);
}

static void test_CalculateSha1(void)
{
   static const uint8_t scu8ar_in[3] = { 'a', 'b', 'c' };
   uint8_t u8ar_out[CRYPTO_SHA_1_LEN];

   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, gt_CalculateSHA1(scu8ar_in, sizeof(scu8ar_in), u8ar_out));
   TEST_ASSERT_EQUAL_HEX32(PSA_ALG_SHA_1, st_hashAlg);
   TEST_ASSERT_EQUAL_UINT32(3U, st_hashInputLen);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(su8ar_digest, u8ar_out, CRYPTO_SHA_1_LEN);

   TEST_ASSERT_EQUAL_INT(PSA_ERROR_INVALID_ARGUMENT, gt_CalculateSHA1(NULL, 3U, u8ar_out));
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_INVALID_ARGUMENT, gt_CalculateSHA1(scu8ar_in, 0U, u8ar_out));
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_INVALID_ARGUMENT, gt_CalculateSHA1(scu8ar_in, 3U, NULL));

   st_hashRet = PSA_ERROR_NOT_SUPPORTED;
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_NOT_SUPPORTED, gt_CalculateSHA1(scu8ar_in, 3U, u8ar_out));
}

static void test_GenerateDeviceKeyRejectsNull(void)
{
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_INVALID_ARGUMENT, st_GenerateDeviceKey(NULL));
   TEST_ASSERT_EQUAL_INT(PSA_ERROR_INVALID_ARGUMENT, st_GenerateUUID(NULL));
   TEST_ASSERT_EQUAL_UINT32(0U, su32_generates);
}

/******************************************************************************/
/*  Initialization failures (one process each, see the file header)           */
/******************************************************************************/
static const char *scpt_initMode = "";

static void test_InitFailureIsKeptAndBlocksTheCsr(void)
{
   psa_status_t t_expected = PSA_ERROR_STORAGE_FAILURE;

   if (strcmp(scpt_initMode, "crypto-fail") == 0) { t_expected = PSA_ERROR_INSUFFICIENT_MEMORY; }

   TEST_ASSERT_EQUAL_INT(t_expected, gt_InitCryptoStorage());
   TEST_ASSERT_EQUAL_INT(t_expected, gt_InitCryptoStorage());
   gv_GenerateOrLoadCSR();

   // Nothing after the failing step runs, and only once
   TEST_ASSERT_EQUAL_UINT32(1U, su32_settingsInits);
   TEST_ASSERT_EQUAL_UINT32((strcmp(scpt_initMode, "settings-fail") == 0) ? 0U : 1U, su32_cryptoInits);
   if (strcmp(scpt_initMode, "huk-missing") == 0)
   {
      TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("No hardware unique key after crypto init"));
   }
   TEST_ASSERT_EQUAL_UINT32(0U, su32_generates);
   TEST_ASSERT_EQUAL_UINT8(0U, gst_CSRData.u8_isCSRGenerated);
}

/** A later boot: the HUK is there before crypto init, which need not write it. */
static void test_InitWithHukPresentSucceeds(void)
{
   TEST_ASSERT_EQUAL_INT(PSA_SUCCESS, gt_InitCryptoStorage());
   TEST_ASSERT_EQUAL_UINT32(1U, su32_settingsInits);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_cryptoInits);
}

int main(int argc, char **argv)
{
   int i;

   (void)setvbuf(stdout, NULL, _IONBF, 0);
   sb_hukWritten = false;
   sb_cryptoWritesHuk = true;
   si_settingsRet = 0;
   st_cryptoInitRet = PSA_SUCCESS;
   for (i = 1; i < argc; i++)
   {
      if (strncmp(argv[i], "--init=", 7) == 0) { scpt_initMode = &argv[i][7]; }
   }

   UNITY_BEGIN();
   if (strcmp(scpt_initMode, "huk-present") == 0)
   {
      sb_hukWritten = true;
      sb_cryptoWritesHuk = false;
      RUN_TEST(test_InitWithHukPresentSucceeds);
   }
   else if (scpt_initMode[0] != '\0')
   {
      // huk-missing: crypto init succeeds but leaves no HUK (write failed or disabled)
      sb_cryptoWritesHuk = (strcmp(scpt_initMode, "huk-missing") != 0);
      si_settingsRet = (strcmp(scpt_initMode, "settings-fail") == 0) ? -EIO : 0;
      st_cryptoInitRet = (strcmp(scpt_initMode, "crypto-fail") == 0) ?
         PSA_ERROR_INSUFFICIENT_MEMORY : PSA_SUCCESS;
      RUN_TEST(test_InitFailureIsKeptAndBlocksTheCsr);
   }
   else
   {
      RUN_TEST(test_InitRunsSettingsThenCryptoOnceAndFindsTheHuk);
      RUN_TEST(test_FirstBootGeneratesKeyWithTheDevicePolicy);
      RUN_TEST(test_FirstBootBuildsAndStoresTheCsr);
      RUN_TEST(test_SubjectIsKconfigPlusUuidCommonName);
      RUN_TEST(test_CommonNameIsSha1OfNamespaceAndDeviceId);
      RUN_TEST(test_CommonNameIsAnRfc4122Version5Uuid);
      RUN_TEST(test_RebootReusesStoredCsrAndKey);
      RUN_TEST(test_StoredCsrWithoutKeyIsReplaced);
      RUN_TEST(test_StoredCsrWithUnreadableKeyIsNotReplaced);
      RUN_TEST(test_CorruptStoredCsrIsRemovedAndRegenerated);
      RUN_TEST(test_ShortReadOfStoredCsrIsCorrupt);
      RUN_TEST(test_StoredCsrReadErrors);
      RUN_TEST(test_KeyGenerationFailureLeavesNoCsr);
      RUN_TEST(test_ExistingKeyThatCannotBeOpenedLeavesNoCsr);
      RUN_TEST(test_HardwareIdFailureLeavesNoCsr);
      RUN_TEST(test_HashFailureLeavesNoCsr);
      RUN_TEST(test_EncoderFailureLeavesNoCsr);
      RUN_TEST(test_StoreFailureKeepsCsrInRam);
      RUN_TEST(test_ProbeDeviceKey);
      RUN_TEST(test_RemoveStoredCsr);
      RUN_TEST(test_DestroyCredentials);
      RUN_TEST(test_DestroyCredentialsErrors);
      RUN_TEST(test_CalculateSha1);
      RUN_TEST(test_GenerateDeviceKeyRejectsNull);
   }
   return UNITY_END();
}
