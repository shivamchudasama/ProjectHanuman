/**
 * @file          test_prov.c
 * @brief         Host unit tests for device provisioning (_ASW/_PROV/Prov.c)
 *                against _DOC/Provisioning/PROTOCOL.md. Prov.c is included; the
 *                tests drive the router callbacks it registers, as the SETU
 *                engine would, then run the provisioning thread until its queue
 *                is empty. Everything it calls is stubbed: the key/CSR module,
 *                the certificate storage and verification (scripted results,
 *                calls recorded in order), PSA, the router, and the SETU
 *                Client and Server.
 *
 * @date          01/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#include "Prov.c"
#include "unity.h"
#include "wire_vectors.h"

/******************************************************************************/
/*  Stubs: key/CSR, certificate buffers and verification                      */
/******************************************************************************/
CSRData_T gst_CSRData;
CACertData_T gst_CACertData;
DeviceCertData_T gst_deviceCertData;

static bool sb_csrReady;
static uint16_t su16_csrLen;

/* Every storage/key call is appended here, so tests can check the order */
static char scar_calls[512];

static void sv_Call(const char *cpt_name)
{
   if (scar_calls[0] != '\0') { (void)strcat(scar_calls, ","); }
   TEST_ASSERT_TRUE(strlen(scar_calls) + strlen(cpt_name) < sizeof(scar_calls));
   (void)strcat(scar_calls, cpt_name);
}

static void sv_AssertCalls(const char *cpt_expected)
{
   TEST_ASSERT_EQUAL_STRING(cpt_expected, scar_calls);
   scar_calls[0] = '\0';
}

void gv_GenerateOrLoadCSR(void)
{
   sv_Call("gen");
   (void)memset(&gst_CSRData, 0, sizeof(gst_CSRData));
   if (sb_csrReady)
   {
      gst_CSRData.u8_isCSRGenerated = 1U;
      gst_CSRData.u16_CSRLen = su16_csrLen;
      (void)memcpy(gst_CSRData.u8ar_CSR, gu8ar_vecCsrDer, MIN(su16_csrLen, VEC_CSR_DER_LEN));
   }
}

static psa_status_t st_initRet;
static psa_status_t st_loadRet;
static psa_status_t st_probeRet;
static psa_status_t st_storeCaRet;
static psa_status_t st_storeDevRet;
static psa_status_t st_rmCertsRet;
static psa_status_t st_destroyRet;

psa_status_t gt_InitCryptoStorage(void) { sv_Call("init"); return st_initRet; }
psa_status_t gt_ProbeDeviceKey(void) { sv_Call("probe"); return st_probeRet; }

psa_status_t gt_RemoveStoredCSR(void)
{
   sv_Call("rmCSR");
   (void)memset(&gst_CSRData, 0, sizeof(gst_CSRData));
   return PSA_SUCCESS;
}

psa_status_t gt_DestroyDeviceCredentials(void)
{
   sv_Call("destroy");
   (void)memset(&gst_CSRData, 0, sizeof(gst_CSRData));
   return st_destroyRet;
}

/* A stored pair, as gt_LoadStoredCerts() would put it in RAM */
#define STORED_CA_LEN                        (300U)
#define STORED_DEV_LEN                       (400U)

psa_status_t gt_LoadStoredCerts(void)
{
   sv_Call("load");
   (void)memset(&gst_CACertData, 0, sizeof(gst_CACertData));
   (void)memset(&gst_deviceCertData, 0, sizeof(gst_deviceCertData));
   if (st_loadRet == PSA_SUCCESS)
   {
      gst_CACertData.u8_isCACertReceived = 1U;
      gst_CACertData.u16_CACertLen = STORED_CA_LEN;
      gst_deviceCertData.u8_isDeviceCertGenerated = 1U;
      gst_deviceCertData.u16_deviceCertLen = STORED_DEV_LEN;
   }
   return st_loadRet;
}

psa_status_t gt_StoreCACert(void)
{
   sv_Call("storeCA");
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(1U, gst_CACertData.u8_isCACertReceived, "CA stored unset");
   return st_storeCaRet;
}

psa_status_t gt_StoreDeviceCert(void)
{
   sv_Call("storeDev");
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(1U, gst_deviceCertData.u8_isDeviceCertGenerated,
      "device certificate stored unset");
   return st_storeDevRet;
}

psa_status_t gt_RemoveStoredCerts(void) { sv_Call("rmCerts"); return st_rmCertsRet; }

void gv_ClearCertData(void)
{
   sv_Call("clearCerts");
   (void)memset(&gst_CACertData, 0, sizeof(gst_CACertData));
   (void)memset(&gst_deviceCertData, 0, sizeof(gst_deviceCertData));
}

void gv_ClearTrustAnchor(void) { sv_Call("clearTA"); }

static DeviceCertStatus_E se_caRet;
static DeviceCertStatus_E se_devRet;
static DeviceCertStatus_E se_storedDevRet;
static uint32_t su32_caCalls;
static uint32_t su32_devCalls;
static uint32_t su32_storedDevCalls;
static uint8_t su8ar_verified[DEVICE_CERT_MAX_DER_LEN];
static size_t st_verifiedLen;

DeviceCertStatus_E ge_VerifyCACertificate(const uint8_t *u8pt_der, size_t t_len)
{
   su32_caCalls++;
   (void)memcpy(su8ar_verified, u8pt_der, t_len);
   st_verifiedLen = t_len;
   return se_caRet;
}

DeviceCertStatus_E ge_VerifyOwnDeviceCertificate(const uint8_t *u8pt_der, size_t t_len)
{
   su32_devCalls++;
   (void)memcpy(su8ar_verified, u8pt_der, t_len);
   st_verifiedLen = t_len;
   return se_devRet;
}

DeviceCertStatus_E ge_VerifyStoredDeviceCertificate(const uint8_t *u8pt_der, size_t t_len)
{
   su32_storedDevCalls++;
   TEST_ASSERT_EQUAL_PTR(gst_deviceCertData.u8ar_DeviceCert, u8pt_der);
   TEST_ASSERT_EQUAL_UINT32(STORED_DEV_LEN, t_len);
   return se_storedDevRet;
}

/******************************************************************************/
/*  Stubs: PSA (public key hash for STATUS)                                   */
/******************************************************************************/
static psa_status_t st_exportRet;

psa_status_t psa_export_public_key(psa_key_id_t key, uint8_t *data, size_t data_size,
   size_t *data_length)
{
   TEST_ASSERT_EQUAL_UINT32(CSR_DEVICE_SIGNING_KEY_ID, key);
   TEST_ASSERT_TRUE(data_size >= VEC_CSR_PUBKEY_LEN);
   (void)memcpy(data, gu8ar_vecCsrPubKey, VEC_CSR_PUBKEY_LEN);
   *data_length = VEC_CSR_PUBKEY_LEN;
   return st_exportRet;
}

/* The hash the STATUS vectors carry is SHA-256 of the vector's public key */
static const ProvShortVector_T *sstpt_Short(const char *cpt_name);

psa_status_t psa_hash_compute(psa_algorithm_t alg, const uint8_t *input, size_t input_length,
   uint8_t *hash, size_t hash_size, size_t *hash_length)
{
   TEST_ASSERT_EQUAL_HEX32(PSA_ALG_SHA_256, alg);
   TEST_ASSERT_EQUAL_UINT32(VEC_CSR_PUBKEY_LEN, input_length);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(gu8ar_vecCsrPubKey, input, VEC_CSR_PUBKEY_LEN);
   TEST_ASSERT_EQUAL_UINT32(32U, hash_size);
   (void)memcpy(hash, &sstpt_Short("status_key_ready")->u8ar_wire[6], 32U);
   *hash_length = 32U;
   return PSA_SUCCESS;
}

/******************************************************************************/
/*  Stubs: router (with its shared Client), SETU, host link, pairing      */
/******************************************************************************/
static struct bt_conn sst_conn;
static bool sb_hostUp;
static uint32_t su32_refreshCalls;
static bool sb_pairRunning;
static uint32_t su32_forgetCalls;

/* The host link; the shim's bt_conn_ref/unref are no-ops */
struct bt_conn *gstpt_BLE_GetHostConn(void) { return sb_hostUp ? &sst_conn : NULL; }
void gv_BLE_RefreshAdv(void) { su32_refreshCalls++; }
bool gb_Pair_IsRunning(void) { return sb_pairRunning; }
void gv_Pair_ForgetBonds(void) { su32_forgetCalls++; }
static uint32_t su32_hostForgetCalls;
void gv_HostAuth_Forget(void) { su32_hostForgetCalls++; }

static SETURoute_T sst_route;
static int si_registerRet;

int gi_SETURouter_Register(const SETURoute_T *stpt_route)
{
   sst_route = *stpt_route;
   return si_registerRet;
}

static bool sb_cliReady;
static int si_attachRet;
static uint32_t su32_attachCalls;
static struct bt_conn *sstpt_attachConn;
static uint8_t su8_attachOwner;
static int si_sendRet;
static uint32_t su32_sendCalls;
static uint8_t su8_sendType;
static const void *svpt_sendData;
static uint32_t su32_sendLen;

/* As the router: -EALREADY when the Client is ready on that link already */
int gi_SETURouter_ClientAttach(struct bt_conn *stpt_conn, uint8_t u8_ownerAppType)
{
   su32_attachCalls++;
   sstpt_attachConn = stpt_conn;
   su8_attachOwner = u8_ownerAppType;
   if (stpt_conn == NULL) { return -EINVAL; }
   if (sb_cliReady) { return -EALREADY; }
   return si_attachRet;
}

int gi_SETUC_SendBuffer(uint8_t u8_appType, const void *vpt_data, uint32_t u32_len)
{
   su32_sendCalls++;
   su8_sendType = u8_appType;
   svpt_sendData = vpt_data;
   su32_sendLen = u32_len;
   return si_sendRet;
}

typedef struct
{
   uint8_t u8_type;
   uint8_t u8_len;
   uint8_t u8ar_payload[SETU_MAX_SHORT_PAYLOAD];
} SentShort_T;

static SentShort_T sstar_sent[16];
static uint32_t su32_sentCount;

int gi_SETUS_SendShort(uint8_t u8_appType, const void *vpt_data, uint8_t u8_len,
   k_timeout_t t_timeout)
{
   SentShort_T *stpt_s = &sstar_sent[su32_sentCount % ARRAY_SIZE(sstar_sent)];

   TEST_ASSERT_TRUE_MESSAGE(t_timeout.ms >= 0, "a reply must not wait for ever");
   stpt_s->u8_type = u8_appType;
   stpt_s->u8_len = u8_len;
   (void)memcpy(stpt_s->u8ar_payload, vpt_data, u8_len);
   su32_sentCount++;
   return 0;
}

/******************************************************************************/
/*  Helpers                                                                   */
/******************************************************************************/
static const ProvShortVector_T *sstpt_Short(const char *cpt_name)
{
   uint32_t i;

   for (i = 0U; i < ARRAY_SIZE(gstar_vecProvShorts); i++)
   {
      if (strcmp(gstar_vecProvShorts[i].cpt_name, cpt_name) == 0) { return &gstar_vecProvShorts[i]; }
   }
   TEST_FAIL_MESSAGE(cpt_name);
   return NULL;
}

/** Run the provisioning thread until its queue is empty. */
static void sv_RunProv(void)
{
   gv_SimRunThread(sv_ProvThread);
}

static const SentShort_T *sstpt_Last(void)
{
   TEST_ASSERT_TRUE_MESSAGE(su32_sentCount > 0U, "nothing sent");
   return &sstar_sent[(su32_sentCount - 1U) % ARRAY_SIZE(sstar_sent)];
}

/** The last short message must be RESULT [ref][status]. */
static void sv_AssertLastResult(uint8_t u8_ref, uint8_t u8_status)
{
   const SentShort_T *s = sstpt_Last();

   TEST_ASSERT_EQUAL_HEX8(VEC_PROV_APP_RESULT, s->u8_type);
   TEST_ASSERT_EQUAL_UINT8(2U, s->u8_len);
   TEST_ASSERT_EQUAL_HEX8_MESSAGE(u8_ref, s->u8ar_payload[0], "RESULT refAppType");
   TEST_ASSERT_EQUAL_HEX8_MESSAGE(u8_status, s->u8ar_payload[1], "RESULT status");
}

/** The last short message must be the golden vector (wire = [len][type][payload]). */
static void sv_AssertLastIs(const char *cpt_name)
{
   const ProvShortVector_T *v = sstpt_Short(cpt_name);
   const SentShort_T *s = sstpt_Last();

   TEST_ASSERT_EQUAL_HEX8_MESSAGE(v->u8ar_wire[1], s->u8_type, cpt_name);
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->u8ar_wire[0], s->u8_len, cpt_name);
   TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(&v->u8ar_wire[2], s->u8ar_payload, v->u8ar_wire[0], cpt_name);
}

/** Send a certificate through the router callbacks in 240-byte chunks. */
static uint8_t su8ar_cert[DEVICE_CERT_MAX_DER_LEN + 1U];

static int si_Receive(uint8_t u8_type, uint32_t u32_len, SETUStatus_E e_status)
{
   uint32_t u32_off;
   int i_ret;

   i_ret = sst_route.fpt_onRxStart(u8_type, u32_len);
   if (i_ret != 0) { return i_ret; }
   for (u32_off = 0U; u32_off < u32_len; u32_off += 240U)
   {
      TEST_ASSERT_EQUAL_INT(0, sst_route.fpt_onRxData(u8_type, u32_off, &su8ar_cert[u32_off],
         (uint16_t)MIN(240U, u32_len - u32_off)));
   }
   sst_route.fpt_onRxDone(u8_type, e_status, u32_len);
   return 0;
}

/** A boot: RAM starts empty, then gi_Prov_Init(). */
static void sv_Init(bool b_csrReady)
{
   sb_csrReady = b_csrReady;
   (void)memset(&gst_CSRData, 0, sizeof(gst_CSRData));
   (void)memset(&gst_CACertData, 0, sizeof(gst_CACertData));
   (void)memset(&gst_deviceCertData, 0, sizeof(gst_deviceCertData));
   TEST_ASSERT_EQUAL_INT(0, gi_Prov_Init());
   sv_RunProv();
}

/** The full wipe: trust anchor, certificates, key and CSR, then a new key/CSR. */
#define WIPE_CALLS                           "clearTA,clearCerts,rmCerts,destroy,gen"

/** Accept a CA (verification scripted OK): state CA_OK. */
static void sv_ToCaOk(void)
{
   se_caRet = eDCS_OK;
   TEST_ASSERT_EQUAL_INT(0, si_Receive(VEC_PROV_APP_CA_CERT, 300U, eBS_OK));
   sv_RunProv();
   TEST_ASSERT_EQUAL_INT(ePS_CA_OK, ge_Prov_GetState());
}

/** CA then device certificate, both verified (scripted OK): PROVISIONED. */
static void sv_ToProvisioned(void)
{
   sv_ToCaOk();
   TEST_ASSERT_EQUAL_INT(0, si_Receive(VEC_PROV_APP_DEV_CERT, 400U, eBS_OK));
   sv_RunProv();
   TEST_ASSERT_EQUAL_INT(ePS_PROVISIONED, ge_Prov_GetState());
   su32_sentCount = 0U;
   scar_calls[0] = '\0';
}

void setUp(void)
{
   uint32_t i;

   // Fresh module state (no reset API)
   atomic_set(&st_state, ePS_NO_KEY);
   atomic_set(&st_certBusy, 0);
   sb_csrTxPending = false;
   k_msgq_purge(&sst_provMsgq);

   (void)memset(&gst_CACertData, 0, sizeof(gst_CACertData));
   (void)memset(&gst_deviceCertData, 0, sizeof(gst_deviceCertData));
   su16_csrLen = 0x01A4U;
   se_caRet = eDCS_OK;
   se_devRet = eDCS_OK;
   se_storedDevRet = eDCS_OK;
   su32_caCalls = 0U;
   su32_devCalls = 0U;
   su32_storedDevCalls = 0U;
   st_initRet = PSA_SUCCESS;
   st_loadRet = PSA_ERROR_DOES_NOT_EXIST;
   st_probeRet = PSA_SUCCESS;
   st_storeCaRet = PSA_SUCCESS;
   st_storeDevRet = PSA_SUCCESS;
   st_rmCertsRet = PSA_SUCCESS;
   st_destroyRet = PSA_SUCCESS;
   scar_calls[0] = '\0';
   st_exportRet = PSA_SUCCESS;
   si_registerRet = 0;
   sb_hostUp = true;
   sb_pairRunning = false;
   su32_forgetCalls = 0U;
   su32_hostForgetCalls = 0U;
   sb_cliReady = false;
   si_attachRet = 0;
   su32_attachCalls = 0U;
   sstpt_attachConn = NULL;
   su8_attachOwner = 0U;
   si_sendRet = 0;
   su32_sendCalls = 0U;
   su32_sentCount = 0U;
   gu32_simLogBuffered = 0U;
   for (i = 0U; i < sizeof(su8ar_cert); i++) { su8ar_cert[i] = (uint8_t)(i * 7U + 3U); }
   gv_SimLogClear();
   sv_Init(true);
   su32_sentCount = 0U;
   su32_caCalls = 0U;
   su32_refreshCalls = 0U;
   scar_calls[0] = '\0';
}

void tearDown(void) {}

/******************************************************************************/
/*  Initialisation                                                            */
/******************************************************************************/
static void test_InitRegistersTheProvisioningRange(void)
{
   TEST_ASSERT_EQUAL_HEX8(VEC_PROV_APP_GET_STATUS, sst_route.u8_firstAppType);
   TEST_ASSERT_EQUAL_HEX8(0x2FU, sst_route.u8_lastAppType);
   TEST_ASSERT_NOT_NULL(sst_route.fpt_onRxStart);
   TEST_ASSERT_NOT_NULL(sst_route.fpt_onRxData);
   TEST_ASSERT_NOT_NULL(sst_route.fpt_onRxDone);
   TEST_ASSERT_NOT_NULL(sst_route.fpt_onRxShort);
   // The router shares the SETU Client: its results come back by range
   TEST_ASSERT_NOT_NULL(sst_route.fpt_onCliReady);
   TEST_ASSERT_NOT_NULL(sst_route.fpt_onTxDone);
   TEST_ASSERT_EQUAL_INT(ePS_KEY_READY, ge_Prov_GetState());
}

static void test_InitWithoutCsrStaysNoKey(void)
{
   sv_Init(false);
   TEST_ASSERT_EQUAL_INT(ePS_NO_KEY, ge_Prov_GetState());
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("provisioning is not possible"));
   // Still registered, so the provisioner gets answers
   TEST_ASSERT_NOT_NULL(sst_route.fpt_onRxShort);
}

static void test_InitFirstBootGeneratesKeyAndCsr(void)
{
   sv_Init(true);
   sv_AssertCalls("init,load,gen");
   TEST_ASSERT_EQUAL_INT(ePS_KEY_READY, ge_Prov_GetState());
}

static void test_InitRestoresStoredProvisioning(void)
{
   st_loadRet = PSA_SUCCESS;
   sv_Init(true);
   // No new key or CSR; a CSR left behind by a reset is removed
   sv_AssertCalls("init,load,probe,rmCSR");
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(1U, su32_caCalls, "the trust anchor is restored");
   TEST_ASSERT_EQUAL_UINT32(STORED_CA_LEN, st_verifiedLen);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_storedDevCalls);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, su32_devCalls, "no CSR subject check at boot");
   TEST_ASSERT_EQUAL_INT(ePS_PROVISIONED, ge_Prov_GetState());

   sst_route.fpt_onRxShort(VEC_PROV_APP_GET_STATUS, NULL, 0U);
   sv_RunProv();
   sv_AssertLastIs("status_provisioned");
}

static void test_InitWipesInvalidStoredProvisioning(void)
{
   static const struct
   {
      psa_status_t t_load;
      psa_status_t t_probe;
      DeviceCertStatus_E e_ca;
      DeviceCertStatus_E e_dev;
      const char *cpt_calls;
   } scstar_cases[] =
   {
      // Corrupt or incomplete pair (also an AEAD tag failure)
      { PSA_ERROR_DATA_CORRUPT, PSA_SUCCESS, eDCS_OK, eDCS_OK, "init,load," WIPE_CALLS },
      { PSA_ERROR_INVALID_SIGNATURE, PSA_SUCCESS, eDCS_OK, eDCS_OK, "init,load," WIPE_CALLS },
      // Key gone
      { PSA_SUCCESS, PSA_ERROR_DOES_NOT_EXIST, eDCS_OK, eDCS_OK, "init,load,probe," WIPE_CALLS },
      // CA or device certificate no longer verifies
      { PSA_SUCCESS, PSA_SUCCESS, eDCS_BAD_SIG, eDCS_OK, "init,load,probe," WIPE_CALLS },
      { PSA_SUCCESS, PSA_SUCCESS, eDCS_OK, eDCS_KEY_MISMATCH, "init,load,probe," WIPE_CALLS },
   };
   uint32_t i;

   for (i = 0U; i < ARRAY_SIZE(scstar_cases); i++)
   {
      st_loadRet = scstar_cases[i].t_load;
      st_probeRet = scstar_cases[i].t_probe;
      se_caRet = scstar_cases[i].e_ca;
      se_storedDevRet = scstar_cases[i].e_dev;
      gv_SimLogClear();
      sv_Init(true);
      sv_AssertCalls(scstar_cases[i].cpt_calls);
      TEST_ASSERT_EQUAL_INT_MESSAGE(ePS_KEY_READY, ge_Prov_GetState(), "a fresh key and CSR");
      TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("stored provisioning is invalid"));
   }
}

static void test_InitKeepsUnreadableStorage(void)
{
   // A storage error that says nothing about the data: nothing is erased
   st_loadRet = PSA_ERROR_STORAGE_FAILURE;
   sv_Init(true);
   sv_AssertCalls("init,load");
   TEST_ASSERT_EQUAL_INT(ePS_NO_KEY, ge_Prov_GetState());

   // Storage or crypto unavailable: nothing is loaded or made
   st_initRet = PSA_ERROR_STORAGE_FAILURE;
   sv_Init(true);
   sv_AssertCalls("init");
   TEST_ASSERT_EQUAL_INT(ePS_NO_KEY, ge_Prov_GetState());
}

static void test_InitErrorsAreReturned(void)
{
   si_registerRet = -EEXIST;
   TEST_ASSERT_EQUAL_INT(-EEXIST, gi_Prov_Init());
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("gi_SETURouter_Register failed"));
}

/******************************************************************************/
/*  STATUS                                                                    */
/******************************************************************************/
static void test_StatusMatchesVector(void)
{
   sst_route.fpt_onRxShort(VEC_PROV_APP_GET_STATUS, NULL, 0U);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, su32_sentCount, "replies come from the thread");
   sv_RunProv();
   sv_AssertLastIs("status_key_ready");
}

static void test_StatusShowsCsrBusyAndState(void)
{
   sv_ToCaOk();
   sb_cliReady = true;
   sst_route.fpt_onRxShort(VEC_PROV_APP_CSR_REQ, NULL, 0U);
   sst_route.fpt_onRxShort(VEC_PROV_APP_GET_STATUS, NULL, 0U);
   sv_RunProv();
   sv_AssertLastIs("status_csr_busy");
}

static void test_StatusWithoutKeyIsZero(void)
{
   uint8_t u8ar_zero[32] = { 0 };

   st_exportRet = PSA_ERROR_DOES_NOT_EXIST;
   sv_Init(true);
   sst_route.fpt_onRxShort(VEC_PROV_APP_GET_STATUS, NULL, 0U);
   sv_RunProv();
   // Hash unavailable: all zero
   TEST_ASSERT_EQUAL_HEX8_ARRAY(u8ar_zero, &sstpt_Last()->u8ar_payload[4], 32U);

   sv_Init(false);
   su32_sentCount = 0U;
   sst_route.fpt_onRxShort(VEC_PROV_APP_GET_STATUS, NULL, 0U);
   sv_RunProv();
   TEST_ASSERT_EQUAL_UINT8(PROV_STATUS_LEN, sstpt_Last()->u8_len);
   TEST_ASSERT_EQUAL_HEX8(ePS_NO_KEY, sstpt_Last()->u8ar_payload[0]);
   TEST_ASSERT_EQUAL_HEX8(0U, sstpt_Last()->u8ar_payload[2]);
   TEST_ASSERT_EQUAL_HEX8(0U, sstpt_Last()->u8ar_payload[3]);
}

static void test_UnknownShortIgnored(void)
{
   uint8_t u8_p = 1U;

   sst_route.fpt_onRxShort(0x2AU, &u8_p, 1U);
   sv_RunProv();
   TEST_ASSERT_EQUAL_UINT32(0U, su32_sentCount);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("short message type 0x2a, 1 bytes ignored"));
}

/******************************************************************************/
/*  CSR                                                                       */
/******************************************************************************/
static void test_CsrSentAtOnceWhenClientAttached(void)
{
   sb_cliReady = true;
   sst_route.fpt_onRxShort(VEC_PROV_APP_CSR_REQ, NULL, 0U);
   sv_RunProv();
   // Asked for the host link, as provisioning; ready there already
   TEST_ASSERT_EQUAL_UINT32(1U, su32_attachCalls);
   TEST_ASSERT_EQUAL_PTR(&sst_conn, sstpt_attachConn);
   TEST_ASSERT_TRUE(su8_attachOwner >= VEC_PROV_APP_GET_STATUS);
   TEST_ASSERT_TRUE(su8_attachOwner <= 0x2FU);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_sendCalls);
   TEST_ASSERT_EQUAL_HEX8(VEC_PROV_APP_CSR, su8_sendType);
   TEST_ASSERT_EQUAL_PTR_MESSAGE(gst_CSRData.u8ar_CSR, svpt_sendData, "sent from the persistent CSR");
   TEST_ASSERT_EQUAL_UINT32(0x01A4U, su32_sendLen);

   sst_route.fpt_onTxDone(VEC_PROV_APP_CSR, eBS_OK);
   sv_RunProv();
   sv_AssertLastIs("result_csr_delivered");
}

static void test_CsrAttachesThenSends(void)
{
   sst_route.fpt_onRxShort(VEC_PROV_APP_CSR_REQ, NULL, 0U);
   sv_RunProv();
   TEST_ASSERT_EQUAL_UINT32(1U, su32_attachCalls);
   TEST_ASSERT_EQUAL_PTR(&sst_conn, sstpt_attachConn);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_sendCalls);

   sst_route.fpt_onCliReady(&sst_conn, 0);
   sv_RunProv();
   TEST_ASSERT_EQUAL_UINT32(1U, su32_sendCalls);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_sentCount);
}

static void test_CsrWithoutHostLink(void)
{
   // No host link to attach to: as if the provisioner had no service
   sb_hostUp = false;
   sst_route.fpt_onRxShort(VEC_PROV_APP_CSR_REQ, NULL, 0U);
   sv_RunProv();
   TEST_ASSERT_NULL(sstpt_attachConn);
   sv_AssertLastIs("result_csr_no_peer");
   TEST_ASSERT_EQUAL_UINT32(0U, su32_sendCalls);
   TEST_ASSERT_FALSE(sb_csrTxPending);
}

static void test_CsrNoPeerService(void)
{
   // Discovery found no SETU service on the provisioner
   sst_route.fpt_onRxShort(VEC_PROV_APP_CSR_REQ, NULL, 0U);
   sv_RunProv();
   sst_route.fpt_onCliReady(&sst_conn, -ENOENT);
   sv_RunProv();
   sv_AssertLastIs("result_csr_no_peer");
   TEST_ASSERT_EQUAL_UINT32(0U, su32_sendCalls);

   // Attach refused outright (e.g. no connection)
   si_attachRet = -EINVAL;
   sst_route.fpt_onRxShort(VEC_PROV_APP_CSR_REQ, NULL, 0U);
   sv_RunProv();
   sv_AssertLastIs("result_csr_no_peer");
}

static void test_CsrSendFailures(void)
{
   sb_cliReady = true;
   si_sendRet = -EBUSY;
   sst_route.fpt_onRxShort(VEC_PROV_APP_CSR_REQ, NULL, 0U);
   sv_RunProv();
   sv_AssertLastResult(VEC_PROV_APP_CSR_REQ, VEC_PROV_ST_INTERNAL);

   si_sendRet = 0;
   sst_route.fpt_onRxShort(VEC_PROV_APP_CSR_REQ, NULL, 0U);
   sv_RunProv();
   sst_route.fpt_onTxDone(VEC_PROV_APP_CSR, eBS_DISCONNECTED);
   sv_RunProv();
   sv_AssertLastResult(VEC_PROV_APP_CSR, VEC_PROV_ST_TRANSFER);
   TEST_ASSERT_FALSE(sb_csrTxPending);
}

static void test_CsrRequestWhileBusyOrWithoutKey(void)
{
   sb_cliReady = true;
   sst_route.fpt_onRxShort(VEC_PROV_APP_CSR_REQ, NULL, 0U);
   sst_route.fpt_onRxShort(VEC_PROV_APP_CSR_REQ, NULL, 0U);
   sv_RunProv();
   TEST_ASSERT_EQUAL_UINT32(1U, su32_sendCalls);
   sv_AssertLastResult(VEC_PROV_APP_CSR_REQ, VEC_PROV_ST_BAD_STATE);

   sv_Init(false);
   sst_route.fpt_onRxShort(VEC_PROV_APP_CSR_REQ, NULL, 0U);
   sv_RunProv();
   sv_AssertLastResult(VEC_PROV_APP_CSR_REQ, VEC_PROV_ST_BAD_STATE);
}

static void test_LateReadyIgnored(void)
{
   // An attach result nobody waits for (e.g. after a failed request)
   sst_route.fpt_onCliReady(&sst_conn, 0);
   sv_RunProv();
   TEST_ASSERT_EQUAL_UINT32(0U, su32_sendCalls);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_sentCount);
}

/******************************************************************************/
/*  CA certificate                                                            */
/******************************************************************************/
static void test_CaVerifiedAndKept(void)
{
   TEST_ASSERT_EQUAL_INT(0, si_Receive(VEC_PROV_APP_CA_CERT, 500U, eBS_OK));
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, su32_caCalls, "verification runs on the thread");
   sv_RunProv();
   TEST_ASSERT_EQUAL_UINT32(1U, su32_caCalls);
   TEST_ASSERT_EQUAL_UINT32(500U, st_verifiedLen);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(su8ar_cert, su8ar_verified, 500U);
   TEST_ASSERT_EQUAL_INT(ePS_CA_OK, ge_Prov_GetState());
   TEST_ASSERT_EQUAL_UINT8(1U, gst_CACertData.u8_isCACertReceived);
   TEST_ASSERT_EQUAL_UINT16(500U, gst_CACertData.u16_CACertLen);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(su8ar_cert, gst_CACertData.u8ar_CACert, 500U);
   sv_AssertLastIs("result_ca_ok");
   sv_AssertCalls("");  // held in RAM only, until the device certificate verifies
}

static void test_CaRejectedKeepsPrevious(void)
{
   sv_ToCaOk();
   su8ar_cert[0] ^= 0xFFU;
   se_caRet = eDCS_NOT_CA;
   TEST_ASSERT_EQUAL_INT(0, si_Receive(VEC_PROV_APP_CA_CERT, 200U, eBS_OK));
   sv_RunProv();
   sv_AssertLastResult(VEC_PROV_APP_CA_CERT, VEC_PROV_ST_NOT_CA);
   TEST_ASSERT_EQUAL_INT(ePS_CA_OK, ge_Prov_GetState());
   // The kept CA is still the first one
   TEST_ASSERT_EQUAL_UINT16(300U, gst_CACertData.u16_CACertLen);
   TEST_ASSERT_EQUAL_HEX8((uint8_t)(su8ar_cert[0] ^ 0xFFU), gst_CACertData.u8ar_CACert[0]);
}

static void test_CaLoggedAsPem(void)
{
   char car_line[80];
   size_t t_len = 0U;

   TEST_ASSERT_EQUAL_INT(0, si_Receive(VEC_PROV_APP_CA_CERT, 49U, eBS_OK));
   gv_SimLogClear();
   sv_RunProv();
   // A title, then a standard PEM block that can be pasted into a .pem file
   TEST_ASSERT_EQUAL_STRING("CA certificate (49 bytes):", gcpt_SimLogLine(0U));
   TEST_ASSERT_EQUAL_STRING("-----BEGIN CERTIFICATE-----", gcpt_SimLogLine(1U));
   TEST_ASSERT_EQUAL_STRING("-----END CERTIFICATE-----", gcpt_SimLogLine(4U));
   // 49 bytes: one 64-character line, then one 4-character line ("xx==")
   (void)base64_encode((uint8_t *)car_line, sizeof(car_line), &t_len, su8ar_cert, 48U);
   TEST_ASSERT_EQUAL_UINT32(64U, t_len);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind(car_line));
   (void)base64_encode((uint8_t *)car_line, sizeof(car_line), &t_len, &su8ar_cert[48], 1U);
   TEST_ASSERT_EQUAL_STRING_LEN("==", &car_line[2], 2U);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind(car_line));
}

static void test_PemWaitsForLogBacklog(void)
{
   int64_t i64_start;

   TEST_ASSERT_EQUAL_INT(0, si_Receive(VEC_PROV_APP_CA_CERT, 10U, eBS_OK));
   gu32_simLogBuffered = 20U;
   i64_start = gi64_simNowMs;
   sv_RunProv();
   TEST_ASSERT_EQUAL_INT(20 - PROV_LOG_BACKLOG_MAX, (int)(gi64_simNowMs - i64_start));
}

/******************************************************************************/
/*  Device certificate                                                        */
/******************************************************************************/
static void test_DeviceCertNeedsCaFirst(void)
{
   TEST_ASSERT_NOT_EQUAL_INT(0, si_Receive(VEC_PROV_APP_DEV_CERT, 300U, eBS_OK));
   sv_RunProv();
   sv_AssertLastResult(VEC_PROV_APP_DEV_CERT, VEC_PROV_ST_BAD_STATE);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_devCalls);
}

static void test_DeviceCertProvisions(void)
{
   sv_ToCaOk();
   TEST_ASSERT_EQUAL_INT(0, si_Receive(VEC_PROV_APP_DEV_CERT, 400U, eBS_OK));
   gv_SimLogClear();
   sv_RunProv();
   TEST_ASSERT_EQUAL_UINT32(1U, su32_devCalls);
   TEST_ASSERT_EQUAL_INT(ePS_PROVISIONED, ge_Prov_GetState());
   TEST_ASSERT_EQUAL_UINT8(1U, gst_deviceCertData.u8_isDeviceCertGenerated);
   TEST_ASSERT_EQUAL_UINT16(400U, gst_deviceCertData.u16_deviceCertLen);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(su8ar_cert, gst_deviceCertData.u8ar_DeviceCert, 400U);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("Device certificate (400 bytes):"));
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("-----BEGIN CERTIFICATE-----"));
   sv_AssertLastResult(VEC_PROV_APP_DEV_CERT, VEC_PROV_ST_OK);
   // Both stored, CA first, then the CSR is deleted
   sv_AssertCalls("storeCA,storeDev,rmCSR");
   TEST_ASSERT_EQUAL_UINT8(0U, gst_CSRData.u8_isCSRGenerated);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(1U, su32_refreshCalls, "advertise for pairing from now on");

   // STATUS: PROVISIONED, no CSR any more
   sst_route.fpt_onRxShort(VEC_PROV_APP_GET_STATUS, NULL, 0U);
   sv_RunProv();
   sv_AssertLastIs("status_provisioned");
}

static void test_StoreFailureKeepsCaOk(void)
{
   sv_ToCaOk();

   // The CA cannot be stored
   st_storeCaRet = PSA_ERROR_INSUFFICIENT_STORAGE;
   TEST_ASSERT_EQUAL_INT(0, si_Receive(VEC_PROV_APP_DEV_CERT, 400U, eBS_OK));
   sv_RunProv();
   sv_AssertLastResult(VEC_PROV_APP_DEV_CERT, VEC_PROV_ST_INTERNAL);
   sv_AssertCalls("storeCA,rmCerts");

   // The device certificate cannot be stored: the CA stored before it goes too
   st_storeCaRet = PSA_SUCCESS;
   st_storeDevRet = PSA_ERROR_STORAGE_FAILURE;
   TEST_ASSERT_EQUAL_INT(0, si_Receive(VEC_PROV_APP_DEV_CERT, 400U, eBS_OK));
   sv_RunProv();
   sv_AssertLastResult(VEC_PROV_APP_DEV_CERT, VEC_PROV_ST_INTERNAL);
   sv_AssertCalls("storeCA,storeDev,rmCerts");

   // Still CA_OK with the CA in RAM and the CSR kept, so a retry can succeed
   TEST_ASSERT_EQUAL_INT(ePS_CA_OK, ge_Prov_GetState());
   TEST_ASSERT_EQUAL_UINT8(1U, gst_CACertData.u8_isCACertReceived);
   TEST_ASSERT_EQUAL_UINT8(0U, gst_deviceCertData.u8_isDeviceCertGenerated);
   TEST_ASSERT_EQUAL_UINT8(1U, gst_CSRData.u8_isCSRGenerated);
   st_storeDevRet = PSA_SUCCESS;
   TEST_ASSERT_EQUAL_INT(0, si_Receive(VEC_PROV_APP_DEV_CERT, 400U, eBS_OK));
   sv_RunProv();
   sv_AssertLastResult(VEC_PROV_APP_DEV_CERT, VEC_PROV_ST_OK);
   TEST_ASSERT_EQUAL_INT(ePS_PROVISIONED, ge_Prov_GetState());
}

static void test_DeviceCertRejected(void)
{
   sv_ToCaOk();
   se_devRet = eDCS_BAD_SIG;
   TEST_ASSERT_EQUAL_INT(0, si_Receive(VEC_PROV_APP_DEV_CERT, 400U, eBS_OK));
   sv_RunProv();
   sv_AssertLastIs("result_dev_bad_sig");
   TEST_ASSERT_EQUAL_INT(ePS_CA_OK, ge_Prov_GetState());
   TEST_ASSERT_EQUAL_UINT8(0U, gst_deviceCertData.u8_isDeviceCertGenerated);

   // Every verification status reaches the provisioner unchanged
   se_devRet = eDCS_KEY_MISMATCH;
   TEST_ASSERT_EQUAL_INT(0, si_Receive(VEC_PROV_APP_DEV_CERT, 400U, eBS_OK));
   sv_RunProv();
   sv_AssertLastResult(VEC_PROV_APP_DEV_CERT, VEC_PROV_ST_KEY_MISMATCH);
   se_devRet = eDCS_SUBJECT_MISMATCH;
   TEST_ASSERT_EQUAL_INT(0, si_Receive(VEC_PROV_APP_DEV_CERT, 400U, eBS_OK));
   sv_RunProv();
   sv_AssertLastResult(VEC_PROV_APP_DEV_CERT, VEC_PROV_ST_SUBJECT_MISMATCH);
   sv_AssertCalls("");  // a rejected certificate stores nothing
}

static void test_NewCaReplacesTheCaBeforeDeviceCert(void)
{
   sv_ToCaOk();
   TEST_ASSERT_EQUAL_INT(0, si_Receive(VEC_PROV_APP_CA_CERT, 200U, eBS_OK));
   sv_RunProv();
   sv_AssertLastIs("result_ca_ok");
   TEST_ASSERT_EQUAL_INT(ePS_CA_OK, ge_Prov_GetState());
   TEST_ASSERT_EQUAL_UINT16(200U, gst_CACertData.u16_CACertLen);
}

/******************************************************************************/
/*  One-time provisioning and the wipe                                        */
/******************************************************************************/
static void test_ProvisionedRefusesEverything(void)
{
   sv_ToProvisioned();

   sb_cliReady = true;
   sst_route.fpt_onRxShort(VEC_PROV_APP_CSR_REQ, NULL, 0U);
   sv_RunProv();
   sv_AssertLastIs("result_csr_req_bad_state");
   TEST_ASSERT_EQUAL_UINT32(0U, su32_sendCalls);

   TEST_ASSERT_NOT_EQUAL_INT(0, si_Receive(VEC_PROV_APP_CA_CERT, 300U, eBS_OK));
   sv_RunProv();
   sv_AssertLastResult(VEC_PROV_APP_CA_CERT, VEC_PROV_ST_BAD_STATE);
   TEST_ASSERT_NOT_EQUAL_INT(0, si_Receive(VEC_PROV_APP_DEV_CERT, 300U, eBS_OK));
   sv_RunProv();
   sv_AssertLastResult(VEC_PROV_APP_DEV_CERT, VEC_PROV_ST_BAD_STATE);

   TEST_ASSERT_EQUAL_UINT32_MESSAGE(1U, su32_caCalls, "refused certificates are not verified");
   TEST_ASSERT_EQUAL_INT(ePS_PROVISIONED, ge_Prov_GetState());
   sv_AssertCalls("");
}

static void test_DeprovisionWipesAndRegenerates(void)
{
   sv_ToProvisioned();

   sst_route.fpt_onRxShort(VEC_PROV_APP_DEPROVISION, NULL, 0U);
   TEST_ASSERT_EQUAL_STRING_MESSAGE("", scar_calls, "the wipe runs on the thread");
   sv_RunProv();
   sv_AssertCalls(WIPE_CALLS);
   sv_AssertLastIs("result_deprovision_ok");
   TEST_ASSERT_EQUAL_INT(ePS_KEY_READY, ge_Prov_GetState());
   TEST_ASSERT_EQUAL_UINT8(0U, gst_CACertData.u8_isCACertReceived);
   TEST_ASSERT_EQUAL_UINT8(0U, gst_deviceCertData.u8_isDeviceCertGenerated);

   // Back to a fresh board: STATUS with the new CSR, and provisioning works again
   sst_route.fpt_onRxShort(VEC_PROV_APP_GET_STATUS, NULL, 0U);
   sv_RunProv();
   sv_AssertLastIs("status_key_ready");
   sv_ToProvisioned();
}

static void test_WipeForgetsBondsAndAdvertising(void)
{
   sv_ToProvisioned();
   su32_refreshCalls = 0U;
   sst_route.fpt_onRxShort(VEC_PROV_APP_DEPROVISION, NULL, 0U);
   sv_RunProv();
   sv_AssertLastIs("result_deprovision_ok");
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(1U, su32_forgetCalls, "bonds belong to the old identity");
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(1U, su32_hostForgetCalls, "so does the host's");
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(1U, su32_refreshCalls, "advertise for provisioning again");
}

static void test_WipeRefusedWhilePairing(void)
{
   sv_ToProvisioned();
   sb_pairRunning = true;
   sst_route.fpt_onRxShort(VEC_PROV_APP_DEPROVISION, NULL, 0U);
   sv_RunProv();
   sv_AssertLastResult(VEC_PROV_APP_DEPROVISION, VEC_PROV_ST_BAD_STATE);
   sv_AssertCalls("");
   TEST_ASSERT_EQUAL_INT(ePS_PROVISIONED, ge_Prov_GetState());
   TEST_ASSERT_EQUAL_UINT32(0U, su32_forgetCalls);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_hostForgetCalls);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("wipe refused: pairing in progress"));

   // The button wipe is refused the same way, without an answer
   su32_sentCount = 0U;
   gv_Prov_RequestWipe();
   sv_RunProv();
   TEST_ASSERT_EQUAL_UINT32(0U, su32_sentCount);
   TEST_ASSERT_EQUAL_INT(ePS_PROVISIONED, ge_Prov_GetState());
}

static void test_DeprovisionFromEveryState(void)
{
   // CA_OK: the CA held in RAM is dropped
   sv_ToCaOk();
   scar_calls[0] = '\0';
   sst_route.fpt_onRxShort(VEC_PROV_APP_DEPROVISION, NULL, 0U);
   sv_RunProv();
   sv_AssertCalls(WIPE_CALLS);
   sv_AssertLastIs("result_deprovision_ok");
   TEST_ASSERT_EQUAL_INT(ePS_KEY_READY, ge_Prov_GetState());
   TEST_ASSERT_EQUAL_UINT8(0U, gst_CACertData.u8_isCACertReceived);

   // NO_KEY: a wipe is how such a device is recovered
   sv_Init(false);
   sb_csrReady = true;
   scar_calls[0] = '\0';
   sst_route.fpt_onRxShort(VEC_PROV_APP_DEPROVISION, NULL, 0U);
   sv_RunProv();
   sv_AssertCalls(WIPE_CALLS);
   sv_AssertLastIs("result_deprovision_ok");
   TEST_ASSERT_EQUAL_INT(ePS_KEY_READY, ge_Prov_GetState());
}

static void test_DeprovisionRefusedWhileBusy(void)
{
   // CSR being sent: gst_CSRData must stay unchanged until the transfer ends
   sb_cliReady = true;
   sst_route.fpt_onRxShort(VEC_PROV_APP_CSR_REQ, NULL, 0U);
   sst_route.fpt_onRxShort(VEC_PROV_APP_DEPROVISION, NULL, 0U);
   sv_RunProv();
   sv_AssertLastResult(VEC_PROV_APP_DEPROVISION, VEC_PROV_ST_BAD_STATE);
   sst_route.fpt_onTxDone(VEC_PROV_APP_CSR, eBS_OK);
   sv_RunProv();

   // Certificate being received: the staging buffer is in use
   TEST_ASSERT_EQUAL_INT(0, sst_route.fpt_onRxStart(VEC_PROV_APP_CA_CERT, 300U));
   sst_route.fpt_onRxShort(VEC_PROV_APP_DEPROVISION, NULL, 0U);
   sv_RunProv();
   sv_AssertLastResult(VEC_PROV_APP_DEPROVISION, VEC_PROV_ST_BAD_STATE);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("wipe refused"));
   sv_AssertCalls("");
   TEST_ASSERT_EQUAL_INT(ePS_KEY_READY, ge_Prov_GetState());
}

static void test_DeprovisionFailures(void)
{
   // Something could not be erased: a new key and CSR are still made, but the
   // provisioner is told
   st_destroyRet = PSA_ERROR_STORAGE_FAILURE;
   sst_route.fpt_onRxShort(VEC_PROV_APP_DEPROVISION, NULL, 0U);
   sv_RunProv();
   sv_AssertLastResult(VEC_PROV_APP_DEPROVISION, VEC_PROV_ST_INTERNAL);
   TEST_ASSERT_EQUAL_INT(ePS_KEY_READY, ge_Prov_GetState());

   st_destroyRet = PSA_SUCCESS;
   st_rmCertsRet = PSA_ERROR_STORAGE_FAILURE;
   sst_route.fpt_onRxShort(VEC_PROV_APP_DEPROVISION, NULL, 0U);
   sv_RunProv();
   sv_AssertLastResult(VEC_PROV_APP_DEPROVISION, VEC_PROV_ST_INTERNAL);

   // No new key and CSR: NO_KEY
   st_rmCertsRet = PSA_SUCCESS;
   sb_csrReady = false;
   sst_route.fpt_onRxShort(VEC_PROV_APP_DEPROVISION, NULL, 0U);
   sv_RunProv();
   sv_AssertLastResult(VEC_PROV_APP_DEPROVISION, VEC_PROV_ST_INTERNAL);
   TEST_ASSERT_EQUAL_INT(ePS_NO_KEY, ge_Prov_GetState());

   // The staging buffer is free again after every wipe
   sb_csrReady = true;
   sst_route.fpt_onRxShort(VEC_PROV_APP_DEPROVISION, NULL, 0U);
   sv_RunProv();
   TEST_ASSERT_EQUAL_INT(0, sst_route.fpt_onRxStart(VEC_PROV_APP_CA_CERT, 300U));
}

static void test_ButtonWipeSendsNoResult(void)
{
   sv_ToProvisioned();
   gv_Prov_RequestWipe();
   sv_RunProv();
   sv_AssertCalls(WIPE_CALLS);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, su32_sentCount, "no provisioner asked");
   TEST_ASSERT_EQUAL_INT(ePS_KEY_READY, ge_Prov_GetState());
}

/******************************************************************************/
/*  Rejections at START                                                       */
/******************************************************************************/
static void test_CertificateLengthLimits(void)
{
   TEST_ASSERT_NOT_EQUAL_INT(0, si_Receive(VEC_PROV_APP_CA_CERT, 0U, eBS_OK));
   sv_RunProv();
   sv_AssertLastResult(VEC_PROV_APP_CA_CERT, VEC_PROV_ST_TOO_LARGE);
   TEST_ASSERT_NOT_EQUAL_INT(0, si_Receive(VEC_PROV_APP_CA_CERT, VEC_PROV_MAX_CERT_LEN + 1U, eBS_OK));
   sv_RunProv();
   sv_AssertLastResult(VEC_PROV_APP_CA_CERT, VEC_PROV_ST_TOO_LARGE);

   TEST_ASSERT_EQUAL_INT(0, si_Receive(VEC_PROV_APP_CA_CERT, VEC_PROV_MAX_CERT_LEN, eBS_OK));
   sv_RunProv();
   TEST_ASSERT_EQUAL_UINT32(VEC_PROV_MAX_CERT_LEN, st_verifiedLen);
   TEST_ASSERT_EQUAL_UINT32(VEC_PROV_MAX_CERT_LEN, DEVICE_CERT_MAX_DER_LEN);
}

static void test_OnlyCertificatesAreTransfers(void)
{
   static const uint8_t scu8ar_types[] = { 0x20U, 0x21U, 0x22U, 0x23U, 0x26U, 0x27U, 0x2FU };
   uint32_t i;

   for (i = 0U; i < sizeof(scu8ar_types); i++)
   {
      TEST_ASSERT_NOT_EQUAL_INT(0, sst_route.fpt_onRxStart(scu8ar_types[i], 10U));
      sv_RunProv();
      sv_AssertLastResult(scu8ar_types[i], VEC_PROV_ST_BAD_STATE);
   }
}

static void test_NoCertificatesWithoutKey(void)
{
   sv_Init(false);
   TEST_ASSERT_NOT_EQUAL_INT(0, si_Receive(VEC_PROV_APP_CA_CERT, 300U, eBS_OK));
   sv_RunProv();
   sv_AssertLastResult(VEC_PROV_APP_CA_CERT, VEC_PROV_ST_BAD_STATE);
}

static void test_OneCertificateAtATime(void)
{
   // First CA announced, still verifying: a second one is refused
   TEST_ASSERT_EQUAL_INT(0, si_Receive(VEC_PROV_APP_CA_CERT, 300U, eBS_OK));
   TEST_ASSERT_NOT_EQUAL_INT(0, sst_route.fpt_onRxStart(VEC_PROV_APP_CA_CERT, 300U));
   sv_RunProv();
   TEST_ASSERT_EQUAL_UINT32(1U, su32_caCalls);
   // Free again once the first got its RESULT
   TEST_ASSERT_EQUAL_INT(0, sst_route.fpt_onRxStart(VEC_PROV_APP_CA_CERT, 300U));
}

static void test_FailedTransferFreesTheBuffer(void)
{
   TEST_ASSERT_EQUAL_INT(0, si_Receive(VEC_PROV_APP_CA_CERT, 300U, eBS_CRC_ERROR));
   sv_RunProv();
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, su32_caCalls, "a failed transfer is not verified");
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, su32_sentCount, "the client already has END(status)");
   TEST_ASSERT_EQUAL_INT(0, sst_route.fpt_onRxStart(VEC_PROV_APP_CA_CERT, 300U));
}

static void test_DataPastBufferIsSinkError(void)
{
   uint8_t u8ar_two[2] = { 0 };

   TEST_ASSERT_EQUAL_INT(0, sst_route.fpt_onRxData(VEC_PROV_APP_CA_CERT,
      DEVICE_CERT_MAX_DER_LEN - 2U, u8ar_two, 2U));
   TEST_ASSERT_NOT_EQUAL_INT(0, sst_route.fpt_onRxData(VEC_PROV_APP_CA_CERT,
      DEVICE_CERT_MAX_DER_LEN - 1U, u8ar_two, 2U));
   TEST_ASSERT_NOT_EQUAL_INT(0, sst_route.fpt_onRxData(VEC_PROV_APP_CA_CERT,
      DEVICE_CERT_MAX_DER_LEN + 1U, u8ar_two, 0U));
}

static void test_QueueOverflowIsLogged(void)
{
   uint32_t i;

   for (i = 0U; i <= PROV_EVENT_QUEUE_LEN; i++)
   {
      sst_route.fpt_onRxShort(VEC_PROV_APP_GET_STATUS, NULL, 0U);
   }
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("queue full"));
   sv_RunProv();
   TEST_ASSERT_EQUAL_UINT32(PROV_EVENT_QUEUE_LEN, su32_sentCount);
}

int main(void)
{
   (void)setvbuf(stdout, NULL, _IONBF, 0);
   UNITY_BEGIN();
   RUN_TEST(test_InitRegistersTheProvisioningRange);
   RUN_TEST(test_InitWithoutCsrStaysNoKey);
   RUN_TEST(test_InitFirstBootGeneratesKeyAndCsr);
   RUN_TEST(test_InitRestoresStoredProvisioning);
   RUN_TEST(test_InitWipesInvalidStoredProvisioning);
   RUN_TEST(test_InitKeepsUnreadableStorage);
   RUN_TEST(test_InitErrorsAreReturned);
   RUN_TEST(test_StatusMatchesVector);
   RUN_TEST(test_StatusShowsCsrBusyAndState);
   RUN_TEST(test_StatusWithoutKeyIsZero);
   RUN_TEST(test_UnknownShortIgnored);
   RUN_TEST(test_CsrSentAtOnceWhenClientAttached);
   RUN_TEST(test_CsrAttachesThenSends);
   RUN_TEST(test_CsrWithoutHostLink);
   RUN_TEST(test_CsrNoPeerService);
   RUN_TEST(test_CsrSendFailures);
   RUN_TEST(test_CsrRequestWhileBusyOrWithoutKey);
   RUN_TEST(test_LateReadyIgnored);
   RUN_TEST(test_CaVerifiedAndKept);
   RUN_TEST(test_CaRejectedKeepsPrevious);
   RUN_TEST(test_CaLoggedAsPem);
   RUN_TEST(test_PemWaitsForLogBacklog);
   RUN_TEST(test_DeviceCertNeedsCaFirst);
   RUN_TEST(test_DeviceCertProvisions);
   RUN_TEST(test_StoreFailureKeepsCaOk);
   RUN_TEST(test_DeviceCertRejected);
   RUN_TEST(test_NewCaReplacesTheCaBeforeDeviceCert);
   RUN_TEST(test_ProvisionedRefusesEverything);
   RUN_TEST(test_DeprovisionWipesAndRegenerates);
   RUN_TEST(test_WipeForgetsBondsAndAdvertising);
   RUN_TEST(test_WipeRefusedWhilePairing);
   RUN_TEST(test_DeprovisionFromEveryState);
   RUN_TEST(test_DeprovisionRefusedWhileBusy);
   RUN_TEST(test_DeprovisionFailures);
   RUN_TEST(test_ButtonWipeSendsNoResult);
   RUN_TEST(test_CertificateLengthLimits);
   RUN_TEST(test_OnlyCertificatesAreTransfers);
   RUN_TEST(test_NoCertificatesWithoutKey);
   RUN_TEST(test_OneCertificateAtATime);
   RUN_TEST(test_FailedTransferFreesTheBuffer);
   RUN_TEST(test_DataPastBufferIsSinkError);
   RUN_TEST(test_QueueOverflowIsLogged);
   return UNITY_END();
}
