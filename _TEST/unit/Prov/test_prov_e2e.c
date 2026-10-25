/**
 * @file          test_prov_e2e.c
 * @brief         Device provisioning end to end on the host: the real SETU
 *                engine in both roles, the real appType router and the real
 *                Prov.c, over the simulated link in sim_link.h. Its scripted
 *                peer plays the provisioner (the PC): it writes the golden
 *                GET_STATUS / CSR_REQ frames from wire.json, hosts the SETU
 *                service the device Client discovers and receives the CSR on,
 *                sends the certificates, and finally wipes the device with
 *                DEPROVISION. Certificate verification, certificate storage and
 *                the key/CSR module are stubbed (they need PSA/mbedTLS/ITS).
 *                Contract: _DOC/Provisioning/PROTOCOL.md.
 *
 * @date          01/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

/* Both roles, as in the firmware */
#include "SETU_Core.c"
#include "SETU_Server.c"
#include "SETU_Client.c"
#include "sim_link.h"
#include "SETURouter.c"
#include "Prov.c"
#include "wire_vectors.h"

/******************************************************************************/
/*  Device-side stand-ins                                                     */
/******************************************************************************/
/* _SETU_SVC: the CTRL attribute is the one the simulated link knows */
const struct bt_gatt_attr *gstpt_SETUSvc_Init(void)
{
   return &sst_ctrlAttr;
}

/* _BLE/ConnectionHandling.c: the simulated link is the host link */
struct bt_conn *gstpt_BLE_GetHostConn(void) { return sb_connected ? &sst_conn : NULL; }
void gv_BLE_RefreshAdv(void) {}

/* _PAIR: no pairing runs here */
bool gb_Pair_IsRunning(void) { return false; }
void gv_Pair_ForgetBonds(void) {}
void gv_HostAuth_Forget(void) {}

/* _CSR: the vector's CSR is this device's CSR; "ITS" is a few flags */
CSRData_T gst_CSRData;
static bool sb_csrStored;
static uint32_t su32_keysMade;

void gv_GenerateOrLoadCSR(void)
{
   // Only a destroyed key (or the first boot) gives a new one
   if (!sb_csrStored) { su32_keysMade++; }
   sb_csrStored = true;
   gst_CSRData.u8_isCSRGenerated = 1U;
   gst_CSRData.u16_CSRLen = (uint16_t)VEC_CSR_DER_LEN;
   (void)memcpy(gst_CSRData.u8ar_CSR, gu8ar_vecCsrDer, VEC_CSR_DER_LEN);
}

psa_status_t gt_InitCryptoStorage(void) { return PSA_SUCCESS; }
psa_status_t gt_ProbeDeviceKey(void) { return PSA_SUCCESS; }

psa_status_t gt_RemoveStoredCSR(void)
{
   sb_csrStored = false;
   (void)memset(&gst_CSRData, 0, sizeof(gst_CSRData));
   return PSA_SUCCESS;
}

psa_status_t gt_DestroyDeviceCredentials(void)
{
   return gt_RemoveStoredCSR();
}

/* _DEVICE_CERT: buffers, storage flags, and verification with scripted results */
CACertData_T gst_CACertData;
DeviceCertData_T gst_deviceCertData;
static bool sb_caStored;
static bool sb_devStored;
static DeviceCertStatus_E se_caRet;
static DeviceCertStatus_E se_devRet;

psa_status_t gt_StoreCACert(void) { sb_caStored = true; return PSA_SUCCESS; }
psa_status_t gt_StoreDeviceCert(void) { sb_devStored = true; return PSA_SUCCESS; }
psa_status_t gt_LoadStoredCerts(void) { return PSA_ERROR_DOES_NOT_EXIST; }

psa_status_t gt_RemoveStoredCerts(void)
{
   sb_caStored = false;
   sb_devStored = false;
   return PSA_SUCCESS;
}

void gv_ClearCertData(void)
{
   (void)memset(&gst_CACertData, 0, sizeof(gst_CACertData));
   (void)memset(&gst_deviceCertData, 0, sizeof(gst_deviceCertData));
}

void gv_ClearTrustAnchor(void) {}

DeviceCertStatus_E ge_VerifyStoredDeviceCertificate(const uint8_t *u8pt_der, size_t t_len)
{
   (void)u8pt_der; (void)t_len;
   return eDCS_OK;
}

DeviceCertStatus_E ge_VerifyCACertificate(const uint8_t *u8pt_der, size_t t_len)
{
   (void)u8pt_der; (void)t_len;
   return se_caRet;
}

DeviceCertStatus_E ge_VerifyOwnDeviceCertificate(const uint8_t *u8pt_der, size_t t_len)
{
   (void)u8pt_der; (void)t_len;
   return se_devRet;
}

/* PSA: SHA-256 of the public key for STATUS (the value the vector carries) */
psa_status_t psa_export_public_key(psa_key_id_t key, uint8_t *data, size_t data_size,
   size_t *data_length)
{
   (void)key; (void)data_size;
   (void)memcpy(data, gu8ar_vecCsrPubKey, VEC_CSR_PUBKEY_LEN);
   *data_length = VEC_CSR_PUBKEY_LEN;
   return PSA_SUCCESS;
}

static const ProvShortVector_T *sstpt_Vec(const char *cpt_name)
{
   uint32_t i;

   for (i = 0U; i < ARRAY_SIZE(gstar_vecProvShorts); i++)
   {
      if (strcmp(gstar_vecProvShorts[i].cpt_name, cpt_name) == 0) { return &gstar_vecProvShorts[i]; }
   }
   TEST_FAIL_MESSAGE(cpt_name);
   return NULL;
}

psa_status_t psa_hash_compute(psa_algorithm_t alg, const uint8_t *input, size_t input_length,
   uint8_t *hash, size_t hash_size, size_t *hash_length)
{
   (void)alg; (void)input; (void)input_length; (void)hash_size;
   (void)memcpy(hash, &sstpt_Vec("status_key_ready")->u8ar_wire[6], 32U);
   *hash_length = 32U;
   return PSA_SUCCESS;
}

/******************************************************************************/
/*  Helpers                                                                   */
/******************************************************************************/
/** Conditions for sb_RunUntil(); each first lets the provisioning thread run. */
static void sv_RunProv(void)
{
   gv_SimRunThread(sv_ProvThread);
}

static bool sb_PeerGotObject(void) { sv_RunProv(); return sst_peer.i_rxDone != STATUS_NONE; }
static bool sb_PeerGotShort(void) { sv_RunProv(); return sst_peer.i_shortNotifies > 0; }
static bool sb_PeerSendDone(void) { sv_RunProv(); return sst_peer.i_txDone != STATUS_NONE; }

/** The provisioner writes one of the golden request frames. */
static void sv_PeerRequest(const char *cpt_vec)
{
   const ProvShortVector_T *v = sstpt_Vec(cpt_vec);

   sst_peer.i_shortNotifies = 0;
   sv_PeerWrite(v->u8ar_wire, v->u8_wireLen);
}

/** Wait for the next short message from the device; it must be wire[]. */
static void sv_AssertPeerGets(const uint8_t *u8pt_wire, uint16_t u16_len, const char *cpt_msg)
{
   TEST_ASSERT_TRUE_MESSAGE(sb_RunUntil(sb_PeerGotShort, 2000), cpt_msg);
   TEST_ASSERT_EQUAL_UINT16_MESSAGE(u16_len, sst_peer.u16_shortFrameLen, cpt_msg);
   TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(u8pt_wire, sst_peer.u8ar_shortFrame, u16_len, cpt_msg);
}

static void sv_AssertPeerGetsVec(const char *cpt_vec)
{
   const ProvShortVector_T *v = sstpt_Vec(cpt_vec);

   sv_AssertPeerGets(v->u8ar_wire, v->u8_wireLen, cpt_vec);
}

static void sv_AssertPeerGetsResult(uint8_t u8_ref, uint8_t u8_status)
{
   uint8_t u8ar_wire[4] = { 2U, VEC_PROV_APP_RESULT, u8_ref, u8_status };

   sv_AssertPeerGets(u8ar_wire, sizeof(u8ar_wire), "RESULT");
}

/** The provisioner sends a certificate and waits for its RESULT. One byte
    over the maximum, for the "too large" case: the peer computes the CRC over
    the whole object before the device refuses it at START. */
static uint8_t su8ar_cert[VEC_PROV_MAX_CERT_LEN + 1U];

static void sv_SendCert(uint8_t u8_type, uint32_t u32_len)
{
   sst_peer.i_shortNotifies = 0;
   sv_PeerStartSend(u8_type, su8ar_cert, u32_len, 6U, false);
   TEST_ASSERT_TRUE_MESSAGE(sb_RunUntil(sb_PeerSendDone, 5000), "certificate transfer stuck");
   TEST_ASSERT_EQUAL_INT_MESSAGE(eBS_OK, sst_peer.i_txDone, "certificate transfer failed");
}

void setUp(void)
{
   uint32_t i;

   atomic_set(&st_state, ePS_KEY_READY);
   atomic_set(&st_certBusy, 0);
   sb_csrTxPending = false;
   k_msgq_purge(&sst_provMsgq);
   (void)memset(&gst_CACertData, 0, sizeof(gst_CACertData));
   (void)memset(&gst_deviceCertData, 0, sizeof(gst_deviceCertData));
   se_caRet = eDCS_OK;
   se_devRet = eDCS_OK;
   gv_GenerateOrLoadCSR();
   sb_dbHasService = true;
   for (i = 0U; i < sizeof(su8ar_cert); i++) { su8ar_cert[i] = (uint8_t)(i ^ 0xA5U); }
   sv_SimConnect(247U);
}

void tearDown(void)
{
   sv_Disconnect();
}

/******************************************************************************/
/*  Tests                                                                     */
/******************************************************************************/
static void test_StatusOverTheAir(void)
{
   const ProvShortVector_T *v = sstpt_Vec("status_key_ready");
   uint8_t u8ar_exp[40];

   // The golden STATUS, with this test's CSR length (the real vector CSR)
   (void)memcpy(u8ar_exp, v->u8ar_wire, v->u8_wireLen);
   sys_put_le16((uint16_t)VEC_CSR_DER_LEN, &u8ar_exp[4]);

   sv_PeerRequest("get_status");
   sv_AssertPeerGets(u8ar_exp, v->u8_wireLen, "STATUS");
}

static void test_CsrDeliveredToTheProvisionersService(void)
{
   sv_PeerRequest("csr_req");

   // The device attaches its Client to the peer's service and sends the CSR
   TEST_ASSERT_TRUE_MESSAGE(sb_RunUntil(sb_PeerGotObject, 5000), "CSR never arrived");
   TEST_ASSERT_EQUAL_INT_MESSAGE(eBS_OK, sst_peer.i_rxDone, "CSR CRC");
   TEST_ASSERT_EQUAL_HEX8(VEC_PROV_APP_CSR, sst_peer.u8_rxType);
   TEST_ASSERT_EQUAL_UINT32(VEC_CSR_DER_LEN, sst_peer.u32_rxTotal);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(gu8ar_vecCsrDer, sst_peer.u8ar_rx, VEC_CSR_DER_LEN);
   sv_AssertPeerGetsVec("result_csr_delivered");

   // A second request reuses the attached Client
   sst_peer.i_rxDone = STATUS_NONE;
   sv_PeerRequest("csr_req");
   TEST_ASSERT_TRUE(sb_RunUntil(sb_PeerGotObject, 5000));
   TEST_ASSERT_EQUAL_HEX8_ARRAY(gu8ar_vecCsrDer, sst_peer.u8ar_rx, VEC_CSR_DER_LEN);
}

static void test_ProvisionerWithoutService(void)
{
   sb_dbHasService = false;
   sv_PeerRequest("csr_req");
   sv_AssertPeerGetsVec("result_csr_no_peer");
   TEST_ASSERT_EQUAL_INT(STATUS_NONE, sst_peer.i_rxDone);
}

static void test_CertificatesProvisionTheDevice(void)
{
   sv_SendCert(VEC_PROV_APP_CA_CERT, 520U);
   sv_AssertPeerGetsVec("result_ca_ok");
   TEST_ASSERT_EQUAL_INT(ePS_CA_OK, ge_Prov_GetState());
   TEST_ASSERT_EQUAL_HEX8_ARRAY(su8ar_cert, gst_CACertData.u8ar_CACert, 520U);

   // Full-size device certificate (5 frames at MTU 247)
   sv_SendCert(VEC_PROV_APP_DEV_CERT, VEC_PROV_MAX_CERT_LEN);
   sv_AssertPeerGetsResult(VEC_PROV_APP_DEV_CERT, VEC_PROV_ST_OK);
   TEST_ASSERT_EQUAL_INT(ePS_PROVISIONED, ge_Prov_GetState());
   TEST_ASSERT_EQUAL_HEX8_ARRAY(su8ar_cert, gst_deviceCertData.u8ar_DeviceCert, VEC_PROV_MAX_CERT_LEN);
   TEST_ASSERT_TRUE_MESSAGE(sb_caStored && sb_devStored, "both certificates stored");
   TEST_ASSERT_FALSE_MESSAGE(sb_csrStored, "the CSR is deleted");

   // One-time: the provisioner gets no CSR and no certificate is taken
   sv_PeerRequest("get_status");
   sv_AssertPeerGetsVec("status_provisioned");
   sv_PeerRequest("csr_req");
   sv_AssertPeerGetsVec("result_csr_req_bad_state");
   sst_peer.i_shortNotifies = 0;
   sv_PeerStartSend(VEC_PROV_APP_CA_CERT, su8ar_cert, 300U, 6U, false);
   TEST_ASSERT_TRUE(sb_RunUntil(sb_PeerSendDone, 2000));
   TEST_ASSERT_EQUAL_INT(PEER_ABORT_BASE + eBS_REJECTED, sst_peer.i_txDone);
   sv_AssertPeerGetsResult(VEC_PROV_APP_CA_CERT, VEC_PROV_ST_BAD_STATE);
}

static void test_DeprovisionMakesAFreshDevice(void)
{
   uint32_t u32_keys = su32_keysMade;

   sv_SendCert(VEC_PROV_APP_CA_CERT, 300U);
   sv_AssertPeerGetsVec("result_ca_ok");
   sv_SendCert(VEC_PROV_APP_DEV_CERT, 400U);
   sv_AssertPeerGetsResult(VEC_PROV_APP_DEV_CERT, VEC_PROV_ST_OK);
   TEST_ASSERT_EQUAL_INT(ePS_PROVISIONED, ge_Prov_GetState());

   sv_PeerRequest("deprovision");
   sv_AssertPeerGetsVec("result_deprovision_ok");
   TEST_ASSERT_EQUAL_INT(ePS_KEY_READY, ge_Prov_GetState());
   TEST_ASSERT_FALSE(sb_caStored || sb_devStored);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(u32_keys + 1U, su32_keysMade, "a new key and CSR");

   // Provisioned again from scratch: the CSR goes to the provisioner once more
   sst_peer.i_rxDone = STATUS_NONE;
   sv_PeerRequest("csr_req");
   TEST_ASSERT_TRUE_MESSAGE(sb_RunUntil(sb_PeerGotObject, 5000), "CSR never arrived");
   TEST_ASSERT_EQUAL_HEX8(VEC_PROV_APP_CSR, sst_peer.u8_rxType);
   sv_AssertPeerGetsVec("result_csr_delivered");
   sv_SendCert(VEC_PROV_APP_CA_CERT, 300U);
   sv_AssertPeerGetsVec("result_ca_ok");
   sv_SendCert(VEC_PROV_APP_DEV_CERT, 400U);
   sv_AssertPeerGetsResult(VEC_PROV_APP_DEV_CERT, VEC_PROV_ST_OK);
   TEST_ASSERT_EQUAL_INT(ePS_PROVISIONED, ge_Prov_GetState());
}

static void test_RejectionsOnTheAir(void)
{
   // Device certificate before the CA: refused at START (ABORT REJECTED) + RESULT
   sst_peer.i_shortNotifies = 0;
   sv_PeerStartSend(VEC_PROV_APP_DEV_CERT, su8ar_cert, 300U, 6U, false);
   TEST_ASSERT_TRUE(sb_RunUntil(sb_PeerSendDone, 2000));
   TEST_ASSERT_EQUAL_INT(PEER_ABORT_BASE + eBS_REJECTED, sst_peer.i_txDone);
   sv_AssertPeerGetsResult(VEC_PROV_APP_DEV_CERT, VEC_PROV_ST_BAD_STATE);

   // Too large
   sst_peer.i_shortNotifies = 0;
   sv_PeerStartSend(VEC_PROV_APP_CA_CERT, su8ar_cert, VEC_PROV_MAX_CERT_LEN + 1U, 6U, false);
   TEST_ASSERT_TRUE(sb_RunUntil(sb_PeerSendDone, 2000));
   TEST_ASSERT_EQUAL_INT(PEER_ABORT_BASE + eBS_REJECTED, sst_peer.i_txDone);
   sv_AssertPeerGetsResult(VEC_PROV_APP_CA_CERT, VEC_PROV_ST_TOO_LARGE);

   // Verification failure
   se_caRet = eDCS_BAD_SIG;
   sv_SendCert(VEC_PROV_APP_CA_CERT, 300U);
   sv_AssertPeerGetsResult(VEC_PROV_APP_CA_CERT, VEC_PROV_ST_BAD_SIG);
   TEST_ASSERT_EQUAL_INT(ePS_KEY_READY, ge_Prov_GetState());
}

static void test_CorruptedCertificateIsNotVerified(void)
{
   sst_peer.i_shortNotifies = 0;
   sv_PeerStartSend(VEC_PROV_APP_CA_CERT, su8ar_cert, 300U, 6U, true);
   TEST_ASSERT_TRUE(sb_RunUntil(sb_PeerSendDone, 2000));
   TEST_ASSERT_EQUAL_INT(eBS_CRC_ERROR, sst_peer.i_txDone);
   sv_Settle(50);
   sv_RunProv();
   TEST_ASSERT_EQUAL_INT(0, sst_peer.i_shortNotifies);
   TEST_ASSERT_EQUAL_INT(ePS_KEY_READY, ge_Prov_GetState());
   // The staging buffer is free again
   sv_SendCert(VEC_PROV_APP_CA_CERT, 300U);
   sv_AssertPeerGetsVec("result_ca_ok");
}

int main(int argc, char **argv)
{
   (void)setvbuf(stdout, NULL, _IONBF, 0);
   gb_simVerbose = (argc > 1) && (strcmp(argv[1], "-v") == 0);

   // As main() does in the firmware, before any connection
   if ((gi_Prov_Init() != 0) || (gi_SETURouter_Start() != 0))
   {
      printf("gi_Prov_Init / gi_SETURouter_Start failed\n");
      return 1;
   }

   UNITY_BEGIN();
   RUN_TEST(test_StatusOverTheAir);
   RUN_TEST(test_CsrDeliveredToTheProvisionersService);
   RUN_TEST(test_ProvisionerWithoutService);
   RUN_TEST(test_CertificatesProvisionTheDevice);
   RUN_TEST(test_DeprovisionMakesAFreshDevice);
   RUN_TEST(test_RejectionsOnTheAir);
   RUN_TEST(test_CorruptedCertificateIsNotVerified);
   return UNITY_END();
}
