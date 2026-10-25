/**
 * @file          test_host_auth.c
 * @brief         Host unit tests for host authentication
 *                (_ASW/_HOST_AUTH/HostAuth.c): the router's gate in every state,
 *                the handshake (HELLO, CHALLENGE, FINISH) with each RESULT, the
 *                host link's SMP callbacks (pairing allowed only after FINISH,
 *                the derived passkey), the bond record, trust of a bonded host
 *                that reconnects, the window and the grace window, forgetting the
 *                host, the wipe, the timeout. The BT stack, the router, the SETU
 *                roles, certificate verification and the handshake cryptography
 *                (its own test, host_auth_crypto) are stubbed and recorded.
 *                Contract: _DOC/HostAuth/PROTOCOL.md.
 *
 * @date          25/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#include "HostAuth.c"
#include "unity.h"
#include "wire_vectors.h"

/******************************************************************************/
/*  Links and addresses                                                       */
/******************************************************************************/
static struct bt_conn sst_host = { 1 };
static struct bt_conn sst_other = { 2 };
static bt_addr_le_t sst_addrHost;
static bt_addr_le_t sst_addrOther;
static bt_security_t se_security;

const bt_addr_le_t *bt_conn_get_dst(const struct bt_conn *conn)
{
   return (conn == &sst_host) ? &sst_addrHost : &sst_addrOther;
}
bt_security_t bt_conn_get_security(const struct bt_conn *conn) { (void)conn; return se_security; }

static uint32_t su32_setSec;
int bt_conn_set_security(struct bt_conn *conn, bt_security_t sec)
{
   TEST_ASSERT_EQUAL_PTR(&sst_host, conn);
   TEST_ASSERT_EQUAL_INT(BT_SECURITY_L4, sec);
   su32_setSec++;
   return 0;
}

static uint32_t su32_disconnect;
static struct bt_conn *sstpt_disconnected;
int bt_conn_disconnect(struct bt_conn *conn, uint8_t reason)
{
   (void)reason;
   su32_disconnect++;
   sstpt_disconnected = conn;
   return 0;
}

static uint32_t su32_unpair;
static bt_addr_le_t sst_unpairAddr;
int bt_unpair(uint8_t id, const bt_addr_le_t *addr)
{
   TEST_ASSERT_EQUAL_UINT8(BT_ID_DEFAULT, id);
   TEST_ASSERT_NOT_NULL_MESSAGE(addr, "only the host's bond is deleted");
   su32_unpair++;
   sst_unpairAddr = *addr;
   return 0;
}

static bool sb_hostBondListed;
void bt_foreach_bond(uint8_t id, void (*func)(const struct bt_bond_info *info, void *user_data),
   void *user_data)
{
   struct bt_bond_info st_info;

   (void)id;
   st_info.addr = sst_addrOther;
   func(&st_info, user_data);
   if (sb_hostBondListed)
   {
      st_info.addr = sst_addrHost;
      func(&st_info, user_data);
   }
}

static const struct bt_conn_auth_cb *sstpt_overlay;
static int si_overlayRet;
int bt_conn_auth_cb_overlay(struct bt_conn *conn, const struct bt_conn_auth_cb *cb)
{
   TEST_ASSERT_EQUAL_PTR(&sst_host, conn);
   sstpt_overlay = cb;
   return si_overlayRet;
}

static struct bt_conn_auth_info_cb *sstpt_authInfo;
static int si_authInfoRet;
int bt_conn_auth_info_cb_register(struct bt_conn_auth_info_cb *cb)
{
   sstpt_authInfo = cb;
   return si_authInfoRet;
}

/******************************************************************************/
/*  Settings, LED, advertising                                                */
/******************************************************************************/
static uint32_t su32_save;
static uint8_t su8ar_saved[8];
static size_t st_savedLen;
static char scar_saveName[32];
int settings_save_one(const char *name, const void *value, size_t val_len)
{
   su32_save++;
   (void)snprintf(scar_saveName, sizeof(scar_saveName), "%s", name);
   st_savedLen = val_len;
   (void)memcpy(su8ar_saved, value, MIN(val_len, sizeof(su8ar_saved)));
   return 0;
}
static uint32_t su32_settingsDelete;
int settings_delete(const char *name)
{
   TEST_ASSERT_EQUAL_STRING("hauth/host", name);
   su32_settingsDelete++;
   return 0;
}

static uint32_t su32_ledValue;
int dk_set_led(uint8_t led_idx, uint32_t val)
{
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(DK_LED2, led_idx, "LED1 of the DK");
   su32_ledValue = val;
   return 0;
}

static uint32_t su32_refresh;
void gv_BLE_RefreshAdv(void) { su32_refresh++; }

static ProvState_E se_provState;
ProvState_E ge_Prov_GetState(void) { return se_provState; }

DeviceCertData_T gst_deviceCertData;

/******************************************************************************/
/*  Router and SETU roles                                                     */
/******************************************************************************/
static SETURoute_T sst_route;
static int si_registerRet;
int gi_SETURouter_Register(const SETURoute_T *stpt_route)
{
   sst_route = *stpt_route;
   return si_registerRet;
}
static SETURouterAdmit_F sfpt_gate;
static SETURouterRefused_F sfpt_gateRefused;
static int si_gateRet;
int gi_SETURouter_SetGate(SETURouterAdmit_F fpt_admit, SETURouterRefused_F fpt_refused)
{
   sfpt_gate = fpt_admit;
   sfpt_gateRefused = fpt_refused;
   return si_gateRet;
}
static int si_attachRet;
static uint32_t su32_attach;
int gi_SETURouter_ClientAttach(struct bt_conn *stpt_conn, uint8_t u8_ownerAppType)
{
   TEST_ASSERT_EQUAL_PTR(&sst_host, stpt_conn);
   TEST_ASSERT_EQUAL_HEX8(HOST_AUTH_APP_TYPE_CHALLENGE, u8_ownerAppType);
   su32_attach++;
   return si_attachRet;
}
static int si_sendRet;
static uint32_t su32_send;
static uint8_t su8ar_sent[HOST_AUTH_CHALLENGE_HDR_LEN + DEVICE_CERT_MAX_DER_LEN];
static uint16_t su16_sentLen;
static bool sb_autoTxDone;                   /* the transfer ends OK at once, as SETU reports */
int gi_SETUC_SendBuffer(uint8_t u8_appType, const void *vpt_data, uint32_t u32_len)
{
   TEST_ASSERT_EQUAL_HEX8(HOST_AUTH_APP_TYPE_CHALLENGE, u8_appType);
   su32_send++;
   su16_sentLen = (uint16_t)u32_len;
   (void)memcpy(su8ar_sent, vpt_data, u32_len);
   if ((si_sendRet == 0) && sb_autoTxDone)
   {
      sst_route.fpt_onTxDone(HOST_AUTH_APP_TYPE_CHALLENGE, eBS_OK);
   }
   return si_sendRet;
}

/* Short messages to the host, kept in order */
#define SHORTS_MAX 16U
static uint8_t su8ar_shortType[SHORTS_MAX];
static uint8_t su8ar_shortData[SHORTS_MAX][4];
static uint32_t su32_shorts;
int gi_SETUS_SendShort(uint8_t u8_appType, const void *vpt_data, uint8_t u8_len, k_timeout_t t_timeout)
{
   (void)t_timeout;
   TEST_ASSERT_TRUE(u8_len <= 4U);
   if (su32_shorts < SHORTS_MAX)
   {
      su8ar_shortType[su32_shorts] = u8_appType;
      (void)memcpy(su8ar_shortData[su32_shorts], vpt_data, u8_len);
   }
   su32_shorts++;
   return 0;
}

/******************************************************************************/
/*  Certificate verification and handshake cryptography                       */
/******************************************************************************/
static DeviceCertStatus_E se_hostCertRet;
static uint32_t su32_hostCertLen;
DeviceCertStatus_E ge_VerifyHostCertificate(const uint8_t *u8pt_der, size_t t_len,
   psa_key_id_t *tpt_hostPubKeyID)
{
   (void)u8pt_der;
   su32_hostCertLen = (uint32_t)t_len;
   *tpt_hostPubKeyID = (se_hostCertRet == eDCS_OK) ? 0x4401U : 0U;
   return se_hostCertRet;
}

static psa_status_t st_cryptoRet;
static psa_status_t st_verifyRet;
static uint32_t su32_destroy;
static psa_key_id_t st_lastVerifyKey;
psa_status_t psa_destroy_key(psa_key_id_t key) { (void)key; su32_destroy++; return PSA_SUCCESS; }
psa_status_t gt_HostAuthCrypto_Random(uint8_t *u8pt_buf, size_t t_len)
{
   (void)memset(u8pt_buf, 0xA5, t_len);
   return PSA_SUCCESS;
}
psa_status_t gt_HostAuthCrypto_NewEphemeral(psa_key_id_t *tpt_key, uint8_t *u8pt_point)
{
   *tpt_key = 0x7701U;
   (void)memset(u8pt_point, 0x04, HOST_AUTH_POINT_LEN);
   return st_cryptoRet;
}
psa_status_t gt_HostAuthCrypto_Agree(psa_key_id_t t_key, const uint8_t *u8pt_peerPoint, uint8_t *u8pt_secret)
{
   TEST_ASSERT_EQUAL_UINT32(0x7701U, t_key);
   TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x51U, u8pt_peerPoint[0], "Qh comes from HELLO");
   (void)memset(u8pt_secret, 0x22, HOST_AUTH_HASH_LEN);
   return PSA_SUCCESS;
}
static uint32_t su32_transcriptCertLen;
psa_status_t gt_HostAuthCrypto_Transcript(const HostAuthTranscript_T *stpt_in, uint8_t *u8pt_transcript)
{
   TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x61U, stpt_in->u8pt_nonceHost[0], "Nh comes from HELLO");
   TEST_ASSERT_EQUAL_PTR(gst_deviceCertData.u8ar_DeviceCert, stpt_in->u8pt_certDev);
   su32_transcriptCertLen = (uint32_t)stpt_in->t_certHostLen;
   (void)memset(u8pt_transcript, 0x11, HOST_AUTH_HASH_LEN);
   return PSA_SUCCESS;
}
psa_status_t gt_HostAuthCrypto_Sign(psa_key_id_t t_key, HostAuthRole_E e_role,
   const uint8_t *u8pt_transcript, uint8_t *u8pt_sig)
{
   TEST_ASSERT_EQUAL_UINT32(CSR_DEVICE_SIGNING_KEY_ID, t_key);
   TEST_ASSERT_EQUAL_INT(eHAR_DEVICE, e_role);
   (void)u8pt_transcript;
   (void)memset(u8pt_sig, 0xD5, HOST_AUTH_SIG_LEN);
   return PSA_SUCCESS;
}
psa_status_t gt_HostAuthCrypto_Verify(psa_key_id_t t_key, HostAuthRole_E e_role,
   const uint8_t *u8pt_transcript, const uint8_t *u8pt_sig)
{
   TEST_ASSERT_EQUAL_INT(eHAR_HOST, e_role);
   TEST_ASSERT_EQUAL_HEX8(0x11U, u8pt_transcript[0]);
   TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xE7U, u8pt_sig[0], "SigH comes from FINISH");
   st_lastVerifyKey = t_key;
   return st_verifyRet;
}
psa_status_t gt_HostAuthCrypto_Passkey(const uint8_t *u8pt_secret, const uint8_t *u8pt_nonceHost,
   const uint8_t *u8pt_nonceDev, const uint8_t *u8pt_transcript, uint32_t *u32pt_passkey)
{
   TEST_ASSERT_EQUAL_HEX8(0x22U, u8pt_secret[0]);
   (void)u8pt_nonceHost; (void)u8pt_nonceDev; (void)u8pt_transcript;
   *u32pt_passkey = 123456U;
   return PSA_SUCCESS;
}

/******************************************************************************/
/*  Helpers                                                                   */
/******************************************************************************/
#define CERT_LEN 300U

static void sv_Run(void)
{
   gv_SimRunThread(sv_HostAuthThread);
   (void)gb_SimRunDelayedWork(&sst_ledWork);
}

static void sv_AdvanceMs(int64_t i64_ms)
{
   gi64_simNowMs += i64_ms;
   (void)gb_SimRunDelayedWork(&sst_windowWork);
   (void)gb_SimRunDelayedWork(&sst_timeoutWork);
   (void)gb_SimRunDelayedWork(&sst_ledWork);
   sv_Run();
}

static const uint8_t *su8pt_LastShort(uint8_t u8_appType)
{
   uint32_t i = MIN(su32_shorts, SHORTS_MAX);

   while (i > 0U)
   {
      i--;
      if (su8ar_shortType[i] == u8_appType) { return su8ar_shortData[i]; }
   }
   TEST_FAIL_MESSAGE("short message not sent");
   return NULL;
}

static void sv_AssertResult(uint8_t u8_ref, HostAuthResult_E e_status, uint8_t u8_detail)
{
   const uint8_t *u8pt_r = su8pt_LastShort(HOST_AUTH_APP_TYPE_RESULT);

   TEST_ASSERT_EQUAL_HEX8(u8_ref, u8pt_r[0]);
   TEST_ASSERT_EQUAL_UINT8(e_status, u8pt_r[1]);
   TEST_ASSERT_EQUAL_UINT8(u8_detail, u8pt_r[2]);
}

static void sv_ResetModule(void)
{
   (void)atomic_set(&st_phase, eHAP_NONE);
   (void)atomic_ptr_set(&st_hostConn, NULL);
   (void)atomic_set(&st_hostBonded, 0);
   (void)atomic_set(&st_window, 0);
   (void)atomic_set(&st_bufBusy, 0);
   sb_challengeTx = false;
   (void)atomic_set(&st_passkey, 0);
   sb_challengePending = false;
   st_hostKey = 0;
   (void)memset(&sst_hostAddr, 0, sizeof(sst_hostAddr));
   (void)k_work_cancel_delayable(&sst_windowWork);
   (void)k_work_cancel_delayable(&sst_timeoutWork);
   (void)k_work_cancel_delayable(&sst_ledWork);
   k_msgq_purge(&sst_hostAuthMsgq);
}

static void sv_Connect(struct bt_conn *stpt_conn)
{
   gv_HostAuth_OnHostConnected(stpt_conn);
   sv_Run();
}

/** HELLO through the router's receive callbacks: [1][Nh 0x61..][Qh 0x51..][cert]. */
static int si_SendHello(uint32_t u32_certLen, uint8_t u8_version)
{
   uint8_t u8ar_hello[HOST_AUTH_HELLO_MAX_LEN];
   uint32_t u32_len = HOST_AUTH_HELLO_HDR_LEN + u32_certLen;
   uint32_t u32_off;
   int i_ret;

   u8ar_hello[0] = u8_version;
   (void)memset(&u8ar_hello[1], 0x61, HOST_AUTH_NONCE_LEN);
   (void)memset(&u8ar_hello[1U + HOST_AUTH_NONCE_LEN], 0x51, HOST_AUTH_POINT_LEN);
   (void)memset(&u8ar_hello[HOST_AUTH_HELLO_HDR_LEN], 0x30, u32_certLen);
   i_ret = sst_route.fpt_onRxStart(HOST_AUTH_APP_TYPE_HELLO, u32_len);
   if (i_ret != 0)
   {
      sv_Run();
      return i_ret;
   }
   for (u32_off = 0U; u32_off < u32_len; u32_off += 200U)
   {
      TEST_ASSERT_EQUAL_INT(0, sst_route.fpt_onRxData(HOST_AUTH_APP_TYPE_HELLO, u32_off,
         &u8ar_hello[u32_off], (uint16_t)MIN(200U, u32_len - u32_off)));
   }
   sst_route.fpt_onRxDone(HOST_AUTH_APP_TYPE_HELLO, eBS_OK, u32_len);
   sv_Run();
   return 0;
}

static void sv_SendFinish(uint8_t u8_len)
{
   uint8_t u8ar_sig[HOST_AUTH_SIG_LEN + 1U];

   (void)memset(u8ar_sig, 0xE7, sizeof(u8ar_sig));
   sst_route.fpt_onRxShort(HOST_AUTH_APP_TYPE_FINISH, u8ar_sig, u8_len);
   sv_Run();
}

/** Connected, HELLO and FINISH done: pairing allowed. */
static void sv_ToAwaitPairing(void)
{
   sv_Connect(&sst_host);
   TEST_ASSERT_EQUAL_INT(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
   sv_SendFinish(HOST_AUTH_SIG_LEN);
   TEST_ASSERT_EQUAL_INT(eHAS_AWAIT_PAIRING, ge_HostAuth_GetState());
}

/** The host pairs (bonded) and reaches level 4: trusted. */
static void sv_ToTrusted(void)
{
   sv_ToAwaitPairing();
   TEST_ASSERT_EQUAL_INT(BT_SECURITY_ERR_SUCCESS, sstpt_overlay->pairing_accept(&sst_host, NULL));
   se_security = BT_SECURITY_L4;
   gv_HostAuth_OnSecurityChanged(&sst_host, BT_SECURITY_L4, 0U);
   sstpt_authInfo->pairing_complete(&sst_host, true);
   sv_Run();
   TEST_ASSERT_EQUAL_INT(eHAS_TRUSTED, ge_HostAuth_GetState());
}

/** A loaded host record, as settings_load() does it. */
static ssize_t st_ReadRecord(void *vpt_arg, void *vpt_data, size_t t_len)
{
   (void)memcpy(vpt_data, vpt_arg, t_len);
   return (ssize_t)t_len;
}
static int si_LoadRecord(const bt_addr_le_t *stpt_addr)
{
   uint8_t u8ar_rec[HOST_AUTH_RECORD_LEN];

   u8ar_rec[0] = stpt_addr->type;
   (void)memcpy(&u8ar_rec[1], stpt_addr->a.val, 6U);
   return settings_handler_hauth.h_set(HOST_AUTH_SETTINGS_KEY, sizeof(u8ar_rec), st_ReadRecord, u8ar_rec);
}

void setUp(void)
{
   sst_addrHost.type = BT_ADDR_LE_PUBLIC;
   (void)memcpy(sst_addrHost.a.val, "\x11\x22\x33\x44\x55\x66", 6U);
   sst_addrOther = sst_addrHost;
   sst_addrOther.a.val[0] ^= 0x5AU;
   se_security = BT_SECURITY_L1;
   su32_setSec = 0U; su32_disconnect = 0U; sstpt_disconnected = NULL;
   su32_unpair = 0U; (void)memset(&sst_unpairAddr, 0, sizeof(sst_unpairAddr)); sb_hostBondListed = false;
   sstpt_overlay = NULL; si_overlayRet = 0; si_authInfoRet = 0;
   su32_save = 0U; st_savedLen = 0U; scar_saveName[0] = '\0'; su32_settingsDelete = 0U;
   su32_ledValue = 0U; su32_refresh = 0U;
   se_provState = ePS_PROVISIONED;
   gst_deviceCertData.u16_deviceCertLen = 400U;
   (void)memset(gst_deviceCertData.u8ar_DeviceCert, 0xCE, 400U);
   si_registerRet = 0; si_gateRet = 0; si_attachRet = -EALREADY; su32_attach = 0U;
   si_sendRet = 0; su32_send = 0U; su16_sentLen = 0U; sb_autoTxDone = true;
   su32_shorts = 0U;
   se_hostCertRet = eDCS_OK; su32_hostCertLen = 0U;
   st_cryptoRet = PSA_SUCCESS; st_verifyRet = PSA_SUCCESS; su32_destroy = 0U; st_lastVerifyKey = 0U;
   gi64_simNowMs = 0;

   sv_ResetModule();
   gv_SimLogClear();
   TEST_ASSERT_EQUAL_INT(0, gi_HostAuth_Init());
}

void tearDown(void) {}

/******************************************************************************/
/*  Start-up                                                                  */
/******************************************************************************/
static void test_InitRegistersRangeGateAndCallbacks(void)
{
   TEST_ASSERT_EQUAL_HEX8(VEC_HAUTH_APP_FIRST, sst_route.u8_firstAppType);
   TEST_ASSERT_EQUAL_HEX8(VEC_HAUTH_APP_LAST, sst_route.u8_lastAppType);
   TEST_ASSERT_NOT_NULL(sst_route.fpt_onRxStart);
   TEST_ASSERT_NOT_NULL(sst_route.fpt_onRxShort);
   TEST_ASSERT_NOT_NULL(sst_route.fpt_onTxDone);
   TEST_ASSERT_NOT_NULL(sst_route.fpt_onCliReady);
   TEST_ASSERT_EQUAL_PTR(gb_HostAuth_Admits, sfpt_gate);
   TEST_ASSERT_NOT_NULL(sfpt_gateRefused);
   TEST_ASSERT_NOT_NULL(sstpt_authInfo->pairing_complete);
   TEST_ASSERT_NOT_NULL(sstpt_authInfo->pairing_failed);
}

static void test_InitErrorsAreReturned(void)
{
   si_registerRet = -ENOMEM;
   TEST_ASSERT_EQUAL_INT(-ENOMEM, gi_HostAuth_Init());
   si_registerRet = 0;
   si_gateRet = -EALREADY;
   TEST_ASSERT_EQUAL_INT(-EALREADY, gi_HostAuth_Init());
   si_gateRet = 0;
   si_authInfoRet = -EINVAL;
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_HostAuth_Init());
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("bt_conn_auth_info_cb_register failed"));
}

static void test_WireConstantsMatchTheVectors(void)
{
   TEST_ASSERT_EQUAL_HEX8(VEC_HAUTH_APP_STATUS_REQ, HOST_AUTH_APP_TYPE_STATUS_REQ);
   TEST_ASSERT_EQUAL_HEX8(VEC_HAUTH_APP_STATUS, HOST_AUTH_APP_TYPE_STATUS);
   TEST_ASSERT_EQUAL_HEX8(VEC_HAUTH_APP_HELLO, HOST_AUTH_APP_TYPE_HELLO);
   TEST_ASSERT_EQUAL_HEX8(VEC_HAUTH_APP_CHALLENGE, HOST_AUTH_APP_TYPE_CHALLENGE);
   TEST_ASSERT_EQUAL_HEX8(VEC_HAUTH_APP_FINISH, HOST_AUTH_APP_TYPE_FINISH);
   TEST_ASSERT_EQUAL_HEX8(VEC_HAUTH_APP_RESULT, HOST_AUTH_APP_TYPE_RESULT);
   TEST_ASSERT_EQUAL_HEX8(VEC_HAUTH_APP_REFUSED, HOST_AUTH_APP_TYPE_REFUSED);
   TEST_ASSERT_EQUAL_UINT8(VEC_HAUTH_VERSION, HOST_AUTH_VERSION);
   TEST_ASSERT_EQUAL_UINT8(VEC_HAUTH_STATE_UNPROVISIONED, eHAS_UNPROVISIONED);
   TEST_ASSERT_EQUAL_UINT8(VEC_HAUTH_STATE_OPEN, eHAS_OPEN);
   TEST_ASSERT_EQUAL_UINT8(VEC_HAUTH_STATE_HOST_BONDED, eHAS_HOST_BONDED);
   TEST_ASSERT_EQUAL_UINT8(VEC_HAUTH_STATE_AWAIT_FINISH, eHAS_AWAIT_FINISH);
   TEST_ASSERT_EQUAL_UINT8(VEC_HAUTH_STATE_AWAIT_PAIRING, eHAS_AWAIT_PAIRING);
   TEST_ASSERT_EQUAL_UINT8(VEC_HAUTH_STATE_TRUSTED, eHAS_TRUSTED);
   TEST_ASSERT_EQUAL_UINT8(VEC_HAUTH_FLAG_WINDOW_OPEN, HOST_AUTH_FLAG_WINDOW_OPEN);
   TEST_ASSERT_EQUAL_UINT8(VEC_HAUTH_FLAG_HOST_BOND, HOST_AUTH_FLAG_HOST_BOND);
   TEST_ASSERT_EQUAL_UINT8(VEC_HAUTH_RES_OK, eHRS_OK);
   TEST_ASSERT_EQUAL_UINT8(VEC_HAUTH_RES_BAD_STATE, eHRS_BAD_STATE);
   TEST_ASSERT_EQUAL_UINT8(VEC_HAUTH_RES_PARSE, eHRS_PARSE);
   TEST_ASSERT_EQUAL_UINT8(VEC_HAUTH_RES_BAD_CERT, eHRS_BAD_CERT);
   TEST_ASSERT_EQUAL_UINT8(VEC_HAUTH_RES_BAD_SIG, eHRS_BAD_SIG);
   TEST_ASSERT_EQUAL_UINT8(VEC_HAUTH_RES_HOST_BONDED, eHRS_HOST_BONDED);
   TEST_ASSERT_EQUAL_UINT8(VEC_HAUTH_RES_NO_PC_SVC, eHRS_NO_PC_SVC);
   TEST_ASSERT_EQUAL_UINT8(VEC_HAUTH_RES_BUSY, eHRS_BUSY);
   TEST_ASSERT_EQUAL_UINT8(VEC_HAUTH_RES_TIMEOUT, eHRS_TIMEOUT);
   TEST_ASSERT_EQUAL_UINT8(VEC_HAUTH_RES_PAIRING, eHRS_PAIRING);
   TEST_ASSERT_EQUAL_UINT8(VEC_HAUTH_RES_INTERNAL, eHRS_INTERNAL);
   TEST_ASSERT_EQUAL_UINT8(VEC_HAUTH_RES_TRANSFER, eHRS_TRANSFER);
   TEST_ASSERT_EQUAL_UINT(VEC_HAUTH_HELLO_MIN_LEN, HOST_AUTH_HELLO_HDR_LEN + 1U);
   TEST_ASSERT_EQUAL_UINT(VEC_HAUTH_CHALLENGE_HEADER_LEN, HOST_AUTH_CHALLENGE_HDR_LEN);
   TEST_ASSERT_EQUAL_UINT(VEC_HAUTH_CERT_MAX_LEN, DEVICE_CERT_MAX_DER_LEN);
}

/******************************************************************************/
/*  Gate                                                                      */
/******************************************************************************/
static void test_GateOfAnUnprovisionedDevice(void)
{
   se_provState = ePS_KEY_READY;
   TEST_ASSERT_TRUE(gb_HostAuth_Admits(0x20U));
   TEST_ASSERT_TRUE(gb_HostAuth_Admits(0x27U));
   TEST_ASSERT_TRUE(gb_HostAuth_Admits(0x2FU));
   TEST_ASSERT_TRUE(gb_HostAuth_Admits(0x60U));
   TEST_ASSERT_FALSE(gb_HostAuth_Admits(0x10U));
   TEST_ASSERT_FALSE(gb_HostAuth_Admits(0x30U));
   TEST_ASSERT_FALSE(gb_HostAuth_Admits(0x40U));
   TEST_ASSERT_FALSE(gb_HostAuth_Admits(0x50U));
   TEST_ASSERT_FALSE(gb_HostAuth_Admits(0x1FU));
   TEST_ASSERT_EQUAL_INT(eHAS_UNPROVISIONED, ge_HostAuth_GetState());
}

static void test_GateOfAProvisionedDevice(void)
{
   uint32_t u32_t;

   sv_Connect(&sst_host);
   for (u32_t = 0U; u32_t <= 0xEFU; u32_t++)
   {
      bool b_open = ((u32_t >= 0x60U) && (u32_t <= 0x6FU)) || (u32_t == 0x20U);

      TEST_ASSERT_EQUAL_MESSAGE(b_open, gb_HostAuth_Admits((uint8_t)u32_t), "untrusted host link");
   }
   TEST_ASSERT_FALSE_MESSAGE(gb_HostAuth_Admits(0x27U), "DEPROVISION needs the trusted host");
}

static void test_TrustedHostReachesEverything(void)
{
   uint32_t u32_t;

   sv_ToTrusted();
   for (u32_t = 0U; u32_t <= 0xEFU; u32_t++)
   {
      TEST_ASSERT_TRUE(gb_HostAuth_Admits((uint8_t)u32_t));
   }
   TEST_ASSERT_TRUE(gb_HostAuth_IsTrustedConn(&sst_host));
   TEST_ASSERT_FALSE(gb_HostAuth_IsTrustedConn(&sst_other));
   TEST_ASSERT_FALSE(gb_HostAuth_IsTrustedConn(NULL));
}

static void test_RefusalsAreReported(void)
{
   const uint8_t *u8pt_r;

   sv_Connect(&sst_host);
   sfpt_gateRefused(0x40U);
   sv_Run();
   u8pt_r = su8pt_LastShort(HOST_AUTH_APP_TYPE_REFUSED);
   TEST_ASSERT_EQUAL_HEX8(0x40U, u8pt_r[0]);
}

/******************************************************************************/
/*  STATUS                                                                    */
/******************************************************************************/
static void test_StatusFollowsTheState(void)
{
   const uint8_t *u8pt_s;

   sv_Connect(&sst_host);
   sst_route.fpt_onRxShort(HOST_AUTH_APP_TYPE_STATUS_REQ, NULL, 0U);
   sv_Run();
   u8pt_s = su8pt_LastShort(HOST_AUTH_APP_TYPE_STATUS);
   TEST_ASSERT_EQUAL_UINT8(VEC_HAUTH_STATE_OPEN, u8pt_s[0]);
   TEST_ASSERT_EQUAL_HEX8(0x00U, u8pt_s[1]);

   sv_ToTrusted();
   u8pt_s = su8pt_LastShort(HOST_AUTH_APP_TYPE_STATUS);
   TEST_ASSERT_EQUAL_UINT8(VEC_HAUTH_STATE_TRUSTED, u8pt_s[0]);
   TEST_ASSERT_EQUAL_HEX8(VEC_HAUTH_FLAG_HOST_BOND, u8pt_s[1]);
}

static void test_NoStatusWithoutAHost(void)
{
   gv_HostAuth_OpenWindow();
   sv_Run();
   TEST_ASSERT_EQUAL_UINT32(0U, su32_shorts);
}

/******************************************************************************/
/*  Handshake                                                                 */
/******************************************************************************/
static void test_HostLinkGetsItsOwnSmpCallbacks(void)
{
   sv_Connect(&sst_host);
   TEST_ASSERT_NOT_NULL(sstpt_overlay);
   TEST_ASSERT_NOT_NULL(sstpt_overlay->pairing_accept);
   TEST_ASSERT_NOT_NULL(sstpt_overlay->app_passkey);
   // app_passkey alone: the device is DisplayOnly, the host enters the passkey
   TEST_ASSERT_NULL(sstpt_overlay->passkey_display);
   TEST_ASSERT_NULL(sstpt_overlay->passkey_entry);
   TEST_ASSERT_NULL(sstpt_overlay->passkey_confirm);
   TEST_ASSERT_NULL(sstpt_overlay->oob_data_request);
   // Before any handshake: no pairing, a random passkey
   TEST_ASSERT_EQUAL_INT(BT_SECURITY_ERR_PAIR_NOT_ALLOWED, sstpt_overlay->pairing_accept(&sst_host, NULL));
   TEST_ASSERT_EQUAL_UINT32(BT_PASSKEY_RAND, sstpt_overlay->app_passkey(&sst_host));
}

static void test_HelloIsAnsweredWithAChallenge(void)
{
   sv_Connect(&sst_host);
   TEST_ASSERT_EQUAL_INT(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
   TEST_ASSERT_EQUAL_UINT32(CERT_LEN, su32_hostCertLen);
   TEST_ASSERT_EQUAL_UINT32(CERT_LEN, su32_transcriptCertLen);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_attach);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_send);
   // [ver][Nd][Qd][SigD][device cert]
   TEST_ASSERT_EQUAL_UINT16(HOST_AUTH_CHALLENGE_HDR_LEN + 400U, su16_sentLen);
   TEST_ASSERT_EQUAL_HEX8(HOST_AUTH_VERSION, su8ar_sent[0]);
   TEST_ASSERT_EQUAL_HEX8(0xA5U, su8ar_sent[1]);
   TEST_ASSERT_EQUAL_HEX8(0x04U, su8ar_sent[1U + HOST_AUTH_NONCE_LEN]);
   TEST_ASSERT_EQUAL_HEX8(0xD5U, su8ar_sent[1U + HOST_AUTH_NONCE_LEN + HOST_AUTH_POINT_LEN]);
   TEST_ASSERT_EQUAL_HEX8(0xCEU, su8ar_sent[HOST_AUTH_CHALLENGE_HDR_LEN]);
   TEST_ASSERT_EQUAL_HEX8(0xCEU, su8ar_sent[su16_sentLen - 1U]);
   TEST_ASSERT_EQUAL_INT(eHAS_AWAIT_FINISH, ge_HostAuth_GetState());
   // The ephemeral key is gone at once; pairing still not allowed
   TEST_ASSERT_EQUAL_UINT32(1U, su32_destroy);
   TEST_ASSERT_EQUAL_INT(BT_SECURITY_ERR_PAIR_NOT_ALLOWED, sstpt_overlay->pairing_accept(&sst_host, NULL));
}

static void test_ChallengeWaitsForTheClient(void)
{
   sv_Connect(&sst_host);
   si_attachRet = 0;
   TEST_ASSERT_EQUAL_INT(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
   TEST_ASSERT_EQUAL_UINT32(0U, su32_send);
   sst_route.fpt_onCliReady(&sst_host, 0);
   sv_Run();
   TEST_ASSERT_EQUAL_UINT32(1U, su32_send);
   // A second ready changes nothing
   sst_route.fpt_onCliReady(&sst_host, 0);
   sv_Run();
   TEST_ASSERT_EQUAL_UINT32(1U, su32_send);
}

static void test_HostWithoutSetuServiceFails(void)
{
   sv_Connect(&sst_host);
   si_attachRet = 0;
   TEST_ASSERT_EQUAL_INT(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
   sst_route.fpt_onCliReady(&sst_host, -ENOENT);
   sv_Run();
   sv_AssertResult(HOST_AUTH_APP_TYPE_HELLO, eHRS_NO_PC_SVC, 0U);
   TEST_ASSERT_EQUAL_INT(eHAS_OPEN, ge_HostAuth_GetState());

   // The attach refused at once
   si_attachRet = -EINVAL;
   TEST_ASSERT_EQUAL_INT(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
   sv_AssertResult(HOST_AUTH_APP_TYPE_HELLO, eHRS_NO_PC_SVC, 0U);
}

static void test_ChallengeTransferFailures(void)
{
   sv_Connect(&sst_host);
   si_sendRet = -EBUSY;
   TEST_ASSERT_EQUAL_INT(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
   sv_AssertResult(HOST_AUTH_APP_TYPE_HELLO, eHRS_TRANSFER, 0U);
   TEST_ASSERT_EQUAL_INT(eHAS_OPEN, ge_HostAuth_GetState());

   si_sendRet = 0;
   TEST_ASSERT_EQUAL_INT(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
   sst_route.fpt_onTxDone(HOST_AUTH_APP_TYPE_CHALLENGE, eBS_TIMEOUT);
   sv_Run();
   sv_AssertResult(HOST_AUTH_APP_TYPE_HELLO, eHRS_TRANSFER, (uint8_t)eBS_TIMEOUT);
   TEST_ASSERT_EQUAL_INT(eHAS_OPEN, ge_HostAuth_GetState());

   // Delivered: nothing to report
   TEST_ASSERT_EQUAL_INT(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
   su32_shorts = 0U;
   sst_route.fpt_onTxDone(HOST_AUTH_APP_TYPE_CHALLENGE, eBS_OK);
   sv_Run();
   TEST_ASSERT_EQUAL_UINT32(0U, su32_shorts);
   TEST_ASSERT_EQUAL_INT(eHAS_AWAIT_FINISH, ge_HostAuth_GetState());
}

static void test_ChallengeKeepsTheBufferUntilItsTransferEnds(void)
{
   // HELLO and CHALLENGE share one buffer: no HELLO overwrites a CHALLENGE in flight
   sb_autoTxDone = false;
   sv_Connect(&sst_host);
   TEST_ASSERT_EQUAL_INT(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
   TEST_ASSERT_EQUAL_UINT32(1U, su32_send);
   // The handshake times out while the transfer still runs: back to a plain link,
   // but the buffer is still SETU's
   sv_AdvanceMs(CONFIG_HOST_AUTH_TIMEOUT_MS);
   TEST_ASSERT_EQUAL_INT(eHAS_OPEN, ge_HostAuth_GetState());
   gv_HostAuth_OnHostDisconnected(&sst_host);
   sv_Run();
   sv_Connect(&sst_host);
   TEST_ASSERT_NOT_EQUAL(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
   sv_AssertResult(HOST_AUTH_APP_TYPE_HELLO, eHRS_BUSY, 0U);
   // The transfer ends (link lost): the buffer is free
   sst_route.fpt_onTxDone(HOST_AUTH_APP_TYPE_CHALLENGE, eBS_DISCONNECTED);
   sv_Run();
   TEST_ASSERT_EQUAL_INT(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
   TEST_ASSERT_EQUAL_INT(eHAS_AWAIT_FINISH, ge_HostAuth_GetState());
}

static void test_HelloIsRefusedAtStart(void)
{
   // No host link
   TEST_ASSERT_NOT_EQUAL(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
   sv_AssertResult(HOST_AUTH_APP_TYPE_HELLO, eHRS_BAD_STATE, 0U);

   sv_Connect(&sst_host);
   // Too short (no certificate) and too long
   TEST_ASSERT_NOT_EQUAL(0, sst_route.fpt_onRxStart(HOST_AUTH_APP_TYPE_HELLO, HOST_AUTH_HELLO_HDR_LEN));
   sv_Run();
   sv_AssertResult(HOST_AUTH_APP_TYPE_HELLO, eHRS_PARSE, 0U);
   TEST_ASSERT_NOT_EQUAL(0, sst_route.fpt_onRxStart(HOST_AUTH_APP_TYPE_HELLO, HOST_AUTH_HELLO_MAX_LEN + 1U));
   sv_Run();
   sv_AssertResult(HOST_AUTH_APP_TYPE_HELLO, eHRS_PARSE, 0U);
   // The longest one is taken
   TEST_ASSERT_EQUAL_INT(0, si_SendHello(DEVICE_CERT_MAX_DER_LEN, HOST_AUTH_VERSION));

   // During a handshake
   TEST_ASSERT_NOT_EQUAL(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
   sv_AssertResult(HOST_AUTH_APP_TYPE_HELLO, eHRS_BUSY, 0U);

   // From the trusted host
   gv_HostAuth_OnHostDisconnected(&sst_host);
   sv_Run();
   sv_ToTrusted();
   TEST_ASSERT_NOT_EQUAL(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
   sv_AssertResult(HOST_AUTH_APP_TYPE_HELLO, eHRS_BAD_STATE, 0U);

   // Not a type the device receives
   TEST_ASSERT_NOT_EQUAL(0, sst_route.fpt_onRxStart(HOST_AUTH_APP_TYPE_CHALLENGE, 100U));
   sv_Run();
   sv_AssertResult(HOST_AUTH_APP_TYPE_CHALLENGE, eHRS_BAD_STATE, 0U);
}

static void test_HelloOfAnUnprovisionedDevice(void)
{
   se_provState = ePS_CA_OK;
   sv_Connect(&sst_host);
   TEST_ASSERT_NOT_EQUAL(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
   sv_AssertResult(HOST_AUTH_APP_TYPE_HELLO, eHRS_BAD_STATE, 0U);
}

static void test_HelloFromAnotherHostWhileOneIsBonded(void)
{
   TEST_ASSERT_EQUAL_INT(0, si_LoadRecord(&sst_addrOther));
   sv_Connect(&sst_host);
   TEST_ASSERT_EQUAL_INT(eHAS_HOST_BONDED, ge_HostAuth_GetState());
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, su32_setSec, "not the bonded host: no security request");
   TEST_ASSERT_NOT_EQUAL(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
   sv_AssertResult(HOST_AUTH_APP_TYPE_HELLO, eHRS_HOST_BONDED, 0U);
}

static void test_BondedHostMayAuthenticateAgain(void)
{
   // Its bond lost on the PC: the same address runs the handshake again
   TEST_ASSERT_EQUAL_INT(0, si_LoadRecord(&sst_addrHost));
   sv_Connect(&sst_host);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_setSec);
   TEST_ASSERT_EQUAL_INT(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
   TEST_ASSERT_EQUAL_INT(eHAS_AWAIT_FINISH, ge_HostAuth_GetState());
}

static void test_HelloContentErrors(void)
{
   sv_Connect(&sst_host);
   TEST_ASSERT_EQUAL_INT(0, si_SendHello(CERT_LEN, 2U));
   sv_AssertResult(HOST_AUTH_APP_TYPE_HELLO, eHRS_PARSE, 2U);

   se_hostCertRet = eDCS_BAD_PROFILE;
   TEST_ASSERT_EQUAL_INT(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
   sv_AssertResult(HOST_AUTH_APP_TYPE_HELLO, eHRS_BAD_CERT, (uint8_t)eDCS_BAD_PROFILE);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, su32_destroy, "no key was imported");

   se_hostCertRet = eDCS_OK;
   st_cryptoRet = PSA_ERROR_INSUFFICIENT_MEMORY;
   TEST_ASSERT_EQUAL_INT(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
   sv_AssertResult(HOST_AUTH_APP_TYPE_HELLO, eHRS_INTERNAL, 0U);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(1U, su32_destroy, "the host key is released");
   TEST_ASSERT_EQUAL_INT(eHAS_OPEN, ge_HostAuth_GetState());

   // After each failure a new HELLO is taken
   st_cryptoRet = PSA_SUCCESS;
   TEST_ASSERT_EQUAL_INT(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
   TEST_ASSERT_EQUAL_INT(eHAS_AWAIT_FINISH, ge_HostAuth_GetState());
}

static void test_FailedHelloTransferFreesTheBuffer(void)
{
   sv_Connect(&sst_host);
   TEST_ASSERT_EQUAL_INT(0, sst_route.fpt_onRxStart(HOST_AUTH_APP_TYPE_HELLO, 200U));
   sst_route.fpt_onRxDone(HOST_AUTH_APP_TYPE_HELLO, eBS_CRC_ERROR, 200U);
   sv_Run();
   TEST_ASSERT_EQUAL_INT(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
}

static void test_FinishVerifiesTheHost(void)
{
   sv_Connect(&sst_host);
   TEST_ASSERT_EQUAL_INT(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
   sv_SendFinish(HOST_AUTH_SIG_LEN);
   TEST_ASSERT_EQUAL_UINT32(0x4401U, st_lastVerifyKey);
   sv_AssertResult(HOST_AUTH_APP_TYPE_FINISH, eHRS_OK, 0U);
   TEST_ASSERT_EQUAL_INT(eHAS_AWAIT_PAIRING, ge_HostAuth_GetState());
   // Now this link may pair, with the derived passkey; another link may not
   TEST_ASSERT_EQUAL_INT(BT_SECURITY_ERR_SUCCESS, sstpt_overlay->pairing_accept(&sst_host, NULL));
   TEST_ASSERT_EQUAL_UINT32(123456U, sstpt_overlay->app_passkey(&sst_host));
   TEST_ASSERT_EQUAL_INT(BT_SECURITY_ERR_PAIR_NOT_ALLOWED, sstpt_overlay->pairing_accept(&sst_other, NULL));
   TEST_ASSERT_EQUAL_UINT32(BT_PASSKEY_RAND, sstpt_overlay->app_passkey(&sst_other));
   // The gate is still closed until the bond is made
   TEST_ASSERT_FALSE(gb_HostAuth_Admits(0x40U));
}

static void test_FinishErrors(void)
{
   sv_Connect(&sst_host);
   // Before HELLO
   sv_SendFinish(HOST_AUTH_SIG_LEN);
   sv_AssertResult(HOST_AUTH_APP_TYPE_FINISH, eHRS_BAD_STATE, 0U);

   // Wrong length: the handshake is over
   TEST_ASSERT_EQUAL_INT(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
   sv_SendFinish(HOST_AUTH_SIG_LEN - 1U);
   sv_AssertResult(HOST_AUTH_APP_TYPE_FINISH, eHRS_PARSE, 0U);
   TEST_ASSERT_EQUAL_INT(eHAS_OPEN, ge_HostAuth_GetState());

   // Bad signature: the host does not hold the certificate's key
   TEST_ASSERT_EQUAL_INT(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
   st_verifyRet = PSA_ERROR_INVALID_SIGNATURE;
   sv_SendFinish(HOST_AUTH_SIG_LEN);
   sv_AssertResult(HOST_AUTH_APP_TYPE_FINISH, eHRS_BAD_SIG, 0U);
   TEST_ASSERT_EQUAL_INT(eHAS_OPEN, ge_HostAuth_GetState());
   TEST_ASSERT_EQUAL_INT(BT_SECURITY_ERR_PAIR_NOT_ALLOWED, sstpt_overlay->pairing_accept(&sst_host, NULL));

   // A second FINISH after a good one
   st_verifyRet = PSA_SUCCESS;
   TEST_ASSERT_EQUAL_INT(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
   sv_SendFinish(HOST_AUTH_SIG_LEN);
   sv_SendFinish(HOST_AUTH_SIG_LEN);
   sv_AssertResult(HOST_AUTH_APP_TYPE_FINISH, eHRS_BAD_STATE, 0U);
   TEST_ASSERT_EQUAL_INT(eHAS_AWAIT_PAIRING, ge_HostAuth_GetState());
}

static void test_UnknownShortIsIgnored(void)
{
   uint8_t u8_b = 0U;

   sv_Connect(&sst_host);
   sst_route.fpt_onRxShort(0x6EU, &u8_b, 1U);
   sv_Run();
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("short message type 0x6e, 1 bytes ignored"));
}

/******************************************************************************/
/*  Pairing and trust                                                         */
/******************************************************************************/
static void test_BondMakesTheTrustedHost(void)
{
   sv_ToTrusted();
   TEST_ASSERT_EQUAL_UINT32(1U, su32_save);
   TEST_ASSERT_EQUAL_STRING("hauth/host", scar_saveName);
   TEST_ASSERT_EQUAL_UINT(HOST_AUTH_RECORD_LEN, st_savedLen);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(&sst_addrHost, su8ar_saved, 7U);
   TEST_ASSERT_TRUE(gb_HostAuth_IsHostAddr(&sst_addrHost));
   TEST_ASSERT_FALSE(gb_HostAuth_IsHostAddr(&sst_addrOther));
   TEST_ASSERT_FALSE(gb_HostAuth_IsHostAddr(NULL));
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(1U, su32_ledValue, "LED1 lit with the trusted host");
   TEST_ASSERT_EQUAL_UINT32(0U, su32_unpair);
}

static void test_TrustNeedsLevel4(void)
{
   sv_ToAwaitPairing();
   se_security = BT_SECURITY_L2;
   sstpt_authInfo->pairing_complete(&sst_host, true);
   sv_Run();
   TEST_ASSERT_EQUAL_INT_MESSAGE(eHAS_AWAIT_PAIRING, ge_HostAuth_GetState(), "bonded, but not level 4");
   se_security = BT_SECURITY_L4;
   gv_HostAuth_OnSecurityChanged(&sst_host, BT_SECURITY_L4, 0U);
   sv_Run();
   TEST_ASSERT_EQUAL_INT(eHAS_TRUSTED, ge_HostAuth_GetState());
}

static void test_PairingWithoutBondFails(void)
{
   sv_ToAwaitPairing();
   se_security = BT_SECURITY_L4;
   sstpt_authInfo->pairing_complete(&sst_host, false);
   sv_Run();
   sv_AssertResult(HOST_AUTH_APP_TYPE_FINISH, eHRS_PAIRING, 0xFFU);
   TEST_ASSERT_EQUAL_INT(eHAS_OPEN, ge_HostAuth_GetState());
   TEST_ASSERT_EQUAL_UINT32(0U, su32_save);
}

static void test_PairingFailureIsReported(void)
{
   sv_ToAwaitPairing();
   sstpt_authInfo->pairing_failed(&sst_host, BT_SECURITY_ERR_AUTH_FAIL);
   sv_Run();
   sv_AssertResult(HOST_AUTH_APP_TYPE_FINISH, eHRS_PAIRING, (uint8_t)BT_SECURITY_ERR_AUTH_FAIL);
   TEST_ASSERT_EQUAL_INT(eHAS_OPEN, ge_HostAuth_GetState());
   // Other links' results are not this module's
   su32_shorts = 0U;
   sstpt_authInfo->pairing_failed(&sst_other, BT_SECURITY_ERR_AUTH_FAIL);
   sstpt_authInfo->pairing_complete(&sst_other, true);
   sv_Run();
   TEST_ASSERT_EQUAL_UINT32(0U, su32_shorts);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_save);
}

static void test_BondedHostIsTrustedWhenEncrypted(void)
{
   TEST_ASSERT_EQUAL_INT(0, si_LoadRecord(&sst_addrHost));
   sb_hostBondListed = true;
   gv_HostAuth_OnBtReady();
   sv_Run();
   sv_Connect(&sst_host);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(1U, su32_setSec, "the bonded host is asked for level 4");
   TEST_ASSERT_EQUAL_INT(eHAS_HOST_BONDED, ge_HostAuth_GetState());
   TEST_ASSERT_FALSE(gb_HostAuth_Admits(0x40U));

   // A failed encryption (the PC lost its keys) changes nothing
   gv_HostAuth_OnSecurityChanged(&sst_host, BT_SECURITY_L1, (uint8_t)BT_SECURITY_ERR_PIN_OR_KEY_MISSING);
   sv_Run();
   TEST_ASSERT_EQUAL_INT(eHAS_HOST_BONDED, ge_HostAuth_GetState());
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("host link security failed"));

   se_security = BT_SECURITY_L4;
   gv_HostAuth_OnSecurityChanged(&sst_host, BT_SECURITY_L4, 0U);
   // Another link's security is not this module's
   gv_HostAuth_OnSecurityChanged(&sst_other, BT_SECURITY_L4, 0U);
   sv_Run();
   TEST_ASSERT_EQUAL_INT(eHAS_TRUSTED, ge_HostAuth_GetState());
   TEST_ASSERT_TRUE(gb_HostAuth_Admits(0x40U));
}

static void test_OneHostBondOnly(void)
{
   // A record of another host is replaced (and its bond deleted) by a new bond
   (void)k_mutex_lock(&sst_addrLock, K_FOREVER);
   sst_hostAddr = sst_addrOther;
   k_mutex_unlock(&sst_addrLock);
   (void)atomic_set(&st_hostBonded, 1);
   sv_SaveHost(&sst_addrHost);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_unpair);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(&sst_addrOther, &sst_unpairAddr, 7U);
   TEST_ASSERT_TRUE(gb_HostAuth_IsHostAddr(&sst_addrHost));
   TEST_ASSERT_FALSE(gb_HostAuth_IsHostAddr(&sst_addrOther));
   // The same host again: its bond stays
   sv_SaveHost(&sst_addrHost);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_unpair);
}

/******************************************************************************/
/*  Links                                                                     */
/******************************************************************************/
static void test_SecondHostLinkIsIgnored(void)
{
   sv_Connect(&sst_host);
   gv_HostAuth_OnHostConnected(&sst_other);
   sv_Run();
   TEST_ASSERT_EQUAL_PTR(&sst_host, atomic_ptr_get(&st_hostConn));
   gv_HostAuth_OnHostConnected(NULL);
   gv_HostAuth_OnHostDisconnected(&sst_other);
   gv_HostAuth_OnHostDisconnected(NULL);
   sv_Run();
   TEST_ASSERT_EQUAL_PTR(&sst_host, atomic_ptr_get(&st_hostConn));
}

static void test_DisconnectEndsTheHandshake(void)
{
   sv_Connect(&sst_host);
   TEST_ASSERT_EQUAL_INT(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
   su32_destroy = 0U;
   gv_HostAuth_OnHostDisconnected(&sst_host);
   // Released at once: the gate is closed and a new host can connect
   TEST_ASSERT_NULL(atomic_ptr_get(&st_hostConn));
   TEST_ASSERT_FALSE(gb_HostAuth_Admits(0x40U));
   sv_Run();
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(1U, su32_destroy, "the host key is released");
   TEST_ASSERT_FALSE_MESSAGE(gb_HostAuth_WindowOpen(), "not trusted: no grace window");
   // A FINISH that arrives late finds no handshake
   sv_SendFinish(HOST_AUTH_SIG_LEN);
   sv_AssertResult(HOST_AUTH_APP_TYPE_FINISH, eHRS_BAD_STATE, 0U);
   sv_Connect(&sst_host);
   TEST_ASSERT_EQUAL_INT(eHAS_OPEN, ge_HostAuth_GetState());
}

static void test_OverlayFailureIsLogged(void)
{
   si_overlayRet = -EALREADY;
   sv_Connect(&sst_host);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("host SMP callbacks not set"));
}

static void test_HandshakeTimesOut(void)
{
   sv_Connect(&sst_host);
   TEST_ASSERT_EQUAL_INT(0, si_SendHello(CERT_LEN, HOST_AUTH_VERSION));
   sv_AdvanceMs(CONFIG_HOST_AUTH_TIMEOUT_MS - 1);
   TEST_ASSERT_EQUAL_INT(eHAS_AWAIT_FINISH, ge_HostAuth_GetState());
   sv_AdvanceMs(1);
   sv_AssertResult(HOST_AUTH_APP_TYPE_HELLO, eHRS_TIMEOUT, 0U);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_disconnect);
   TEST_ASSERT_EQUAL_PTR(&sst_host, sstpt_disconnected);

   // The pairing after FINISH has the same limit
   gv_HostAuth_OnHostDisconnected(&sst_host);
   sv_Run();
   sv_ToAwaitPairing();
   sv_AdvanceMs(CONFIG_HOST_AUTH_TIMEOUT_MS);
   sv_AssertResult(HOST_AUTH_APP_TYPE_FINISH, eHRS_TIMEOUT, 0U);
   TEST_ASSERT_EQUAL_UINT32(2U, su32_disconnect);

   // A trusted host has no limit
   gv_HostAuth_OnHostDisconnected(&sst_host);
   sv_Run();
   sv_ToTrusted();
   sv_AdvanceMs(CONFIG_HOST_AUTH_TIMEOUT_MS * 2);
   TEST_ASSERT_EQUAL_INT(eHAS_TRUSTED, ge_HostAuth_GetState());
   TEST_ASSERT_EQUAL_UINT32(2U, su32_disconnect);
}

/******************************************************************************/
/*  Window                                                                    */
/******************************************************************************/
static void test_WindowOpensAndCloses(void)
{
   TEST_ASSERT_FALSE(gb_HostAuth_WindowOpen());
   gv_HostAuth_OpenWindow();
   sv_Run();
   TEST_ASSERT_TRUE(gb_HostAuth_WindowOpen());
   TEST_ASSERT_EQUAL_UINT32(1U, su32_refresh);
   // The LED blinks
   TEST_ASSERT_EQUAL_UINT32(1U, su32_ledValue);
   sv_AdvanceMs(HOST_AUTH_BLINK_MS);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_ledValue);

   sv_AdvanceMs(CONFIG_HOST_AUTH_WINDOW_MS);
   TEST_ASSERT_FALSE(gb_HostAuth_WindowOpen());
   TEST_ASSERT_EQUAL_UINT32(2U, su32_refresh);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_ledValue);
}

static void test_WindowPressAgainRestartsIt(void)
{
   gv_HostAuth_OpenWindow();
   sv_Run();
   sv_AdvanceMs(CONFIG_HOST_AUTH_WINDOW_MS - 1000);
   gv_HostAuth_OpenWindow();
   sv_Run();
   sv_AdvanceMs(2000);
   TEST_ASSERT_TRUE(gb_HostAuth_WindowOpen());
}

static void test_HostConnectionClosesTheWindow(void)
{
   gv_HostAuth_OpenWindow();
   sv_Run();
   sv_Connect(&sst_host);
   TEST_ASSERT_FALSE(gb_HostAuth_WindowOpen());
   TEST_ASSERT_EQUAL_UINT32(2U, su32_refresh);
}

static void test_TrustedHostLossOpensTheGraceWindow(void)
{
   sv_ToTrusted();
   gv_HostAuth_OnHostDisconnected(&sst_host);
   TEST_ASSERT_FALSE(gb_HostAuth_Admits(0x40U));
   sv_Run();
   TEST_ASSERT_TRUE(gb_HostAuth_WindowOpen());
   sv_AdvanceMs(CONFIG_HOST_AUTH_GRACE_MS);
   TEST_ASSERT_FALSE(gb_HostAuth_WindowOpen());
}

static void test_WindowFlagInStatus(void)
{
   const uint8_t *u8pt_s;

   sv_Connect(&sst_host);
   gv_HostAuth_OpenWindow();
   sv_Run();
   u8pt_s = su8pt_LastShort(HOST_AUTH_APP_TYPE_STATUS);
   TEST_ASSERT_EQUAL_HEX8(VEC_HAUTH_FLAG_WINDOW_OPEN, u8pt_s[1]);
}

/******************************************************************************/
/*  Forgetting the host                                                       */
/******************************************************************************/
static void test_HoldForgetsTheHostAndOpensTheWindow(void)
{
   sv_ToTrusted();
   gv_HostAuth_ForgetHostAndOpen();
   sv_Run();
   TEST_ASSERT_EQUAL_UINT32(1U, su32_unpair);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(&sst_addrHost, &sst_unpairAddr, 7U);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_settingsDelete);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_disconnect);
   TEST_ASSERT_FALSE_MESSAGE(gb_HostAuth_Admits(0x40U), "untrusted at once");
   TEST_ASSERT_FALSE(gb_HostAuth_IsHostAddr(&sst_addrHost));
   TEST_ASSERT_TRUE(gb_HostAuth_WindowOpen());

   // Its link goes down: no grace window on top, the button's window stays
   gv_HostAuth_OnHostDisconnected(&sst_host);
   sv_Run();
   sv_AdvanceMs(CONFIG_HOST_AUTH_WINDOW_MS - 1);
   TEST_ASSERT_TRUE(gb_HostAuth_WindowOpen());

   // A new host can now authenticate
   sv_ToTrusted();
}

static void test_HoldWithoutHost(void)
{
   gv_HostAuth_ForgetHostAndOpen();
   sv_Run();
   TEST_ASSERT_EQUAL_UINT32(0U, su32_unpair);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_disconnect);
   TEST_ASSERT_TRUE(gb_HostAuth_WindowOpen());
}

static void test_WipeForgetsTheRecord(void)
{
   sv_ToTrusted();
   gv_HostAuth_Forget();
   sv_Run();
   TEST_ASSERT_EQUAL_UINT32(1U, su32_settingsDelete);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, su32_unpair, "the wipe deleted every bond already");
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, su32_disconnect, "the host link stays");
   TEST_ASSERT_FALSE(gb_HostAuth_IsTrustedConn(&sst_host));
   TEST_ASSERT_FALSE(gb_HostAuth_IsHostAddr(&sst_addrHost));
   // Unprovisioned now: the host reaches provisioning only
   se_provState = ePS_KEY_READY;
   TEST_ASSERT_TRUE(gb_HostAuth_Admits(0x22U));
   TEST_ASSERT_FALSE(gb_HostAuth_Admits(0x40U));
}

/******************************************************************************/
/*  Start-up and the record                                                   */
/******************************************************************************/
static void test_BtReadyKeepsTheRecordWithItsBond(void)
{
   TEST_ASSERT_EQUAL_INT(0, si_LoadRecord(&sst_addrHost));
   sb_hostBondListed = true;
   gv_HostAuth_OnBtReady();
   sv_Run();
   TEST_ASSERT_TRUE(gb_HostAuth_IsHostAddr(&sst_addrHost));
   TEST_ASSERT_EQUAL_UINT32(0U, su32_settingsDelete);
   TEST_ASSERT_FALSE_MESSAGE(gb_HostAuth_WindowOpen(), "no window at boot");
}

static void test_BtReadyDropsAStaleRecord(void)
{
   // No bond for it
   TEST_ASSERT_EQUAL_INT(0, si_LoadRecord(&sst_addrHost));
   gv_HostAuth_OnBtReady();
   sv_Run();
   TEST_ASSERT_FALSE(gb_HostAuth_IsHostAddr(&sst_addrHost));
   TEST_ASSERT_EQUAL_UINT32(1U, su32_settingsDelete);

   // An unprovisioned device keeps none
   TEST_ASSERT_EQUAL_INT(0, si_LoadRecord(&sst_addrHost));
   sb_hostBondListed = true;
   se_provState = ePS_KEY_READY;
   gv_HostAuth_OnBtReady();
   sv_Run();
   TEST_ASSERT_FALSE(gb_HostAuth_IsHostAddr(&sst_addrHost));
   TEST_ASSERT_EQUAL_UINT32(2U, su32_settingsDelete);

   // No record: nothing to do
   gv_HostAuth_OnBtReady();
   sv_Run();
   TEST_ASSERT_EQUAL_UINT32(2U, su32_settingsDelete);
}

static void test_RecordLoadErrors(void)
{
   uint8_t u8ar_rec[HOST_AUTH_RECORD_LEN] = { 0 };

   TEST_ASSERT_EQUAL_INT(-ENOENT, settings_handler_hauth.h_set("other", 7U, st_ReadRecord, u8ar_rec));
   TEST_ASSERT_EQUAL_INT(-EINVAL, settings_handler_hauth.h_set("host", 6U, st_ReadRecord, u8ar_rec));
   u8ar_rec[0] = 2U;
   TEST_ASSERT_EQUAL_INT(-EINVAL, settings_handler_hauth.h_set("host", 7U, st_ReadRecord, u8ar_rec));
   TEST_ASSERT_EQUAL_INT(0, atomic_get(&st_hostBonded));
}

int main(void)
{
   (void)setvbuf(stdout, NULL, _IONBF, 0);
   UNITY_BEGIN();
   RUN_TEST(test_InitRegistersRangeGateAndCallbacks);
   RUN_TEST(test_InitErrorsAreReturned);
   RUN_TEST(test_WireConstantsMatchTheVectors);
   RUN_TEST(test_GateOfAnUnprovisionedDevice);
   RUN_TEST(test_GateOfAProvisionedDevice);
   RUN_TEST(test_TrustedHostReachesEverything);
   RUN_TEST(test_RefusalsAreReported);
   RUN_TEST(test_StatusFollowsTheState);
   RUN_TEST(test_NoStatusWithoutAHost);
   RUN_TEST(test_HostLinkGetsItsOwnSmpCallbacks);
   RUN_TEST(test_HelloIsAnsweredWithAChallenge);
   RUN_TEST(test_ChallengeWaitsForTheClient);
   RUN_TEST(test_HostWithoutSetuServiceFails);
   RUN_TEST(test_ChallengeTransferFailures);
   RUN_TEST(test_ChallengeKeepsTheBufferUntilItsTransferEnds);
   RUN_TEST(test_HelloIsRefusedAtStart);
   RUN_TEST(test_HelloOfAnUnprovisionedDevice);
   RUN_TEST(test_HelloFromAnotherHostWhileOneIsBonded);
   RUN_TEST(test_BondedHostMayAuthenticateAgain);
   RUN_TEST(test_HelloContentErrors);
   RUN_TEST(test_FailedHelloTransferFreesTheBuffer);
   RUN_TEST(test_FinishVerifiesTheHost);
   RUN_TEST(test_FinishErrors);
   RUN_TEST(test_UnknownShortIsIgnored);
   RUN_TEST(test_BondMakesTheTrustedHost);
   RUN_TEST(test_TrustNeedsLevel4);
   RUN_TEST(test_PairingWithoutBondFails);
   RUN_TEST(test_PairingFailureIsReported);
   RUN_TEST(test_BondedHostIsTrustedWhenEncrypted);
   RUN_TEST(test_OneHostBondOnly);
   RUN_TEST(test_SecondHostLinkIsIgnored);
   RUN_TEST(test_DisconnectEndsTheHandshake);
   RUN_TEST(test_OverlayFailureIsLogged);
   RUN_TEST(test_HandshakeTimesOut);
   RUN_TEST(test_WindowOpensAndCloses);
   RUN_TEST(test_WindowPressAgainRestartsIt);
   RUN_TEST(test_HostConnectionClosesTheWindow);
   RUN_TEST(test_TrustedHostLossOpensTheGraceWindow);
   RUN_TEST(test_WindowFlagInStatus);
   RUN_TEST(test_HoldForgetsTheHostAndOpensTheWindow);
   RUN_TEST(test_HoldWithoutHost);
   RUN_TEST(test_WipeForgetsTheRecord);
   RUN_TEST(test_BtReadyKeepsTheRecordWithItsBond);
   RUN_TEST(test_BtReadyDropsAStaleRecord);
   RUN_TEST(test_RecordLoadErrors);
   return UNITY_END();
}
