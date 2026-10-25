/**
 * @file          test_pair.c
 * @brief         Host unit tests for certificate-based pairing (_ASW/_PAIR/Pair.c):
 *                the host's CONTROL commands and STATUS, both roles from START
 *                to PAIRED, every failure with its error and detail, the
 *                guards on SETU objects, SMP and SECURED, timeouts, link
 *                loss, CANCEL, UNPAIR and the provisioning wipe. Pair.c is
 *                included; the BT stack, SETU, the router, certificate
 *                verification, OOB signing (tested on real crypto by
 *                test_pair_oob.c), provisioning, the DK LEDs and the service
 *                are stubbed and record their calls. Frames and statuses are
 *                checked against wire.json ("pairing").
 *                Contract: _DOC/Pairing/PROTOCOL.md.
 *
 * @date          06/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#include "Pair.c"
#include "unity.h"
#include "wire_vectors.h"

/******************************************************************************/
/*  Links and addresses                                                       */
/******************************************************************************/
static struct bt_conn sst_host = { 1 };
static struct bt_conn sst_peer = { 2 };
static struct bt_conn sst_other = { 3 };
static bt_addr_le_t sst_addrA;            /* this device (vector "own")  */
static bt_addr_le_t sst_addrB;            /* the peer (vector "peer")    */
static bt_addr_le_t sst_addrOther;
static bt_addr_le_t sst_ownId;
static bool sb_hostUp;

const bt_addr_le_t *bt_conn_get_dst(const struct bt_conn *conn)
{
   if (conn == &sst_peer) { return &sst_addrB; }
   if (conn == &sst_other) { return &sst_addrOther; }
   return &sst_addrOther;
}

void bt_id_get(bt_addr_le_t *addrs, size_t *count)
{
   TEST_ASSERT_TRUE(*count >= 1U);
   addrs[0] = sst_ownId;
   *count = 1U;
}

struct bt_conn *gstpt_BLE_GetHostConn(void) { return sb_hostUp ? &sst_host : NULL; }

static uint32_t su32_refresh;
void gv_BLE_RefreshAdv(void) { su32_refresh++; }

/******************************************************************************/
/*  Stubs: advertising, scanning, connections                                 */
/******************************************************************************/
static int si_advStartRet;
static uint32_t su32_advStart, su32_advStop;
static struct bt_le_adv_param sst_advParam;
static bt_addr_le_t sst_advPeer;
static size_t st_advDataLen;

int bt_le_adv_start(const struct bt_le_adv_param *param, const struct bt_data *ad,
   size_t ad_len, const struct bt_data *sd, size_t sd_len)
{
   su32_advStart++;
   sst_advParam = *param;
   if (param->peer != NULL) { sst_advPeer = *param->peer; }
   st_advDataLen = ad_len + sd_len + ((ad != NULL) ? 1U : 0U) + ((sd != NULL) ? 1U : 0U);
   return si_advStartRet;
}

int bt_le_adv_stop(void) { su32_advStop++; return 0; }

static int si_scanStartRet;
static uint32_t su32_scanStart, su32_scanStop;
static bt_le_scan_cb_t *sfpt_scanCb;

int bt_le_scan_start(const struct bt_le_scan_param *param, bt_le_scan_cb_t cb)
{
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(BT_LE_SCAN_TYPE_PASSIVE, param->type, "passive scan");
   su32_scanStart++;
   sfpt_scanCb = cb;
   return si_scanStartRet;
}

int bt_le_scan_stop(void) { su32_scanStop++; return 0; }

static int si_createRet;
static uint32_t su32_create;
static bt_addr_le_t sst_createPeer;
static struct bt_le_conn_param sst_createParam;

int bt_conn_le_create(const bt_addr_le_t *peer, const struct bt_conn_le_create_param *create_param,
   const struct bt_le_conn_param *conn_param, struct bt_conn **conn)
{
   (void)create_param;
   su32_create++;
   sst_createPeer = *peer;
   sst_createParam = *conn_param;
   *conn = (si_createRet == 0) ? &sst_peer : NULL;
   return si_createRet;
}

static uint32_t su32_disconnect;
static struct bt_conn *sstpt_disconnected;

int bt_conn_disconnect(struct bt_conn *conn, uint8_t reason)
{
   TEST_ASSERT_EQUAL_HEX8(BT_HCI_ERR_REMOTE_USER_TERM_CONN, reason);
   su32_disconnect++;
   sstpt_disconnected = conn;
   return 0;
}

/******************************************************************************/
/*  Stubs: bonds and SMP                                                      */
/******************************************************************************/
static uint32_t su32_unpair;
static bool sb_unpairAll;
static bt_addr_le_t sst_unpairAddr;
static bool sb_hasBond;
static bool sb_otherBondFirst;

int bt_unpair(uint8_t id, const bt_addr_le_t *addr)
{
   TEST_ASSERT_EQUAL_UINT8(BT_ID_DEFAULT, id);
   su32_unpair++;
   sb_unpairAll = (addr == NULL);
   if (addr != NULL) { sst_unpairAddr = *addr; }
   return 0;
}

void bt_foreach_bond(uint8_t id, void (*func)(const struct bt_bond_info *info, void *user_data),
   void *user_data)
{
   struct bt_bond_info st_info;

   TEST_ASSERT_EQUAL_UINT8(BT_ID_DEFAULT, id);
   if (sb_hasBond)
   {
      /* two bonds: without a record the first one wins */
      st_info.addr = sb_otherBondFirst ? sst_addrOther : sst_addrB;
      func(&st_info, user_data);
      st_info.addr = sb_otherBondFirst ? sst_addrB : sst_addrOther;
      func(&st_info, user_data);
   }
}

/******************************************************************************/
/*  Stubs: settings (the bond record)                                         */
/******************************************************************************/
static int si_saveRet;
static uint32_t su32_save, su32_settingsDelete;
static char scar_saveName[32], scar_deleteName[32];
static uint8_t su8ar_saved[16];
static size_t st_savedLen;

int settings_save_one(const char *name, const void *value, size_t val_len)
{
   su32_save++;
   (void)snprintf(scar_saveName, sizeof(scar_saveName), "%s", name);
   TEST_ASSERT_TRUE(val_len <= sizeof(su8ar_saved));
   (void)memcpy(su8ar_saved, value, val_len);
   st_savedLen = val_len;
   return si_saveRet;
}

int settings_delete(const char *name)
{
   su32_settingsDelete++;
   (void)snprintf(scar_deleteName, sizeof(scar_deleteName), "%s", name);
   return 0;
}

/** settings_load()'s read callback: hands out su8ar_saved, or an error. */
static ssize_t st_readRet;
static ssize_t st_ReadRecord(void *cb_arg, void *data, size_t len)
{
   (void)cb_arg;
   if (st_readRet < 0) { return st_readRet; }
   (void)memcpy(data, su8ar_saved, MIN(len, st_savedLen));
   return (ssize_t)MIN(len, st_savedLen);
}

static int si_setSecRet;
static uint32_t su32_setSec;
static bt_security_t se_security;

int bt_conn_set_security(struct bt_conn *conn, bt_security_t sec)
{
   TEST_ASSERT_EQUAL_PTR(&sst_peer, conn);
   TEST_ASSERT_EQUAL_INT_MESSAGE(BT_SECURITY_L4, sec, "authenticated LE Secure Connections");
   su32_setSec++;
   return si_setSecRet;
}

bt_security_t bt_conn_get_security(const struct bt_conn *conn)
{
   (void)conn;
   return se_security;
}

static int si_oobGetRet;
static uint32_t su32_oobGet;
static bool sb_scFlag;
static uint32_t su32_scFlagSets;

int bt_le_oob_get_local(uint8_t id, struct bt_le_oob *oob)
{
   TEST_ASSERT_EQUAL_UINT8(BT_ID_DEFAULT, id);
   su32_oobGet++;
   oob->addr = sst_ownId;
   (void)memcpy(oob->le_sc_data.r, gu8ar_vecPairOobR, 16U);
   (void)memcpy(oob->le_sc_data.c, gu8ar_vecPairOobC, 16U);
   return si_oobGetRet;
}

void bt_le_oob_set_sc_flag(bool enable) { sb_scFlag = enable; su32_scFlagSets++; }

static int si_setScDataRet;
static uint32_t su32_setScData;
static const struct bt_le_oob_sc_data *sstpt_scLocal;
static const struct bt_le_oob_sc_data *sstpt_scRemote;

int bt_le_oob_set_sc_data(struct bt_conn *conn, const struct bt_le_oob_sc_data *oobd_local,
   const struct bt_le_oob_sc_data *oobd_remote)
{
   TEST_ASSERT_EQUAL_PTR(&sst_peer, conn);
   su32_setScData++;
   sstpt_scLocal = oobd_local;
   sstpt_scRemote = oobd_remote;
   return si_setScDataRet;
}

static const struct bt_conn_auth_cb *sstpt_authCb;
static struct bt_conn_auth_info_cb *sstpt_authInfoCb;
static int si_authRegRet, si_authInfoRegRet;
static uint32_t su32_authCancel;
static struct bt_conn *sstpt_authCancelConn;

int bt_conn_auth_cb_register(const struct bt_conn_auth_cb *cb) { sstpt_authCb = cb; return si_authRegRet; }
int bt_conn_auth_info_cb_register(struct bt_conn_auth_info_cb *cb)
{
   sstpt_authInfoCb = cb;
   return si_authInfoRegRet;
}
int bt_conn_auth_cancel(struct bt_conn *conn)
{
   su32_authCancel++;
   sstpt_authCancelConn = conn;
   return 0;
}

/******************************************************************************/
/*  Stubs: GATT client (SECURED on the peer)                                  */
/******************************************************************************/
static int si_discoverRet, si_writeRet;
static uint32_t su32_discover, su32_write;
static struct bt_gatt_discover_params *sstpt_discover;
static struct bt_gatt_write_params *sstpt_write;

int bt_gatt_discover(struct bt_conn *conn, struct bt_gatt_discover_params *params)
{
   TEST_ASSERT_EQUAL_PTR(&sst_peer, conn);
   su32_discover++;
   sstpt_discover = params;
   return si_discoverRet;
}

int bt_gatt_write(struct bt_conn *conn, struct bt_gatt_write_params *params)
{
   TEST_ASSERT_EQUAL_PTR(&sst_peer, conn);
   su32_write++;
   sstpt_write = params;
   return si_writeRet;
}

/******************************************************************************/
/*  Stubs: SETU, router, certificates, OOB signing, provisioning, LED     */
/******************************************************************************/
static SETURoute_T sst_route;
static int si_registerRet;
static uint32_t su32_filterSet, su32_filterClear;
static uint8_t su8_filterFirst, su8_filterLast;
static bool sb_filterOn;

int gi_SETURouter_Register(const SETURoute_T *stpt_route) { sst_route = *stpt_route; return si_registerRet; }
void gv_SETURouter_SetFilter(uint8_t u8_first, uint8_t u8_last)
{
   su32_filterSet++;
   su8_filterFirst = u8_first;
   su8_filterLast = u8_last;
   sb_filterOn = true;
}
void gv_SETURouter_ClearFilter(void) { su32_filterClear++; sb_filterOn = false; }

static int si_attachRet;
static uint32_t su32_attach;
static struct bt_conn *sstpt_attachConn;
static uint8_t su8_attachOwner;

int gi_SETURouter_ClientAttach(struct bt_conn *stpt_conn, uint8_t u8_ownerAppType)
{
   su32_attach++;
   sstpt_attachConn = stpt_conn;
   su8_attachOwner = u8_ownerAppType;
   return si_attachRet;
}

static int si_rebindRet;
static uint32_t su32_rebind;
static struct bt_conn *sstpt_srvConn;
static uint32_t su32_detach;
static bool sb_rxBusy, sb_txBusy;
static uint32_t su32_abortRx, su32_abortTx;

int gi_SETUS_Rebind(struct bt_conn *stpt_conn)
{
   su32_rebind++;
   if (si_rebindRet == 0) { sstpt_srvConn = stpt_conn; }
   return si_rebindRet;
}
int gi_SETUC_Detach(void) { su32_detach++; return 0; }
bool gb_SETUS_IsRxBusy(void) { return sb_rxBusy; }
bool gb_SETUC_IsTxBusy(void) { return sb_txBusy; }
void gv_SETUS_AbortRx(void) { su32_abortRx++; }
void gv_SETUC_AbortTx(void) { su32_abortTx++; }

static int si_sendRet;
static uint32_t su32_send;
static uint8_t su8ar_sendTypes[8];
static const void *svptar_sendData[8];
static uint32_t su32ar_sendLen[8];

int gi_SETUC_SendBuffer(uint8_t u8_appType, const void *vpt_data, uint32_t u32_len)
{
   if (si_sendRet == 0)
   {
      su8ar_sendTypes[su32_send % 8U] = u8_appType;
      svptar_sendData[su32_send % 8U] = vpt_data;
      su32ar_sendLen[su32_send % 8U] = u32_len;
      su32_send++;
   }
   return si_sendRet;
}

DeviceCertData_T gst_deviceCertData;
static DeviceCertStatus_E se_verifyRet;
static uint32_t su32_verify;
static uint32_t su32_verifyLen;
static bool sb_anchor;
#define PEER_KEY_ID          (77U)

DeviceCertStatus_E ge_VerifyRemoteDeviceCertificate(const uint8_t *u8pt_der, size_t t_len,
   psa_key_id_t *tpt_remotePubKeyID)
{
   (void)u8pt_der;
   su32_verify++;
   su32_verifyLen = (uint32_t)t_len;
   if (se_verifyRet == eDCS_OK) { *tpt_remotePubKeyID = PEER_KEY_ID; }
   return se_verifyRet;
}
bool gb_IsTrustAnchorSet(void) { return sb_anchor; }

static uint32_t su32_destroy;
static psa_key_id_t st_destroyed;
psa_status_t psa_destroy_key(psa_key_id_t key) { su32_destroy++; st_destroyed = key; return PSA_SUCCESS; }

static psa_status_t st_signRet, st_oobVerifyRet;
static uint32_t su32_sign, su32_oobVerify;
static uint8_t su8ar_signSender[7], su8ar_signReceiver[7];
static uint8_t su8ar_verifySender[7], su8ar_verifyReceiver[7];
static psa_key_id_t st_signKeyUsed, st_verifyKeyUsed;

psa_status_t gt_PairOob_Sign(psa_key_id_t t_key, const uint8_t *u8pt_rand,
   const uint8_t *u8pt_confirm, const uint8_t *u8pt_sender, const uint8_t *u8pt_receiver,
   uint8_t *u8pt_frame)
{
   su32_sign++;
   st_signKeyUsed = t_key;
   (void)memcpy(su8ar_signSender, u8pt_sender, 7U);
   (void)memcpy(su8ar_signReceiver, u8pt_receiver, 7U);
   (void)memcpy(&u8pt_frame[0], u8pt_rand, 16U);
   (void)memcpy(&u8pt_frame[16], u8pt_confirm, 16U);
   (void)memset(&u8pt_frame[32], 0x5A, 64U);
   return st_signRet;
}

psa_status_t gt_PairOob_Verify(psa_key_id_t t_peerKey, const uint8_t *u8pt_frame,
   const uint8_t *u8pt_sender, const uint8_t *u8pt_receiver)
{
   (void)u8pt_frame;
   su32_oobVerify++;
   st_verifyKeyUsed = t_peerKey;
   (void)memcpy(su8ar_verifySender, u8pt_sender, 7U);
   (void)memcpy(su8ar_verifyReceiver, u8pt_receiver, 7U);
   return st_oobVerifyRet;
}

static ProvState_E se_provState;
ProvState_E ge_Prov_GetState(void) { return se_provState; }

/* Host authentication: the host link is the trusted host unless a test says
   otherwise; a host bond (the address) can be listed among the bonds */
static bool sb_hostTrusted;
static bool sb_hostBondIsOther;
bool gb_HostAuth_IsTrustedConn(const struct bt_conn *stpt_conn)
{
   return sb_hostTrusted && (stpt_conn == &sst_host);
}
bool gb_HostAuth_IsHostAddr(const bt_addr_le_t *stpt_addr)
{
   return sb_hostBondIsOther && (bt_addr_le_cmp(stpt_addr, &sst_addrOther) == 0);
}

static int si_ledInitRet;
static uint32_t su32_ledSets;
static uint32_t su32_ledValue;
int dk_leds_init(void) { return si_ledInitRet; }
int dk_set_led(uint8_t led_idx, uint32_t val)
{
   TEST_ASSERT_EQUAL_UINT8(DK_LED1, led_idx);
   su32_ledSets++;
   su32_ledValue = val;
   return 0;
}

static uint32_t su32_notify;
static uint8_t su8ar_notified[PAIR_STATUS_LEN];
int gi_PairSvc_NotifyStatus(struct bt_conn *stpt_conn, const uint8_t *u8pt_status, uint16_t u16_len)
{
   TEST_ASSERT_EQUAL_PTR_MESSAGE(&sst_host, stpt_conn, "STATUS goes to the host only");
   TEST_ASSERT_EQUAL_UINT16(PAIR_STATUS_LEN, u16_len);
   su32_notify++;
   (void)memcpy(su8ar_notified, u8pt_status, u16_len);
   return 0;
}

/******************************************************************************/
/*  Helpers                                                                   */
/******************************************************************************/
static const PairVector_T *sstpt_PairVec(const PairVector_T *stpt_set, uint32_t u32_n,
   const char *cpt_name)
{
   uint32_t i;

   for (i = 0U; i < u32_n; i++)
   {
      if (strcmp(stpt_set[i].cpt_name, cpt_name) == 0) { return &stpt_set[i]; }
   }
   TEST_FAIL_MESSAGE(cpt_name);
   return NULL;
}
#define CONTROL_VEC(n)       sstpt_PairVec(gstar_vecPairControls, ARRAY_SIZE(gstar_vecPairControls), (n))
#define STATUS_VEC(n)        sstpt_PairVec(gstar_vecPairStatuses, ARRAY_SIZE(gstar_vecPairStatuses), (n))

static void sv_RunPair(void)
{
   gv_SimRunThread(sv_PairThread);
   // The work queue shows the LED
   (void)gb_SimRunDelayedWork(&sst_ledWork);
}

static uint8_t su8ar_statusNow[PAIR_STATUS_LEN];

static uint8_t su8_State(void)
{
   gv_Pair_GetStatus(su8ar_statusNow);
   return su8ar_statusNow[0];
}

/** STATUS (read and last notified) is the vector. */
static void sv_AssertStatusIs(const char *cpt_name)
{
   const PairVector_T *v = STATUS_VEC(cpt_name);

   TEST_ASSERT_EQUAL_UINT8(PAIR_STATUS_LEN, v->u8_wireLen);
   gv_Pair_GetStatus(su8ar_statusNow);
   TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(v->u8ar_wire, su8ar_statusNow, PAIR_STATUS_LEN, cpt_name);
   TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(v->u8ar_wire, su8ar_notified, PAIR_STATUS_LEN, cpt_name);
}

static void sv_AssertFailed(uint8_t u8_error, uint8_t u8_detail)
{
   gv_Pair_GetStatus(su8ar_statusNow);
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(ePST_FAILED, su8ar_statusNow[0], "state");
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(u8_error, su8ar_statusNow[1], "error");
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(u8_detail, su8ar_statusNow[2], "detail");
   TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(su8ar_statusNow, su8ar_notified, PAIR_STATUS_LEN,
      "the host was told");
   TEST_ASSERT_FALSE(gb_Pair_IsRunning());
   TEST_ASSERT_FALSE_MESSAGE(sb_scFlag, "OOB flag cleared");
   TEST_ASSERT_FALSE_MESSAGE(gb_Pair_IsAdvertising(), "advertiser released");
}

static void sv_StartRun(PairRole_E e_role)
{
   uint8_t u8ar_cmd[PAIR_START_LEN];

   u8ar_cmd[0] = PAIR_OP_START;
   u8ar_cmd[1] = (uint8_t)e_role;
   (void)memcpy(&u8ar_cmd[2], &sst_addrB, 7U);
   TEST_ASSERT_EQUAL_INT(0, gt_Pair_OnControlWrite(&sst_host, u8ar_cmd, sizeof(u8ar_cmd)));
   sv_RunPair();
}

/** The peer link comes up (the central first sees the peer and connects). */
static void sv_LinkUp(PairRole_E e_role)
{
   uint32_t u32_creates = su32_create;

   if (e_role == ePRL_CENTRAL)
   {
      sfpt_scanCb(&sst_addrB, -40, BT_GAP_ADV_TYPE_ADV_DIRECT_IND, NULL);
      sv_RunPair();
      TEST_ASSERT_EQUAL_UINT32(u32_creates + 1U, su32_create);
   }
   TEST_ASSERT_TRUE(gb_Pair_ClaimConn(&sst_peer, 0U));
   sv_RunPair();
}

/** Send a peer object through the route, in 20-byte chunks (MTU 23). */
static uint8_t su8ar_obj[DEVICE_CERT_MAX_DER_LEN + 1U];

static int si_RxObject(uint8_t u8_type, uint32_t u32_len, SETUStatus_E e_status)
{
   uint32_t u32_off;
   int i_ret;

   i_ret = sst_route.fpt_onRxStart(u8_type, u32_len);
   if (i_ret != 0) { return i_ret; }
   for (u32_off = 0U; u32_off < u32_len; u32_off += 20U)
   {
      TEST_ASSERT_EQUAL_INT(0, sst_route.fpt_onRxData(u8_type, u32_off, &su8ar_obj[u32_off],
         (uint16_t)MIN(20U, u32_len - u32_off)));
   }
   sst_route.fpt_onRxDone(u8_type, e_status, u32_len);
   return 0;
}

/** START .. both certificates exchanged and the peer's verified. */
static void sv_ToOobExchange(PairRole_E e_role)
{
   sv_StartRun(e_role);
   sv_LinkUp(e_role);
   sst_route.fpt_onCliReady(&sst_peer, 0);
   sv_RunPair();
   sst_route.fpt_onTxDone(PAIR_APP_TYPE_PEER_CERT, eBS_OK);
   TEST_ASSERT_EQUAL_INT(0, si_RxObject(PAIR_APP_TYPE_PEER_CERT, 450U, eBS_OK));
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_OOB_EXCHANGE, su8_State());
}

/** .. both OOB frames exchanged and the peer's verified. */
static void sv_ToPairing(PairRole_E e_role)
{
   sv_ToOobExchange(e_role);
   sst_route.fpt_onTxDone(PAIR_APP_TYPE_OOB, eBS_OK);
   TEST_ASSERT_EQUAL_INT(0, si_RxObject(PAIR_APP_TYPE_OOB, PAIR_OOB_FRAME_LEN, eBS_OK));
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_PAIRING, su8_State());
}

/** SMP asks for OOB data and finishes at level 4, bonded. */
static void sv_SmpDone(void)
{
   struct bt_conn_oob_info st_info;

   st_info.type = BT_CONN_OOB_LE_SC;
   st_info.lesc.oob_config = BT_CONN_OOB_BOTH_PEERS;
   sstpt_authCb->oob_data_request(&sst_peer, &st_info);
   sv_RunPair();
   se_security = BT_SECURITY_L4;
   sstpt_authInfoCb->pairing_complete(&sst_peer, true);
   sv_RunPair();
}

/** Central: SECURED found on the peer and written. */
static void sv_PeerAcceptsSecured(uint8_t u8_err)
{
   struct bt_gatt_chrc st_chrc = { NULL, 0x0123U, BT_GATT_CHRC_WRITE };
   struct bt_gatt_attr st_attr = { NULL, &st_chrc, 0x0122U };

   TEST_ASSERT_EQUAL_UINT32(1U, su32_discover);
   TEST_ASSERT_EQUAL_UINT8(BT_ATT_FIRST_ATTRIBUTE_HANDLE, sstpt_discover->start_handle);
   TEST_ASSERT_EQUAL_UINT16(BT_ATT_LAST_ATTRIBUTE_HANDLE, sstpt_discover->end_handle);
   TEST_ASSERT_EQUAL_UINT8(BT_GATT_DISCOVER_CHARACTERISTIC, sstpt_discover->type);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(gu8ar_vecPairUuidSecured,
      ((const struct bt_uuid_128 *)sstpt_discover->uuid)->val, 16U);
   TEST_ASSERT_EQUAL_UINT8(BT_GATT_ITER_STOP, sstpt_discover->func(&sst_peer, &st_attr, sstpt_discover));
   TEST_ASSERT_EQUAL_UINT32(1U, su32_write);
   TEST_ASSERT_EQUAL_UINT16(0x0123U, sstpt_write->handle);
   TEST_ASSERT_EQUAL_UINT16(1U, sstpt_write->length);
   TEST_ASSERT_EQUAL_HEX8(VEC_PAIR_SECURED_VALUE, ((const uint8_t *)sstpt_write->data)[0]);
   sstpt_write->func(&sst_peer, u8_err, sstpt_write);
   sv_RunPair();
}

/** Run every due delayable work item after time moved on. */
static void sv_AdvanceMs(int64_t i64_ms)
{
   gi64_simNowMs += i64_ms;
   (void)gb_SimRunDelayedWork(&sst_connectTimeout);
   (void)gb_SimRunDelayedWork(&sst_runTimeout);
   (void)gb_SimRunDelayedWork(&sst_reconnectWork);
   (void)gb_SimRunDelayedWork(&sst_secureTimeout);
   (void)gb_SimRunDelayedWork(&sst_ledWork);
   sv_RunPair();
}

/** The peer link drops as the stack reports it. */
static void sv_LinkDown(uint8_t u8_reason)
{
   gv_Pair_OnDisconnected(&sst_peer, u8_reason);
   sv_RunPair();
}

static void sv_ResetModule(void)
{
   PairEvent_T st_event;

   // Fresh module state (no reset API)
   while (k_msgq_get(&sst_pairMsgq, &st_event, K_NO_WAIT) == 0) {}
   (void)atomic_set(&st_state, ePST_IDLE);
   (void)atomic_set(&st_dirAdv, 0);
   (void)atomic_set(&st_scanMatched, 0);
   (void)atomic_ptr_set(&st_peerConn, NULL);
   se_error = ePER_NONE;
   su8_detail = 0U;
   se_role = ePRL_NONE;
   (void)memset(&sst_ownAddr, 0, sizeof(sst_ownAddr));
   (void)memset(&sst_peerAddr, 0, sizeof(sst_peerAddr));
   sstpt_createConn = NULL;
   sb_scanning = false;
   st_peerKey = 0U;
   sv_ResetRun();
   sb_rolesMoved = false;
   (void)atomic_set(&st_bondRole, ePRL_NONE);
   sb_savedBondValid = false;
   (void)memset(su8ar_savedBond, 0, sizeof(su8ar_savedBond));
   (void)atomic_set(&st_ledMode, ePLD_OFF);
   sb_ledLit = false;
   (void)k_work_cancel_delayable(&sst_connectTimeout);
   (void)k_work_cancel_delayable(&sst_runTimeout);
   (void)k_work_cancel_delayable(&sst_reconnectWork);
   (void)k_work_cancel_delayable(&sst_secureTimeout);
   (void)k_work_cancel_delayable(&sst_ledWork);
}

/** A bond record as settings_load() hands it to the module. */
static int si_LoadRecord(PairRole_E e_role, const bt_addr_le_t *stpt_peer)
{
   su8ar_saved[0] = (uint8_t)e_role;
   (void)memcpy(&su8ar_saved[1], stpt_peer, 7U);
   st_savedLen = PAIR_BOND_RECORD_LEN;
   st_readRet = 0;
   return settings_handler_pair.h_set("peer", PAIR_BOND_RECORD_LEN, st_ReadRecord, NULL);
}

/** Start-up of a device bonded with the peer in the given role. */
static void sv_RestoreBond(PairRole_E e_role)
{
   sv_ResetModule();
   TEST_ASSERT_EQUAL_INT(0, si_LoadRecord(e_role, &sst_addrB));
   sb_hasBond = true;
   gv_Pair_OnBtReady();
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_PAIRED, su8_State());
}

/** The bonded peer link comes up (the central sees the peer and connects). */
static void sv_BondLinkUp(PairRole_E e_role)
{
   if (e_role == ePRL_CENTRAL)
   {
      TEST_ASSERT_NOT_NULL(sfpt_scanCb);
      sfpt_scanCb(&sst_addrB, -40, BT_GAP_ADV_TYPE_ADV_IND, NULL);
      sv_RunPair();
   }
   TEST_ASSERT_TRUE(gb_Pair_ClaimConn(&sst_peer, 0U));
   sv_RunPair();
}

/** The stack reports the bonded link encrypted at the given level. */
static void sv_BondSecurity(bt_security_t e_level, enum bt_security_err e_err)
{
   gv_Pair_OnSecurityChanged(&sst_peer, (uint8_t)e_level, (uint8_t)e_err);
   sv_RunPair();
}

void setUp(void)
{
   uint32_t i;
   const uint8_t *u8pt_peer = &CONTROL_VEC("start_central")->u8ar_wire[2];
   const uint8_t *u8pt_own = &CONTROL_VEC("start_peripheral")->u8ar_wire[2];

   (void)memcpy(&sst_addrB, u8pt_peer, 7U);
   (void)memcpy(&sst_addrA, u8pt_own, 7U);
   sst_addrOther = sst_addrB;
   sst_addrOther.a.val[0] ^= 0x55U;
   sst_ownId = sst_addrA;
   sb_hostUp = true;

   si_advStartRet = 0; su32_advStart = 0U; su32_advStop = 0U; st_advDataLen = 0U;
   (void)memset(&sst_advPeer, 0, sizeof(sst_advPeer));
   si_scanStartRet = 0; su32_scanStart = 0U; su32_scanStop = 0U; sfpt_scanCb = NULL;
   si_createRet = 0; su32_create = 0U;
   su32_disconnect = 0U; sstpt_disconnected = NULL;
   su32_unpair = 0U; sb_unpairAll = false; sb_hasBond = false; sb_otherBondFirst = false;
   si_saveRet = 0; su32_save = 0U; su32_settingsDelete = 0U; st_savedLen = 0U; st_readRet = 0;
   scar_saveName[0] = '\0'; scar_deleteName[0] = '\0';
   si_setSecRet = 0; su32_setSec = 0U; se_security = BT_SECURITY_L1;
   si_oobGetRet = 0; su32_oobGet = 0U; sb_scFlag = false; su32_scFlagSets = 0U;
   si_setScDataRet = 0; su32_setScData = 0U; sstpt_scLocal = NULL; sstpt_scRemote = NULL;
   si_authRegRet = 0; si_authInfoRegRet = 0; su32_authCancel = 0U; sstpt_authCancelConn = NULL;
   si_discoverRet = 0; si_writeRet = 0; su32_discover = 0U; su32_write = 0U;
   si_registerRet = 0; su32_filterSet = 0U; su32_filterClear = 0U; sb_filterOn = false;
   si_attachRet = 0; su32_attach = 0U; sstpt_attachConn = NULL; su8_attachOwner = 0U;
   si_rebindRet = 0; su32_rebind = 0U; sstpt_srvConn = &sst_host; su32_detach = 0U;
   sb_rxBusy = false; sb_txBusy = false; su32_abortRx = 0U; su32_abortTx = 0U;
   si_sendRet = 0; su32_send = 0U;
   se_verifyRet = eDCS_OK; su32_verify = 0U; su32_verifyLen = 0U; sb_anchor = true;
   su32_destroy = 0U; st_destroyed = 0U;
   st_signRet = PSA_SUCCESS; st_oobVerifyRet = PSA_SUCCESS; su32_sign = 0U; su32_oobVerify = 0U;
   se_provState = ePS_PROVISIONED;
   sb_hostTrusted = true; sb_hostBondIsOther = false;
   si_ledInitRet = 0; su32_ledSets = 0U; su32_ledValue = 0U;
   su32_notify = 0U; (void)memset(su8ar_notified, 0, sizeof(su8ar_notified));
   su32_refresh = 0U;
   gi64_simNowMs = 0;

   gst_deviceCertData.u8_isDeviceCertGenerated = 1U;
   gst_deviceCertData.u16_deviceCertLen = 500U;
   for (i = 0U; i < sizeof(su8ar_obj); i++) { su8ar_obj[i] = (uint8_t)(i * 13U + 1U); }

   sv_ResetModule();
   gv_SimLogClear();
   TEST_ASSERT_EQUAL_INT(0, gi_Pair_Init());
   gv_Pair_OnBtReady();
   sv_RunPair();
   su32_notify = 0U;
   su32_unpair = 0U;
}

void tearDown(void) {}

/******************************************************************************/
/*  Start-up                                                                  */
/******************************************************************************/
static void test_InitRegistersRangeAndSmpCallbacks(void)
{
   TEST_ASSERT_EQUAL_HEX8(VEC_PAIR_APP_FIRST, sst_route.u8_firstAppType);
   TEST_ASSERT_EQUAL_HEX8(VEC_PAIR_APP_LAST, sst_route.u8_lastAppType);
   TEST_ASSERT_EQUAL_HEX8(VEC_PAIR_APP_PEER_CERT, PAIR_APP_TYPE_PEER_CERT);
   TEST_ASSERT_EQUAL_HEX8(VEC_PAIR_APP_OOB, PAIR_APP_TYPE_OOB);
   TEST_ASSERT_NOT_NULL(sst_route.fpt_onRxStart);
   TEST_ASSERT_NOT_NULL(sst_route.fpt_onRxData);
   TEST_ASSERT_NOT_NULL(sst_route.fpt_onRxDone);
   TEST_ASSERT_NULL_MESSAGE(sst_route.fpt_onRxShort, "no short messages between devices");
   TEST_ASSERT_NOT_NULL(sst_route.fpt_onTxDone);
   TEST_ASSERT_NOT_NULL(sst_route.fpt_onCliReady);
   TEST_ASSERT_NOT_NULL(sstpt_authCb->pairing_accept);
   TEST_ASSERT_NOT_NULL(sstpt_authCb->oob_data_request);
   TEST_ASSERT_NOT_NULL(sstpt_authInfoCb->pairing_complete);
   TEST_ASSERT_NOT_NULL(sstpt_authInfoCb->pairing_failed);
}

static void test_InitErrorsAreReturned(void)
{
   si_registerRet = -EEXIST;
   TEST_ASSERT_EQUAL_INT(-EEXIST, gi_Pair_Init());
   si_registerRet = 0;
   si_authRegRet = -EALREADY;
   TEST_ASSERT_EQUAL_INT(-EALREADY, gi_Pair_Init());
   si_authRegRet = 0;
   si_authInfoRegRet = -EINVAL;
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_Pair_Init());
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("bt_conn_auth_info_cb_register failed"));
   // No LEDs: pairing works without them
   si_authInfoRegRet = 0;
   si_ledInitRet = -ENODEV;
   TEST_ASSERT_EQUAL_INT(0, gi_Pair_Init());
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("DK LEDs not available"));
}

static void test_BtReadyLearnsTheOwnAddress(void)
{
   // setUp ran BT_READY: own address known, no peer, told to the host
   sv_AssertStatusIs("idle_provisioned");
}

static void test_BtReadyRestoresTheBond(void)
{
   sv_ResetModule();
   sb_hasBond = true;
   gv_Pair_OnBtReady();
   sv_RunPair();
   gv_Pair_GetStatus(su8ar_statusNow);
   TEST_ASSERT_EQUAL_UINT8(ePST_PAIRED, su8ar_statusNow[0]);
   TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(&sst_addrB, &su8ar_statusNow[12], 7U, "the first bond");
   TEST_ASSERT_EQUAL_UINT32(0U, su32_unpair);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("bonded peer restored"));
}

static void test_BtReadyDropsBondsOfAnUnprovisionedDevice(void)
{
   sv_ResetModule();
   sb_hasBond = true;
   se_provState = ePS_KEY_READY;
   gv_Pair_OnBtReady();
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT32(1U, su32_unpair);
   TEST_ASSERT_TRUE(sb_unpairAll);
   TEST_ASSERT_EQUAL_UINT8(ePST_IDLE, su8_State());
   TEST_ASSERT_EQUAL_UINT8(ePS_KEY_READY, su8ar_statusNow[3]);
}

/******************************************************************************/
/*  CONTROL                                                                   */
/******************************************************************************/
static void test_ControlVectorsAreAccepted(void)
{
   const PairVector_T *v = CONTROL_VEC("start_central");

   TEST_ASSERT_EQUAL_UINT8(PAIR_START_LEN, v->u8_wireLen);
   TEST_ASSERT_EQUAL_INT(0, gt_Pair_OnControlWrite(&sst_host, v->u8ar_wire, v->u8_wireLen));
   sv_RunPair();
   sv_AssertStatusIs("armed_central");
   TEST_ASSERT_TRUE(gb_Pair_IsRunning());

   v = CONTROL_VEC("cancel");
   TEST_ASSERT_EQUAL_INT(0, gt_Pair_OnControlWrite(&sst_host, v->u8ar_wire, v->u8_wireLen));
   sv_RunPair();
   sv_AssertFailed(ePER_CANCELLED, 0U);

   v = CONTROL_VEC("unpair");
   TEST_ASSERT_EQUAL_INT(0, gt_Pair_OnControlWrite(&sst_host, v->u8ar_wire, v->u8_wireLen));
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_IDLE, su8_State());
}

static void test_MalformedControlIsRefused(void)
{
   uint8_t u8ar_cmd[PAIR_START_LEN + 1U];

   (void)memcpy(u8ar_cmd, CONTROL_VEC("start_central")->u8ar_wire, PAIR_START_LEN);
   TEST_ASSERT_EQUAL_INT(BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN),
      gt_Pair_OnControlWrite(&sst_host, u8ar_cmd, 0U));
   TEST_ASSERT_EQUAL_INT(BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN),
      gt_Pair_OnControlWrite(&sst_host, u8ar_cmd, PAIR_START_LEN - 1U));
   TEST_ASSERT_EQUAL_INT(BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN),
      gt_Pair_OnControlWrite(&sst_host, u8ar_cmd, PAIR_START_LEN + 1U));
   u8ar_cmd[1] = 0U;
   TEST_ASSERT_EQUAL_INT(BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED),
      gt_Pair_OnControlWrite(&sst_host, u8ar_cmd, PAIR_START_LEN));
   u8ar_cmd[1] = 3U;
   TEST_ASSERT_EQUAL_INT(BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED),
      gt_Pair_OnControlWrite(&sst_host, u8ar_cmd, PAIR_START_LEN));
   u8ar_cmd[1] = ePRL_CENTRAL;
   u8ar_cmd[2] = 2U;
   TEST_ASSERT_EQUAL_INT(BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED),
      gt_Pair_OnControlWrite(&sst_host, u8ar_cmd, PAIR_START_LEN));
   u8ar_cmd[0] = 0x04U;
   TEST_ASSERT_EQUAL_INT(BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED),
      gt_Pair_OnControlWrite(&sst_host, u8ar_cmd, 1U));
   u8ar_cmd[0] = PAIR_OP_CANCEL;
   TEST_ASSERT_EQUAL_INT(BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN),
      gt_Pair_OnControlWrite(&sst_host, u8ar_cmd, 2U));
   u8ar_cmd[0] = PAIR_OP_UNPAIR;
   TEST_ASSERT_EQUAL_INT(BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN),
      gt_Pair_OnControlWrite(&sst_host, u8ar_cmd, 2U));
   TEST_ASSERT_EQUAL_INT(BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN),
      gt_Pair_OnControlWrite(&sst_host, NULL, 1U));
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(ePST_IDLE, su8_State(), "nothing was queued");
}

static void test_StartDuringARunIsRefused(void)
{
   const PairVector_T *v = CONTROL_VEC("start_central");

   sv_StartRun(ePRL_CENTRAL);
   TEST_ASSERT_EQUAL_INT(BT_GATT_ERR(BT_ATT_ERR_PROCEDURE_IN_PROGRESS),
      gt_Pair_OnControlWrite(&sst_host, v->u8ar_wire, v->u8_wireLen));
   // A START queued behind the first one is ignored by the thread
   sv_HandleStart(&(PairEvent_T){ .u8_type = ePEV_START, .u8_role = ePRL_PERIPHERAL });
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("START ignored: pairing in progress"));
   TEST_ASSERT_EQUAL_UINT32(1U, su32_scanStart);
}

static void test_PeerCannotDriveThisDevice(void)
{
   const PairVector_T *v = CONTROL_VEC("unpair");

   sv_ToOobExchange(ePRL_CENTRAL);
   TEST_ASSERT_EQUAL_INT(BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED),
      gt_Pair_OnControlWrite(&sst_peer, v->u8ar_wire, v->u8_wireLen));
}

static void test_OnlyTheTrustedHostDrivesThisDevice(void)
{
   const char *cpar_names[] = { "start_central", "cancel", "unpair" };
   uint32_t i;

   // A host link that has not authenticated, and any other link
   sb_hostTrusted = false;
   for (i = 0U; i < ARRAY_SIZE(cpar_names); i++)
   {
      const PairVector_T *v = CONTROL_VEC(cpar_names[i]);

      TEST_ASSERT_EQUAL_INT_MESSAGE(BT_GATT_ERR(BT_ATT_ERR_AUTHORIZATION),
         gt_Pair_OnControlWrite(&sst_host, v->u8ar_wire, v->u8_wireLen), cpar_names[i]);
      TEST_ASSERT_EQUAL_INT_MESSAGE(BT_GATT_ERR(BT_ATT_ERR_AUTHORIZATION),
         gt_Pair_OnControlWrite(&sst_other, v->u8ar_wire, v->u8_wireLen), cpar_names[i]);
   }
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(ePST_IDLE, su8_State(), "nothing was queued");
   TEST_ASSERT_EQUAL_UINT32(0U, su32_scanStart);

   // Trusted: the same START runs
   sb_hostTrusted = true;
   TEST_ASSERT_EQUAL_INT(0, gt_Pair_OnControlWrite(&sst_host, CONTROL_VEC("start_central")->u8ar_wire,
      CONTROL_VEC("start_central")->u8_wireLen));
}

static void test_FullQueueIsReported(void)
{
   const PairVector_T *v = CONTROL_VEC("cancel");
   uint32_t i;

   for (i = 0U; i < PAIR_EVENT_QUEUE_LEN; i++)
   {
      TEST_ASSERT_EQUAL_INT(0, gt_Pair_OnControlWrite(&sst_host, v->u8ar_wire, v->u8_wireLen));
   }
   TEST_ASSERT_EQUAL_INT(BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES),
      gt_Pair_OnControlWrite(&sst_host, v->u8ar_wire, v->u8_wireLen));
   sv_RunPair();
}

/******************************************************************************/
/*  START                                                                     */
/******************************************************************************/
static void test_StartAsPeripheralAdvertisesToThePeer(void)
{
   sv_StartRun(ePRL_PERIPHERAL);
   TEST_ASSERT_EQUAL_UINT8(ePST_ARMED, su8_State());
   TEST_ASSERT_EQUAL_UINT8(ePRL_PERIPHERAL, su8ar_statusNow[4]);
   TEST_ASSERT_TRUE(gb_Pair_IsAdvertising());
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(1U, su32_advStop, "undirected advertising stops first");
   TEST_ASSERT_EQUAL_UINT32(1U, su32_advStart);
   TEST_ASSERT_TRUE((sst_advParam.options & BT_LE_ADV_OPT_CONN) != 0U);
   TEST_ASSERT_TRUE((sst_advParam.options & BT_LE_ADV_OPT_DIR_MODE_LOW_DUTY) != 0U);
   TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(&sst_addrB, &sst_advPeer, 7U, "directed to the peer");
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, st_advDataLen, "directed advertising has no data");
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(1U, su32_unpair, "an older bond with the peer goes");
   TEST_ASSERT_EQUAL_HEX8_ARRAY(&sst_addrB, &sst_unpairAddr, 7U);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_scanStart);
   TEST_ASSERT_TRUE(su32_notify > 0U);
}

static void test_StartAsCentralScansAndConnects(void)
{
   sv_StartRun(ePRL_CENTRAL);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_scanStart);
   TEST_ASSERT_FALSE(gb_Pair_IsAdvertising());
   TEST_ASSERT_EQUAL_UINT32(0U, su32_advStart);

   // Other devices, and the peer's non-connectable reports, are ignored
   sfpt_scanCb(&sst_addrOther, -40, BT_GAP_ADV_TYPE_ADV_IND, NULL);
   sfpt_scanCb(&sst_addrB, -40, BT_GAP_ADV_TYPE_ADV_NONCONN_IND, NULL);
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT32(0U, su32_create);

   // The peer: once, however many reports arrive
   sfpt_scanCb(&sst_addrB, -40, BT_GAP_ADV_TYPE_ADV_DIRECT_IND, NULL);
   sfpt_scanCb(&sst_addrB, -40, BT_GAP_ADV_TYPE_ADV_DIRECT_IND, NULL);
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT32(1U, su32_scanStop);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_create);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(&sst_addrB, &sst_createPeer, 7U);
   TEST_ASSERT_EQUAL_UINT16(PAIR_CONN_INTERVAL, sst_createParam.interval_min);
   TEST_ASSERT_EQUAL_UINT16(PAIR_CONN_INTERVAL, sst_createParam.interval_max);
   TEST_ASSERT_EQUAL_UINT16(PAIR_CONN_TIMEOUT, sst_createParam.timeout);
   TEST_ASSERT_EQUAL_UINT8(ePST_ARMED, su8_State());
}

static void test_StartRefusals(void)
{
   // Not provisioned
   se_provState = ePS_KEY_READY;
   sv_StartRun(ePRL_CENTRAL);
   sv_AssertStatusIs("failed_not_provisioned");
   sv_AssertFailed(ePER_NOT_PROVISIONED, 0U);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_scanStart);

   // No trust anchor
   se_provState = ePS_PROVISIONED;
   sb_anchor = false;
   sv_StartRun(ePRL_CENTRAL);
   sv_AssertFailed(ePER_NOT_PROVISIONED, 0U);
   sb_anchor = true;

   // Itself as the peer
   sst_ownId = sst_addrB;
   sv_ResetModule();
   gv_Pair_OnBtReady();
   sv_RunPair();
   sv_StartRun(ePRL_PERIPHERAL);
   sv_AssertFailed(ePER_BAD_ARG, 0U);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_advStart);
   sst_ownId = sst_addrA;
   sv_ResetModule();
   gv_Pair_OnBtReady();
   sv_RunPair();

   // SETU busy with the host
   sb_rxBusy = true;
   sv_StartRun(ePRL_CENTRAL);
   sv_AssertFailed(ePER_BUSY, 0U);
   sb_rxBusy = false;
   sb_txBusy = true;
   sv_StartRun(ePRL_CENTRAL);
   sv_AssertFailed(ePER_BUSY, 0U);
   sb_txBusy = false;

   // The radio refuses
   si_advStartRet = -ENOMEM;
   sv_StartRun(ePRL_PERIPHERAL);
   sv_AssertFailed(ePER_INTERNAL, (uint8_t)-ENOMEM);
   si_scanStartRet = -EAGAIN;
   sv_StartRun(ePRL_CENTRAL);
   sv_AssertFailed(ePER_INTERNAL, (uint8_t)-EAGAIN);
   si_scanStartRet = 0;
   si_createRet = -EINVAL;
   sv_StartRun(ePRL_CENTRAL);
   sfpt_scanCb(&sst_addrB, -40, BT_GAP_ADV_TYPE_ADV_IND, NULL);
   sv_RunPair();
   sv_AssertFailed(ePER_CONNECT, (uint8_t)-EINVAL);
}

/******************************************************************************/
/*  Peer link                                                                 */
/******************************************************************************/
static void test_ClaimTakesOnlyThePeerOfARun(void)
{
   // No run
   TEST_ASSERT_FALSE(gb_Pair_ClaimConn(&sst_peer, 0U));
   sv_StartRun(ePRL_PERIPHERAL);
   // Another device (e.g. a host) is not the peer
   TEST_ASSERT_FALSE(gb_Pair_ClaimConn(&sst_other, 0U));
   TEST_ASSERT_TRUE(gb_Pair_ClaimConn(&sst_peer, 0U));
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_CONNECTED, su8_State());
   // Up now: a second link from the peer is not claimed
   TEST_ASSERT_FALSE(gb_Pair_ClaimConn(&sst_peer, 0U));
   TEST_ASSERT_FALSE_MESSAGE(gb_Pair_IsAdvertising(), "connectable advertising ends with the link");
}

static void test_LinkUpMovesSETUToThePeer(void)
{
   sv_StartRun(ePRL_CENTRAL);
   sv_LinkUp(ePRL_CENTRAL);
   TEST_ASSERT_EQUAL_UINT8(ePST_CONNECTED, su8_State());
   TEST_ASSERT_TRUE(sb_filterOn);
   TEST_ASSERT_EQUAL_HEX8(VEC_PAIR_APP_FIRST, su8_filterFirst);
   TEST_ASSERT_EQUAL_HEX8(VEC_PAIR_APP_LAST, su8_filterLast);
   TEST_ASSERT_EQUAL_PTR(&sst_peer, sstpt_srvConn);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_attach);
   TEST_ASSERT_EQUAL_PTR(&sst_peer, sstpt_attachConn);
   TEST_ASSERT_TRUE(su8_attachOwner >= VEC_PAIR_APP_FIRST);
   TEST_ASSERT_TRUE(su8_attachOwner <= VEC_PAIR_APP_LAST);

   // Attached: this device's certificate goes to the peer
   sst_route.fpt_onCliReady(&sst_peer, 0);
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_CERT_EXCHANGE, su8_State());
   TEST_ASSERT_EQUAL_UINT32(1U, su32_send);
   TEST_ASSERT_EQUAL_HEX8(VEC_PAIR_APP_PEER_CERT, su8ar_sendTypes[0]);
   TEST_ASSERT_EQUAL_PTR(gst_deviceCertData.u8ar_DeviceCert, svptar_sendData[0]);
   TEST_ASSERT_EQUAL_UINT32(500U, su32ar_sendLen[0]);
}

static void test_LinkUpFailures(void)
{
   // Connection attempt failed
   sv_StartRun(ePRL_CENTRAL);
   sfpt_scanCb(&sst_addrB, -40, BT_GAP_ADV_TYPE_ADV_IND, NULL);
   sv_RunPair();
   TEST_ASSERT_TRUE(gb_Pair_ClaimConn(&sst_peer, 0x3EU));
   sv_RunPair();
   sv_AssertFailed(ePER_CONNECT, 0x3EU);

   // The Server cannot move (a host transfer started meanwhile)
   si_rebindRet = -EBUSY;
   sv_StartRun(ePRL_PERIPHERAL);
   sv_LinkUp(ePRL_PERIPHERAL);
   sv_AssertFailed(ePER_BUSY, (uint8_t)-EBUSY);
   TEST_ASSERT_EQUAL_PTR_MESSAGE(&sst_peer, sstpt_disconnected, "the peer link is dropped");
   sv_LinkDown(0x16U);
   TEST_ASSERT_FALSE_MESSAGE(sb_filterOn, "the host gets SETU back");
   si_rebindRet = 0;

   // No SETU service on the peer, refused at once or by discovery
   si_attachRet = -ENOTCONN;
   sv_StartRun(ePRL_PERIPHERAL);
   sv_LinkUp(ePRL_PERIPHERAL);
   sv_AssertFailed(ePER_NO_PEER_SVC, (uint8_t)-ENOTCONN);
   sv_LinkDown(0x16U);
   si_attachRet = 0;
   sv_StartRun(ePRL_PERIPHERAL);
   sv_LinkUp(ePRL_PERIPHERAL);
   sst_route.fpt_onCliReady(&sst_peer, -ENOENT);
   sv_RunPair();
   sv_AssertFailed(ePER_NO_PEER_SVC, (uint8_t)-ENOENT);
   sv_LinkDown(0x16U);

   // Ready at once (attached before): the certificate goes immediately
   si_attachRet = -EALREADY;
   sv_StartRun(ePRL_PERIPHERAL);
   sv_LinkUp(ePRL_PERIPHERAL);
   TEST_ASSERT_EQUAL_UINT8(ePST_CERT_EXCHANGE, su8_State());

   // The certificate cannot be sent
   sv_LinkDown(0x13U);
   si_attachRet = 0;
   si_sendRet = -EBUSY;
   sv_StartRun(ePRL_PERIPHERAL);
   sv_LinkUp(ePRL_PERIPHERAL);
   sst_route.fpt_onCliReady(&sst_peer, 0);
   sv_RunPair();
   sv_AssertFailed(ePER_TRANSFER, (uint8_t)-EBUSY);
}

static void test_LateLinkAfterTheRunIsDropped(void)
{
   sv_StartRun(ePRL_PERIPHERAL);
   TEST_ASSERT_TRUE(gb_Pair_ClaimConn(&sst_peer, 0U));
   // The run ends before the thread sees the link
   sv_HandleEvent(&(PairEvent_T){ .u8_type = ePEV_CANCEL });
   sv_RunPair();
   TEST_ASSERT_EQUAL_PTR(&sst_peer, sstpt_disconnected);
}

/******************************************************************************/
/*  Objects from the peer                                                     */
/******************************************************************************/
static void test_PeerObjectsAreChecked(void)
{
   uint8_t u8_d = 0U;

   // No run with a link: nothing accepted
   TEST_ASSERT_EQUAL_INT(-EPERM, sst_route.fpt_onRxStart(PAIR_APP_TYPE_PEER_CERT, 400U));
   sv_StartRun(ePRL_CENTRAL);
   TEST_ASSERT_EQUAL_INT(-EPERM, sst_route.fpt_onRxStart(PAIR_APP_TYPE_PEER_CERT, 400U));
   sv_LinkUp(ePRL_CENTRAL);

   // Sizes and types
   TEST_ASSERT_EQUAL_INT(-EINVAL, sst_route.fpt_onRxStart(PAIR_APP_TYPE_PEER_CERT, 0U));
   TEST_ASSERT_EQUAL_INT(-EINVAL, sst_route.fpt_onRxStart(PAIR_APP_TYPE_PEER_CERT,
      DEVICE_CERT_MAX_DER_LEN + 1U));
   TEST_ASSERT_EQUAL_INT(-EINVAL, sst_route.fpt_onRxStart(PAIR_APP_TYPE_OOB, 95U));
   TEST_ASSERT_EQUAL_INT(-EINVAL, sst_route.fpt_onRxStart(PAIR_APP_TYPE_OOB, 97U));
   TEST_ASSERT_EQUAL_INT(-EINVAL, sst_route.fpt_onRxStart(0x32U, 10U));

   // One object at a time
   TEST_ASSERT_EQUAL_INT(0, sst_route.fpt_onRxStart(PAIR_APP_TYPE_PEER_CERT,
      DEVICE_CERT_MAX_DER_LEN));
   TEST_ASSERT_EQUAL_INT(-EBUSY, sst_route.fpt_onRxStart(PAIR_APP_TYPE_OOB, PAIR_OOB_FRAME_LEN));
   // A chunk of another type, or past the buffer, aborts
   TEST_ASSERT_EQUAL_INT(-EIO, sst_route.fpt_onRxData(PAIR_APP_TYPE_OOB, 0U, &u8_d, 1U));
   TEST_ASSERT_EQUAL_INT(-EIO, sst_route.fpt_onRxData(PAIR_APP_TYPE_PEER_CERT,
      DEVICE_CERT_MAX_DER_LEN, &u8_d, 1U));
   TEST_ASSERT_EQUAL_INT(0, sst_route.fpt_onRxData(PAIR_APP_TYPE_PEER_CERT,
      DEVICE_CERT_MAX_DER_LEN - 1U, &u8_d, 1U));
   // A result for a transfer that was not accepted is ignored
   sst_route.fpt_onRxDone(PAIR_APP_TYPE_OOB, eBS_OK, PAIR_OOB_FRAME_LEN);
   TEST_ASSERT_EQUAL_UINT32(0U, k_msgq_num_used_get(&sst_pairMsgq));
   sst_route.fpt_onRxDone(PAIR_APP_TYPE_PEER_CERT, eBS_OK, DEVICE_CERT_MAX_DER_LEN);
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT32(DEVICE_CERT_MAX_DER_LEN, su32_verifyLen);

   // Each once per run
   TEST_ASSERT_EQUAL_INT(-EALREADY, sst_route.fpt_onRxStart(PAIR_APP_TYPE_PEER_CERT, 400U));
   TEST_ASSERT_EQUAL_INT(0, si_RxObject(PAIR_APP_TYPE_OOB, PAIR_OOB_FRAME_LEN, eBS_OK));
   TEST_ASSERT_EQUAL_INT(-EALREADY, sst_route.fpt_onRxStart(PAIR_APP_TYPE_OOB, PAIR_OOB_FRAME_LEN));
}

static void test_PeerCertificateIsVerified(void)
{
   sv_ToOobExchange(ePRL_CENTRAL);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_verify);
   TEST_ASSERT_EQUAL_UINT32(450U, su32_verifyLen);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(su8ar_obj, su8ar_rxCert, 450U);
   // Fresh OOB data, signed with the device key for this peer
   TEST_ASSERT_EQUAL_UINT32(1U, su32_oobGet);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_sign);
   TEST_ASSERT_EQUAL_UINT32(CSR_DEVICE_SIGNING_KEY_ID, st_signKeyUsed);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(&sst_addrA, su8ar_signSender, 7U);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(&sst_addrB, su8ar_signReceiver, 7U);
   TEST_ASSERT_TRUE_MESSAGE(sb_scFlag, "the OOB flag is set before pairing starts");
   // Sent once the peer has this device's certificate
   TEST_ASSERT_EQUAL_UINT32(2U, su32_send);
   TEST_ASSERT_EQUAL_HEX8(VEC_PAIR_APP_OOB, su8ar_sendTypes[1]);
   TEST_ASSERT_EQUAL_PTR(su8ar_txOob, svptar_sendData[1]);
   TEST_ASSERT_EQUAL_UINT32(PAIR_OOB_FRAME_LEN, su32ar_sendLen[1]);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(gu8ar_vecPairOobR, su8ar_txOob, 16U);
}

static void test_OobWaitsForTheOwnCertificate(void)
{
   sv_StartRun(ePRL_PERIPHERAL);
   sv_LinkUp(ePRL_PERIPHERAL);
   sst_route.fpt_onCliReady(&sst_peer, 0);
   sv_RunPair();
   // The peer's certificate verifies before the peer has this one
   TEST_ASSERT_EQUAL_INT(0, si_RxObject(PAIR_APP_TYPE_PEER_CERT, 300U, eBS_OK));
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_OOB_EXCHANGE, su8_State());
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(1U, su32_send, "the Client is still busy with the certificate");
   sst_route.fpt_onTxDone(PAIR_APP_TYPE_PEER_CERT, eBS_OK);
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT32(2U, su32_send);
   TEST_ASSERT_EQUAL_HEX8(VEC_PAIR_APP_OOB, su8ar_sendTypes[1]);
}

static void test_EarlyPeerOobIsVerifiedLater(void)
{
   sv_StartRun(ePRL_CENTRAL);
   sv_LinkUp(ePRL_CENTRAL);
   sst_route.fpt_onCliReady(&sst_peer, 0);
   sv_RunPair();
   // The peer verified this device faster and its OOB frame came first
   TEST_ASSERT_EQUAL_INT(0, si_RxObject(PAIR_APP_TYPE_PEER_CERT, 300U, eBS_OK));
   TEST_ASSERT_EQUAL_INT(0, si_RxObject(PAIR_APP_TYPE_OOB, PAIR_OOB_FRAME_LEN, eBS_OK));
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_PAIRING, su8_State());
   TEST_ASSERT_EQUAL_UINT32(1U, su32_oobVerify);
   TEST_ASSERT_EQUAL_UINT32(PEER_KEY_ID, st_verifyKeyUsed);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(&sst_addrB, su8ar_verifySender, 7U);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(&sst_addrA, su8ar_verifyReceiver, 7U);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(&su8ar_obj[0], sst_remoteOob.r, 16U);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(&su8ar_obj[16], sst_remoteOob.c, 16U);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_setSec);
}

/******************************************************************************/
/*  Both roles to PAIRED                                                      */
/******************************************************************************/
static void test_CentralPairs(void)
{
   sv_ToPairing(ePRL_CENTRAL);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(1U, su32_setSec, "the central starts pairing at level 4");
   sv_SmpDone();
   TEST_ASSERT_EQUAL_UINT32(1U, su32_setScData);
   TEST_ASSERT_EQUAL_PTR(&sst_localOob.le_sc_data, sstpt_scLocal);
   TEST_ASSERT_EQUAL_PTR(&sst_remoteOob, sstpt_scRemote);
   TEST_ASSERT_EQUAL_UINT8(ePST_PAIRING, su8_State());
   sv_PeerAcceptsSecured(0U);

   TEST_ASSERT_EQUAL_UINT8(ePST_PAIRED, su8_State());
   TEST_ASSERT_EQUAL_UINT8(ePER_NONE, su8ar_statusNow[1]);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(su8ar_statusNow, su8ar_notified, PAIR_STATUS_LEN);
   TEST_ASSERT_FALSE(gb_Pair_IsRunning());
   // The link stays up, encrypted; SETU goes back to the host
   TEST_ASSERT_EQUAL_UINT32(0U, su32_disconnect);
   TEST_ASSERT_FALSE(sb_filterOn);
   TEST_ASSERT_EQUAL_PTR(&sst_host, sstpt_srvConn);
   TEST_ASSERT_TRUE(su32_detach > 0U);
   TEST_ASSERT_FALSE(sb_scFlag);
   TEST_ASSERT_EQUAL_UINT32(PEER_KEY_ID, st_destroyed);
   TEST_ASSERT_TRUE(su32_refresh > 0U);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, su32_ledValue, "only the peripheral lights its LED");
}

static void test_PeripheralPairs(void)
{
   uint8_t u8_v = VEC_PAIR_SECURED_VALUE;

   sst_ownId = sst_addrB;
   sst_addrB = sst_addrA;
   sv_ResetModule();
   gv_Pair_OnBtReady();
   sv_RunPair();

   sv_ToPairing(ePRL_PERIPHERAL);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, su32_setSec, "the peripheral waits for the central");
   sv_SmpDone();
   TEST_ASSERT_EQUAL_UINT32(1U, su32_setScData);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, su32_discover, "the peripheral does not write SECURED");
   TEST_ASSERT_EQUAL_UINT8(ePST_PAIRING, su8_State());

   TEST_ASSERT_EQUAL_INT(0, gt_Pair_OnSecuredWrite(&sst_peer, &u8_v, 1U));
   sv_RunPair();
   sv_AssertStatusIs("paired_peripheral");
   TEST_ASSERT_EQUAL_UINT32(1U, su32_ledValue);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_disconnect);
}

static void test_OobRequestBeforeThePeerOobIsAnsweredLater(void)
{
   struct bt_conn_oob_info st_info;

   sv_ToOobExchange(ePRL_PERIPHERAL);
   // SMP asks first (the central verified sooner)
   st_info.type = BT_CONN_OOB_LE_SC;
   st_info.lesc.oob_config = BT_CONN_OOB_BOTH_PEERS;
   sstpt_authCb->oob_data_request(&sst_peer, &st_info);
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT32(0U, su32_setScData);
   TEST_ASSERT_EQUAL_INT(0, si_RxObject(PAIR_APP_TYPE_OOB, PAIR_OOB_FRAME_LEN, eBS_OK));
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT32(1U, su32_setScData);
}

static void test_RestartReleasesThePreviousLink(void)
{
   sv_ToPairing(ePRL_CENTRAL);
   sv_SmpDone();
   sv_PeerAcceptsSecured(0U);
   TEST_ASSERT_EQUAL_UINT8(ePST_PAIRED, su8_State());

   // A new START: the old link goes, and its disconnect is not this run's
   su32_create = 0U;
   sv_StartRun(ePRL_CENTRAL);
   TEST_ASSERT_EQUAL_PTR(&sst_peer, sstpt_disconnected);
   TEST_ASSERT_NULL(atomic_ptr_get(&st_peerConn));
   gv_Pair_OnDisconnected(&sst_peer, 0x16U);
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_ARMED, su8_State());
}

/******************************************************************************/
/*  Failures                                                                  */
/******************************************************************************/
static void test_PeerCertificateRejected(void)
{
   se_verifyRet = eDCS_BAD_SIG;
   sv_StartRun(ePRL_CENTRAL);
   sv_LinkUp(ePRL_CENTRAL);
   sst_route.fpt_onCliReady(&sst_peer, 0);
   TEST_ASSERT_EQUAL_INT(0, si_RxObject(PAIR_APP_TYPE_PEER_CERT, 400U, eBS_OK));
   sv_RunPair();
   sv_AssertStatusIs("failed_peer_cert_bad_sig");
   sv_AssertFailed(ePER_PEER_CERT, eDCS_BAD_SIG);
   TEST_ASSERT_EQUAL_PTR(&sst_peer, sstpt_disconnected);
   TEST_ASSERT_TRUE(su32_abortRx > 0U);
   TEST_ASSERT_TRUE(su32_abortTx > 0U);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_sign);
   TEST_ASSERT_EQUAL_UINT32(0U, st_peerKey);
}

static void test_OobFailures(void)
{
   // OOB data cannot be made
   si_oobGetRet = -EIO;
   sv_StartRun(ePRL_CENTRAL);
   sv_LinkUp(ePRL_CENTRAL);
   sst_route.fpt_onCliReady(&sst_peer, 0);
   TEST_ASSERT_EQUAL_INT(0, si_RxObject(PAIR_APP_TYPE_PEER_CERT, 400U, eBS_OK));
   sv_RunPair();
   sv_AssertFailed(ePER_INTERNAL, (uint8_t)-EIO);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(PEER_KEY_ID, st_destroyed, "the peer key is destroyed");
   sv_LinkDown(0x16U);
   si_oobGetRet = 0;

   // Or not signed
   st_signRet = PSA_ERROR_NOT_PERMITTED;
   sv_StartRun(ePRL_CENTRAL);
   sv_LinkUp(ePRL_CENTRAL);
   sst_route.fpt_onCliReady(&sst_peer, 0);
   TEST_ASSERT_EQUAL_INT(0, si_RxObject(PAIR_APP_TYPE_PEER_CERT, 400U, eBS_OK));
   sv_RunPair();
   sv_AssertFailed(ePER_INTERNAL, (uint8_t)PSA_ERROR_NOT_PERMITTED);
   sv_LinkDown(0x16U);
   st_signRet = PSA_SUCCESS;

   // The peer's signature does not verify
   st_oobVerifyRet = PSA_ERROR_INVALID_SIGNATURE;
   sv_ToOobExchange(ePRL_CENTRAL);
   TEST_ASSERT_EQUAL_INT(0, si_RxObject(PAIR_APP_TYPE_OOB, PAIR_OOB_FRAME_LEN, eBS_OK));
   sv_RunPair();
   sv_AssertFailed(ePER_OOB_SIG, (uint8_t)PSA_ERROR_INVALID_SIGNATURE);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_setSec);
   sv_LinkDown(0x16U);
   st_oobVerifyRet = PSA_SUCCESS;

   // The OOB frame cannot be sent
   si_sendRet = 0;
   sv_StartRun(ePRL_CENTRAL);
   sv_LinkUp(ePRL_CENTRAL);
   sst_route.fpt_onCliReady(&sst_peer, 0);
   sv_RunPair();
   sst_route.fpt_onTxDone(PAIR_APP_TYPE_PEER_CERT, eBS_OK);
   si_sendRet = -ENOMEM;
   TEST_ASSERT_EQUAL_INT(0, si_RxObject(PAIR_APP_TYPE_PEER_CERT, 400U, eBS_OK));
   sv_RunPair();
   sv_AssertFailed(ePER_TRANSFER, (uint8_t)-ENOMEM);
}

static void test_TransferFailures(void)
{
   // This device's certificate did not arrive
   sv_StartRun(ePRL_CENTRAL);
   sv_LinkUp(ePRL_CENTRAL);
   sst_route.fpt_onCliReady(&sst_peer, 0);
   sv_RunPair();
   sst_route.fpt_onTxDone(PAIR_APP_TYPE_PEER_CERT, eBS_TIMEOUT);
   sv_RunPair();
   sv_AssertFailed(ePER_TRANSFER, eBS_TIMEOUT);
   sv_LinkDown(0x16U);

   // The peer's certificate did not arrive intact
   sv_StartRun(ePRL_CENTRAL);
   sv_LinkUp(ePRL_CENTRAL);
   TEST_ASSERT_EQUAL_INT(0, si_RxObject(PAIR_APP_TYPE_PEER_CERT, 400U, eBS_CRC_ERROR));
   sv_RunPair();
   sv_AssertFailed(ePER_TRANSFER, eBS_CRC_ERROR);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_verify);
}

static void test_SmpFailures(void)
{
   struct bt_conn_oob_info st_info;

   // Only one side has OOB data
   sv_ToPairing(ePRL_CENTRAL);
   st_info.type = BT_CONN_OOB_LE_SC;
   st_info.lesc.oob_config = BT_CONN_OOB_LOCAL_ONLY;
   sstpt_authCb->oob_data_request(&sst_peer, &st_info);
   sv_RunPair();
   sv_AssertFailed(ePER_SMP, 0x80U | BT_CONN_OOB_LOCAL_ONLY);
   TEST_ASSERT_EQUAL_PTR(&sst_peer, sstpt_authCancelConn);
   sv_LinkDown(0x16U);

   // Legacy OOB is not used
   sv_ToPairing(ePRL_CENTRAL);
   st_info.type = BT_CONN_OOB_LE_LEGACY;
   sstpt_authCb->oob_data_request(&sst_peer, &st_info);
   sv_RunPair();
   sv_AssertFailed(ePER_SMP, 0xFFU);
   sv_LinkDown(0x16U);

   // SMP refuses the data, or pairing cannot start
   si_setScDataRet = -EINVAL;
   sv_ToPairing(ePRL_CENTRAL);
   st_info.type = BT_CONN_OOB_LE_SC;
   st_info.lesc.oob_config = BT_CONN_OOB_BOTH_PEERS;
   sstpt_authCb->oob_data_request(&sst_peer, &st_info);
   sv_RunPair();
   sv_AssertFailed(ePER_SMP, (uint8_t)-EINVAL);
   sv_LinkDown(0x16U);
   si_setScDataRet = 0;
   si_setSecRet = -ENOMEM;
   sv_ToOobExchange(ePRL_CENTRAL);
   TEST_ASSERT_EQUAL_INT(0, si_RxObject(PAIR_APP_TYPE_OOB, PAIR_OOB_FRAME_LEN, eBS_OK));
   sv_RunPair();
   sv_AssertFailed(ePER_SMP, (uint8_t)-ENOMEM);
   sv_LinkDown(0x16U);
   si_setSecRet = 0;

   // Pairing failed
   sv_ToPairing(ePRL_CENTRAL);
   sstpt_authInfoCb->pairing_failed(&sst_peer, BT_SECURITY_ERR_AUTH_FAIL);
   sv_RunPair();
   sv_AssertFailed(ePER_SMP, BT_SECURITY_ERR_AUTH_FAIL);
   sv_LinkDown(0x16U);

   // Paired, but below level 4, or not bonded
   sv_ToPairing(ePRL_CENTRAL);
   se_security = BT_SECURITY_L2;
   sstpt_authInfoCb->pairing_complete(&sst_peer, true);
   sv_RunPair();
   sv_AssertFailed(ePER_SMP, BT_SECURITY_L2);
   sv_LinkDown(0x16U);
   sv_ToPairing(ePRL_CENTRAL);
   se_security = BT_SECURITY_L4;
   sstpt_authInfoCb->pairing_complete(&sst_peer, false);
   sv_RunPair();
   sv_AssertFailed(ePER_SMP, 0xFFU);
}

static void test_SecuredFailures(void)
{
   // The peer has no SECURED characteristic
   sv_ToPairing(ePRL_CENTRAL);
   sv_SmpDone();
   TEST_ASSERT_EQUAL_UINT8(BT_GATT_ITER_STOP, sstpt_discover->func(&sst_peer, NULL, sstpt_discover));
   sv_RunPair();
   sv_AssertFailed(ePER_SECURED, (uint8_t)-ENOENT);
   sv_LinkDown(0x16U);

   // Discovery cannot start
   si_discoverRet = -ENOMEM;
   su32_discover = 0U;
   sv_ToPairing(ePRL_CENTRAL);
   sv_SmpDone();
   sv_AssertFailed(ePER_SECURED, (uint8_t)-ENOMEM);
   sv_LinkDown(0x16U);
   si_discoverRet = 0;

   // The peer refuses the write (its link is not at level 4)
   su32_discover = 0U;
   su32_write = 0U;
   sv_ToPairing(ePRL_CENTRAL);
   sv_SmpDone();
   sv_PeerAcceptsSecured(0x05U);
   sv_AssertFailed(ePER_SECURED, 0x05U);
   sv_LinkDown(0x16U);

   // The write cannot be sent
   su32_discover = 0U;
   su32_write = 0U;
   si_writeRet = -ENOTCONN;
   sv_ToPairing(ePRL_CENTRAL);
   sv_SmpDone();
   sv_PeerAcceptsSecured(0U);
   sv_AssertFailed(ePER_SECURED, (uint8_t)-ENOTCONN);
}

/******************************************************************************/
/*  Guards on SMP and SECURED                                                 */
/******************************************************************************/
static void test_PairingIsAllowedOnlyOnTheVerifiedPeerLink(void)
{
   struct bt_conn_pairing_feat st_feat = { 0 };
   struct bt_conn_oob_info st_info = { .type = BT_CONN_OOB_LE_SC };

   // No run: a host (or anyone) cannot pair
   TEST_ASSERT_EQUAL_INT(BT_SECURITY_ERR_PAIR_NOT_ALLOWED,
      sstpt_authCb->pairing_accept(&sst_host, &st_feat));
   sv_StartRun(ePRL_PERIPHERAL);
   sv_LinkUp(ePRL_PERIPHERAL);
   // The peer, before its certificate is verified
   TEST_ASSERT_EQUAL_INT(BT_SECURITY_ERR_PAIR_NOT_ALLOWED,
      sstpt_authCb->pairing_accept(&sst_peer, &st_feat));
   sst_route.fpt_onCliReady(&sst_peer, 0);
   TEST_ASSERT_EQUAL_INT(0, si_RxObject(PAIR_APP_TYPE_PEER_CERT, 400U, eBS_OK));
   sv_RunPair();
   TEST_ASSERT_EQUAL_INT(BT_SECURITY_ERR_SUCCESS, sstpt_authCb->pairing_accept(&sst_peer, &st_feat));
   TEST_ASSERT_EQUAL_INT(BT_SECURITY_ERR_PAIR_NOT_ALLOWED,
      sstpt_authCb->pairing_accept(&sst_host, &st_feat));

   // OOB data is given to the peer link only
   sstpt_authCb->oob_data_request(&sst_host, &st_info);
   TEST_ASSERT_EQUAL_PTR(&sst_host, sstpt_authCancelConn);
   TEST_ASSERT_EQUAL_UINT32(0U, k_msgq_num_used_get(&sst_pairMsgq));

   // SMP results of other links are ignored
   sstpt_authInfoCb->pairing_complete(&sst_host, true);
   sstpt_authInfoCb->pairing_failed(&sst_host, BT_SECURITY_ERR_AUTH_FAIL);
   TEST_ASSERT_EQUAL_UINT32(0U, k_msgq_num_used_get(&sst_pairMsgq));
}

static void test_SecuredWriteIsGuarded(void)
{
   uint8_t u8_v = VEC_PAIR_SECURED_VALUE;
   uint8_t u8_bad = 0x02U;

   // Not pairing
   TEST_ASSERT_EQUAL_INT(BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED),
      gt_Pair_OnSecuredWrite(&sst_peer, &u8_v, 1U));
   sv_ToPairing(ePRL_PERIPHERAL);
   // From another link
   TEST_ASSERT_EQUAL_INT(BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED),
      gt_Pair_OnSecuredWrite(&sst_host, &u8_v, 1U));
   TEST_ASSERT_EQUAL_INT(BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED),
      gt_Pair_OnSecuredWrite(NULL, &u8_v, 1U));
   // Another value
   TEST_ASSERT_EQUAL_INT(BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED),
      gt_Pair_OnSecuredWrite(&sst_peer, &u8_bad, 1U));
   TEST_ASSERT_EQUAL_INT(BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED),
      gt_Pair_OnSecuredWrite(&sst_peer, &u8_v, 2U));
   TEST_ASSERT_EQUAL_UINT32(0U, k_msgq_num_used_get(&sst_pairMsgq));
}

static void test_CentralIgnoresSecuredWrites(void)
{
   uint8_t u8_v = VEC_PAIR_SECURED_VALUE;

   sv_ToPairing(ePRL_CENTRAL);
   TEST_ASSERT_EQUAL_INT(0, gt_Pair_OnSecuredWrite(&sst_peer, &u8_v, 1U));
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_PAIRING, su8_State());
   TEST_ASSERT_EQUAL_UINT32(0U, su32_ledValue);
}

/******************************************************************************/
/*  Timeouts, link loss, CANCEL, UNPAIR, wipe                                 */
/******************************************************************************/
static void test_PeerNotReachedInTime(void)
{
   sv_StartRun(ePRL_PERIPHERAL);
   sv_AdvanceMs(CONFIG_PAIR_CONNECT_TIMEOUT_MS - 1);
   TEST_ASSERT_EQUAL_UINT8(ePST_ARMED, su8_State());
   sv_AdvanceMs(1);
   sv_AssertFailed(ePER_TIMEOUT, ePST_ARMED);
   TEST_ASSERT_TRUE_MESSAGE(su32_advStop >= 2U, "directed advertising stopped");

   sv_StartRun(ePRL_CENTRAL);
   sv_AdvanceMs(CONFIG_PAIR_CONNECT_TIMEOUT_MS);
   sv_AssertFailed(ePER_TIMEOUT, ePST_ARMED);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(1U, su32_scanStop, "scan stopped");

   // The central's attempt is cancelled too
   sv_StartRun(ePRL_CENTRAL);
   sfpt_scanCb(&sst_addrB, -40, BT_GAP_ADV_TYPE_ADV_IND, NULL);
   sv_RunPair();
   sv_AdvanceMs(CONFIG_PAIR_CONNECT_TIMEOUT_MS);
   sv_AssertFailed(ePER_TIMEOUT, ePST_ARMED);
   TEST_ASSERT_EQUAL_PTR(&sst_peer, sstpt_disconnected);
}

static void test_PairingNotDoneInTime(void)
{
   sv_ToOobExchange(ePRL_CENTRAL);
   sv_AdvanceMs(CONFIG_PAIR_TIMEOUT_MS);
   sv_AssertFailed(ePER_TIMEOUT, ePST_OOB_EXCHANGE);
   TEST_ASSERT_EQUAL_PTR(&sst_peer, sstpt_disconnected);
}

static void test_StaleTimerIsIgnored(void)
{
   PairEvent_T st_event = { 0 };

   sv_StartRun(ePRL_CENTRAL);
   st_event.u8_type = ePEV_TIMEOUT;
   st_event.i32_value = (int32_t)(su32_runId - 1U);
   sv_HandleEvent(&st_event);
   TEST_ASSERT_EQUAL_UINT8(ePST_ARMED, su8_State());
   // The connect timer only fires while the peer is awaited
   sv_LinkUp(ePRL_CENTRAL);
   sv_ConnectTimeout(NULL);
   TEST_ASSERT_EQUAL_UINT32(0U, k_msgq_num_used_get(&sst_pairMsgq));
}

static void test_LinkLoss(void)
{
   // During a run
   sv_ToOobExchange(ePRL_PERIPHERAL);
   sv_LinkDown(0x08U);
   sv_AssertFailed(ePER_LINK_LOST, 0x08U);
   TEST_ASSERT_FALSE(sb_filterOn);
   TEST_ASSERT_EQUAL_PTR(&sst_host, sstpt_srvConn);

   // After pairing: still paired (bonded)
   sv_ToPairing(ePRL_CENTRAL);
   sv_SmpDone();
   sv_PeerAcceptsSecured(0U);
   sv_LinkDown(0x13U);
   TEST_ASSERT_EQUAL_UINT8(ePST_PAIRED, su8_State());

   // Other links are not the peer's
   gv_Pair_OnDisconnected(&sst_host, 0x13U);
   gv_Pair_OnDisconnected(NULL, 0x13U);
   TEST_ASSERT_EQUAL_UINT32(0U, k_msgq_num_used_get(&sst_pairMsgq));
}

static void test_CancelStopsARun(void)
{
   const PairVector_T *v = CONTROL_VEC("cancel");

   // Idle: nothing to cancel
   TEST_ASSERT_EQUAL_INT(0, gt_Pair_OnControlWrite(&sst_host, v->u8ar_wire, v->u8_wireLen));
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_IDLE, su8_State());

   sv_ToOobExchange(ePRL_CENTRAL);
   TEST_ASSERT_EQUAL_INT(0, gt_Pair_OnControlWrite(&sst_host, v->u8ar_wire, v->u8_wireLen));
   sv_RunPair();
   sv_AssertFailed(ePER_CANCELLED, 0U);
   TEST_ASSERT_EQUAL_PTR(&sst_peer, sstpt_disconnected);
}

static void test_UnpairForgetsThePeer(void)
{
   const PairVector_T *v = CONTROL_VEC("unpair");

   sst_ownId = sst_addrB;
   sst_addrB = sst_addrA;
   sv_ResetModule();
   gv_Pair_OnBtReady();
   sv_RunPair();
   sv_ToPairing(ePRL_PERIPHERAL);
   sv_SmpDone();
   TEST_ASSERT_EQUAL_INT(0, gt_Pair_OnSecuredWrite(&sst_peer, &(uint8_t){ VEC_PAIR_SECURED_VALUE }, 1U));
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_PAIRED, su8_State());
   su32_unpair = 0U;

   TEST_ASSERT_EQUAL_INT(0, gt_Pair_OnControlWrite(&sst_host, v->u8ar_wire, v->u8_wireLen));
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_IDLE, su8_State());
   TEST_ASSERT_EQUAL_UINT8(ePRL_NONE, su8ar_statusNow[4]);
   TEST_ASSERT_EQUAL_PTR(&sst_peer, sstpt_disconnected);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_unpair);
   TEST_ASSERT_FALSE(sb_unpairAll);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(&sst_addrB, &sst_unpairAddr, 7U);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_ledValue);
   sv_LinkDown(0x16U);
   TEST_ASSERT_EQUAL_UINT8(ePST_IDLE, su8_State());

   // UNPAIR during a run ends it
   sv_StartRun(ePRL_PERIPHERAL);
   TEST_ASSERT_EQUAL_INT(0, gt_Pair_OnControlWrite(&sst_host, v->u8ar_wire, v->u8_wireLen));
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_IDLE, su8_State());
   TEST_ASSERT_FALSE(gb_Pair_IsAdvertising());
}

static void test_WipeForgetsEveryBond(void)
{
   sv_ToPairing(ePRL_CENTRAL);
   TEST_ASSERT_TRUE(gb_Pair_IsRunning());
   gv_Pair_ForgetBonds();
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_IDLE, su8_State());
   TEST_ASSERT_TRUE(sb_unpairAll);
   TEST_ASSERT_FALSE(sb_scFlag);
}

static void test_StatusWithoutHostIsNotNotified(void)
{
   sb_hostUp = false;
   sv_StartRun(ePRL_CENTRAL);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_notify);
   // Read on demand all the same
   TEST_ASSERT_EQUAL_UINT8(ePST_ARMED, su8_State());
}

/******************************************************************************/
/*  Bond record and bonded reconnection                                       */
/******************************************************************************/
static void test_PairingSavesTheBondRecord(void)
{
   // Central: [role][peer address] under pair/peer
   sv_ToPairing(ePRL_CENTRAL);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(1U, su32_settingsDelete, "START drops an older record");
   TEST_ASSERT_EQUAL_STRING("pair/peer", scar_deleteName);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_save);
   sv_SmpDone();
   sv_PeerAcceptsSecured(0U);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_save);
   TEST_ASSERT_EQUAL_STRING("pair/peer", scar_saveName);
   TEST_ASSERT_EQUAL_UINT32(PAIR_BOND_RECORD_LEN, st_savedLen);
   TEST_ASSERT_EQUAL_HEX8(ePRL_CENTRAL, su8ar_saved[0]);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(&sst_addrB, &su8ar_saved[1], 7U);

   // Peripheral; a failed save is logged, and the pairing stands
   si_saveRet = -ENOSPC;
   sv_ToPairing(ePRL_PERIPHERAL);
   sv_SmpDone();
   TEST_ASSERT_EQUAL_INT(0, gt_Pair_OnSecuredWrite(&sst_peer, &(uint8_t){ VEC_PAIR_SECURED_VALUE }, 1U));
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_PAIRED, su8_State());
   TEST_ASSERT_EQUAL_HEX8(ePRL_PERIPHERAL, su8ar_saved[0]);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("bond record not saved"));

   // A failed run saves nothing
   su32_save = 0U;
   sv_StartRun(ePRL_CENTRAL);
   sv_AdvanceMs(CONFIG_PAIR_CONNECT_TIMEOUT_MS);
   sv_AssertFailed(ePER_TIMEOUT, ePST_ARMED);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_save);
}

static void test_SettingsHandlerChecksTheRecord(void)
{
   sv_ResetModule();
   TEST_ASSERT_EQUAL_STRING("pair", settings_handler_pair.name);
   TEST_ASSERT_EQUAL_INT(-ENOENT, settings_handler_pair.h_set("other", PAIR_BOND_RECORD_LEN,
      st_ReadRecord, NULL));
   TEST_ASSERT_EQUAL_INT(-EINVAL, settings_handler_pair.h_set("peer", PAIR_BOND_RECORD_LEN - 1U,
      st_ReadRecord, NULL));
   TEST_ASSERT_EQUAL_INT(-EINVAL, si_LoadRecord(ePRL_NONE, &sst_addrB));
   TEST_ASSERT_EQUAL_INT(-EINVAL, si_LoadRecord((PairRole_E)3, &sst_addrB));
   TEST_ASSERT_FALSE(sb_savedBondValid);

   // A read error, or a short read
   su8ar_saved[0] = ePRL_CENTRAL;
   st_readRet = -EIO;
   TEST_ASSERT_EQUAL_INT(-EIO, settings_handler_pair.h_set("peer", PAIR_BOND_RECORD_LEN,
      st_ReadRecord, NULL));
   st_readRet = 0;
   st_savedLen = 3U;
   TEST_ASSERT_EQUAL_INT(-EINVAL, settings_handler_pair.h_set("peer", PAIR_BOND_RECORD_LEN,
      st_ReadRecord, NULL));
   TEST_ASSERT_FALSE(sb_savedBondValid);

   TEST_ASSERT_EQUAL_INT(0, si_LoadRecord(ePRL_PERIPHERAL, &sst_addrB));
   TEST_ASSERT_TRUE(sb_savedBondValid);
}

static void test_BtReadyRestoresTheRecordedBond(void)
{
   // The record's bond wins over a bond listed before it
   sv_ResetModule();
   TEST_ASSERT_EQUAL_INT(0, si_LoadRecord(ePRL_CENTRAL, &sst_addrB));
   sb_hasBond = true;
   sb_otherBondFirst = true;
   gv_Pair_OnBtReady();
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_PAIRED, su8_State());
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(ePRL_CENTRAL, su8ar_statusNow[4], "the saved role");
   TEST_ASSERT_EQUAL_HEX8_ARRAY(&sst_addrB, &su8ar_statusNow[12], 7U);
   TEST_ASSERT_TRUE(su32_notify > 0U);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_settingsDelete);
   // The central looks for its peer at once
   TEST_ASSERT_EQUAL_UINT32(1U, su32_scanStart);
   TEST_ASSERT_FALSE(gb_Pair_AwaitsBondedPeer());

   // Without a record: the first bond, not reconnected to
   sv_ResetModule();
   su32_scanStart = 0U;
   gv_Pair_OnBtReady();
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_PAIRED, su8_State());
   TEST_ASSERT_EQUAL_UINT8(ePRL_NONE, su8ar_statusNow[4]);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(&sst_addrOther, &su8ar_statusNow[12], 7U);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_scanStart);
   TEST_ASSERT_FALSE(gb_Pair_ClaimConn(&sst_other, 0U));
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("no record: not reconnected"));
}

static void test_HostBondIsNoPeer(void)
{
   // Without a record the first bond would be the peer; the host's is skipped
   sv_ResetModule();
   sb_hasBond = true;
   sb_otherBondFirst = true;
   sb_hostBondIsOther = true;
   gv_Pair_OnBtReady();
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_PAIRED, su8_State());
   TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(&sst_addrB, &su8ar_statusNow[12], 7U, "the peer, not the host");

   // The host's bond alone makes no peer
   sv_ResetModule();
   sb_hasBond = true;
   sb_otherBondFirst = true;
   sb_hostBondIsOther = true;
   sst_addrB = sst_addrOther;
   gv_Pair_OnBtReady();
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_IDLE, su8_State());
}

static void test_BondedPeerAddressForDirectedAdvertising(void)
{
   bt_addr_le_t st_addr;

   TEST_ASSERT_FALSE(gb_Pair_GetBondedPeer(&st_addr));
   TEST_ASSERT_FALSE(gb_Pair_GetBondedPeer(NULL));
   sv_RestoreBond(ePRL_PERIPHERAL);
   TEST_ASSERT_TRUE(gb_Pair_AwaitsBondedPeer());
   TEST_ASSERT_TRUE(gb_Pair_GetBondedPeer(&st_addr));
   TEST_ASSERT_EQUAL_HEX8_ARRAY(&sst_addrB, &st_addr, 7U);
}

static void test_StaleRecordIsDeleted(void)
{
   // A record without its bond
   sv_ResetModule();
   TEST_ASSERT_EQUAL_INT(0, si_LoadRecord(ePRL_CENTRAL, &sst_addrB));
   gv_Pair_OnBtReady();
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_IDLE, su8_State());
   TEST_ASSERT_EQUAL_UINT32(1U, su32_settingsDelete);
   TEST_ASSERT_EQUAL_STRING("pair/peer", scar_deleteName);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_scanStart);

   // A device that is not provisioned keeps neither
   sv_ResetModule();
   su32_settingsDelete = 0U;
   se_provState = ePS_KEY_READY;
   sb_hasBond = true;
   TEST_ASSERT_EQUAL_INT(0, si_LoadRecord(ePRL_PERIPHERAL, &sst_addrB));
   gv_Pair_OnBtReady();
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_IDLE, su8_State());
   TEST_ASSERT_TRUE(sb_unpairAll);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_settingsDelete);
   TEST_ASSERT_FALSE(gb_Pair_AwaitsBondedPeer());
}

static void test_CentralReconnectsAndBlinks(void)
{
   sv_RestoreBond(ePRL_CENTRAL);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_scanStart);

   // Another device, then the peer's undirected advertising
   sfpt_scanCb(&sst_addrOther, -40, BT_GAP_ADV_TYPE_ADV_IND, NULL);
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT32(0U, su32_create);
   sv_BondLinkUp(ePRL_CENTRAL);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_scanStop);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_create);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(&sst_addrB, &sst_createPeer, 7U);
   TEST_ASSERT_EQUAL_UINT16(PAIR_CONN_INTERVAL, sst_createParam.interval_min);

   // The central encrypts with the stored keys; SETU stays with the host
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(1U, su32_setSec, "encryption at level 4");
   TEST_ASSERT_EQUAL_UINT32(0U, su32_filterSet);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_rebind);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_attach);
   TEST_ASSERT_EQUAL_UINT8(ePST_PAIRED, su8_State());
   TEST_ASSERT_EQUAL_UINT32(0U, su32_ledValue);

   // Level 4: the LED blinks for as long as the link is up
   sv_BondSecurity(BT_SECURITY_L4, BT_SECURITY_ERR_SUCCESS);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("bonded peer reconnected at level 4"));
   TEST_ASSERT_EQUAL_UINT32(1U, su32_ledValue);
   sv_AdvanceMs(PAIR_LED_BLINK_MS);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_ledValue);
   sv_AdvanceMs(PAIR_LED_BLINK_MS);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_ledValue);
   // The secure timer was stopped
   sv_AdvanceMs(PAIR_RECONNECT_SECURE_MS);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_disconnect);
   // A later security event changes nothing
   su32_ledSets = 0U;
   sv_BondSecurity(BT_SECURITY_L4, BT_SECURITY_ERR_SUCCESS);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_ledSets);

   // The link drops: LED off, no more blinking, and the central looks again
   sv_LinkDown(0x08U);
   TEST_ASSERT_EQUAL_UINT8(ePST_PAIRED, su8_State());
   TEST_ASSERT_EQUAL_UINT32(0U, su32_ledValue);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, su32_filterClear, "SETU never moved");
   TEST_ASSERT_EQUAL_UINT32(0U, su32_detach);
   su32_ledSets = 0U;
   sv_AdvanceMs(PAIR_RECONNECT_DELAY_MS - 1);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_scanStart);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_ledSets);
   sv_AdvanceMs(1);
   TEST_ASSERT_EQUAL_UINT32(2U, su32_scanStart);

   // And reconnects again, every time
   sv_BondLinkUp(ePRL_CENTRAL);
   sv_BondSecurity(BT_SECURITY_L4, BT_SECURITY_ERR_SUCCESS);
   TEST_ASSERT_EQUAL_UINT32(2U, su32_setSec);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_ledValue);
}

static void test_PeripheralAwaitsItsCentralAndBlinks(void)
{
   su32_refresh = 0U;
   sv_RestoreBond(ePRL_PERIPHERAL);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, su32_scanStart, "the peripheral does not scan");
   TEST_ASSERT_TRUE_MESSAGE(gb_Pair_AwaitsBondedPeer(), "advertising runs even with a host");
   TEST_ASSERT_TRUE(su32_refresh > 0U);
   TEST_ASSERT_FALSE(gb_Pair_IsAdvertising());

   // The central connects; the peripheral leaves encryption to it
   TEST_ASSERT_FALSE(gb_Pair_ClaimConn(&sst_other, 0U));
   sv_BondLinkUp(ePRL_PERIPHERAL);
   TEST_ASSERT_FALSE(gb_Pair_AwaitsBondedPeer());
   TEST_ASSERT_FALSE_MESSAGE(gb_Pair_ClaimConn(&sst_peer, 0U), "one peer link");
   TEST_ASSERT_EQUAL_UINT32(0U, su32_setSec);
   sv_BondSecurity(BT_SECURITY_L4, BT_SECURITY_ERR_SUCCESS);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_ledValue);
   sv_AdvanceMs(PAIR_LED_BLINK_MS);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_ledValue);

   // The link drops: LED off, advertising for the central again
   su32_refresh = 0U;
   sv_LinkDown(0x13U);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_ledValue);
   TEST_ASSERT_TRUE(gb_Pair_AwaitsBondedPeer());
   TEST_ASSERT_TRUE(su32_refresh > 0U);
   sv_AdvanceMs(PAIR_RECONNECT_DELAY_MS);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_scanStart);
}

static void test_BondedLinkMustReachLevel4(void)
{
   // Encryption fails (the peer lost its keys)
   sv_RestoreBond(ePRL_CENTRAL);
   sv_BondLinkUp(ePRL_CENTRAL);
   sv_BondSecurity(BT_SECURITY_L1, BT_SECURITY_ERR_PIN_OR_KEY_MISSING);
   TEST_ASSERT_EQUAL_PTR(&sst_peer, sstpt_disconnected);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_ledValue);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, su32_abortRx, "the host's transfers go on");
   TEST_ASSERT_EQUAL_UINT32(0U, su32_abortTx);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("bonded link not secured: level 1, error 2"));

   // Encrypted below level 4
   sv_RestoreBond(ePRL_PERIPHERAL);
   su32_disconnect = 0U;
   sv_BondLinkUp(ePRL_PERIPHERAL);
   sv_BondSecurity(BT_SECURITY_L2, BT_SECURITY_ERR_SUCCESS);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_disconnect);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_ledValue);

   // Not encrypted in time
   sv_RestoreBond(ePRL_PERIPHERAL);
   su32_disconnect = 0U;
   sv_BondLinkUp(ePRL_PERIPHERAL);
   sv_AdvanceMs(PAIR_RECONNECT_SECURE_MS - 1);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_disconnect);
   sv_AdvanceMs(1);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_disconnect);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("bonded link not secured in time"));

   // Encryption cannot start
   si_setSecRet = -ENOMEM;
   sv_RestoreBond(ePRL_CENTRAL);
   su32_disconnect = 0U;
   sv_BondLinkUp(ePRL_CENTRAL);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_disconnect);
   si_setSecRet = 0;

   // Security of other links is not the bond's
   sv_RestoreBond(ePRL_PERIPHERAL);
   sv_BondLinkUp(ePRL_PERIPHERAL);
   gv_Pair_OnSecurityChanged(&sst_host, BT_SECURITY_L4, 0U);
   gv_Pair_OnSecurityChanged(NULL, BT_SECURITY_L4, 0U);
   TEST_ASSERT_EQUAL_UINT32(0U, k_msgq_num_used_get(&sst_pairMsgq));
}

static void test_RunIgnoresSecurityEvents(void)
{
   // A pairing run follows SMP; security events of its link change nothing
   sv_ToPairing(ePRL_PERIPHERAL);
   sv_BondSecurity(BT_SECURITY_L1, BT_SECURITY_ERR_AUTH_FAIL);
   TEST_ASSERT_EQUAL_UINT8(ePST_PAIRING, su8_State());
   TEST_ASSERT_EQUAL_UINT32(0U, su32_disconnect);
   // Nor once paired over that link: its LED stays steady
   sv_SmpDone();
   TEST_ASSERT_EQUAL_INT(0, gt_Pair_OnSecuredWrite(&sst_peer, &(uint8_t){ VEC_PAIR_SECURED_VALUE }, 1U));
   sv_RunPair();
   sv_BondSecurity(BT_SECURITY_L4, BT_SECURITY_ERR_SUCCESS);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_ledValue);
   sv_AdvanceMs(PAIR_LED_BLINK_MS);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(1U, su32_ledValue, "steady, not blinking");
}

static void test_ReconnectionRetries(void)
{
   // The scan cannot start
   si_scanStartRet = -EAGAIN;
   sv_RestoreBond(ePRL_CENTRAL);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_scanStart);
   si_scanStartRet = 0;
   sv_AdvanceMs(PAIR_RECONNECT_DELAY_MS);
   TEST_ASSERT_EQUAL_UINT32(2U, su32_scanStart);
   TEST_ASSERT_TRUE(sb_scanning);

   // Already scanning: no second scan
   sv_ReconnectStart();
   TEST_ASSERT_EQUAL_UINT32(2U, su32_scanStart);

   // The connection cannot be created
   si_createRet = -ENOMEM;
   sfpt_scanCb(&sst_addrB, -40, BT_GAP_ADV_TYPE_ADV_IND, NULL);
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_PAIRED, su8_State());
   si_createRet = 0;
   sv_AdvanceMs(PAIR_RECONNECT_DELAY_MS);
   TEST_ASSERT_EQUAL_UINT32(3U, su32_scanStart);

   // The connection fails
   sfpt_scanCb(&sst_addrB, -40, BT_GAP_ADV_TYPE_ADV_IND, NULL);
   sv_RunPair();
   TEST_ASSERT_TRUE(gb_Pair_ClaimConn(&sst_peer, 0x3EU));
   sv_RunPair();
   TEST_ASSERT_NULL(sstpt_createConn);
   TEST_ASSERT_EQUAL_UINT8(ePST_PAIRED, su8_State());
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("bonded peer not reached (0x3e)"));
   sv_AdvanceMs(PAIR_RECONNECT_DELAY_MS);
   TEST_ASSERT_EQUAL_UINT32(4U, su32_scanStart);
   sv_BondLinkUp(ePRL_CENTRAL);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_setSec);
}

static void test_UnpairStopsTheReconnection(void)
{
   const PairVector_T *v = CONTROL_VEC("unpair");

   // While the central looks for the peer
   sv_RestoreBond(ePRL_CENTRAL);
   TEST_ASSERT_EQUAL_INT(0, gt_Pair_OnControlWrite(&sst_host, v->u8ar_wire, v->u8_wireLen));
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_IDLE, su8_State());
   TEST_ASSERT_EQUAL_UINT32(1U, su32_scanStop);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_settingsDelete);
   TEST_ASSERT_FALSE(gb_Pair_ClaimConn(&sst_peer, 0U));

   // While the bonded link blinks: the link goes, SETU of the host is untouched
   sv_RestoreBond(ePRL_PERIPHERAL);
   sv_BondLinkUp(ePRL_PERIPHERAL);
   sv_BondSecurity(BT_SECURITY_L4, BT_SECURITY_ERR_SUCCESS);
   TEST_ASSERT_EQUAL_INT(0, gt_Pair_OnControlWrite(&sst_host, v->u8ar_wire, v->u8_wireLen));
   sv_RunPair();
   TEST_ASSERT_EQUAL_PTR(&sst_peer, sstpt_disconnected);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_abortRx);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_ledValue);
   sv_AdvanceMs(PAIR_LED_BLINK_MS);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, su32_ledValue, "blinking stopped");
   sv_LinkDown(0x16U);
   TEST_ASSERT_EQUAL_UINT8(ePST_IDLE, su8_State());
   TEST_ASSERT_FALSE(gb_Pair_AwaitsBondedPeer());
   TEST_ASSERT_EQUAL_UINT32(0U, su32_filterClear);
}

static void test_StartStopsTheReconnection(void)
{
   // The central's connection attempt to the bonded peer is pending
   sv_RestoreBond(ePRL_CENTRAL);
   sfpt_scanCb(&sst_addrB, -40, BT_GAP_ADV_TYPE_ADV_IND, NULL);
   sv_RunPair();
   TEST_ASSERT_EQUAL_PTR(&sst_peer, sstpt_createConn);

   // START pairs the same peer afresh: the attempt is cancelled ...
   sv_StartRun(ePRL_CENTRAL);
   TEST_ASSERT_EQUAL_PTR(&sst_peer, sstpt_disconnected);
   TEST_ASSERT_EQUAL_UINT8(ePST_ARMED, su8_State());
   TEST_ASSERT_EQUAL_UINT32(1U, su32_settingsDelete);
   // ... and its end is not taken for the run's
   TEST_ASSERT_TRUE(gb_Pair_ClaimConn(&sst_peer, 0x02U));
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_ARMED, su8_State());
   TEST_ASSERT_TRUE(sb_scanning);
   // No reconnection timer is left
   sv_AdvanceMs(PAIR_RECONNECT_DELAY_MS);
   TEST_ASSERT_EQUAL_UINT32(2U, su32_scanStart);

   // A late bonded link after the bond was dropped is let go
   sv_RestoreBond(ePRL_PERIPHERAL);
   su32_disconnect = 0U;
   TEST_ASSERT_TRUE(gb_Pair_ClaimConn(&sst_peer, 0U));
   sv_HandleEvent(&(PairEvent_T){ .u8_type = ePEV_UNPAIR });
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_IDLE, su8_State());
   TEST_ASSERT_TRUE(su32_disconnect >= 1U);
}

static void test_PairedLinkLossStartsTheReconnection(void)
{
   uint8_t u8_v = VEC_PAIR_SECURED_VALUE;

   // Central: right after the pairing
   sv_ToPairing(ePRL_CENTRAL);
   sv_SmpDone();
   sv_PeerAcceptsSecured(0U);
   su32_scanStart = 0U;
   sv_LinkDown(0x08U);
   sv_AdvanceMs(PAIR_RECONNECT_DELAY_MS);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_scanStart);
   sv_BondLinkUp(ePRL_CENTRAL);
   sv_BondSecurity(BT_SECURITY_L4, BT_SECURITY_ERR_SUCCESS);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_ledValue);

   // Peripheral: the steady LED goes off with the link, blinks on its return
   sst_ownId = sst_addrB;
   sst_addrB = sst_addrA;
   sv_ResetModule();
   gv_Pair_OnBtReady();
   sv_RunPair();
   sv_ToPairing(ePRL_PERIPHERAL);
   sv_SmpDone();
   TEST_ASSERT_EQUAL_INT(0, gt_Pair_OnSecuredWrite(&sst_peer, &u8_v, 1U));
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT32(1U, su32_ledValue);
   TEST_ASSERT_FALSE(gb_Pair_AwaitsBondedPeer());
   sv_LinkDown(0x08U);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_ledValue);
   TEST_ASSERT_TRUE(gb_Pair_AwaitsBondedPeer());
   sv_BondLinkUp(ePRL_PERIPHERAL);
   sv_BondSecurity(BT_SECURITY_L4, BT_SECURITY_ERR_SUCCESS);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_ledValue);
   sv_AdvanceMs(PAIR_LED_BLINK_MS);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_ledValue);
}

static void test_WipeStopsTheReconnection(void)
{
   sv_RestoreBond(ePRL_PERIPHERAL);
   gv_Pair_ForgetBonds();
   sv_RunPair();
   TEST_ASSERT_EQUAL_UINT8(ePST_IDLE, su8_State());
   TEST_ASSERT_TRUE(sb_unpairAll);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_settingsDelete);
   TEST_ASSERT_FALSE(gb_Pair_AwaitsBondedPeer());
}

int main(void)
{
   (void)setvbuf(stdout, NULL, _IONBF, 0);
   UNITY_BEGIN();
   RUN_TEST(test_InitRegistersRangeAndSmpCallbacks);
   RUN_TEST(test_InitErrorsAreReturned);
   RUN_TEST(test_BtReadyLearnsTheOwnAddress);
   RUN_TEST(test_BtReadyRestoresTheBond);
   RUN_TEST(test_BtReadyDropsBondsOfAnUnprovisionedDevice);
   RUN_TEST(test_ControlVectorsAreAccepted);
   RUN_TEST(test_MalformedControlIsRefused);
   RUN_TEST(test_StartDuringARunIsRefused);
   RUN_TEST(test_PeerCannotDriveThisDevice);
   RUN_TEST(test_OnlyTheTrustedHostDrivesThisDevice);
   RUN_TEST(test_FullQueueIsReported);
   RUN_TEST(test_StartAsPeripheralAdvertisesToThePeer);
   RUN_TEST(test_StartAsCentralScansAndConnects);
   RUN_TEST(test_StartRefusals);
   RUN_TEST(test_ClaimTakesOnlyThePeerOfARun);
   RUN_TEST(test_LinkUpMovesSETUToThePeer);
   RUN_TEST(test_LinkUpFailures);
   RUN_TEST(test_LateLinkAfterTheRunIsDropped);
   RUN_TEST(test_PeerObjectsAreChecked);
   RUN_TEST(test_PeerCertificateIsVerified);
   RUN_TEST(test_OobWaitsForTheOwnCertificate);
   RUN_TEST(test_EarlyPeerOobIsVerifiedLater);
   RUN_TEST(test_CentralPairs);
   RUN_TEST(test_PeripheralPairs);
   RUN_TEST(test_OobRequestBeforeThePeerOobIsAnsweredLater);
   RUN_TEST(test_RestartReleasesThePreviousLink);
   RUN_TEST(test_PeerCertificateRejected);
   RUN_TEST(test_OobFailures);
   RUN_TEST(test_TransferFailures);
   RUN_TEST(test_SmpFailures);
   RUN_TEST(test_SecuredFailures);
   RUN_TEST(test_PairingIsAllowedOnlyOnTheVerifiedPeerLink);
   RUN_TEST(test_SecuredWriteIsGuarded);
   RUN_TEST(test_CentralIgnoresSecuredWrites);
   RUN_TEST(test_PeerNotReachedInTime);
   RUN_TEST(test_PairingNotDoneInTime);
   RUN_TEST(test_StaleTimerIsIgnored);
   RUN_TEST(test_LinkLoss);
   RUN_TEST(test_CancelStopsARun);
   RUN_TEST(test_UnpairForgetsThePeer);
   RUN_TEST(test_WipeForgetsEveryBond);
   RUN_TEST(test_StatusWithoutHostIsNotNotified);
   RUN_TEST(test_PairingSavesTheBondRecord);
   RUN_TEST(test_SettingsHandlerChecksTheRecord);
   RUN_TEST(test_BtReadyRestoresTheRecordedBond);
   RUN_TEST(test_StaleRecordIsDeleted);
   RUN_TEST(test_HostBondIsNoPeer);
   RUN_TEST(test_BondedPeerAddressForDirectedAdvertising);
   RUN_TEST(test_CentralReconnectsAndBlinks);
   RUN_TEST(test_PeripheralAwaitsItsCentralAndBlinks);
   RUN_TEST(test_BondedLinkMustReachLevel4);
   RUN_TEST(test_RunIgnoresSecurityEvents);
   RUN_TEST(test_ReconnectionRetries);
   RUN_TEST(test_UnpairStopsTheReconnection);
   RUN_TEST(test_StartStopsTheReconnection);
   RUN_TEST(test_PairedLinkLossStartsTheReconnection);
   RUN_TEST(test_WipeStopsTheReconnection);
   return UNITY_END();
}
