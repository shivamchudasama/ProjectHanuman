/**
 * @file          test_pair_e2e.c
 * @brief         Device pairing end to end on the host: the real SETU engine
 *                in both roles, the real appType router and the real Pair.c,
 *                over the simulated link in sim_link.h. The device is the
 *                peripheral; the host link is sim_link's second link
 *                (sst_conn2) and the peer link is its simulated link, whose
 *                scripted peer plays the other device: it hosts the SETU
 *                service the device Client attaches to and receives this
 *                device's certificate and OOB frame on, and sends its own
 *                certificate and OOB frame to the device Server. The BT stack
 *                beyond GATT (advertising, SMP), certificate verification and
 *                OOB signing are stubbed (test_pair.c and test_pair_oob.c cover
 *                them). Checks that SETU moves to the peer link and back,
 *                that the peer reaches nothing but the pairing range, and that
 *                both objects cross intact.
 *                Contract: _DOC/Pairing/PROTOCOL.md.
 *
 * @date          06/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

/* Both roles, as in the firmware */
#include "SETU_Core.c"
#include "SETU_Server.c"
#include "SETU_Client.c"
#include "sim_link.h"
#include "SETURouter.c"
#include "Pair.c"
#include "wire_vectors.h"

/******************************************************************************/
/*  Device-side stand-ins                                                     */
/******************************************************************************/
/* _SETU_SVC: the CTRL attribute is the one the simulated link knows */
const struct bt_gatt_attr *gstpt_SETUSvc_Init(void) { return &sst_ctrlAttr; }

/* _BLE: the host is the second simulated link */
struct bt_conn *gstpt_BLE_GetHostConn(void) { return &sst_conn2; }
void gv_BLE_RefreshAdv(void) {}

/* _HOST_AUTH: the host link is the trusted host; it holds no bond here */
bool gb_HostAuth_IsTrustedConn(const struct bt_conn *stpt_conn) { return stpt_conn == &sst_conn2; }
bool gb_HostAuth_IsHostAddr(const bt_addr_le_t *stpt_addr) { (void)stpt_addr; return false; }

/* Addresses: this device (peripheral) and the peer device on sst_conn */
static bt_addr_le_t sst_own;
static bt_addr_le_t sst_peerDev;
const bt_addr_le_t *bt_conn_get_dst(const struct bt_conn *conn)
{
   return (conn == &sst_conn) ? &sst_peerDev : &sst_own;
}
void bt_id_get(bt_addr_le_t *addrs, size_t *count) { addrs[0] = sst_own; *count = 1U; }

/* Advertising, scanning, connections, bonds */
static bool sb_directed;
int bt_le_adv_start(const struct bt_le_adv_param *param, const struct bt_data *ad,
   size_t ad_len, const struct bt_data *sd, size_t sd_len)
{
   (void)ad; (void)ad_len; (void)sd; (void)sd_len;
   sb_directed = (param->peer != NULL) && (bt_addr_le_cmp(param->peer, &sst_peerDev) == 0);
   return 0;
}
int bt_le_adv_stop(void) { return 0; }
int bt_le_scan_start(const struct bt_le_scan_param *param, bt_le_scan_cb_t cb) { (void)param; (void)cb; return 0; }
int bt_le_scan_stop(void) { return 0; }
int bt_conn_le_create(const bt_addr_le_t *peer, const struct bt_conn_le_create_param *create_param,
   const struct bt_le_conn_param *conn_param, struct bt_conn **conn)
{
   (void)peer; (void)create_param; (void)conn_param; (void)conn;
   return -ENOTSUP;
}
static uint32_t su32_disconnects;
int bt_conn_disconnect(struct bt_conn *conn, uint8_t reason) { (void)conn; (void)reason; su32_disconnects++; return 0; }
int bt_unpair(uint8_t id, const bt_addr_le_t *addr) { (void)id; (void)addr; return 0; }
int settings_save_one(const char *name, const void *value, size_t val_len)
{
   (void)name; (void)value; (void)val_len;
   return 0;
}
int settings_delete(const char *name) { (void)name; return 0; }
void bt_foreach_bond(uint8_t id, void (*func)(const struct bt_bond_info *info, void *user_data),
   void *user_data)
{
   (void)id; (void)func; (void)user_data;
}

/* SMP: driven by the test through the registered callbacks */
static const struct bt_conn_auth_cb *sstpt_auth;
static struct bt_conn_auth_info_cb *sstpt_authInfo;
static bool sb_scFlag;
static uint32_t su32_scData;
int bt_conn_auth_cb_register(const struct bt_conn_auth_cb *cb) { sstpt_auth = cb; return 0; }
int bt_conn_auth_info_cb_register(struct bt_conn_auth_info_cb *cb) { sstpt_authInfo = cb; return 0; }
int bt_conn_auth_cancel(struct bt_conn *conn) { (void)conn; return 0; }
int bt_conn_set_security(struct bt_conn *conn, bt_security_t sec) { (void)conn; (void)sec; return 0; }
bt_security_t bt_conn_get_security(const struct bt_conn *conn) { (void)conn; return BT_SECURITY_L4; }
int bt_le_oob_get_local(uint8_t id, struct bt_le_oob *oob)
{
   (void)id;
   (void)memcpy(oob->le_sc_data.r, gu8ar_vecPairOobR, 16U);
   (void)memcpy(oob->le_sc_data.c, gu8ar_vecPairOobC, 16U);
   return 0;
}
void bt_le_oob_set_sc_flag(bool enable) { sb_scFlag = enable; }
int bt_le_oob_set_sc_data(struct bt_conn *conn, const struct bt_le_oob_sc_data *oobd_local,
   const struct bt_le_oob_sc_data *oobd_remote)
{
   TEST_ASSERT_EQUAL_PTR(&sst_conn, conn);
   // The peer's verified OOB data is what its frame carried
   TEST_ASSERT_EQUAL_HEX8_ARRAY(&gu8ar_vecPairOobFrame[0], oobd_remote->r, 16U);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(&gu8ar_vecPairOobFrame[16], oobd_remote->c, 16U);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(gu8ar_vecPairOobR, oobd_local->r, 16U);
   su32_scData++;
   return 0;
}
int bt_gatt_write(struct bt_conn *conn, struct bt_gatt_write_params *params)
{
   (void)conn; (void)params;
   return -ENOTSUP;
}

/* Certificates and OOB signing */
DeviceCertData_T gst_deviceCertData;
static uint8_t su8ar_peerCert[VEC_PROV_MAX_CERT_LEN];
static uint32_t su32_peerCertLen;
static bool sb_peerCertSeen;

DeviceCertStatus_E ge_VerifyRemoteDeviceCertificate(const uint8_t *u8pt_der, size_t t_len,
   psa_key_id_t *tpt_remotePubKeyID)
{
   // The device verifies exactly what the peer sent
   TEST_ASSERT_EQUAL_UINT32(su32_peerCertLen, t_len);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(su8ar_peerCert, u8pt_der, t_len);
   sb_peerCertSeen = true;
   *tpt_remotePubKeyID = 9U;
   return eDCS_OK;
}
bool gb_IsTrustAnchorSet(void) { return true; }
psa_status_t psa_destroy_key(psa_key_id_t key) { (void)key; return PSA_SUCCESS; }
psa_status_t gt_PairOob_Sign(psa_key_id_t t_key, const uint8_t *u8pt_rand,
   const uint8_t *u8pt_confirm, const uint8_t *u8pt_sender, const uint8_t *u8pt_receiver,
   uint8_t *u8pt_frame)
{
   (void)t_key; (void)u8pt_sender; (void)u8pt_receiver;
   (void)memcpy(&u8pt_frame[0], u8pt_rand, 16U);
   (void)memcpy(&u8pt_frame[16], u8pt_confirm, 16U);
   (void)memcpy(&u8pt_frame[32], gu8ar_vecPairOobSig, 64U);
   return PSA_SUCCESS;
}
psa_status_t gt_PairOob_Verify(psa_key_id_t t_peerKey, const uint8_t *u8pt_frame,
   const uint8_t *u8pt_sender, const uint8_t *u8pt_receiver)
{
   (void)u8pt_sender; (void)u8pt_receiver;
   TEST_ASSERT_EQUAL_UINT32(9U, t_peerKey);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(gu8ar_vecPairOobFrame, u8pt_frame, PAIR_OOB_FRAME_LEN);
   return PSA_SUCCESS;
}

/* Provisioning, LEDs, the service */
ProvState_E ge_Prov_GetState(void) { return ePS_PROVISIONED; }
int dk_leds_init(void) { return 0; }
static uint32_t su32_led;
int dk_set_led(uint8_t led_idx, uint32_t val) { (void)led_idx; su32_led = val; return 0; }
static uint8_t su8ar_hostStatus[PAIR_STATUS_LEN];
int gi_PairSvc_NotifyStatus(struct bt_conn *stpt_conn, const uint8_t *u8pt_status, uint16_t u16_len)
{
   TEST_ASSERT_EQUAL_PTR(&sst_conn2, stpt_conn);
   (void)memcpy(su8ar_hostStatus, u8pt_status, u16_len);
   return 0;
}

/* Another module on the Server (as hex upload): the peer must not reach it */
static uint32_t su32_otherStarts;
static int si_OtherStart(uint8_t t, uint32_t n) { (void)t; (void)n; su32_otherStarts++; return 0; }
static int si_OtherData(uint8_t t, uint32_t o, const uint8_t *d, uint16_t n)
{
   (void)t; (void)o; (void)d; (void)n;
   return 0;
}

/******************************************************************************/
/*  Helpers                                                                   */
/******************************************************************************/
static void sv_RunPairThread(void)
{
   gv_SimRunThread(sv_PairThread);
   // The work queue shows the LED
   (void)gb_SimRunDelayedWork(&sst_ledWork);
}

static uint8_t su8_StateNow(void)
{
   uint8_t u8ar_status[PAIR_STATUS_LEN];

   sv_RunPairThread();
   gv_Pair_GetStatus(u8ar_status);
   return u8ar_status[0];
}

static bool sb_PeerGotObject(void) { sv_RunPairThread(); return sst_peer.i_rxDone != STATUS_NONE; }
static bool sb_PeerSendDone(void) { sv_RunPairThread(); return sst_peer.i_txDone != STATUS_NONE; }
static bool sb_Pairing(void) { return su8_StateNow() == ePST_PAIRING; }
static bool sb_OobExchange(void) { return su8_StateNow() == ePST_OOB_EXCHANGE; }
static bool sb_CertExchange(void) { return su8_StateNow() == ePST_CERT_EXCHANGE; }

/** The peer device sends one object to this device's Server. */
static void sv_PeerSends(uint8_t u8_type, const uint8_t *u8pt_data, uint32_t u32_len)
{
   sst_peer.i_txDone = STATUS_NONE;
   sv_PeerStartSend(u8_type, u8pt_data, u32_len, 6U, false);
   TEST_ASSERT_TRUE_MESSAGE(sb_RunUntil(sb_PeerSendDone, 5000), "peer transfer stuck");
}

/** The peer device receives one object from this device's Client. */
static void sv_PeerReceives(uint8_t u8_type, const uint8_t *u8pt_exp, uint32_t u32_len)
{
   TEST_ASSERT_TRUE_MESSAGE(sb_RunUntil(sb_PeerGotObject, 5000), "device transfer stuck");
   TEST_ASSERT_EQUAL_INT(eBS_OK, sst_peer.i_rxDone);
   TEST_ASSERT_EQUAL_HEX8(u8_type, sst_peer.u8_rxType);
   TEST_ASSERT_EQUAL_UINT32(u32_len, sst_peer.u32_rxTotal);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(u8pt_exp, sst_peer.u8ar_rx, u32_len);
   sst_peer.i_rxDone = STATUS_NONE;
}

void setUp(void)
{
   uint32_t i;
   uint8_t u8ar_cmd[PAIR_START_LEN];

   (void)memcpy(&sst_own, &gstar_vecPairControls[1].u8ar_wire[2], 7U);    /* "start_peripheral" peer */
   (void)memcpy(&sst_peerDev, &gstar_vecPairControls[0].u8ar_wire[2], 7U); /* "start_central" peer  */
   gst_deviceCertData.u8_isDeviceCertGenerated = 1U;
   gst_deviceCertData.u16_deviceCertLen = 517U;
   for (i = 0U; i < 517U; i++) { gst_deviceCertData.u8ar_DeviceCert[i] = (uint8_t)(i * 3U + 7U); }
   su32_peerCertLen = 611U;
   for (i = 0U; i < su32_peerCertLen; i++) { su8ar_peerCert[i] = (uint8_t)(i ^ 0x3CU); }
   sb_peerCertSeen = false;
   su32_scData = 0U;
   su32_otherStarts = 0U;
   sb_dbHasService = true;

   // The host is connected and holds the Server, as ConnectionHandling.c does
   (void)gi_SETUS_Rebind(&sst_conn2);
   gv_Pair_OnBtReady();
   sv_RunPairThread();

   // The host starts the run: this device is the peripheral
   u8ar_cmd[0] = PAIR_OP_START;
   u8ar_cmd[1] = ePRL_PERIPHERAL;
   (void)memcpy(&u8ar_cmd[2], &sst_peerDev, 7U);
   TEST_ASSERT_EQUAL_INT(0, gt_Pair_OnControlWrite(&sst_conn2, u8ar_cmd, sizeof(u8ar_cmd)));
   sv_RunPairThread();
   TEST_ASSERT_TRUE_MESSAGE(sb_directed, "advertising directed to the peer");

   // The peer connects (the simulated link); the stack's connected callback
   // offers it to Pair.c, which claims it
   sv_SimConnect(247U);
   TEST_ASSERT_EQUAL_PTR_MESSAGE(&sst_conn2, sstpt_SETUS_conn, "the host keeps the Server so far");
   TEST_ASSERT_TRUE(gb_Pair_ClaimConn(&sst_conn, 0U));
}

void tearDown(void)
{
   // The stack reports the drop to both SETU (sim_link) and Pair.c
   gv_Pair_OnDisconnected(&sst_conn, 0x16U);
   sv_Disconnect();
   sv_RunPairThread();
}

/******************************************************************************/
/*  Tests                                                                     */
/******************************************************************************/
static void test_TwoDevicesExchangeAndPair(void)
{
   uint8_t u8_v = PAIR_SECURED_VALUE;
   struct bt_conn_oob_info st_info;

   // The Server moves to the peer, the Client attaches to the peer's service,
   // and this device's certificate crosses
   TEST_ASSERT_TRUE(sb_RunUntil(sb_CertExchange, 2000));
   TEST_ASSERT_EQUAL_PTR(&sst_conn, sstpt_SETUS_conn);
   sv_PeerReceives(VEC_PAIR_APP_PEER_CERT, gst_deviceCertData.u8ar_DeviceCert, 517U);

   // The peer's certificate crosses and verifies; this device's OOB frame follows
   sv_PeerSends(VEC_PAIR_APP_PEER_CERT, su8ar_peerCert, su32_peerCertLen);
   TEST_ASSERT_EQUAL_INT(eBS_OK, sst_peer.i_txDone);
   TEST_ASSERT_TRUE(sb_RunUntil(sb_OobExchange, 2000));
   TEST_ASSERT_TRUE(sb_peerCertSeen);
   TEST_ASSERT_TRUE(sb_scFlag);
   {
      uint8_t u8ar_exp[PAIR_OOB_FRAME_LEN];

      (void)memcpy(&u8ar_exp[0], gu8ar_vecPairOobR, 16U);
      (void)memcpy(&u8ar_exp[16], gu8ar_vecPairOobC, 16U);
      (void)memcpy(&u8ar_exp[32], gu8ar_vecPairOobSig, 64U);
      sv_PeerReceives(VEC_PAIR_APP_OOB, u8ar_exp, PAIR_OOB_FRAME_LEN);
   }

   // The peer's signed OOB frame crosses and verifies
   sv_PeerSends(VEC_PAIR_APP_OOB, gu8ar_vecPairOobFrame, PAIR_OOB_FRAME_LEN);
   TEST_ASSERT_EQUAL_INT(eBS_OK, sst_peer.i_txDone);
   TEST_ASSERT_TRUE(sb_RunUntil(sb_Pairing, 2000));

   // SMP (driven here as the stack would) and the central's SECURED write
   st_info.type = BT_CONN_OOB_LE_SC;
   st_info.lesc.oob_config = BT_CONN_OOB_BOTH_PEERS;
   sstpt_auth->oob_data_request(&sst_conn, &st_info);
   sv_RunPairThread();
   TEST_ASSERT_EQUAL_UINT32(1U, su32_scData);
   sstpt_authInfo->pairing_complete(&sst_conn, true);
   sv_RunPairThread();
   TEST_ASSERT_EQUAL_INT(0, gt_Pair_OnSecuredWrite(&sst_conn, &u8_v, 1U));
   TEST_ASSERT_EQUAL_UINT8(ePST_PAIRED, su8_StateNow());
   TEST_ASSERT_EQUAL_UINT8(ePST_PAIRED, su8ar_hostStatus[0]);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_led);

   // SETU back with the host: Server rebound, Client released, no filter
   sv_Settle(10);
   TEST_ASSERT_EQUAL_PTR(&sst_conn2, sstpt_SETUS_conn);
   TEST_ASSERT_NULL(sstpt_SETUC_conn);
   TEST_ASSERT_EQUAL_INT(1, si_unsubscribes);
   TEST_ASSERT_EQUAL_HEX(0, atomic_get(&st_filter));
   TEST_ASSERT_FALSE(sb_scFlag);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, su32_disconnects, "the paired link stays up");
}

static void test_PeerReachesOnlyThePairingRange(void)
{
   static const uint8_t scu8ar_data[300] = { 1, 2, 3 };

   TEST_ASSERT_TRUE(sb_RunUntil(sb_CertExchange, 2000));

   // A transfer for another module (here 0x10, hex upload) is refused at START
   sv_PeerSends(0x10U, scu8ar_data, sizeof(scu8ar_data));
   TEST_ASSERT_EQUAL_INT(PEER_ABORT_BASE + eBS_REJECTED, sst_peer.i_txDone);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_otherStarts);

   // So is an object of the pairing range that is not expected
   sv_PeerSends(0x3FU, scu8ar_data, sizeof(scu8ar_data));
   TEST_ASSERT_EQUAL_INT(PEER_ABORT_BASE + eBS_REJECTED, sst_peer.i_txDone);
   sv_PeerSends(VEC_PAIR_APP_OOB, scu8ar_data, 95U);
   TEST_ASSERT_EQUAL_INT(PEER_ABORT_BASE + eBS_REJECTED, sst_peer.i_txDone);

   // The run goes on: the certificate is still accepted
   sv_PeerReceives(VEC_PAIR_APP_PEER_CERT, gst_deviceCertData.u8ar_DeviceCert, 517U);
   sv_PeerSends(VEC_PAIR_APP_PEER_CERT, su8ar_peerCert, su32_peerCertLen);
   TEST_ASSERT_EQUAL_INT(eBS_OK, sst_peer.i_txDone);
   TEST_ASSERT_TRUE(sb_RunUntil(sb_OobExchange, 2000));
}

static void test_LinkLossReturnsSETUToTheHost(void)
{
   uint8_t u8ar_status[PAIR_STATUS_LEN];

   TEST_ASSERT_TRUE(sb_RunUntil(sb_CertExchange, 2000));
   TEST_ASSERT_EQUAL_PTR(&sst_conn, sstpt_SETUS_conn);
   // The peer link drops in the middle of the exchange
   sst_peer.b_silent = true;
   sv_Settle(5);
   gv_Pair_OnDisconnected(&sst_conn, 0x08U);
   sv_Disconnect();
   sv_RunPairThread();
   gv_Pair_GetStatus(u8ar_status);
   TEST_ASSERT_EQUAL_UINT8(ePST_FAILED, u8ar_status[0]);
   TEST_ASSERT_EQUAL_UINT8(ePER_LINK_LOST, u8ar_status[1]);
   TEST_ASSERT_EQUAL_UINT8(0x08U, u8ar_status[2]);
   TEST_ASSERT_EQUAL_PTR(&sst_conn2, sstpt_SETUS_conn);
   TEST_ASSERT_EQUAL_HEX(0, atomic_get(&st_filter));
}

int main(int argc, char **argv)
{
   SETURoute_T st_other = { 0 };

   (void)setvbuf(stdout, NULL, _IONBF, 0);
   gb_simVerbose = (argc > 1) && (strcmp(argv[1], "-v") == 0);

   // As main() does in the firmware, before any connection, with another
   // module on the Server
   st_other.u8_firstAppType = 0x10U;
   st_other.u8_lastAppType = 0x10U;
   st_other.fpt_onRxStart = si_OtherStart;
   st_other.fpt_onRxData = si_OtherData;
   if ((gi_SETURouter_Register(&st_other) != 0) || (gi_Pair_Init() != 0) ||
      (gi_SETURouter_Start() != 0))
   {
      printf("init failed\n");
      return 1;
   }

   UNITY_BEGIN();
   RUN_TEST(test_TwoDevicesExchangeAndPair);
   RUN_TEST(test_PeerReachesOnlyThePairingRange);
   RUN_TEST(test_LinkLossReturnsSETUToTheHost);
   return UNITY_END();
}
