/**
 * @file          test_uds_client.c
 * @brief         Host unit tests for the UDS client (_LIB/UdsClient/UdsClient.c)
 *                against a scripted transport (sim_uds_tp.h): matching responses
 *                to requests, NRC 0x78 / P2*, NRC 0x21 retries, P2 timeouts, the
 *                session timing and keep-alive, functional and suppressed
 *                requests, and every service helper's request and checks.
 *                Contract: _DOC/UdsClient/API_REFERENCE.md.
 *
 * @date          12/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#include "UdsClient.c"
#include "sim_uds_tp.h"
#include "unity.h"

/******************************************************************************/
/*  Helpers                                                                   */
/******************************************************************************/
static UdsClient_T sst_client;
static uint8_t su8ar_rsp[SIM_TP_MSG_MAX];
static size_t st_rspLen;

static const UdsTarget_T scst_target =
{
   0x7E0U, 0x7E8U, 0x7DFU, UDS_TGT_PAD | UDS_TGT_FUNC, 8U, 0U, 0U
};

static int si_Req(const char *cpt_hex)
{
   uint8_t u8ar_req[64];
   size_t t_len = st_SimHex(cpt_hex, u8ar_req, sizeof(u8ar_req));

   return gi_UdsClient_Request(&sst_client, u8ar_req, t_len, false, su8ar_rsp, sizeof(su8ar_rsp), &st_rspLen);
}

/** Key callback: each seed byte inverted; counts calls; can fail. */
static uint32_t su32_keyCalls;
static int si_keyRet;
static int si_TestKey(uint8_t u8_level, const uint8_t *u8pt_seed, size_t t_seedLen, uint8_t *u8pt_key,
   size_t t_keyMax, size_t *tpt_keyLen, void *vpt_user)
{
   size_t i;

   TEST_ASSERT_EQUAL_PTR(&su32_keyCalls, vpt_user);
   TEST_ASSERT_EQUAL_UINT8(1U, u8_level);
   su32_keyCalls++;
   if (si_keyRet != 0)
   {
      return si_keyRet;
   }
   TEST_ASSERT_TRUE(t_keyMax >= t_seedLen);
   for (i = 0U; i < t_seedLen; i++)
   {
      u8pt_key[i] = (uint8_t)~u8pt_seed[i];
   }
   *tpt_keyLen = t_seedLen;
   return 0;
}

void setUp(void)
{
   sv_SimTpReset();
   gi64_simNowMs = 1000;
   su32_keyCalls = 0U;
   si_keyRet = 0;
   st_rspLen = 0U;
   gv_SimLogClear();
   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_Init(&sst_client, &sst_simTp));
   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_SetTarget(&sst_client, &scst_target));
}

void tearDown(void) {}

/******************************************************************************/
/*  Set-up and target                                                         */
/******************************************************************************/
static void test_InitRejectsAnIncompleteTransport(void)
{
   UdsTp_T st_tp = sst_simTp;
   UdsClient_T st_client;

   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_UdsClient_Init(NULL, &sst_simTp));
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_UdsClient_Init(&st_client, NULL));
   st_tp.fpt_recv = NULL;
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_UdsClient_Init(&st_client, &st_tp));
   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_Init(&st_client, &sst_simTp));
   TEST_ASSERT_EQUAL_UINT32(UDS_P2_MS, st_client.u32_p2Ms);
   TEST_ASSERT_EQUAL_UINT32(UDS_P2STAR_MS, st_client.u32_p2StarMs);
}

static void test_RequestNeedsATarget(void)
{
   UdsClient_T st_client;
   uint8_t u8_req = 0x3EU;

   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_Init(&st_client, &sst_simTp));
   TEST_ASSERT_EQUAL_INT(-ENOTCONN, gi_UdsClient_Request(&st_client, &u8_req, 1U, false, su8ar_rsp, 8U, &st_rspLen));
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_UdsClient_Request(&st_client, &u8_req, 0U, false, su8ar_rsp, 8U, &st_rspLen));
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_UdsClient_Request(&st_client, &u8_req, 1U, false, NULL, 8U, &st_rspLen));
   TEST_ASSERT_EQUAL_UINT32(0U, sst_tp.u32_sends);
}

static void test_SetTargetChecksAndBinds(void)
{
   UdsTarget_T st_target = scst_target;

   TEST_ASSERT_EQUAL_UINT32(1U, sst_tp.u32_binds);
   TEST_ASSERT_EQUAL_HEX32(0x7E8U, sst_tp.st_bound.u32_rxId);

   st_target.u32_txId = 0x800U;
   TEST_ASSERT_EQUAL_INT_MESSAGE(-EINVAL, gi_UdsClient_SetTarget(&sst_client, &st_target), "11-bit ID");
   st_target = scst_target;
   st_target.u8_flags |= UDS_TGT_BRS;
   TEST_ASSERT_EQUAL_INT_MESSAGE(-EINVAL, gi_UdsClient_SetTarget(&sst_client, &st_target), "BRS without FD");
   st_target = scst_target;
   st_target.u8_txDl = 64U;
   TEST_ASSERT_EQUAL_INT_MESSAGE(-EINVAL, gi_UdsClient_SetTarget(&sst_client, &st_target), "DL 64 without FD");
   st_target.u8_flags |= UDS_TGT_FD;
   st_target.u8_txDl = 13U;
   TEST_ASSERT_EQUAL_INT_MESSAGE(-EINVAL, gi_UdsClient_SetTarget(&sst_client, &st_target), "DL 13");
   st_target = scst_target;
   st_target.u8_flags = 0x40U;
   TEST_ASSERT_EQUAL_INT_MESSAGE(-EINVAL, gi_UdsClient_SetTarget(&sst_client, &st_target), "unknown flag");
   st_target = scst_target;
   st_target.u8_flags |= UDS_TGT_EXT_ADDR;
   TEST_ASSERT_EQUAL_INT(-ENOTSUP, gi_UdsClient_SetTarget(&sst_client, &st_target));
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(1U, sst_tp.u32_binds, "refused targets are not bound");

   // A 29-bit FD target with its own timing replaces the first
   st_target.u8_flags = UDS_TGT_EXT_ID | UDS_TGT_FD | UDS_TGT_BRS;
   st_target.u32_txId = 0x18DA10F1U;
   st_target.u32_rxId = 0x18DAF110U;
   st_target.u8_txDl = 64U;
   st_target.u16_p2Ms = 300U;
   st_target.u16_p2StarMs = 9000U;
   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_SetTarget(&sst_client, &st_target));
   TEST_ASSERT_EQUAL_UINT32(1U, sst_tp.u32_unbinds);
   TEST_ASSERT_EQUAL_UINT32(300U, sst_client.u32_p2Ms);
   TEST_ASSERT_EQUAL_UINT32(9000U, sst_client.u32_p2StarMs);

   // A failed bind leaves the client unbound
   sst_tp.i_bindRet = -ENOSPC;
   TEST_ASSERT_EQUAL_INT(-ENOSPC, gi_UdsClient_SetTarget(&sst_client, &scst_target));
   TEST_ASSERT_EQUAL_INT(-ENOTCONN, si_Req("3e00"));
}

/******************************************************************************/
/*  Request and response                                                      */
/******************************************************************************/
static void test_PositiveResponse(void)
{
   SIM_RSP("62f190574d49");
   TEST_ASSERT_EQUAL_INT(0, si_Req("22f190"));
   TEST_ASSERT_TRUE(sb_SimTpSent(0U, "22f190"));
   TEST_ASSERT_FALSE(sst_tp.bar_sentFunc[0]);
   TEST_ASSERT_EQUAL_size_t(6U, st_rspLen);
   TEST_ASSERT_EQUAL_HEX8(0x62U, su8ar_rsp[0]);
   TEST_ASSERT_EQUAL_HEX8(0x22U, gu8_UdsClient_LastSid(&sst_client));
   TEST_ASSERT_EQUAL_HEX8(0U, gu8_UdsClient_LastNrc(&sst_client));
}

static void test_NegativeResponseReturnsTheNrc(void)
{
   SIM_RSP("7f2231");
   TEST_ASSERT_EQUAL_INT(0x31, si_Req("22f190"));
   TEST_ASSERT_EQUAL_size_t(3U, st_rspLen);
   TEST_ASSERT_EQUAL_HEX8(0x31U, gu8_UdsClient_LastNrc(&sst_client));
}

static void test_NoResponseTimesOutAfterP2(void)
{
   int64_t i64_start = gi64_simNowMs;

   TEST_ASSERT_EQUAL_INT(-ETIMEDOUT, si_Req("22f190"));
   TEST_ASSERT_EQUAL_INT64(i64_start + UDS_P2_MS, gi64_simNowMs);
}

static void test_ResponsePendingExtendsTheWaitToP2Star(void)
{
   int64_t i64_start = gi64_simNowMs;

   // Three "pending" answers, each well after P2, then the result
   SIM_RSP_AFTER(100, "7f3178");
   SIM_RSP_AFTER(4000, "7f3178");
   SIM_RSP_AFTER(4000, "7f3178");
   SIM_RSP_AFTER(4999, "7101ff0000");
   TEST_ASSERT_EQUAL_INT(0, si_Req("3101ff00"));
   TEST_ASSERT_EQUAL_UINT32(3U, sst_client.u32_pending);
   TEST_ASSERT_EQUAL_INT64(i64_start + 100 + 4000 + 4000 + 4999, gi64_simNowMs);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(1U, sst_tp.u32_sends, "not repeated");

   // A pending answer and then silence: timeout after P2*
   i64_start = gi64_simNowMs;
   SIM_RSP("7f3178");
   TEST_ASSERT_EQUAL_INT(-ETIMEDOUT, si_Req("3101ff00"));
   TEST_ASSERT_EQUAL_INT64(i64_start + UDS_P2STAR_MS, gi64_simNowMs);
}

static void test_BusyRepeatRequestIsRetried(void)
{
   SIM_RSP("7f1021");
   SIM_RSP_N(2U, "7f1021");
   SIM_RSP_N(3U, "5003");
   TEST_ASSERT_EQUAL_INT(0, si_Req("1003"));
   TEST_ASSERT_EQUAL_UINT32(3U, sst_tp.u32_sends);
   TEST_ASSERT_TRUE(sb_SimTpSent(2U, "1003"));

   // More busy answers than retries: the NRC is returned
   sv_SimTpReset();
   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_SetTarget(&sst_client, &scst_target));
   SIM_RSP("7f1021");
   SIM_RSP_N(2U, "7f1021");
   SIM_RSP_N(3U, "7f1021");
   SIM_RSP_N(4U, "7f1021");
   TEST_ASSERT_EQUAL_INT(UDS_NRC_BUSY_REPEAT, si_Req("1003"));
   TEST_ASSERT_EQUAL_UINT32(1U + UDS_BUSY_RETRIES, sst_tp.u32_sends);
}

static void test_StaleAndForeignResponsesAreSkipped(void)
{
   // A late answer to an earlier request, released before this one, is drained
   SIM_RSP_N(0U, "7e00");
   // Another service's answer arrives before ours and is skipped
   SIM_RSP("6ef15a");
   SIM_RSP("62f190aa");
   TEST_ASSERT_EQUAL_INT(0, si_Req("22f190"));
   TEST_ASSERT_EQUAL_size_t(4U, st_rspLen);
   TEST_ASSERT_EQUAL_HEX8(0xAAU, su8ar_rsp[3]);

   // A negative response for another service is skipped too
   SIM_RSP("7f2e31");
   SIM_RSP("62f190bb");
   TEST_ASSERT_EQUAL_INT(0, si_Req("22f190"));
}

static void test_SubFunctionMustBeEchoed(void)
{
   SIM_RSP("5001");
   TEST_ASSERT_EQUAL_INT(-EBADMSG, si_Req("1003"));
   SIM_RSP("50");
   TEST_ASSERT_EQUAL_INT(-EBADMSG, si_Req("1003"));
}

static void test_SuppressedPositiveResponse(void)
{
   int64_t i64_start = gi64_simNowMs;

   TEST_ASSERT_EQUAL_INT(0, si_Req("3e80"));
   TEST_ASSERT_EQUAL_size_t(0U, st_rspLen);
   TEST_ASSERT_EQUAL_INT64_MESSAGE(i64_start + UDS_P2_MS, gi64_simNowMs, "waits P2 for an NRC");

   SIM_RSP("7f3e12");
   TEST_ASSERT_EQUAL_INT(0x12, si_Req("3e80"));
}

static void test_FunctionalRequests(void)
{
   UdsTarget_T st_target = scst_target;
   uint8_t u8ar_req[8] = { 0x3EU, 0x00U };

   SIM_RSP("7e00");
   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_Request(&sst_client, u8ar_req, 2U, true, su8ar_rsp, sizeof(su8ar_rsp),
      &st_rspLen));
   TEST_ASSERT_TRUE(sst_tp.bar_sentFunc[0]);

   TEST_ASSERT_EQUAL_INT_MESSAGE(-EINVAL, gi_UdsClient_Request(&sst_client, u8ar_req, 8U, true, su8ar_rsp,
      sizeof(su8ar_rsp), &st_rspLen), "one single frame at most");
   st_target.u8_flags = UDS_TGT_PAD;
   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_SetTarget(&sst_client, &st_target));
   TEST_ASSERT_EQUAL_INT_MESSAGE(-EINVAL, gi_UdsClient_Request(&sst_client, u8ar_req, 2U, true, su8ar_rsp,
      sizeof(su8ar_rsp), &st_rspLen), "no functional ID");
}

static void test_TransportErrorsPassThrough(void)
{
   sst_tp.i_sendRet = -EIO;
   TEST_ASSERT_EQUAL_INT(-EIO, si_Req("22f190"));
   sst_tp.i_sendRet = 0;
   SIM_RSP_ERR(-EIO);
   TEST_ASSERT_EQUAL_INT(-EIO, si_Req("22f190"));
   SIM_RSP("62f190000102030405");
   TEST_ASSERT_EQUAL_INT(-EMSGSIZE, gi_UdsClient_Request(&sst_client, (const uint8_t *)"\x22\xf1\x90", 3U, false,
      su8ar_rsp, 4U, &st_rspLen));
}

/******************************************************************************/
/*  Session timing and keep-alive                                             */
/******************************************************************************/
static void test_SessionTakesTheEcuTimingAndKeepsAlive(void)
{
   UdsTarget_T st_target = scst_target;

   TEST_ASSERT_EQUAL_INT32(UDS_KEEPALIVE_NONE, gi32_UdsClient_KeepAlive(&sst_client));

   SIM_RSP("5003003201f4");
   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_Session(&sst_client, 0x03U));
   TEST_ASSERT_TRUE(sb_SimTpSent(0U, "1003"));
   TEST_ASSERT_EQUAL_UINT32(50U + UDS_P2_MARGIN_MS, sst_client.u32_p2Ms);
   TEST_ASSERT_EQUAL_UINT32(5000U + UDS_P2_MARGIN_MS, sst_client.u32_p2StarMs);

   // Due after UDS_TESTER_PRESENT_MS without a request
   TEST_ASSERT_EQUAL_INT32(UDS_TESTER_PRESENT_MS, gi32_UdsClient_KeepAlive(&sst_client));
   gi64_simNowMs += 500;
   TEST_ASSERT_EQUAL_INT32(UDS_TESTER_PRESENT_MS - 500, gi32_UdsClient_KeepAlive(&sst_client));
   TEST_ASSERT_EQUAL_UINT32(1U, sst_tp.u32_sends);
   gi64_simNowMs += UDS_TESTER_PRESENT_MS;
   TEST_ASSERT_EQUAL_INT32(UDS_TESTER_PRESENT_MS, gi32_UdsClient_KeepAlive(&sst_client));
   TEST_ASSERT_TRUE(sb_SimTpSent(1U, "3e80"));

   // Back to the default session: nothing to keep alive
   SIM_RSP("5001003201f4");
   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_Session(&sst_client, 0x01U));
   TEST_ASSERT_EQUAL_INT32(UDS_KEEPALIVE_NONE, gi32_UdsClient_KeepAlive(&sst_client));

   // A reset ends the session as well
   SIM_RSP("5002");
   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_Session(&sst_client, 0x02U));
   SIM_RSP("5101");
   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_EcuReset(&sst_client, 0x01U));
   TEST_ASSERT_EQUAL_INT32(UDS_KEEPALIVE_NONE, gi32_UdsClient_KeepAlive(&sst_client));

   // A target with its own timing keeps it
   st_target.u16_p2Ms = 200U;
   st_target.u16_p2StarMs = 7000U;
   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_SetTarget(&sst_client, &st_target));
   SIM_RSP("5003003201f4");
   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_Session(&sst_client, 0x03U));
   TEST_ASSERT_EQUAL_UINT32(200U, sst_client.u32_p2Ms);
   TEST_ASSERT_EQUAL_UINT32(7000U, sst_client.u32_p2StarMs);
}

/******************************************************************************/
/*  Service helpers                                                           */
/******************************************************************************/
static void test_SimpleServicesBuildTheirRequests(void)
{
   SIM_RSP("6803");
   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_CommControl(&sst_client, 0x03U, 0x01U));
   TEST_ASSERT_TRUE(sb_SimTpSent(0U, "280301"));
   SIM_RSP("c502");
   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_DtcSetting(&sst_client, 0x02U));
   TEST_ASSERT_TRUE(sb_SimTpSent(1U, "8502"));
   SIM_RSP("77");
   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_TransferExit(&sst_client));
   TEST_ASSERT_TRUE(sb_SimTpSent(2U, "37"));
   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_TesterPresent(&sst_client));
   TEST_ASSERT_TRUE(sb_SimTpSent(3U, "3e80"));
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_UdsClient_Session(NULL, 1U));
}

static void test_SecurityAccess(void)
{
   SIM_RSP("670111223344");
   SIM_RSP_N(2U, "6702");
   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_SecurityAccess(&sst_client, 1U, si_TestKey, &su32_keyCalls));
   TEST_ASSERT_TRUE(sb_SimTpSent(0U, "2701"));
   TEST_ASSERT_TRUE(sb_SimTpSent(1U, "2702eeddccbb"));

   // An all-zero seed: unlocked already, no key sent
   SIM_RSP("670100000000");
   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_SecurityAccess(&sst_client, 1U, si_TestKey, &su32_keyCalls));
   TEST_ASSERT_EQUAL_UINT32(3U, sst_tp.u32_sends);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_keyCalls);

   // A wrong key
   SIM_RSP("670101020304");
   SIM_RSP_N(2U, "7f2735");
   TEST_ASSERT_EQUAL_INT(0x35, gi_UdsClient_SecurityAccess(&sst_client, 1U, si_TestKey, &su32_keyCalls));

   // The seed refused, no seed, a key the callback cannot make, bad levels
   SIM_RSP("7f2737");
   TEST_ASSERT_EQUAL_INT(0x37, gi_UdsClient_SecurityAccess(&sst_client, 1U, si_TestKey, &su32_keyCalls));
   SIM_RSP("6701");
   TEST_ASSERT_EQUAL_INT(-EBADMSG, gi_UdsClient_SecurityAccess(&sst_client, 1U, si_TestKey, &su32_keyCalls));
   si_keyRet = -ENOTSUP;
   SIM_RSP("670101020304");
   TEST_ASSERT_EQUAL_INT(-ENOTSUP, gi_UdsClient_SecurityAccess(&sst_client, 1U, si_TestKey, &su32_keyCalls));
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_UdsClient_SecurityAccess(&sst_client, 2U, si_TestKey, &su32_keyCalls));
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_UdsClient_SecurityAccess(&sst_client, 0x7FU, si_TestKey, &su32_keyCalls));
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_UdsClient_SecurityAccess(&sst_client, 1U, NULL, NULL));
}

static void test_ReadAndWriteDid(void)
{
   uint8_t u8ar_data[16];
   size_t t_len = 99U;

   SIM_RSP("62f190574d4930");
   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_ReadDid(&sst_client, 0xF190U, u8ar_data, sizeof(u8ar_data), &t_len));
   TEST_ASSERT_TRUE(sb_SimTpSent(0U, "22f190"));
   TEST_ASSERT_EQUAL_size_t(4U, t_len);
   TEST_ASSERT_EQUAL_MEMORY("WMI0", u8ar_data, 4U);

   SIM_RSP("62f18c01");
   TEST_ASSERT_EQUAL_INT_MESSAGE(-EBADMSG, gi_UdsClient_ReadDid(&sst_client, 0xF190U, u8ar_data, sizeof(u8ar_data),
      &t_len), "another DID");
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_UdsClient_ReadDid(&sst_client, 0xF190U, u8ar_data, 2U, &t_len));

   SIM_RSP("6ef15a");
   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_WriteDid(&sst_client, 0xF15AU, (const uint8_t *)"\x20\x26", 2U));
   TEST_ASSERT_TRUE(sb_SimTpSent(2U, "2ef15a2026"));
   SIM_RSP("6ef15b");
   TEST_ASSERT_EQUAL_INT(-EBADMSG, gi_UdsClient_WriteDid(&sst_client, 0xF15AU, (const uint8_t *)"\x20", 1U));
   TEST_ASSERT_EQUAL_INT(-EMSGSIZE, gi_UdsClient_WriteDid(&sst_client, 0xF15AU, u8ar_data, UDS_CLIENT_BUF_SIZE));
}

static void test_Routine(void)
{
   uint8_t u8ar_status[4];
   size_t t_len = 0U;

   SIM_RSP("7101ff00000102");
   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_Routine(&sst_client, 0x01U, 0xFF00U, (const uint8_t *)"\x44\x01", 2U,
      u8ar_status, 2U, &t_len));
   TEST_ASSERT_TRUE(sb_SimTpSent(0U, "3101ff004401"));
   TEST_ASSERT_EQUAL_size_t_MESSAGE(2U, t_len, "cut to the buffer");
   TEST_ASSERT_EQUAL_HEX8(0x00U, u8ar_status[0]);

   SIM_RSP("7101ff01");
   TEST_ASSERT_EQUAL_INT(-EBADMSG, gi_UdsClient_Routine(&sst_client, 0x01U, 0xFF00U, NULL, 0U, NULL, 0U, NULL));
   SIM_RSP("7101ff00");
   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_Routine(&sst_client, 0x01U, 0xFF00U, NULL, 0U, NULL, 0U, NULL));
   TEST_ASSERT_EQUAL_INT(-EMSGSIZE, gi_UdsClient_Routine(&sst_client, 0x01U, 0xFF00U, u8ar_status,
      UDS_CLIENT_BUF_SIZE, NULL, 0U, NULL));
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_UdsClient_Routine(&sst_client, 0x01U, 0xFF00U, NULL, 2U, NULL, 0U, NULL));
}

static void test_RequestDownload(void)
{
   uint32_t u32_max = 0U;

   SIM_RSP("74200ffa");
   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_RequestDownload(&sst_client, 0x00U, 0x44U, 0x00008000UL, 20UL, &u32_max));
   TEST_ASSERT_TRUE(sb_SimTpSent(0U, "3400440000800000000014"));
   TEST_ASSERT_EQUAL_UINT32(0x0FFAU, u32_max);

   // Shorter address and size fields, a four-byte block length
   SIM_RSP("744000010002");
   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_RequestDownload(&sst_client, 0x11U, 0x23U, 0x123456UL, 0x0102UL, &u32_max));
   TEST_ASSERT_TRUE(sb_SimTpSent(1U, "3411231234560102"));
   TEST_ASSERT_EQUAL_UINT32(0x00010002UL, u32_max);

   SIM_RSP("7400");
   TEST_ASSERT_EQUAL_INT_MESSAGE(-EBADMSG, gi_UdsClient_RequestDownload(&sst_client, 0U, 0x44U, 0UL, 1UL, &u32_max),
      "no block length");
   SIM_RSP("742000");
   TEST_ASSERT_EQUAL_INT_MESSAGE(-EBADMSG, gi_UdsClient_RequestDownload(&sst_client, 0U, 0x44U, 0UL, 1UL, &u32_max),
      "block length cut short");
   SIM_RSP("74100002");
   TEST_ASSERT_EQUAL_INT_MESSAGE(-EBADMSG, gi_UdsClient_RequestDownload(&sst_client, 0U, 0x44U, 0UL, 1UL, &u32_max),
      "no room for data");

   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_UdsClient_RequestDownload(&sst_client, 0U, 0x40U, 0UL, 1UL, &u32_max));
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_UdsClient_RequestDownload(&sst_client, 0U, 0x54U, 0UL, 1UL, &u32_max));
   TEST_ASSERT_EQUAL_INT_MESSAGE(-EINVAL, gi_UdsClient_RequestDownload(&sst_client, 0U, 0x21U, 0x100UL, 1UL,
      &u32_max), "address does not fit one byte");
   TEST_ASSERT_EQUAL_UINT32(5U, sst_tp.u32_sends);
}

static void test_TransferData(void)
{
   uint8_t u8ar_req[2 + 4] = { 0U, 0U, 0xDEU, 0xADU, 0xBEU, 0xEFU };

   SIM_RSP("76ff");
   TEST_ASSERT_EQUAL_INT(0, gi_UdsClient_TransferData(&sst_client, 0xFFU, u8ar_req, 4U));
   TEST_ASSERT_TRUE(sb_SimTpSent(0U, "36ffdeadbeef"));
   SIM_RSP("7601");
   TEST_ASSERT_EQUAL_INT_MESSAGE(-EBADMSG, gi_UdsClient_TransferData(&sst_client, 0x00U, u8ar_req, 4U),
      "counter not echoed");
   SIM_RSP("7f3673");
   TEST_ASSERT_EQUAL_INT(0x73, gi_UdsClient_TransferData(&sst_client, 0x01U, u8ar_req, 4U));
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_UdsClient_TransferData(&sst_client, 0x01U, u8ar_req, 0U));
}

int main(void)
{
   (void)setvbuf(stdout, NULL, _IONBF, 0);
   UNITY_BEGIN();
   RUN_TEST(test_InitRejectsAnIncompleteTransport);
   RUN_TEST(test_RequestNeedsATarget);
   RUN_TEST(test_SetTargetChecksAndBinds);
   RUN_TEST(test_PositiveResponse);
   RUN_TEST(test_NegativeResponseReturnsTheNrc);
   RUN_TEST(test_NoResponseTimesOutAfterP2);
   RUN_TEST(test_ResponsePendingExtendsTheWaitToP2Star);
   RUN_TEST(test_BusyRepeatRequestIsRetried);
   RUN_TEST(test_StaleAndForeignResponsesAreSkipped);
   RUN_TEST(test_SubFunctionMustBeEchoed);
   RUN_TEST(test_SuppressedPositiveResponse);
   RUN_TEST(test_FunctionalRequests);
   RUN_TEST(test_TransportErrorsPassThrough);
   RUN_TEST(test_SessionTakesTheEcuTimingAndKeepsAlive);
   RUN_TEST(test_SimpleServicesBuildTheirRequests);
   RUN_TEST(test_SecurityAccess);
   RUN_TEST(test_ReadAndWriteDid);
   RUN_TEST(test_Routine);
   RUN_TEST(test_RequestDownload);
   RUN_TEST(test_TransferData);
   return UNITY_END();
}
