/**
 * @file          test_uds_cmd.c
 * @brief         Host unit tests for UDS over BLE (_ASW/_UDS/UdsCmd.c) on the real
 *                SETU router, with the SETU Server and UdsJob stubbed: every
 *                host -> device frame of the uds_cmd vectors becomes the expected
 *                UdsJob call, every device -> host frame is built byte for byte,
 *                long responses are split, and malformed or refused messages are
 *                answered. Built as uds_cmd (CONFIG_UDS_CMD) and uds_cmd_disabled.
 *                Contract: _DOC/UDS/PROTOCOL.md.
 *
 * @date          12/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#include "UdsCmd.c"
#include "SETURouter.c"
#include "unity.h"
#include "wire_vectors.h"

/******************************************************************************/
/*  Stubs: SETU Server, GATT service                                          */
/******************************************************************************/
static struct bt_gatt_attr sst_ctrlAttr;
static SETUSrvCfg_T sst_cfg;

typedef struct
{
   uint8_t u8_type;
   uint8_t u8_len;
   uint8_t u8ar_payload[SETU_MAX_SHORT_PAYLOAD];
} SentShort_T;

static SentShort_T sstar_sent[8];
static uint32_t su32_sentCount;

const struct bt_gatt_attr *gstpt_SETUSvc_Init(void)
{
   return &sst_ctrlAttr;
}

int gi_SETUS_Init(const SETUSrvCfg_T *stpt_cfg)
{
   sst_cfg = *stpt_cfg;
   return 0;
}

int gi_SETUS_SendShort(uint8_t u8_appType, const void *vpt_data, uint8_t u8_len, k_timeout_t t_timeout)
{
   SentShort_T *s = &sstar_sent[su32_sentCount % ARRAY_SIZE(sstar_sent)];

   TEST_ASSERT_TRUE_MESSAGE(t_timeout.ms >= 0, "a reply must not wait for ever");
   TEST_ASSERT_TRUE(u8_len <= SETU_MAX_SHORT_PAYLOAD);
   s->u8_type = u8_appType;
   s->u8_len = u8_len;
   memcpy(s->u8ar_payload, vpt_data, u8_len);
   su32_sentCount++;
   return 0;
}

void gv_SimOnBlock(struct k_sem *stpt_sem)
{
   (void)stpt_sem;
}

/******************************************************************************/
/*  Stub: UdsJob (records the calls, returns a scripted result)               */
/******************************************************************************/
static struct
{
   uint8_t u8_ret;                           /* what the next call returns          */
   uint32_t u32_calls;
   UdsJobTarget_T st_target;
   uint8_t u8ar_req[UDS_JOB_REQ_MAX];
   size_t t_reqLen;
   bool b_functional;
   uint8_t u8_level;
   uint8_t u8_algo;
   char car_name[UDS_FILE_NAME_MAX + 1U];
   UdsFlashParams_T st_params;
   UdsJobResult_F fpt_done;
   UdsJobStatus_F fpt_status;
   void *vpt_user;
   UdsJobStatus_T st_status;                 /* what GetStatus gives                */
} sst_job;

uint8_t gu8_UdsJob_SetTarget(const UdsJobTarget_T *stpt_target, UdsJobResult_F fpt_done, void *vpt_user)
{
   sst_job.u32_calls++;
   sst_job.st_target = *stpt_target;
   sst_job.fpt_done = fpt_done;
   sst_job.vpt_user = vpt_user;
   return sst_job.u8_ret;
}

uint8_t gu8_UdsJob_Diag(const uint8_t *u8pt_req, size_t t_len, bool b_functional, UdsJobResult_F fpt_done,
   void *vpt_user)
{
   sst_job.u32_calls++;
   memcpy(sst_job.u8ar_req, u8pt_req, t_len);
   sst_job.t_reqLen = t_len;
   sst_job.b_functional = b_functional;
   sst_job.fpt_done = fpt_done;
   sst_job.vpt_user = vpt_user;
   return sst_job.u8_ret;
}

uint8_t gu8_UdsJob_Unlock(uint8_t u8_level, uint8_t u8_algo, UdsJobResult_F fpt_done, void *vpt_user)
{
   sst_job.u32_calls++;
   sst_job.u8_level = u8_level;
   sst_job.u8_algo = u8_algo;
   sst_job.fpt_done = fpt_done;
   sst_job.vpt_user = vpt_user;
   return sst_job.u8_ret;
}

uint8_t gu8_UdsJob_Flash(const char *cpt_name, size_t t_nameLen, const UdsFlashParams_T *stpt_params,
   UdsJobStatus_F fpt_status, void *vpt_user)
{
   sst_job.u32_calls++;
   memset(sst_job.car_name, 0, sizeof(sst_job.car_name));
   memcpy(sst_job.car_name, cpt_name, MIN(t_nameLen, UDS_FILE_NAME_MAX));
   sst_job.st_params = *stpt_params;
   sst_job.fpt_status = fpt_status;
   sst_job.vpt_user = vpt_user;
   return sst_job.u8_ret;
}

uint8_t gu8_UdsJob_Abort(void)
{
   sst_job.u32_calls++;
   return sst_job.u8_ret;
}

void gv_UdsJob_GetStatus(UdsJobStatus_T *stpt_status)
{
   *stpt_status = sst_job.st_status;
}

/******************************************************************************/
/*  Helpers                                                                   */
/******************************************************************************/
#if defined(CONFIG_UDS_CMD)
static const ShortVector_T *sstpt_Vec(const char *cpt_name)
{
   uint32_t i;

   for (i = 0U; i < ARRAY_SIZE(gstar_vecUdsShorts); i++)
   {
      if (strcmp(gstar_vecUdsShorts[i].cpt_name, cpt_name) == 0)
      {
         return &gstar_vecUdsShorts[i];
      }
   }
   TEST_FAIL_MESSAGE(cpt_name);
   return NULL;
}

/** The host sends a vector frame. */
static void sv_Host(const char *cpt_name)
{
   const ShortVector_T *v = sstpt_Vec(cpt_name);

   sst_cfg.fpt_onRxShort(v->u8_appType, &v->u8ar_wire[2], v->u8ar_wire[0]);
}

/** The host sends a frame of its own. */
static void sv_HostRaw(uint8_t u8_type, const uint8_t *u8pt_payload, uint8_t u8_len)
{
   sst_cfg.fpt_onRxShort(u8_type, u8pt_payload, u8_len);
}

/** Message u32_idx sent to the host equals a vector frame. */
static void sv_AssertSent(uint32_t u32_idx, const char *cpt_name)
{
   const ShortVector_T *v = sstpt_Vec(cpt_name);
   const SentShort_T *s = &sstar_sent[u32_idx % ARRAY_SIZE(sstar_sent)];

   TEST_ASSERT_TRUE_MESSAGE(u32_idx < su32_sentCount, cpt_name);
   TEST_ASSERT_EQUAL_HEX8_MESSAGE(v->u8_appType, s->u8_type, cpt_name);
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->u8ar_wire[0], s->u8_len, cpt_name);
   TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(&v->u8ar_wire[2], s->u8ar_payload, s->u8_len, cpt_name);
}

/** The last message sent: appType and its first bytes. */
static void sv_AssertLast(uint8_t u8_type, const uint8_t *u8pt_head, uint8_t u8_headLen)
{
   const SentShort_T *s;

   TEST_ASSERT_TRUE(su32_sentCount > 0U);
   s = &sstar_sent[(su32_sentCount - 1U) % ARRAY_SIZE(sstar_sent)];
   TEST_ASSERT_EQUAL_HEX8(u8_type, s->u8_type);
   TEST_ASSERT_TRUE(s->u8_len >= u8_headLen);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(u8pt_head, s->u8ar_payload, u8_headLen);
}
#endif // CONFIG_UDS_CMD

void setUp(void)
{
   su8_routeCnt = 0U;
   sb_isStarted = false;
   memset(&sst_cfg, 0, sizeof(sst_cfg));
   memset(&sst_job, 0, sizeof(sst_job));
   su32_sentCount = 0U;
   gv_SimLogClear();
   TEST_ASSERT_EQUAL_INT(0, gi_UdsCmd_Init());
   TEST_ASSERT_EQUAL_INT(0, gi_SETURouter_Start());
}

void tearDown(void) {}

#if defined(CONFIG_UDS_CMD)
/******************************************************************************/
/*  Constants and registration                                                */
/******************************************************************************/
static void test_DefinesMatchVectors(void)
{
   TEST_ASSERT_EQUAL_HEX8(VEC_UDS_APP_TARGET, UDSCMD_APP_TYPE_TARGET);
   TEST_ASSERT_EQUAL_HEX8(VEC_UDS_APP_RESULT, UDSCMD_APP_TYPE_RESULT);
   TEST_ASSERT_EQUAL_HEX8(VEC_UDS_APP_DIAG_REQ, UDSCMD_APP_TYPE_DIAG_REQ);
   TEST_ASSERT_EQUAL_HEX8(VEC_UDS_APP_DIAG_RSP, UDSCMD_APP_TYPE_DIAG_RSP);
   TEST_ASSERT_EQUAL_HEX8(VEC_UDS_APP_UNLOCK, UDSCMD_APP_TYPE_UNLOCK);
   TEST_ASSERT_EQUAL_HEX8(VEC_UDS_APP_FLASH, UDSCMD_APP_TYPE_FLASH);
   TEST_ASSERT_EQUAL_HEX8(VEC_UDS_APP_STATUS, UDSCMD_APP_TYPE_STATUS);
   TEST_ASSERT_EQUAL_HEX8(VEC_UDS_APP_ABORT, UDSCMD_APP_TYPE_ABORT);
   TEST_ASSERT_EQUAL_HEX8(VEC_UDS_APP_STATUS_REQ, UDSCMD_APP_TYPE_STATUS_REQ);
   TEST_ASSERT_EQUAL_HEX8(VEC_UDS_APP_LAST, UDSCMD_APP_TYPE_LAST);
   TEST_ASSERT_EQUAL_UINT(VEC_UDS_TARGET_LEN, UDSCMD_TARGET_LEN);
   TEST_ASSERT_EQUAL_UINT(VEC_UDS_PARAMS_LEN, UDSCMD_PARAMS_LEN);
   TEST_ASSERT_EQUAL_UINT(VEC_UDS_STATUS_LEN, UDSCMD_STATUS_LEN);
   TEST_ASSERT_EQUAL_UINT(VEC_UDS_DIAG_PART_MAX, UDSCMD_PART_MAX);
   TEST_ASSERT_EQUAL_UINT(VEC_UDS_DIAG_REQ_MAX, UDS_JOB_REQ_MAX);
   TEST_ASSERT_EQUAL_UINT(VEC_UDS_FINGERPRINT_MAX, UDS_FP_MAX);
   TEST_ASSERT_EQUAL_UINT(VEC_UDS_NAME_MAX, UDS_FILE_NAME_MAX);
   TEST_ASSERT_EQUAL_UINT(VEC_UDS_ST_NOT_SUPPORTED, eUDS_NOT_SUPPORTED);
   TEST_ASSERT_EQUAL_UINT(VEC_UDS_ST_BUS_OFF, eUDS_BUS_OFF);
   TEST_ASSERT_EQUAL_UINT(VEC_UDS_STATE_ABORTED, eUDS_STATE_ABORTED);
   TEST_ASSERT_EQUAL_UINT(VEC_UDS_STEP_DONE, eUDS_STEP_DONE);
   TEST_ASSERT_EQUAL_HEX16(VEC_UDS_FF_RESET, UDS_FF_RESET);
   TEST_ASSERT_EQUAL_HEX8(VEC_UDS_TF_FUNC, UDS_TGT_FUNC);
   TEST_ASSERT_EQUAL_HEX8(VEC_UDS_TF_EXT_ADDR, UDSCMD_TGT_EXT_ADDR);
}

static void test_RangeIsRegisteredForShortMessagesOnly(void)
{
   TEST_ASSERT_EQUAL_UINT8(1U, su8_routeCnt);
   TEST_ASSERT_EQUAL_HEX8(0x50U, sstar_routes[0].u8_firstAppType);
   TEST_ASSERT_EQUAL_HEX8(0x5FU, sstar_routes[0].u8_lastAppType);
   TEST_ASSERT_NULL(sstar_routes[0].fpt_onRxStart);
   TEST_ASSERT_NOT_NULL(sstar_routes[0].fpt_onRxShort);
}

/******************************************************************************/
/*  TARGET                                                                    */
/******************************************************************************/
static void test_TargetIsDecoded(void)
{
   const UdsJobTarget_T *t = &sst_job.st_target;

   sv_Host("target_classic");
   TEST_ASSERT_EQUAL_UINT32(1U, sst_job.u32_calls);
   TEST_ASSERT_FALSE(t->st_can.b_fd);
   TEST_ASSERT_FALSE(t->st_can.b_listenOnly);
   TEST_ASSERT_EQUAL_UINT32(500000U, t->st_can.u32_bitrate);
   TEST_ASSERT_EQUAL_HEX32(0x7E0U, t->st_uds.u32_txId);
   TEST_ASSERT_EQUAL_HEX32(0x7E8U, t->st_uds.u32_rxId);
   TEST_ASSERT_EQUAL_HEX32(0x7DFU, t->st_uds.u32_funcId);
   TEST_ASSERT_EQUAL_HEX8(UDS_TGT_PAD | UDS_TGT_FUNC, t->st_uds.u8_flags);
   TEST_ASSERT_EQUAL_UINT8(8U, t->st_uds.u8_txDl);
   TEST_ASSERT_EQUAL_UINT16(0U, t->st_uds.u16_p2Ms);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, su32_sentCount, "the result comes from the job thread");
   sst_job.fpt_done(eUDS_OK, NULL, 0U, sst_job.vpt_user);
   sv_AssertSent(0U, "result_target_ok");

   sv_Host("target_fd_29bit");
   TEST_ASSERT_TRUE(t->st_can.b_fd);
   TEST_ASSERT_EQUAL_UINT32(2000000U, t->st_can.u32_bitrateData);
   TEST_ASSERT_EQUAL_HEX32(0x18DA10F1U, t->st_uds.u32_txId);
   TEST_ASSERT_EQUAL_HEX8(UDS_TGT_EXT_ID | UDS_TGT_FD | UDS_TGT_BRS | UDS_TGT_PAD, t->st_uds.u8_flags);
   TEST_ASSERT_EQUAL_UINT8(64U, t->st_uds.u8_txDl);
   TEST_ASSERT_EQUAL_UINT16(100U, t->st_uds.u16_p2Ms);
   TEST_ASSERT_EQUAL_UINT16(6000U, t->st_uds.u16_p2StarMs);
   sst_job.fpt_done(eUDS_BUSY, NULL, 0U, sst_job.vpt_user);
   sv_AssertSent(1U, "result_target_busy");
}

static void test_TargetRefusals(void)
{
   const ShortVector_T *v = sstpt_Vec("target_classic");
   uint8_t u8ar_msg[UDSCMD_TARGET_LEN + 1U];
   static const uint8_t scu8ar_badArg[] = { 1U, UDSCMD_APP_TYPE_TARGET, eUDS_BAD_ARG };
   static const uint8_t scu8ar_notSup[] = { 1U, UDSCMD_APP_TYPE_TARGET, eUDS_NOT_SUPPORTED };
   static const uint8_t scu8ar_busy[] = { 1U, UDSCMD_APP_TYPE_TARGET, eUDS_BUSY };

   memcpy(u8ar_msg, &v->u8ar_wire[2], UDSCMD_TARGET_LEN);
   sv_HostRaw(UDSCMD_APP_TYPE_TARGET, u8ar_msg, UDSCMD_TARGET_LEN - 1U);
   sv_AssertLast(UDSCMD_APP_TYPE_RESULT, scu8ar_badArg, 3U);

   u8ar_msg[24] = 0xAAU;
   sv_HostRaw(UDSCMD_APP_TYPE_TARGET, u8ar_msg, UDSCMD_TARGET_LEN);
   sv_AssertLast(UDSCMD_APP_TYPE_RESULT, scu8ar_notSup, 3U);
   u8ar_msg[24] = 0xCCU;
   u8ar_msg[1] |= UDSCMD_TGT_EXT_ADDR;
   sv_HostRaw(UDSCMD_APP_TYPE_TARGET, u8ar_msg, UDSCMD_TARGET_LEN);
   sv_AssertLast(UDSCMD_APP_TYPE_RESULT, scu8ar_notSup, 3U);
   u8ar_msg[1] = v->u8ar_wire[3];
   u8ar_msg[22] = 0x01U;
   sv_HostRaw(UDSCMD_APP_TYPE_TARGET, u8ar_msg, UDSCMD_TARGET_LEN);
   sv_AssertLast(UDSCMD_APP_TYPE_RESULT, scu8ar_badArg, 3U);
   TEST_ASSERT_EQUAL_UINT32(0U, sst_job.u32_calls);

   sst_job.u8_ret = eUDS_BUSY;
   sv_Host("target_classic");
   sv_AssertLast(UDSCMD_APP_TYPE_RESULT, scu8ar_busy, 3U);
}

/******************************************************************************/
/*  DIAG_REQ / DIAG_RSP                                                       */
/******************************************************************************/
static void test_DiagRequestAndResponse(void)
{
   static const char scar_vin[] = VEC_UDS_VIN;
   uint8_t u8ar_rsp[3U + sizeof(scar_vin)];

   sv_Host("diag_req_vin");
   TEST_ASSERT_EQUAL_size_t(3U, sst_job.t_reqLen);
   TEST_ASSERT_EQUAL_HEX8_ARRAY("\x22\xf1\x90", sst_job.u8ar_req, 3U);
   TEST_ASSERT_FALSE(sst_job.b_functional);
   u8ar_rsp[0] = 0x62U; u8ar_rsp[1] = 0xF1U; u8ar_rsp[2] = 0x90U;
   memcpy(&u8ar_rsp[3], scar_vin, sizeof(scar_vin) - 1U);
   sst_job.fpt_done(eUDS_OK, u8ar_rsp, 3U + sizeof(scar_vin) - 1U, sst_job.vpt_user);
   sv_AssertSent(0U, "diag_rsp_vin");

   sv_Host("diag_req_functional");
   TEST_ASSERT_TRUE(sst_job.b_functional);
   sst_job.fpt_done(eUDS_OK, NULL, 0U, sst_job.vpt_user);
   sv_AssertSent(1U, "diag_rsp_suppressed");

   // A negative response and a timeout, for requests with seq 5 and 6
   sv_HostRaw(UDSCMD_APP_TYPE_DIAG_REQ, (const uint8_t *)"\x05\x00\x22\xf1\x90", 5U);
   sst_job.fpt_done(eUDS_NRC, (const uint8_t *)"\x7f\x22\x31", 3U, sst_job.vpt_user);
   sv_AssertSent(2U, "diag_rsp_nrc");
   sv_HostRaw(UDSCMD_APP_TYPE_DIAG_REQ, (const uint8_t *)"\x06\x00\x22\xf1\x90", 5U);
   sst_job.fpt_done(eUDS_TIMEOUT, NULL, 0U, sst_job.vpt_user);
   sv_AssertSent(3U, "diag_rsp_timeout");
}

static void test_LongResponseIsSplit(void)
{
   sv_HostRaw(UDSCMD_APP_TYPE_DIAG_REQ, (const uint8_t *)"\x07\x00\x19\x02\xff", 5U);
   sst_job.fpt_done(eUDS_OK, gu8ar_vecUdsLongRsp, VEC_UDS_LONG_RSP_LEN, sst_job.vpt_user);
   TEST_ASSERT_EQUAL_UINT32(2U, su32_sentCount);
   sv_AssertSent(0U, "diag_rsp_long_part0");
   sv_AssertSent(1U, "diag_rsp_long_part1");
}

static void test_DiagRefusals(void)
{
   static const uint8_t scu8ar_badArg[] = { 9U, eUDS_BAD_ARG, 0U, 0U, 0U, 0U };
   static const uint8_t scu8ar_busy[] = { 9U, eUDS_BUSY, 0U, 0U, 0U, 0U };

   sv_HostRaw(UDSCMD_APP_TYPE_DIAG_REQ, (const uint8_t *)"\x09\x00", 2U);
   sv_AssertLast(UDSCMD_APP_TYPE_DIAG_RSP, scu8ar_badArg, 6U);
   sv_HostRaw(UDSCMD_APP_TYPE_DIAG_REQ, (const uint8_t *)"\x09\x02\x3e\x00", 4U);
   sv_AssertLast(UDSCMD_APP_TYPE_DIAG_RSP, scu8ar_badArg, 6U);
   TEST_ASSERT_EQUAL_UINT32(0U, sst_job.u32_calls);

   sst_job.u8_ret = eUDS_BUSY;
   sv_HostRaw(UDSCMD_APP_TYPE_DIAG_REQ, (const uint8_t *)"\x09\x00\x3e\x00", 4U);
   sv_AssertLast(UDSCMD_APP_TYPE_DIAG_RSP, scu8ar_busy, 6U);
}

/******************************************************************************/
/*  UNLOCK                                                                    */
/******************************************************************************/
static void test_Unlock(void)
{
   uint8_t u8_nrc = 0x35U;

   sv_Host("unlock_l1");
   TEST_ASSERT_EQUAL_UINT8(1U, sst_job.u8_level);
   TEST_ASSERT_EQUAL_UINT8(VEC_UDS_ALGO_BENCH_XOR, sst_job.u8_algo);
   sst_job.fpt_done(eUDS_OK, NULL, 0U, sst_job.vpt_user);
   sv_AssertSent(0U, "result_unlock_ok");

   sv_HostRaw(UDSCMD_APP_TYPE_UNLOCK, (const uint8_t *)"\x09\x01\x01", 3U);
   sst_job.fpt_done(eUDS_NRC, &u8_nrc, 1U, sst_job.vpt_user);
   sv_AssertSent(1U, "result_unlock_nrc");

   sst_job.u8_ret = eUDS_NOT_SUPPORTED;
   sv_HostRaw(UDSCMD_APP_TYPE_UNLOCK, (const uint8_t *)"\x0a\x01\x00", 3U);
   sv_AssertSent(2U, "result_unlock_unknown_algo");

   sv_HostRaw(UDSCMD_APP_TYPE_UNLOCK, (const uint8_t *)"\x0b\x01", 2U);
   sv_AssertLast(UDSCMD_APP_TYPE_RESULT, (const uint8_t *)"\x0b\x54\x02", 3U);
}

/******************************************************************************/
/*  FLASH, STATUS, ABORT                                                      */
/******************************************************************************/
static void test_FlashIsDecodedAndAnsweredAtOnce(void)
{
   const UdsFlashParams_T *p = &sst_job.st_params;
   static const uint8_t scu8ar_fp[] = { 0x20U, 0x26U, 0x10U, 0x12U, 0x01U, 0x02U, 0x03U };

   sv_Host("flash_app1");
   TEST_ASSERT_EQUAL_STRING("APP1.BIN", sst_job.car_name);
   TEST_ASSERT_EQUAL_HEX16(0x03FFU, p->u16_flags);
   TEST_ASSERT_EQUAL_UINT8(1U, p->u8_securityLevel);
   TEST_ASSERT_EQUAL_UINT8(VEC_UDS_ALGO_BENCH_XOR, p->u8_keyAlgo);
   TEST_ASSERT_EQUAL_HEX8(0x03U, p->u8_commControl);
   TEST_ASSERT_EQUAL_HEX8(0x01U, p->u8_commType);
   TEST_ASSERT_EQUAL_HEX8(0x01U, p->u8_resetType);
   TEST_ASSERT_EQUAL_HEX8(0x44U, p->u8_alfid);
   TEST_ASSERT_EQUAL_HEX8(0x00U, p->u8_dfi);
   TEST_ASSERT_EQUAL_HEX16(0xFF00U, p->u16_eraseRid);
   TEST_ASSERT_EQUAL_HEX16(0xFF01U, p->u16_checkRid);
   TEST_ASSERT_EQUAL_UINT16(0U, p->u16_maxBlock);
   TEST_ASSERT_EQUAL_HEX16(0xF15AU, p->u16_fingerprintDid);
   TEST_ASSERT_EQUAL_UINT8(sizeof(scu8ar_fp), p->u8_fingerprintLen);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(scu8ar_fp, p->u8ar_fingerprint, sizeof(scu8ar_fp));
   sv_AssertSent(0U, "result_flash_ok");

   // Its progress
   sst_job.fpt_status(&(UdsJobStatus_T){ eUDS_STATE_RUNNING, eUDS_STEP_TRANSFER, 0U, 2U, 16U, 30U, 0x36U, 0U, eUDS_OK },
      sst_job.vpt_user);
   sv_AssertSent(1U, "status_running");
   sst_job.fpt_status(&(UdsJobStatus_T){ eUDS_STATE_DONE, eUDS_STEP_DONE, 2U, 2U, 30U, 30U, 0x11U, 0U, eUDS_OK },
      sst_job.vpt_user);
   sv_AssertSent(2U, "status_done");
   sst_job.fpt_status(&(UdsJobStatus_T){ eUDS_STATE_FAILED, eUDS_STEP_TRANSFER, 1U, 2U, 20U, 30U, 0x36U, 0x72U,
      eUDS_NRC }, sst_job.vpt_user);
   sv_AssertSent(3U, "status_failed_nrc");

   // Refused at once: the RESULT says why
   sst_job.u8_ret = eUDS_NOT_READY;
   {
      const ShortVector_T *v = sstpt_Vec("flash_app1");
      uint8_t u8ar_msg[SETU_MAX_SHORT_PAYLOAD];

      memcpy(u8ar_msg, &v->u8ar_wire[2], v->u8ar_wire[0]);
      u8ar_msg[0] = 12U;
      sv_HostRaw(UDSCMD_APP_TYPE_FLASH, u8ar_msg, v->u8ar_wire[0]);
      sv_AssertSent(4U, "result_flash_not_ready");

      // A name length that does not match the message, a message too short
      u8ar_msg[0] = 13U;
      u8ar_msg[1U + UDSCMD_PARAMS_LEN] = 9U;
      sv_HostRaw(UDSCMD_APP_TYPE_FLASH, u8ar_msg, v->u8ar_wire[0]);
      sv_AssertLast(UDSCMD_APP_TYPE_RESULT, (const uint8_t *)"\x0d\x55\x02", 3U);
      sv_HostRaw(UDSCMD_APP_TYPE_FLASH, u8ar_msg, 1U + UDSCMD_PARAMS_LEN);
      sv_AssertLast(UDSCMD_APP_TYPE_RESULT, (const uint8_t *)"\x0d\x55\x02", 3U);
   }
   TEST_ASSERT_EQUAL_UINT32(2U, sst_job.u32_calls);
}

static void test_StatusRequestAndAbort(void)
{
   sv_Host("status_req");
   sv_AssertSent(0U, "status_idle");

   sv_Host("abort");
   sv_AssertSent(1U, "result_abort_ok");
   sst_job.u8_ret = eUDS_BAD_STATE;
   sv_Host("abort");
   sv_AssertLast(UDSCMD_APP_TYPE_RESULT, (const uint8_t *)"\x0d\x57\x03", 3U);
   sv_HostRaw(UDSCMD_APP_TYPE_ABORT, (const uint8_t *)"\x0e\x00", 2U);
   sv_AssertLast(UDSCMD_APP_TYPE_RESULT, (const uint8_t *)"\x0e\x57\x02", 3U);
}

static void test_OtherMessagesAreIgnored(void)
{
   sv_HostRaw(UDSCMD_APP_TYPE_TARGET, NULL, 0U);
   sv_HostRaw(UDSCMD_APP_TYPE_RESULT, (const uint8_t *)"\x01\x50\x00", 3U);
   sv_HostRaw(0x59U, (const uint8_t *)"\x01", 1U);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_sentCount);
   TEST_ASSERT_EQUAL_UINT32(0U, sst_job.u32_calls);
}
#else
static void test_DisabledRegistersNothing(void)
{
   TEST_ASSERT_EQUAL_UINT8(0U, su8_routeCnt);
}
#endif // CONFIG_UDS_CMD

int main(void)
{
   (void)setvbuf(stdout, NULL, _IONBF, 0);
   UNITY_BEGIN();
#if defined(CONFIG_UDS_CMD)
   RUN_TEST(test_DefinesMatchVectors);
   RUN_TEST(test_RangeIsRegisteredForShortMessagesOnly);
   RUN_TEST(test_TargetIsDecoded);
   RUN_TEST(test_TargetRefusals);
   RUN_TEST(test_DiagRequestAndResponse);
   RUN_TEST(test_LongResponseIsSplit);
   RUN_TEST(test_DiagRefusals);
   RUN_TEST(test_Unlock);
   RUN_TEST(test_FlashIsDecodedAndAnsweredAtOnce);
   RUN_TEST(test_StatusRequestAndAbort);
   RUN_TEST(test_OtherMessagesAreIgnored);
#else
   RUN_TEST(test_DisabledRegistersNothing);
#endif // CONFIG_UDS_CMD
   return UNITY_END();
}
