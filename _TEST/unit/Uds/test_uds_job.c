/**
 * @file          test_uds_job.c
 * @brief         Host unit tests for the UDS job engine (_ASW/_UDS/UdsJob.c) with
 *                the real UDS client, seed -> key and File System Manager (on
 *                fs_sim.c), a scripted transport (sim_uds_tp.h) and a C ECU on
 *                the other side of it, and CanIf stubbed (lock, configure, traffic
 *                log and state listener recorded). The flash job is checked
 *                against the uds_flash conversation of wire.json, request by
 *                request; every step's NRC, timeouts, abort, bus-off, file errors,
 *                a long transfer (block counter wrap), targets, diagnostic
 *                requests, unlocks and the keep-alive are covered.
 *                Contract: _DOC/UDS/README.md.
 *
 * @date          12/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#define CONFIG_UDS_RESPONSE_MAX              400
#define CONFIG_UDS_FLASH_BLOCK_MAX           64
#define CONFIG_ISOTP_ENABLE_TX_PADDING       1

#include "UdsJob.c"
#include "UdsKey.c"
#include "UdsClient.c"
#include "FileSysManager.c"
#include "FileSysManagerFSM.c"
#include "sim_uds_tp.h"
#include "unity.h"
#include "wire_vectors.h"

/******************************************************************************/
/*  Stubs: transport factory, CanIf, data store                               */
/******************************************************************************/
static const struct device sst_canDev = { "can@0" };

/* The job's ISO-TP transport is replaced by the scripted one */
void gv_UdsTpIsotp_Init(UdsTp_T *stpt_tp, UdsTpIsotp_T *stpt_ctx, const struct device *stpt_can)
{
   (void)stpt_ctx;
   TEST_ASSERT_EQUAL_PTR(&sst_canDev, stpt_can);
   *stpt_tp = sst_simTp;
}

static struct
{
   bool b_noDev;
   int i_cfgRet;
   uint32_t u32_cfgs;
   CanIfConfig_T st_cfg;
   const void *vpt_cfgOwner;
   int i_lockRet;
   const void *vpt_lock;
   uint32_t u32_locks;
   uint32_t u32_unlocks;
   bool b_monitor;
   uint32_t u32_monOff;
   CanIfState_F fpt_listener;
} sst_canIf;

const struct device *gstpt_CanIf_GetDevice(void)
{
   return sst_canIf.b_noDev ? NULL : &sst_canDev;
}

int gi_CanIf_Configure(const CanIfConfig_T *stpt_config, const void *vpt_owner)
{
   sst_canIf.u32_cfgs++;
   sst_canIf.st_cfg = *stpt_config;
   sst_canIf.vpt_cfgOwner = vpt_owner;
   return sst_canIf.i_cfgRet;
}

int gi_CanIf_Lock(const void *vpt_owner)
{
   if (sst_canIf.i_lockRet != 0)
   {
      return sst_canIf.i_lockRet;
   }
   TEST_ASSERT_NULL_MESSAGE(sst_canIf.vpt_lock, "locked once");
   sst_canIf.vpt_lock = vpt_owner;
   sst_canIf.u32_locks++;
   return 0;
}

int gi_CanIf_Unlock(const void *vpt_owner)
{
   TEST_ASSERT_EQUAL_PTR(sst_canIf.vpt_lock, vpt_owner);
   sst_canIf.vpt_lock = NULL;
   sst_canIf.u32_unlocks++;
   return 0;
}

void gv_CanIf_SetMonitor(bool b_on)
{
   sst_canIf.b_monitor = b_on;
   sst_canIf.u32_monOff += b_on ? 0U : 1U;
}

int gi_CanIf_GetStatus(CanIfStatus_T *stpt_status)
{
   memset(stpt_status, 0, sizeof(*stpt_status));
   stpt_status->b_ready = true;
   stpt_status->b_monitor = sst_canIf.b_monitor;
   return 0;
}

int gi_CanIf_AddStateListener(CanIfState_F fpt_cb, void *vpt_user)
{
   TEST_ASSERT_NULL(vpt_user);
   sst_canIf.fpt_listener = fpt_cb;
   return 0;
}

static bool sb_uploadOpen;

bool gb_DataStore_UploadOpen(void)
{
   return sb_uploadOpen;
}

/* A wait blocks: the File System Manager works off its queue */
void gv_SimOnBlock(struct k_sem *stpt_sem)
{
   (void)stpt_sem;
   while (sb_ProcessNext(K_NO_WAIT)) {}
}

void gv_SimRegisterTimer(struct k_timer *t)
{
   (void)t;
}

/******************************************************************************/
/*  The ECU                                                                   */
/******************************************************************************/
#define STEP_NONE                            (-1)
#define ECU_IMG_MAX                          (20000U)

static struct
{
   /* uds_flash conversation */
   uint32_t u32_step;
   int i_failStep;
   int i_silentStep;
   int i_abortStep;
   int i_busOffStep;
   char car_mismatch[96];
   /* generic ECU */
   uint16_t u16_max;
   uint8_t u8_expectBsc;
   uint32_t u32_blocks;
   uint32_t u32_imgLen;
   uint8_t u8ar_img[ECU_IMG_MAX];
   uint8_t u8ar_routineArgs[16];
   size_t t_routineArgLen;
   uint32_t u32_routines;
} sst_ecu;

static int si_StepIndex(const char *cpt_name)
{
   uint32_t i;

   for (i = 0U; i < ARRAY_SIZE(gstar_vecUdsSteps); i++)
   {
      if (strcmp(gstar_vecUdsSteps[i].cpt_name, cpt_name) == 0)
      {
         return (int)i;
      }
   }
   TEST_FAIL_MESSAGE(cpt_name);
   return STEP_NONE;
}

static void sv_Answer(const uint8_t *u8pt_rsp, size_t t_len, int64_t i64_delay)
{
   sv_SimTpQueueBytes(sst_tp.u32_sends, i64_delay, u8pt_rsp, t_len, 0);
}

/** The ECU of the uds_flash conversation: checks every request, gives its answers. */
static void sv_EcuVector(const uint8_t *u8pt_req, size_t t_len, bool b_functional)
{
   const UdsStepVector_T *v;
   uint8_t u8ar_nrc[3];
   int i_idx = (int)sst_ecu.u32_step;
   uint8_t i;

   (void)b_functional;
   if (sst_ecu.u32_step >= ARRAY_SIZE(gstar_vecUdsSteps))
   {
      (void)snprintf(sst_ecu.car_mismatch, sizeof(sst_ecu.car_mismatch), "request 0x%02x after the last step",
         u8pt_req[0]);
      return;
   }
   v = &gstar_vecUdsSteps[sst_ecu.u32_step++];
   if ((t_len != v->u8_reqLen) || (memcmp(u8pt_req, v->u8ar_req, t_len) != 0))
   {
      (void)snprintf(sst_ecu.car_mismatch, sizeof(sst_ecu.car_mismatch), "step %s: request differs", v->cpt_name);
   }

   if (i_idx == sst_ecu.i_abortStep)
   {
      TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_Abort());
   }
   if (i_idx == sst_ecu.i_busOffStep)
   {
      struct can_bus_err_cnt st_err = { 255U, 0U };

      sst_canIf.fpt_listener(CAN_STATE_BUS_OFF, &st_err, NULL);
      return;
   }
   if (i_idx == sst_ecu.i_silentStep)
   {
      return;
   }
   if (i_idx == sst_ecu.i_failStep)
   {
      u8ar_nrc[0] = 0x7FU;
      u8ar_nrc[1] = u8pt_req[0];
      u8ar_nrc[2] = 0x31U;
      sv_Answer(u8ar_nrc, 3U, 0);
      return;
   }
   for (i = 0U; i < v->u8_rspCount; i++)
   {
      sv_Answer(v->u8ar_rsp[i], v->u8ar_rspLen[i], (i == 0U) ? 0 : 100);
   }
}

/** A generic ECU: positive answers, an image it keeps, the block counter checked. */
static void sv_EcuGeneric(const uint8_t *u8pt_req, size_t t_len, bool b_functional)
{
   uint8_t u8ar_rsp[8];
   size_t t_rsp = 2U;

   (void)b_functional;
   u8ar_rsp[0] = (uint8_t)(u8pt_req[0] + 0x40U);
   u8ar_rsp[1] = (t_len > 1U) ? u8pt_req[1] : 0U;
   switch (u8pt_req[0])
   {
      case 0x10:
         u8ar_rsp[2] = 0x00U; u8ar_rsp[3] = 0x32U; u8ar_rsp[4] = 0x01U; u8ar_rsp[5] = 0xF4U;
         t_rsp = 6U;
         break;

      case 0x27:
         if ((u8pt_req[1] & 1U) != 0U)
         {
            u8ar_rsp[2] = 0x11U; u8ar_rsp[3] = 0x22U;
            t_rsp = 4U;
         }
         break;

      case 0x2E:
         u8ar_rsp[2] = u8pt_req[2];
         t_rsp = 3U;
         break;

      case 0x31:
         u8ar_rsp[2] = u8pt_req[2]; u8ar_rsp[3] = u8pt_req[3]; u8ar_rsp[4] = 0x00U;
         t_rsp = 5U;
         sst_ecu.u32_routines++;
         sst_ecu.t_routineArgLen = t_len - 4U;
         memcpy(sst_ecu.u8ar_routineArgs, &u8pt_req[4], MIN(t_len - 4U, sizeof(sst_ecu.u8ar_routineArgs)));
         break;

      case 0x34:
         sst_ecu.u8_expectBsc = 1U;
         u8ar_rsp[1] = 0x20U; u8ar_rsp[2] = (uint8_t)(sst_ecu.u16_max >> 8); u8ar_rsp[3] = (uint8_t)sst_ecu.u16_max;
         t_rsp = 4U;
         break;

      case 0x36:
         if (u8pt_req[1] != sst_ecu.u8_expectBsc)
         {
            u8ar_rsp[0] = 0x7FU; u8ar_rsp[1] = 0x36U; u8ar_rsp[2] = 0x73U;
            t_rsp = 3U;
            break;
         }
         TEST_ASSERT_TRUE(sst_ecu.u32_imgLen + (t_len - 2U) <= ECU_IMG_MAX);
         memcpy(&sst_ecu.u8ar_img[sst_ecu.u32_imgLen], &u8pt_req[2], t_len - 2U);
         sst_ecu.u32_imgLen += (uint32_t)(t_len - 2U);
         sst_ecu.u32_blocks++;
         sst_ecu.u8_expectBsc++;
         break;

      case 0x37:
         t_rsp = 1U;
         break;

      default:
         break;
   }
   sv_Answer(u8ar_rsp, t_rsp, 0);
}

/******************************************************************************/
/*  Helpers                                                                   */
/******************************************************************************/
#define FLASH_FILE                           "/FLASH_DISK:/FW/APP1.BIN"
#define USER                                 ((void *)&sst_ecu)
#define STATUS_MAX                           (64U)

static const UdsJobTarget_T scst_zeroTarget;
static uint8_t su8_result;
static uint8_t su8ar_data[CONFIG_UDS_RESPONSE_MAX];
static size_t st_dataLen;
static uint32_t su32_results;
static UdsJobStatus_T sstar_status[STATUS_MAX];
static uint32_t su32_statuses;

static void sv_OnResult(uint8_t u8_result, const uint8_t *u8pt_data, size_t t_len, void *vpt_user)
{
   TEST_ASSERT_EQUAL_PTR(USER, vpt_user);
   TEST_ASSERT_EQUAL_INT_MESSAGE(0, atomic_get(&st_busy), "free before the result");
   su8_result = u8_result;
   st_dataLen = t_len;
   if (t_len > 0U)
   {
      TEST_ASSERT_NOT_NULL(u8pt_data);
      memcpy(su8ar_data, u8pt_data, t_len);
   }
   su32_results++;
}

static void sv_OnStatus(const UdsJobStatus_T *stpt_status, void *vpt_user)
{
   TEST_ASSERT_EQUAL_PTR(USER, vpt_user);
   sstar_status[MIN(su32_statuses, STATUS_MAX - 1U)] = *stpt_status;
   su32_statuses++;
}

static const UdsJobStatus_T *sstpt_LastStatus(void)
{
   TEST_ASSERT_TRUE(su32_statuses > 0U);
   return &sstar_status[MIN(su32_statuses, STATUS_MAX) - 1U];
}

static UdsJobTarget_T sst_Target(void)
{
   UdsJobTarget_T st_target;

   memset(&st_target, 0, sizeof(st_target));
   st_target.st_can.u32_bitrate = 500000U;
   st_target.st_uds.u32_txId = 0x7E0U;
   st_target.st_uds.u32_rxId = 0x7E8U;
   st_target.st_uds.u32_funcId = 0x7DFU;
   st_target.st_uds.u8_flags = UDS_TGT_PAD | UDS_TGT_FUNC;
   st_target.st_uds.u8_txDl = 8U;
   return st_target;
}

/** The simulator's parameters (uds_cmd.sim_params of wire.json). */
static UdsFlashParams_T sst_SimParams(void)
{
   static const uint8_t scu8ar_fp[] = { 0x20U, 0x26U, 0x10U, 0x12U, 0x01U, 0x02U, 0x03U };
   UdsFlashParams_T st_params;

   memset(&st_params, 0, sizeof(st_params));
   st_params.u16_flags = UDS_FF_ALL;
   st_params.u8_securityLevel = 1U;
   st_params.u8_keyAlgo = UDS_KEY_ALGO_BENCH_XOR;
   st_params.u8_commControl = 0x03U;
   st_params.u8_commType = 0x01U;
   st_params.u8_resetType = 0x01U;
   st_params.u8_alfid = 0x44U;
   st_params.u8_dfi = 0x00U;
   st_params.u16_eraseRid = 0xFF00U;
   st_params.u16_checkRid = 0xFF01U;
   st_params.u16_fingerprintDid = 0xF15AU;
   st_params.u8_fingerprintLen = sizeof(scu8ar_fp);
   memcpy(st_params.u8ar_fingerprint, scu8ar_fp, sizeof(scu8ar_fp));
   TEST_ASSERT_EQUAL_HEX16(VEC_UDS_FF_EXT_SESSION | VEC_UDS_FF_DTC_OFF | VEC_UDS_FF_COMM_OFF | VEC_UDS_FF_SECURITY
      | VEC_UDS_FF_FINGERPRINT | VEC_UDS_FF_ERASE | VEC_UDS_FF_ERASE_PER_RECORD | VEC_UDS_FF_CHECK
      | VEC_UDS_FF_CHECK_CRC | VEC_UDS_FF_RESET, st_params.u16_flags);
   return st_params;
}

static void sv_ResetAll(void)
{
   sv_SimTpReset();
   memset(&sst_ecu, 0, sizeof(sst_ecu));
   sst_ecu.i_failStep = STEP_NONE;
   sst_ecu.i_silentStep = STEP_NONE;
   sst_ecu.i_abortStep = STEP_NONE;
   sst_ecu.i_busOffStep = STEP_NONE;
   sst_ecu.u16_max = 0x0FFAU;
   memset(&sst_canIf, 0, sizeof(sst_canIf));
   sst_canIf.b_monitor = true;
   sb_uploadOpen = false;
   gi64_simNowMs = 0;
   gv_SimLogClear();
   su8_result = 0xEEU;
   st_dataLen = 0U;
   su32_results = 0U;
   su32_statuses = 0U;

   // A mounted volume holding the conversation's file
   gv_SimFsReset();
   gv_SimFsFormat(false);
   k_msgq_purge(&sst_fsmgrMsgQ);
   sb_mounted = false;
   memset(&sst_FSMGRContext, 0, sizeof(sst_FSMGRContext));
   gv_SimRunThread(sv_FSMGR_Thread);
   TEST_ASSERT_EQUAL_INT(0, gi_SimFsPutDir("/FLASH_DISK:/FW"));
   TEST_ASSERT_EQUAL_INT(0, gi_SimFsPut(FLASH_FILE, gu8ar_vecUdsFile, VEC_UDS_FILE_LEN));

   // The engine as after boot
   sb_clientReady = false;
   sb_targetSet = false;
   (void)atomic_set(&st_busy, 0);
   (void)atomic_set(&st_abort, 0);
   (void)atomic_set(&st_busOff, 0);
   (void)atomic_set(&st_fileOpen, 0);
   memset(&sst_status, 0, sizeof(sst_status));
   sfpt_status = NULL;
   k_msgq_purge(&sst_udsJobQ);
   k_sem_reset(&sst_readSem);
   TEST_ASSERT_EQUAL_INT(0, gi_UdsJob_Init());
   TEST_ASSERT_NOT_NULL(sst_canIf.fpt_listener);
}

static void sv_SetTargetOk(void)
{
   UdsJobTarget_T st_target = sst_Target();

   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_SetTarget(&st_target, sv_OnResult, USER));
   sv_JobStep();
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, su8_result);
}

static void sv_FlashApp1(UdsFlashParams_T st_params)
{
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_Flash("APP1.BIN", 8U, &st_params, sv_OnStatus, USER));
   sv_JobStep();
}

/** After any job: the bus, the log, the file and the engine are back. */
static void sv_AssertCleanedUp(void)
{
   TEST_ASSERT_NULL_MESSAGE(sst_canIf.vpt_lock, "bus unlocked");
   TEST_ASSERT_EQUAL_UINT32(sst_canIf.u32_locks, sst_canIf.u32_unlocks);
   TEST_ASSERT_TRUE_MESSAGE(sst_canIf.b_monitor, "traffic log back on");
   TEST_ASSERT_FALSE(gb_UdsJob_FileOpen());
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, gu32_SimFsOpenHandles(), "file closed");
   TEST_ASSERT_EQUAL_INT(0, atomic_get(&st_busy));
   TEST_ASSERT_EQUAL_INT(0, atomic_get(&st_abort));
}

void setUp(void)
{
   sv_ResetAll();
}

void tearDown(void)
{
   TEST_ASSERT_EQUAL_INT_MESSAGE(0, sst_statusMutex.i_held, "status mutex released");
}

/******************************************************************************/
/*  Flash job: the golden conversation                                        */
/******************************************************************************/
static void test_FlashFollowsTheGoldenConversation(void)
{
   const UdsJobStatus_T *stpt_last;
   UdsJobStatus_T st_status;
   bool b_sawTransfer = false;
   uint32_t i;

   sv_SetTargetOk();
   sst_tp.fpt_responder = sv_EcuVector;
   sv_FlashApp1(sst_SimParams());

   TEST_ASSERT_EQUAL_STRING("", sst_ecu.car_mismatch);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(ARRAY_SIZE(gstar_vecUdsSteps), sst_ecu.u32_step, "every step, in order");
   stpt_last = sstpt_LastStatus();
   TEST_ASSERT_EQUAL_UINT8(eUDS_STATE_DONE, stpt_last->u8_state);
   TEST_ASSERT_EQUAL_UINT8(eUDS_STEP_DONE, stpt_last->u8_step);
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, stpt_last->u8_result);
   TEST_ASSERT_EQUAL_UINT8(VEC_UDS_IMAGE_RECORDS, stpt_last->u8_recCnt);
   TEST_ASSERT_EQUAL_UINT8(VEC_UDS_IMAGE_RECORDS, stpt_last->u8_recIdx);
   TEST_ASSERT_EQUAL_UINT32(VEC_UDS_IMAGE_BYTES, stpt_last->u32_total);
   TEST_ASSERT_EQUAL_UINT32(VEC_UDS_IMAGE_BYTES, stpt_last->u32_done);
   TEST_ASSERT_EQUAL_HEX8(0x11U, stpt_last->u8_lastSid);
   for (i = 0U; i < MIN(su32_statuses, STATUS_MAX); i++)
   {
      b_sawTransfer = b_sawTransfer || ((sstar_status[i].u8_step == eUDS_STEP_TRANSFER)
         && (sstar_status[i].u8_state == eUDS_STATE_RUNNING));
   }
   TEST_ASSERT_TRUE(b_sawTransfer);

   // The bus was the job's alone, and quiet
   TEST_ASSERT_EQUAL_UINT32(1U, sst_canIf.u32_locks);
   TEST_ASSERT_EQUAL_UINT32(1U, sst_canIf.u32_monOff);
   sv_AssertCleanedUp();
   gv_UdsJob_GetStatus(&st_status);
   TEST_ASSERT_EQUAL_MEMORY(stpt_last, &st_status, sizeof(st_status));
   TEST_ASSERT_EQUAL_INT32_MESSAGE(UDS_KEEPALIVE_NONE, gi32_UdsClient_KeepAlive(&sst_client), "reset ends the session");
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("flash APP1.BIN done"));
}

static void test_EveryStepsNrcFailsTheJobCleanly(void)
{
   const UdsJobStatus_T *stpt_last;
   uint32_t u32_step;
   char car_msg[64];

   for (u32_step = 0U; u32_step < ARRAY_SIZE(gstar_vecUdsSteps); u32_step++)
   {
      sv_ResetAll();
      sv_SetTargetOk();
      sst_tp.fpt_responder = sv_EcuVector;
      sst_ecu.i_failStep = (int)u32_step;
      sv_FlashApp1(sst_SimParams());

      (void)snprintf(car_msg, sizeof(car_msg), "NRC at %s", gstar_vecUdsSteps[u32_step].cpt_name);
      stpt_last = sstpt_LastStatus();
      TEST_ASSERT_EQUAL_UINT8_MESSAGE(eUDS_STATE_FAILED, stpt_last->u8_state, car_msg);
      TEST_ASSERT_EQUAL_UINT8_MESSAGE(eUDS_NRC, stpt_last->u8_result, car_msg);
      TEST_ASSERT_EQUAL_HEX8_MESSAGE(gstar_vecUdsSteps[u32_step].u8ar_req[0], stpt_last->u8_lastSid, car_msg);
      TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x31U, stpt_last->u8_lastNrc, car_msg);
      TEST_ASSERT_EQUAL_UINT32_MESSAGE(u32_step + 1U, sst_ecu.u32_step, car_msg);
      sv_AssertCleanedUp();
      TEST_ASSERT_EQUAL_INT32_MESSAGE(UDS_KEEPALIVE_NONE, gi32_UdsClient_KeepAlive(&sst_client),
         "a failed job keeps no session alive");
   }
}

static void test_SilentEcuTimesOut(void)
{
   sv_SetTargetOk();
   sst_tp.fpt_responder = sv_EcuVector;
   sst_ecu.i_silentStep = si_StepIndex("download_0");
   sv_FlashApp1(sst_SimParams());
   TEST_ASSERT_EQUAL_UINT8(eUDS_STATE_FAILED, sstpt_LastStatus()->u8_state);
   TEST_ASSERT_EQUAL_UINT8(eUDS_TIMEOUT, sstpt_LastStatus()->u8_result);
   TEST_ASSERT_EQUAL_UINT8(eUDS_STEP_DOWNLOAD, sstpt_LastStatus()->u8_step);
   sv_AssertCleanedUp();
}

static void test_AbortStopsAtTheNextRequest(void)
{
   sv_SetTargetOk();
   sst_tp.fpt_responder = sv_EcuVector;
   sst_ecu.i_abortStep = si_StepIndex("transfer_0_1");
   sv_FlashApp1(sst_SimParams());
   TEST_ASSERT_EQUAL_UINT32_MESSAGE((uint32_t)si_StepIndex("transfer_0_1") + 1U, sst_ecu.u32_step,
      "no request after the aborted one");
   TEST_ASSERT_EQUAL_UINT8(eUDS_STATE_ABORTED, sstpt_LastStatus()->u8_state);
   TEST_ASSERT_EQUAL_UINT8(eUDS_ABORTED, sstpt_LastStatus()->u8_result);
   sv_AssertCleanedUp();
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(eUDS_BAD_STATE, gu8_UdsJob_Abort(), "nothing left to abort");
}

static void test_BusOffStopsTheJob(void)
{
   sv_SetTargetOk();
   sst_tp.fpt_responder = sv_EcuVector;
   sst_ecu.i_busOffStep = si_StepIndex("erase_0");
   sv_FlashApp1(sst_SimParams());
   TEST_ASSERT_EQUAL_UINT8(eUDS_STATE_FAILED, sstpt_LastStatus()->u8_state);
   TEST_ASSERT_EQUAL_UINT8(eUDS_BUS_OFF, sstpt_LastStatus()->u8_result);
   sv_AssertCleanedUp();

   // Back to error-active: the next request is not reported as bus-off
   sst_canIf.fpt_listener(CAN_STATE_ERROR_ACTIVE, &(struct can_bus_err_cnt){ 0U, 0U }, NULL);
   TEST_ASSERT_EQUAL_INT(0, atomic_get(&st_busOff));
}

/******************************************************************************/
/*  Flash job: other parameters, a long transfer                              */
/******************************************************************************/
static void sv_PutBigFile(uint32_t u32_len)
{
   static uint8_t su8ar_file[8U + ECU_IMG_MAX];
   uint32_t i;

   TEST_ASSERT_TRUE(u32_len <= ECU_IMG_MAX);
   sys_put_le32(0x00020000UL, su8ar_file);
   sys_put_le32(u32_len, &su8ar_file[4]);
   for (i = 0U; i < u32_len; i++)
   {
      su8ar_file[8U + i] = (uint8_t)((i * 31U) ^ (i >> 8));
   }
   TEST_ASSERT_EQUAL_INT(0, gi_SimFsPut("/FLASH_DISK:/FW/BIG.BIN", su8ar_file, 8U + u32_len));
}

static void test_LongTransferWrapsTheBlockCounter(void)
{
   const uint32_t u32_len = 300U * (CONFIG_UDS_FLASH_BLOCK_MAX - 2U) + 7U;
   const uint8_t *u8pt_file;
   UdsFlashParams_T st_params = sst_SimParams();
   uint32_t u32_size = 0U;

   sv_PutBigFile(u32_len);
   sv_SetTargetOk();
   sst_tp.fpt_responder = sv_EcuGeneric;
   st_params.u16_flags = UDS_FF_ERASE | UDS_FF_CHECK;      // erase once, check without the CRC
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_Flash("BIG.BIN", 7U, &st_params, sv_OnStatus, USER));
   sv_JobStep();

   TEST_ASSERT_EQUAL_UINT8(eUDS_STATE_DONE, sstpt_LastStatus()->u8_state);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(301U, sst_ecu.u32_blocks, "blocks capped by the buffer (64 bytes)");
   u8pt_file = gu8pt_SimFsData("/FLASH_DISK:/FW/BIG.BIN", &u32_size);
   TEST_ASSERT_EQUAL_UINT32(u32_len, sst_ecu.u32_imgLen);
   TEST_ASSERT_EQUAL_MEMORY(&u8pt_file[8], sst_ecu.u8ar_img, u32_len);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(2U, sst_ecu.u32_routines, "erase once, check once");
   TEST_ASSERT_EQUAL_size_t_MESSAGE(0U, sst_ecu.t_routineArgLen, "check without the CRC");
   TEST_ASSERT_TRUE(sb_SimTpSent(0U, "1002"));
   TEST_ASSERT_TRUE_MESSAGE(sb_SimTpSent(1U, "3101ff00"), "erase without arguments");
   sv_AssertCleanedUp();
}

static void test_MaxBlockParameterCapsTheBlocks(void)
{
   UdsFlashParams_T st_params = sst_SimParams();

   sv_PutBigFile(100U);
   sv_SetTargetOk();
   sst_tp.fpt_responder = sv_EcuGeneric;
   st_params.u16_flags = 0U;
   st_params.u16_maxBlock = 34U;
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_Flash("BIG.BIN", 7U, &st_params, sv_OnStatus, USER));
   sv_JobStep();
   TEST_ASSERT_EQUAL_UINT8(eUDS_STATE_DONE, sstpt_LastStatus()->u8_state);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(4U, sst_ecu.u32_blocks, "32 data bytes per block");

   // An ECU that allows no data per block is refused
   sv_ResetAll();
   sv_PutBigFile(100U);
   sv_SetTargetOk();
   sst_tp.fpt_responder = sv_EcuGeneric;
   sst_ecu.u16_max = 2U;
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_Flash("BIG.BIN", 7U, &st_params, sv_OnStatus, USER));
   sv_JobStep();
   TEST_ASSERT_EQUAL_UINT8(eUDS_STATE_FAILED, sstpt_LastStatus()->u8_state);
   sv_AssertCleanedUp();
}

/******************************************************************************/
/*  Flash job: the file                                                       */
/******************************************************************************/
static void sv_ExpectFileFailure(const char *cpt_name, uint8_t u8_result)
{
   UdsFlashParams_T st_params = sst_SimParams();

   sst_tp.fpt_responder = sv_EcuGeneric;
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_Flash(cpt_name, strlen(cpt_name), &st_params, sv_OnStatus, USER));
   sv_JobStep();
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(eUDS_STATE_FAILED, sstpt_LastStatus()->u8_state, cpt_name);
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(u8_result, sstpt_LastStatus()->u8_result, cpt_name);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, sst_tp.u32_sends, "the ECU is not touched");
   TEST_ASSERT_EQUAL_UINT32(0U, sst_canIf.u32_locks);
   sv_AssertCleanedUp();
}

static void test_BadFilesNeverReachTheEcu(void)
{
   uint8_t u8ar_file[VEC_UDS_FILE_LEN + 3U];

   sv_SetTargetOk();
   sv_ExpectFileFailure("NOPE.BIN", eUDS_FILE);

   // A cut header after the records
   memcpy(u8ar_file, gu8ar_vecUdsFile, VEC_UDS_FILE_LEN);
   memset(&u8ar_file[VEC_UDS_FILE_LEN], 0, 3U);
   TEST_ASSERT_EQUAL_INT(0, gi_SimFsPut("/FLASH_DISK:/FW/CUT.BIN", u8ar_file, sizeof(u8ar_file)));
   sv_ExpectFileFailure("CUT.BIN", eUDS_FILE);

   // A record whose data is cut short
   TEST_ASSERT_EQUAL_INT(0, gi_SimFsPut("/FLASH_DISK:/FW/SHORT.BIN", gu8ar_vecUdsFile, 8U + 10U));
   sv_ExpectFileFailure("SHORT.BIN", eUDS_FILE);

   // An empty record, an empty file
   memset(u8ar_file, 0, 8U);
   TEST_ASSERT_EQUAL_INT(0, gi_SimFsPut("/FLASH_DISK:/FW/ZERO.BIN", u8ar_file, 8U));
   sv_ExpectFileFailure("ZERO.BIN", eUDS_FILE);
   TEST_ASSERT_EQUAL_INT(0, gi_SimFsPut("/FLASH_DISK:/FW/EMPTY.BIN", u8ar_file, 0U));
   sv_ExpectFileFailure("EMPTY.BIN", eUDS_FILE);
}

static void test_FileInUseIsBusy(void)
{
   FileSysMessage_T st_msg;

   sv_SetTargetOk();
   memset(&st_msg, 0, sizeof(st_msg));
   st_msg.e_command = eFSC_OPEN_FILE_WRITE;
   memcpy(st_msg.u8_data, "/FLASH_DISK:/FW/X.TXT", 21U);
   st_msg.u32_sizeOfData = 21U;
   TEST_ASSERT_EQUAL_INT(0, gi_FSMGR_Call(&st_msg));

   sst_tp.fpt_responder = sv_EcuGeneric;
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_Flash("APP1.BIN", 8U, &(UdsFlashParams_T){ .u8_alfid = 0x44U },
      sv_OnStatus, USER));
   sv_JobStep();
   TEST_ASSERT_EQUAL_UINT8(eUDS_BUSY, sstpt_LastStatus()->u8_result);
   TEST_ASSERT_EQUAL_UINT32(0U, sst_tp.u32_sends);

   memset(&st_msg, 0, sizeof(st_msg));
   st_msg.e_command = eFSC_CLOSE_FILE;
   TEST_ASSERT_EQUAL_INT(0, gi_FSMGR_Call(&st_msg));
}

static void test_FileIsHeldOnlyWhileTheJobReadsIt(void)
{
   sv_SetTargetOk();
   sst_tp.fpt_responder = sv_EcuVector;
   TEST_ASSERT_FALSE(gb_UdsJob_FileOpen());
   sv_FlashApp1(sst_SimParams());
   TEST_ASSERT_FALSE(gb_UdsJob_FileOpen());
   TEST_ASSERT_TRUE_MESSAGE(gu32_SimFsCalls(eSFS_OPEN) >= 2U, "read twice: checked, then sent");
}

/******************************************************************************/
/*  Flash job: refused at once                                                */
/******************************************************************************/
static void test_FlashRefusals(void)
{
   UdsFlashParams_T st_params = sst_SimParams();
   UdsFlashParams_T st_bad;

   TEST_ASSERT_EQUAL_UINT8_MESSAGE(eUDS_NOT_READY, gu8_UdsJob_Flash("APP1.BIN", 8U, &st_params, sv_OnStatus, USER),
      "no target");
   sv_SetTargetOk();

   TEST_ASSERT_EQUAL_UINT8(eUDS_BAD_ARG, gu8_UdsJob_Flash("APP1.BIN", 8U, NULL, sv_OnStatus, USER));
   TEST_ASSERT_EQUAL_UINT8(eUDS_BAD_ARG, gu8_UdsJob_Flash("APP1.BIN", 8U, &st_params, NULL, USER));
   TEST_ASSERT_EQUAL_UINT8(eUDS_BAD_ARG, gu8_UdsJob_Flash("", 0U, &st_params, sv_OnStatus, USER));
   TEST_ASSERT_EQUAL_UINT8(eUDS_BAD_ARG, gu8_UdsJob_Flash("..", 2U, &st_params, sv_OnStatus, USER));
   TEST_ASSERT_EQUAL_UINT8(eUDS_BAD_ARG, gu8_UdsJob_Flash("A/B", 3U, &st_params, sv_OnStatus, USER));
   TEST_ASSERT_EQUAL_UINT8(eUDS_BAD_ARG, gu8_UdsJob_Flash("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456", 33U, &st_params,
      sv_OnStatus, USER));

   st_bad = st_params; st_bad.u16_flags = 0x0400U;
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(eUDS_BAD_ARG, gu8_UdsJob_Flash("APP1.BIN", 8U, &st_bad, sv_OnStatus, USER),
      "unknown flag");
   st_bad = st_params; st_bad.u8_alfid = 0x50U;
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(eUDS_BAD_ARG, gu8_UdsJob_Flash("APP1.BIN", 8U, &st_bad, sv_OnStatus, USER), "ALFID");
   st_bad = st_params; st_bad.u8_alfid = 0x40U;
   TEST_ASSERT_EQUAL_UINT8(eUDS_BAD_ARG, gu8_UdsJob_Flash("APP1.BIN", 8U, &st_bad, sv_OnStatus, USER));
   st_bad = st_params; st_bad.u16_flags = UDS_FF_ERASE_PER_RECORD;
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(eUDS_BAD_ARG, gu8_UdsJob_Flash("APP1.BIN", 8U, &st_bad, sv_OnStatus, USER),
      "per record without erase");
   st_bad = st_params; st_bad.u16_flags = UDS_FF_CHECK_CRC;
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(eUDS_BAD_ARG, gu8_UdsJob_Flash("APP1.BIN", 8U, &st_bad, sv_OnStatus, USER),
      "CRC without check");
   st_bad = st_params; st_bad.u8_fingerprintLen = 0U;
   TEST_ASSERT_EQUAL_UINT8(eUDS_BAD_ARG, gu8_UdsJob_Flash("APP1.BIN", 8U, &st_bad, sv_OnStatus, USER));
   st_bad = st_params; st_bad.u8_fingerprintLen = UDS_FP_MAX + 1U;
   TEST_ASSERT_EQUAL_UINT8(eUDS_BAD_ARG, gu8_UdsJob_Flash("APP1.BIN", 8U, &st_bad, sv_OnStatus, USER));
   st_bad = st_params; st_bad.u8_securityLevel = 2U;
   TEST_ASSERT_EQUAL_UINT8(eUDS_BAD_ARG, gu8_UdsJob_Flash("APP1.BIN", 8U, &st_bad, sv_OnStatus, USER));
   st_bad = st_params; st_bad.u8_keyAlgo = UDS_KEY_ALGO_NONE;
   TEST_ASSERT_EQUAL_UINT8(eUDS_NOT_SUPPORTED, gu8_UdsJob_Flash("APP1.BIN", 8U, &st_bad, sv_OnStatus, USER));

   sb_uploadOpen = true;
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(eUDS_BUSY, gu8_UdsJob_Flash("APP1.BIN", 8U, &st_params, sv_OnStatus, USER),
      "a hex upload is being stored");
   sb_uploadOpen = false;

   // One at a time: the second is refused while the first waits in the queue
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_Flash("APP1.BIN", 8U, &st_params, sv_OnStatus, USER));
   gv_UdsJob_GetStatus(&sstar_status[0]);
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(eUDS_STATE_RUNNING, sstar_status[0].u8_state, "running once accepted");
   TEST_ASSERT_EQUAL_UINT8(eUDS_BUSY, gu8_UdsJob_Flash("APP1.BIN", 8U, &st_params, sv_OnStatus, USER));
   TEST_ASSERT_EQUAL_UINT8(eUDS_BUSY, gu8_UdsJob_Diag((const uint8_t *)"\x22\xf1\x90", 3U, false, sv_OnResult, USER));
   TEST_ASSERT_EQUAL_UINT8(eUDS_BUSY, gu8_UdsJob_SetTarget(&scst_zeroTarget, sv_OnResult, USER));
   TEST_ASSERT_EQUAL_UINT32(0U, sst_tp.u32_sends);
}

static void test_BusLockedElsewhereIsBusy(void)
{
   sv_SetTargetOk();
   sst_tp.fpt_responder = sv_EcuVector;
   sst_canIf.i_lockRet = -EBUSY;
   sv_FlashApp1(sst_SimParams());
   TEST_ASSERT_EQUAL_UINT8(eUDS_BUSY, sstpt_LastStatus()->u8_result);
   TEST_ASSERT_EQUAL_UINT32(0U, sst_tp.u32_sends);
   TEST_ASSERT_TRUE(sst_canIf.b_monitor);
}

/******************************************************************************/
/*  Target                                                                    */
/******************************************************************************/
static void test_TargetConfiguresTheBusThenTheClient(void)
{
   UdsJobTarget_T st_target = sst_Target();

   sv_SetTargetOk();
   TEST_ASSERT_EQUAL_UINT32(1U, sst_canIf.u32_cfgs);
   TEST_ASSERT_EQUAL_UINT32(500000U, sst_canIf.st_cfg.u32_bitrate);
   TEST_ASSERT_NULL_MESSAGE(sst_canIf.vpt_cfgOwner, "no lock owner outside a job");
   TEST_ASSERT_EQUAL_HEX32(0x7E8U, sst_tp.st_bound.u32_rxId);

   // CAN FD addressing needs a CAN FD bus
   st_target.st_uds.u8_flags |= UDS_TGT_FD;
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_SetTarget(&st_target, sv_OnResult, USER));
   sv_JobStep();
   TEST_ASSERT_EQUAL_UINT8(eUDS_BAD_ARG, su8_result);
   st_target.st_can.b_fd = true;
   st_target.st_can.u32_bitrateData = 2000000U;
   st_target.st_uds.u8_flags |= UDS_TGT_BRS;
   st_target.st_uds.u8_txDl = 64U;
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_SetTarget(&st_target, sv_OnResult, USER));
   sv_JobStep();
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, su8_result);
   TEST_ASSERT_TRUE(sst_canIf.st_cfg.b_fd);
}

static void test_TargetRefusals(void)
{
   UdsJobTarget_T st_target = sst_Target();
   struct { int i_cfgRet; uint8_t u8_result; } star_cfg[] =
   {
      { -EBUSY, eUDS_BUSY }, { -EINVAL, eUDS_BAD_ARG }, { -ENOTSUP, eUDS_NOT_SUPPORTED }, { -ENODEV, eUDS_NOT_READY },
      { -EIO, eUDS_TRANSPORT },
   };
   uint32_t i;

   TEST_ASSERT_EQUAL_UINT8(eUDS_BAD_ARG, gu8_UdsJob_SetTarget(NULL, sv_OnResult, USER));
   TEST_ASSERT_EQUAL_UINT8(eUDS_BAD_ARG, gu8_UdsJob_SetTarget(&st_target, NULL, USER));

   sst_canIf.b_noDev = true;
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_SetTarget(&st_target, sv_OnResult, USER));
   sv_JobStep();
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(eUDS_NOT_READY, su8_result, "no CAN controller");
   sst_canIf.b_noDev = false;

   st_target.st_uds.u8_flags &= (uint8_t)~UDS_TGT_PAD;
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_SetTarget(&st_target, sv_OnResult, USER));
   sv_JobStep();
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(eUDS_NOT_SUPPORTED, su8_result, "padding is the build's");
   st_target = sst_Target();

   for (i = 0U; i < ARRAY_SIZE(star_cfg); i++)
   {
      sst_canIf.i_cfgRet = star_cfg[i].i_cfgRet;
      TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_SetTarget(&st_target, sv_OnResult, USER));
      sv_JobStep();
      TEST_ASSERT_EQUAL_UINT8(star_cfg[i].u8_result, su8_result);
   }
   sst_canIf.i_cfgRet = 0;

   st_target.st_uds.u32_txId = 0x800U;
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_SetTarget(&st_target, sv_OnResult, USER));
   sv_JobStep();
   TEST_ASSERT_EQUAL_UINT8(eUDS_BAD_ARG, su8_result);
   st_target = sst_Target();
   st_target.st_uds.u8_flags |= UDS_TGT_EXT_ADDR;
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_SetTarget(&st_target, sv_OnResult, USER));
   sv_JobStep();
   TEST_ASSERT_EQUAL_UINT8(eUDS_NOT_SUPPORTED, su8_result);
   st_target = sst_Target();
   sst_tp.i_bindRet = -ENOSPC;
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_SetTarget(&st_target, sv_OnResult, USER));
   sv_JobStep();
   TEST_ASSERT_EQUAL_UINT8(eUDS_TRANSPORT, su8_result);

   // A refused target leaves none: requests are not ready
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_Diag((const uint8_t *)"\x22\xf1\x90", 3U, false, sv_OnResult, USER));
   sv_JobStep();
   TEST_ASSERT_EQUAL_UINT8(eUDS_NOT_READY, su8_result);
}

/******************************************************************************/
/*  Diagnostic requests and unlock                                            */
/******************************************************************************/
static void test_DiagRequests(void)
{
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_Diag((const uint8_t *)"\x22\xf1\x90", 3U, false, sv_OnResult, USER));
   sv_JobStep();
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(eUDS_NOT_READY, su8_result, "no target");

   sv_SetTargetOk();
   SIM_RSP("62f190574d49");
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_Diag((const uint8_t *)"\x22\xf1\x90", 3U, false, sv_OnResult, USER));
   sv_JobStep();
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, su8_result);
   TEST_ASSERT_EQUAL_size_t(6U, st_dataLen);
   TEST_ASSERT_EQUAL_HEX8(0x62U, su8ar_data[0]);

   SIM_RSP("7f2231");
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_Diag((const uint8_t *)"\x22\xf1\x90", 3U, false, sv_OnResult, USER));
   sv_JobStep();
   TEST_ASSERT_EQUAL_UINT8(eUDS_NRC, su8_result);
   TEST_ASSERT_EQUAL_size_t(3U, st_dataLen);
   TEST_ASSERT_EQUAL_HEX8(0x31U, su8ar_data[2]);

   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_Diag((const uint8_t *)"\x22\xf1\x90", 3U, false, sv_OnResult, USER));
   sv_JobStep();
   TEST_ASSERT_EQUAL_UINT8(eUDS_TIMEOUT, su8_result);
   TEST_ASSERT_EQUAL_size_t(0U, st_dataLen);

   // Functional, without a positive response
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_Diag((const uint8_t *)"\x3e\x80", 2U, true, sv_OnResult, USER));
   sv_JobStep();
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, su8_result);
   TEST_ASSERT_TRUE(sst_tp.bar_sentFunc[sst_tp.u32_sends - 1U]);

   // While the bus is off
   sst_canIf.fpt_listener(CAN_STATE_BUS_OFF, &(struct can_bus_err_cnt){ 255U, 0U }, NULL);
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_Diag((const uint8_t *)"\x22\xf1\x90", 3U, false, sv_OnResult, USER));
   sv_JobStep();
   TEST_ASSERT_EQUAL_UINT8(eUDS_BUS_OFF, su8_result);

   TEST_ASSERT_EQUAL_UINT8(eUDS_BAD_ARG, gu8_UdsJob_Diag(su8ar_data, 0U, false, sv_OnResult, USER));
   TEST_ASSERT_EQUAL_UINT8(eUDS_BAD_ARG, gu8_UdsJob_Diag(su8ar_data, UDS_JOB_REQ_MAX + 1U, false, sv_OnResult, USER));
   TEST_ASSERT_EQUAL_UINT8(eUDS_BAD_ARG, gu8_UdsJob_Diag(su8ar_data, 3U, false, NULL, USER));
}

static void test_Unlock(void)
{
   const UdsKeyVector_T *v = &gstar_vecUdsKeys[0];
   char car_key[32];
   uint32_t i;

   sv_SetTargetOk();
   SIM_RSP("670111223344");
   SIM_RSP_N(2U, "6702");
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_Unlock(1U, UDS_KEY_ALGO_BENCH_XOR, sv_OnResult, USER));
   sv_JobStep();
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, su8_result);
   (void)snprintf(car_key, sizeof(car_key), "2702");
   for (i = 0U; i < v->u8_keyLen; i++)
   {
      (void)snprintf(&car_key[4U + (2U * i)], 3U, "%02x", v->u8ar_key[i]);
   }
   TEST_ASSERT_TRUE_MESSAGE(sb_SimTpSent(1U, car_key), "BENCH_XOR key of the vector seed");

   SIM_RSP("670101020304");
   SIM_RSP_N(2U, "7f2735");
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_Unlock(1U, UDS_KEY_ALGO_BENCH_XOR, sv_OnResult, USER));
   sv_JobStep();
   TEST_ASSERT_EQUAL_UINT8(eUDS_NRC, su8_result);
   TEST_ASSERT_EQUAL_size_t(1U, st_dataLen);
   TEST_ASSERT_EQUAL_HEX8(0x35U, su8ar_data[0]);

   TEST_ASSERT_EQUAL_UINT8(eUDS_NOT_SUPPORTED, gu8_UdsJob_Unlock(1U, UDS_KEY_ALGO_NONE, sv_OnResult, USER));
   TEST_ASSERT_EQUAL_UINT8(eUDS_NOT_SUPPORTED, gu8_UdsJob_Unlock(1U, 0x80U, sv_OnResult, USER));
   TEST_ASSERT_EQUAL_UINT8(eUDS_BAD_ARG, gu8_UdsJob_Unlock(2U, UDS_KEY_ALGO_BENCH_XOR, sv_OnResult, USER));
   TEST_ASSERT_EQUAL_UINT8(eUDS_BAD_ARG, gu8_UdsJob_Unlock(1U, UDS_KEY_ALGO_BENCH_XOR, NULL, USER));
}

static void test_KeepAliveBetweenRequests(void)
{
   sv_SetTargetOk();
   SIM_RSP("5003003201f4");
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, gu8_UdsJob_Diag((const uint8_t *)"\x10\x03", 2U, false, sv_OnResult, USER));
   sv_JobStep();
   TEST_ASSERT_EQUAL_UINT8(eUDS_OK, su8_result);

   // Nothing queued: the thread waits no longer than the keep-alive
   sv_JobStep();
   TEST_ASSERT_EQUAL_UINT32(1U, sst_tp.u32_sends);
   gi64_simNowMs += UDS_TESTER_PRESENT_MS;
   sv_JobStep();
   TEST_ASSERT_EQUAL_UINT32(2U, sst_tp.u32_sends);
   TEST_ASSERT_TRUE(sb_SimTpSent(1U, "3e80"));
}

int main(void)
{
   (void)setvbuf(stdout, NULL, _IONBF, 0);
   UNITY_BEGIN();
   RUN_TEST(test_FlashFollowsTheGoldenConversation);
   RUN_TEST(test_EveryStepsNrcFailsTheJobCleanly);
   RUN_TEST(test_SilentEcuTimesOut);
   RUN_TEST(test_AbortStopsAtTheNextRequest);
   RUN_TEST(test_BusOffStopsTheJob);
   RUN_TEST(test_LongTransferWrapsTheBlockCounter);
   RUN_TEST(test_MaxBlockParameterCapsTheBlocks);
   RUN_TEST(test_BadFilesNeverReachTheEcu);
   RUN_TEST(test_FileInUseIsBusy);
   RUN_TEST(test_FileIsHeldOnlyWhileTheJobReadsIt);
   RUN_TEST(test_FlashRefusals);
   RUN_TEST(test_BusLockedElsewhereIsBusy);
   RUN_TEST(test_TargetConfiguresTheBusThenTheClient);
   RUN_TEST(test_TargetRefusals);
   RUN_TEST(test_DiagRequests);
   RUN_TEST(test_Unlock);
   RUN_TEST(test_KeepAliveBetweenRequests);
   return UNITY_END();
}
