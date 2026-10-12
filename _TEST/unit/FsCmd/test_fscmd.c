/**
 * @file          test_fscmd.c
 * @brief         Host unit tests for _ASW/_FS_CMD against the file command
 *                contract in _DOC/FileSysManager/PROTOCOL.md: every golden CMD,
 *                REPLY and ENTRY frame of wire.json "file_system", the immediate
 *                refusals (bad op or argument, busy, upload in progress, queue
 *                full) and the limits. FsCmd.c is included with the real router
 *                and the real File System Manager on the in-memory volume of
 *                shim/fs_sim.c; the SETU Server and the data store are stubbed.
 *
 *                Built twice: with CONFIG_FS_CMD (the firmware's setting) and
 *                without, where it must register nothing.
 *
 * @date          07/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#include "FsCmd.c"
#include "SETURouter.c"
#include "FileSysManager.c"
#include "FileSysManagerFSM.c"
#include "unity.h"
#include "wire_vectors.h"

/******************************************************************************/
/*  Stubs: SETU Server, GATT service, data store                          */
/******************************************************************************/
static struct bt_gatt_attr sst_ctrlAttr;
static SETUSrvCfg_T sst_cfg;
static int si_sendRet;
static bool sb_uploadOpen;

typedef struct
{
   uint8_t u8_type;
   uint8_t u8_len;
   uint8_t u8ar_payload[SETU_MAX_SHORT_PAYLOAD];
} SentShort_T;

static SentShort_T sstar_sent[16];
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

int gi_SETUS_SendShort(uint8_t u8_appType, const void *vpt_data, uint8_t u8_len,
   k_timeout_t t_timeout)
{
   SentShort_T *s = &sstar_sent[su32_sentCount % ARRAY_SIZE(sstar_sent)];

   TEST_ASSERT_TRUE_MESSAGE(t_timeout.ms >= 0, "a reply must not wait for ever");
   TEST_ASSERT_TRUE(u8_len <= SETU_MAX_SHORT_PAYLOAD);
   s->u8_type = u8_appType;
   s->u8_len = u8_len;
   (void)memcpy(s->u8ar_payload, vpt_data, u8_len);
   su32_sentCount++;
   return si_sendRet;
}

bool gb_DataStore_UploadOpen(void)
{
   return sb_uploadOpen;
}

#if defined(CONFIG_UDS)
static bool sb_flashRunning;

bool gb_UdsJob_FlashRunning(void)
{
   return sb_flashRunning;
}
#endif // CONFIG_UDS

void gv_SimOnBlock(struct k_sem *stpt_sem)
{
   (void)stpt_sem;
}

void gv_SimRegisterTimer(struct k_timer *t)
{
   (void)t;
}

#if defined(CONFIG_FS_CMD)
/******************************************************************************/
/*  Helpers                                                                   */
/******************************************************************************/
static const ShortVector_T *sstpt_Vec(const char *cpt_name)
{
   uint32_t i;

   for (i = 0U; i < ARRAY_SIZE(gstar_vecFsShorts); i++)
   {
      if (strcmp(gstar_vecFsShorts[i].cpt_name, cpt_name) == 0) { return &gstar_vecFsShorts[i]; }
   }
   TEST_FAIL_MESSAGE(cpt_name);
   return NULL;
}

/** The host sends a CMD; the File System Manager runs until its queue is empty. */
static void sv_Cmd(const uint8_t *u8pt_payload, uint8_t u8_len)
{
   sst_cfg.fpt_onRxShort(FSCMD_APP_TYPE_CMD, u8pt_payload, u8_len);
   while (sb_ProcessNext(K_NO_WAIT)) {}
}

static void sv_CmdVec(const char *cpt_name)
{
   const ShortVector_T *v = sstpt_Vec(cpt_name);

   TEST_ASSERT_EQUAL_HEX8(FSCMD_APP_TYPE_CMD, v->u8ar_wire[1]);
   sv_Cmd(&v->u8ar_wire[2], v->u8ar_wire[0]);
}

/** A CMD built here: [seq][op][arg]. */
static void sv_CmdRaw(uint8_t u8_seq, uint8_t u8_op, const void *vpt_arg, uint8_t u8_argLen)
{
   uint8_t u8ar_p[SETU_MAX_SHORT_PAYLOAD];

   u8ar_p[0] = u8_seq;
   u8ar_p[1] = u8_op;
   if (u8_argLen > 0U) { (void)memcpy(&u8ar_p[2], vpt_arg, u8_argLen); }
   sv_Cmd(u8ar_p, (uint8_t)(u8_argLen + 2U));
}

static const SentShort_T *sstpt_Sent(uint32_t u32_idx)
{
   TEST_ASSERT_TRUE(u32_idx < su32_sentCount);
   return &sstar_sent[u32_idx % ARRAY_SIZE(sstar_sent)];
}

static const SentShort_T *sstpt_Last(void)
{
   TEST_ASSERT_TRUE_MESSAGE(su32_sentCount > 0U, "nothing sent");
   return sstpt_Sent(su32_sentCount - 1U);
}

/** Sent frame u32_idx must be the golden frame cpt_name. */
static void sv_AssertSent(uint32_t u32_idx, const char *cpt_name)
{
   const ShortVector_T *v = sstpt_Vec(cpt_name);
   const SentShort_T *s = sstpt_Sent(u32_idx);

   TEST_ASSERT_EQUAL_HEX8_MESSAGE(v->u8ar_wire[1], s->u8_type, cpt_name);
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(v->u8ar_wire[0], s->u8_len, cpt_name);
   TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(&v->u8ar_wire[2], s->u8ar_payload, v->u8ar_wire[0], cpt_name);
}

static void sv_AssertLast(const char *cpt_name)
{
   sv_AssertSent(su32_sentCount - 1U, cpt_name);
}

/** The last frame is a REPLY with this seq, op and status. */
static void sv_AssertReply(uint8_t u8_seq, uint8_t u8_op, uint8_t u8_status)
{
   const SentShort_T *s = sstpt_Last();

   TEST_ASSERT_EQUAL_HEX8(FSCMD_APP_TYPE_REPLY, s->u8_type);
   TEST_ASSERT_EQUAL_UINT8(u8_seq, s->u8ar_payload[0]);
   TEST_ASSERT_EQUAL_UINT8(u8_op, s->u8ar_payload[1]);
   TEST_ASSERT_EQUAL_UINT8_MESSAGE(u8_status, s->u8ar_payload[2], "status");
}

#endif // CONFIG_FS_CMD

static void sv_Mount(bool b_ok)
{
   gv_SimFsReset();
   if (!b_ok) { gv_SimFsFailOnce(eSFS_MKFS, 0U, -EIO); }
   else { gv_SimFsFormat(false); }
   k_msgq_purge(&sst_fsmgrMsgQ);
   sb_mounted = false;
   (void)memset(&sst_FSMGRContext, 0, sizeof(sst_FSMGRContext));
   gv_SimRunThread(sv_FSMGR_Thread);
}

void setUp(void)
{
   su8_routeCnt = 0U;
   sb_isStarted = false;
   (void)memset(&sst_cfg, 0, sizeof(sst_cfg));
   atomic_set(&st_busy, 0);
   si_sendRet = 0;
   sb_uploadOpen = false;
#if defined(CONFIG_UDS)
   sb_flashRunning = false;
#endif // CONFIG_UDS
   su32_sentCount = 0U;
   gv_SimLogClear();
   sv_Mount(true);
   TEST_ASSERT_EQUAL_INT(0, gi_FsCmd_Init());
   TEST_ASSERT_EQUAL_INT(0, gi_SETURouter_Start());
}

void tearDown(void) {}

#if defined(CONFIG_FS_CMD)
/******************************************************************************/
/*  Constants and registration                                                */
/******************************************************************************/
static void test_DefinesMatchVectors(void)
{
   TEST_ASSERT_EQUAL_HEX8(VEC_FS_APP_CMD, FSCMD_APP_TYPE_CMD);
   TEST_ASSERT_EQUAL_HEX8(VEC_FS_APP_REPLY, FSCMD_APP_TYPE_REPLY);
   TEST_ASSERT_EQUAL_HEX8(VEC_FS_APP_ENTRY, FSCMD_APP_TYPE_ENTRY);
   TEST_ASSERT_EQUAL_HEX8(VEC_FS_APP_LAST, FSCMD_APP_TYPE_LAST);
   TEST_ASSERT_EQUAL_UINT32(VEC_FS_ARG_MAX, FSCMD_ARG_MAX);
   TEST_ASSERT_EQUAL_UINT32(VEC_FS_READ_MAX, FSCMD_READ_MAX);
   TEST_ASSERT_EQUAL_UINT32(VEC_FS_ENTRY_PATH_MAX, FSCMD_ENTRY_PATH_MAX);
   TEST_ASSERT_EQUAL_UINT32(SETU_MAX_SHORT_PAYLOAD, FSCMD_ARG_MAX + FSCMD_CMD_HDR_LEN);
   TEST_ASSERT_EQUAL_UINT32(SETU_MAX_SHORT_PAYLOAD, FSCMD_READ_MAX + FSCMD_REPLY_HDR_LEN);
   TEST_ASSERT_EQUAL_UINT32(SETU_MAX_SHORT_PAYLOAD, FSCMD_ENTRY_PATH_MAX + FSCMD_ENTRY_HDR_LEN);
   TEST_ASSERT_EQUAL_UINT8(VEC_FS_OP_MKDIR, eFSOP_MKDIR);
   TEST_ASSERT_EQUAL_UINT8(VEC_FS_OP_CD, eFSOP_CD);
   TEST_ASSERT_EQUAL_UINT8(VEC_FS_OP_OPENR, eFSOP_OPENR);
   TEST_ASSERT_EQUAL_UINT8(VEC_FS_OP_OPENW, eFSOP_OPENW);
   TEST_ASSERT_EQUAL_UINT8(VEC_FS_OP_WRITE, eFSOP_WRITE);
   TEST_ASSERT_EQUAL_UINT8(VEC_FS_OP_READ, eFSOP_READ);
   TEST_ASSERT_EQUAL_UINT8(VEC_FS_OP_LS, eFSOP_LS);
   TEST_ASSERT_EQUAL_UINT8(VEC_FS_OP_DELFILE, eFSOP_DELFILE);
   TEST_ASSERT_EQUAL_UINT8(VEC_FS_OP_DELDIR, eFSOP_DELDIR);
   TEST_ASSERT_EQUAL_UINT8(VEC_FS_OP_CLOSE, eFSOP_CLOSE);
   TEST_ASSERT_EQUAL_UINT8(VEC_FS_OP_ABORT, eFSOP_ABORT);
   TEST_ASSERT_EQUAL_UINT8(VEC_FS_ST_OK, eFSS_OK);
   TEST_ASSERT_EQUAL_UINT8(VEC_FS_ST_NOT_FOUND, eFSS_NOT_FOUND);
   TEST_ASSERT_EQUAL_UINT8(VEC_FS_ST_EXISTS, eFSS_EXISTS);
   TEST_ASSERT_EQUAL_UINT8(VEC_FS_ST_NOT_EMPTY, eFSS_NOT_EMPTY);
   TEST_ASSERT_EQUAL_UINT8(VEC_FS_ST_NO_SPACE, eFSS_NO_SPACE);
   TEST_ASSERT_EQUAL_UINT8(VEC_FS_ST_BAD_ARG, eFSS_BAD_ARG);
   TEST_ASSERT_EQUAL_UINT8(VEC_FS_ST_BAD_STATE, eFSS_BAD_STATE);
   TEST_ASSERT_EQUAL_UINT8(VEC_FS_ST_BUSY, eFSS_BUSY);
   TEST_ASSERT_EQUAL_UINT8(VEC_FS_ST_NOT_MOUNTED, eFSS_NOT_MOUNTED);
   TEST_ASSERT_EQUAL_UINT8(VEC_FS_ST_IO, eFSS_IO);
   TEST_ASSERT_EQUAL_UINT8(VEC_FS_ST_NOT_SUPPORTED, eFSS_NOT_SUPPORTED);
   TEST_ASSERT_EQUAL_UINT8(VEC_FS_ST_WRONG_TYPE, eFSS_WRONG_TYPE);
   TEST_ASSERT_EQUAL_UINT8(VEC_FS_ST_DENIED, eFSS_DENIED);
   TEST_ASSERT_EQUAL_UINT8(VEC_FS_ENTRY_FILE, FSMGR_ENTRY_FILE);
   TEST_ASSERT_EQUAL_UINT8(VEC_FS_ENTRY_DIR, FSMGR_ENTRY_DIR);
}

static void test_RangeRefusesTransfers(void)
{
   // Only short messages: a transfer of the range is refused
   TEST_ASSERT_NOT_EQUAL_INT(0, sst_cfg.fpt_onRxStart(FSCMD_APP_TYPE_CMD, 10U));
   TEST_ASSERT_NOT_EQUAL_INT(0, sst_cfg.fpt_onRxStart(FSCMD_APP_TYPE_LAST, 10U));
}

/******************************************************************************/
/*  The golden session                                                        */
/******************************************************************************/
static void test_WriteReadSession(void)
{
   sv_CmdVec("cmd_mkdir");
   sv_AssertLast("reply_mkdir_ok");
   sv_CmdVec("cmd_cd_abs");
   TEST_ASSERT_EQUAL_UINT32(2U, su32_sentCount);
   sv_AssertReply(2U, eFSOP_CD, eFSS_OK);
   sv_CmdVec("cmd_openw");
   sv_AssertLast("reply_openw_ok");
   sv_CmdVec("cmd_write");
   sv_AssertLast("reply_write_ok");
   sv_CmdVec("cmd_close");
   sv_AssertLast("reply_close_ok");

   sv_CmdVec("cmd_openr");
   sv_AssertReply(6U, eFSOP_OPENR, eFSS_OK);
   sv_CmdVec("cmd_read_16");
   sv_AssertLast("reply_read_data");
   sv_CmdRaw(9U, eFSOP_READ, NULL, 0U);
   sv_AssertLast("reply_read_eof");
   sv_CmdRaw(20U, eFSOP_CLOSE, NULL, 0U);
   sv_AssertReply(20U, eFSOP_CLOSE, eFSS_OK);
   TEST_ASSERT_EQUAL_HEX32(0U, sys_get_le32(&sstpt_Last()->u8ar_payload[3]));

   sv_CmdVec("cmd_delfile");
   sv_AssertReply(11U, eFSOP_DELFILE, eFSS_OK);
   TEST_ASSERT_FALSE(gb_SimFsExists("/FLASH_DISK:/FW/a.txt"));
   TEST_ASSERT_EQUAL_INT(0, atomic_get(&st_busy));
}

static void test_CdNotFound(void)
{
   sv_CmdVec("cmd_cd_abs");
   sv_AssertLast("reply_cd_not_found");
}

static void test_ListGivesEntriesThenReply(void)
{
   static uint8_t su8ar_fw[6568];

   TEST_ASSERT_EQUAL_INT(0, gi_SimFsPutDir("/FLASH_DISK:/FW"));
   TEST_ASSERT_EQUAL_INT(0, gi_SimFsPut("/FLASH_DISK:/FW/FW1", su8ar_fw, sizeof(su8ar_fw)));
   sv_CmdVec("cmd_ls");
   TEST_ASSERT_EQUAL_UINT32(3U, su32_sentCount);
   sv_AssertSent(0U, "entry_dir_fw");
   sv_AssertSent(1U, "entry_file_fw1");
   sv_AssertSent(2U, "reply_ls_ok");
}

static void test_DeleteDirWithSubdirNotSupported(void)
{
   TEST_ASSERT_EQUAL_INT(0, gi_SimFsPutDir("/FLASH_DISK:/FW"));
   TEST_ASSERT_EQUAL_INT(0, gi_SimFsPutDir("/FLASH_DISK:/FW/OLD"));
   sv_CmdVec("cmd_deldir");
   sv_AssertLast("reply_deldir_not_supported");
   TEST_ASSERT_TRUE(gb_SimFsExists("/FLASH_DISK:/FW/OLD"));
}

static void test_WriteWithoutOpenIsBadState(void)
{
   sv_CmdRaw(14U, eFSOP_WRITE, "x", 1U);
   sv_AssertLast("reply_write_bad_state");
}

static void test_AbortClosesAndResets(void)
{
   sv_CmdVec("cmd_mkdir");
   sv_CmdRaw(3U, eFSOP_OPENW, "b.txt", 5U);
   // With a file open, ABORT closes it (buffered data dropped) and keeps the directory
   sv_CmdVec("cmd_abort");
   sv_AssertReply(13U, eFSOP_ABORT, eFSS_OK);
   TEST_ASSERT_FALSE(gb_FSMGR_IsFileOpen());
   TEST_ASSERT_EQUAL_STRING("/FLASH_DISK:/FW", sst_FSMGRContext.as8_currentDir);
   // Without one, it resets the context: the root is current again
   sv_CmdRaw(14U, eFSOP_ABORT, NULL, 0U);
   sv_AssertReply(14U, eFSOP_ABORT, eFSS_OK);
   TEST_ASSERT_EQUAL_STRING("/FLASH_DISK:", sst_FSMGRContext.as8_currentDir);
}

static void test_NotMounted(void)
{
   sv_Mount(false);
   sv_CmdRaw(16U, eFSOP_LS, NULL, 0U);
   sv_AssertLast("reply_not_mounted");
}

/******************************************************************************/
/*  Immediate refusals                                                        */
/******************************************************************************/
static void test_EmptyArgumentFromLibrary(void)
{
   sv_CmdRaw(17U, eFSOP_MKDIR, NULL, 0U);
   sv_AssertLast("reply_bad_op");
}

static void test_UnknownOps(void)
{
   static const uint8_t scu8ar_bad[] = { 0U, 12U, 0x40U, 0xFFU };
   uint32_t i;

   for (i = 0U; i < sizeof(scu8ar_bad); i++)
   {
      sv_CmdRaw((uint8_t)i, scu8ar_bad[i], "x", 1U);
      sv_AssertReply((uint8_t)i, scu8ar_bad[i], eFSS_BAD_ARG);
   }
   TEST_ASSERT_EQUAL_UINT32(0U, gu32_SimFsCalls(eSFS_MKDIR));
}

static void test_EmptyWriteRefusedAndFileStaysOpen(void)
{
   sv_CmdRaw(1U, eFSOP_OPENW, "w.txt", 5U);
   sv_CmdRaw(2U, eFSOP_WRITE, NULL, 0U);
   sv_AssertReply(2U, eFSOP_WRITE, eFSS_BAD_ARG);
   TEST_ASSERT_TRUE(gb_FSMGR_IsFileOpen());
   sv_CmdRaw(3U, eFSOP_WRITE, "ok", 2U);
   sv_AssertReply(3U, eFSOP_WRITE, eFSS_OK);
   TEST_ASSERT_EQUAL_HEX32(2U, sys_get_le32(&sstpt_Last()->u8ar_payload[3]));
}

static void test_ReadCounts(void)
{
   uint8_t u8ar_data[600];
   uint8_t u8ar_n[2];
   uint32_t i;

   for (i = 0U; i < sizeof(u8ar_data); i++) { u8ar_data[i] = (uint8_t)i; }
   TEST_ASSERT_EQUAL_INT(0, gi_SimFsPut("/FLASH_DISK:/r.bin", u8ar_data, sizeof(u8ar_data)));
   sv_CmdRaw(1U, eFSOP_OPENR, "r.bin", 5U);

   // No argument and a count of 0 read as much as fits a REPLY
   sv_CmdRaw(2U, eFSOP_READ, NULL, 0U);
   TEST_ASSERT_EQUAL_UINT8(3U + FSCMD_READ_MAX, sstpt_Last()->u8_len);
   sys_put_le16(0U, u8ar_n);
   sv_CmdRaw(3U, eFSOP_READ, u8ar_n, 2U);
   TEST_ASSERT_EQUAL_UINT8(3U + FSCMD_READ_MAX, sstpt_Last()->u8_len);
   TEST_ASSERT_EQUAL_HEX8_ARRAY(&u8ar_data[FSCMD_READ_MAX], &sstpt_Last()->u8ar_payload[3], FSCMD_READ_MAX);

   // A larger count is cut; a smaller one is kept
   sys_put_le16(1000U, u8ar_n);
   sv_CmdRaw(4U, eFSOP_READ, u8ar_n, 2U);
   TEST_ASSERT_EQUAL_UINT8(3U + (600U - (2U * FSCMD_READ_MAX)), sstpt_Last()->u8_len);
   sys_put_le16(1U, u8ar_n);
   sv_CmdRaw(5U, eFSOP_READ, u8ar_n, 2U);
   TEST_ASSERT_EQUAL_UINT8(3U, sstpt_Last()->u8_len);

   // A one-byte or three-byte argument is malformed
   sv_CmdRaw(6U, eFSOP_READ, u8ar_n, 1U);
   sv_AssertReply(6U, eFSOP_READ, eFSS_BAD_ARG);
   sv_CmdRaw(7U, eFSOP_READ, "abc", 3U);
   sv_AssertReply(7U, eFSOP_READ, eFSS_BAD_ARG);
}

static void test_LongestArguments(void)
{
   uint8_t u8ar_arg[FSCMD_ARG_MAX];

   (void)memset(u8ar_arg, 'w', sizeof(u8ar_arg));
   sv_CmdRaw(1U, eFSOP_OPENW, "big.bin", 7U);
   sv_CmdRaw(2U, eFSOP_WRITE, u8ar_arg, FSCMD_ARG_MAX);
   sv_AssertReply(2U, eFSOP_WRITE, eFSS_OK);
   TEST_ASSERT_EQUAL_HEX32(FSCMD_ARG_MAX, sys_get_le32(&sstpt_Last()->u8ar_payload[3]));
}

static void test_MalformedOrForeignShortsIgnored(void)
{
   uint8_t u8ar_p[2] = { 1U, eFSOP_LS };

   sst_cfg.fpt_onRxShort(FSCMD_APP_TYPE_CMD, u8ar_p, 1U);
   sst_cfg.fpt_onRxShort(FSCMD_APP_TYPE_CMD, u8ar_p, 0U);
   sst_cfg.fpt_onRxShort(FSCMD_APP_TYPE_REPLY, u8ar_p, 2U);
   sst_cfg.fpt_onRxShort(0x4EU, u8ar_p, 2U);
   while (sb_ProcessNext(K_NO_WAIT)) {}
   TEST_ASSERT_EQUAL_UINT32(0U, su32_sentCount);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("ignored"));
}

static void test_BusyWhileACommandRuns(void)
{
   const ShortVector_T *v = sstpt_Vec("cmd_ls");

   // The first command waits in the manager's queue
   sst_cfg.fpt_onRxShort(FSCMD_APP_TYPE_CMD, &v->u8ar_wire[2], v->u8ar_wire[0]);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_sentCount);
   sst_cfg.fpt_onRxShort(FSCMD_APP_TYPE_CMD, (const uint8_t *)"\x0f\x04" "a", 3U);
   sv_AssertLast("reply_busy");

   // Once it is answered, the next one runs
   while (sb_ProcessNext(K_NO_WAIT)) {}
   sv_AssertReply(10U, eFSOP_LS, eFSS_OK);
   sv_CmdRaw(16U, eFSOP_LS, NULL, 0U);
   sv_AssertReply(16U, eFSOP_LS, eFSS_OK);
}

static void test_BusyWhileUploadIsStored(void)
{
   sb_uploadOpen = true;
   sv_CmdRaw(15U, eFSOP_OPENW, "a", 1U);
   sv_AssertLast("reply_busy");
   TEST_ASSERT_EQUAL_UINT32(0U, gu32_SimFsCalls(eSFS_OPEN));
}

#if defined(CONFIG_UDS)
static void test_BusyWhileFlashing(void)
{
   sb_flashRunning = true;
   sv_CmdRaw(15U, eFSOP_OPENW, "a", 1U);
   sv_AssertLast("reply_busy");
   TEST_ASSERT_EQUAL_UINT32(0U, gu32_SimFsCalls(eSFS_OPEN));
}
#endif // CONFIG_UDS

static void test_BusyWhenManagerQueueFull(void)
{
   FileSysMessage_T st_msg;
   uint32_t i;

   (void)memset(&st_msg, 0, sizeof(st_msg));
   st_msg.e_command = eFSC_CLOSE_FILE;
   for (i = 0U; i < FSMGR_QUEUE_DEPTH; i++)
   {
      TEST_ASSERT_EQUAL_INT(0, gi_FSMGR_Submit(&st_msg, NULL, NULL, K_NO_WAIT));
   }
   sst_cfg.fpt_onRxShort(FSCMD_APP_TYPE_CMD, (const uint8_t *)"\x0f\x04" "a", 3U);
   sv_AssertLast("reply_busy");
   TEST_ASSERT_EQUAL_INT(0, atomic_get(&st_busy));
   while (sb_ProcessNext(K_NO_WAIT)) {}
}

/******************************************************************************/
/*  Limits and send failures                                                  */
/******************************************************************************/
static void test_LongEntryPathIsCut(void)
{
   char car_path[FSMGR_MAX_PATH_LEN];
   size_t s_root = strlen("/FLASH_DISK:/");

   (void)memcpy(car_path, "/FLASH_DISK:/", s_root);
   (void)memset(&car_path[s_root], 'L', 230U);
   car_path[s_root + 230U] = '\0';
   TEST_ASSERT_EQUAL_INT(0, gi_SimFsPut(car_path, "x", 1U));

   sv_CmdRaw(1U, eFSOP_LS, NULL, 0U);
   TEST_ASSERT_EQUAL_UINT32(2U, su32_sentCount);
   TEST_ASSERT_EQUAL_HEX8(FSCMD_APP_TYPE_ENTRY, sstpt_Sent(0U)->u8_type);
   TEST_ASSERT_EQUAL_UINT8(SETU_MAX_SHORT_PAYLOAD, sstpt_Sent(0U)->u8_len);
   TEST_ASSERT_EQUAL_MEMORY(car_path, &sstpt_Sent(0U)->u8ar_payload[6], FSCMD_ENTRY_PATH_MAX);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("cut to 236"));
   sv_AssertReply(1U, eFSOP_LS, eFSS_OK);
}

static void test_SendFailureStillFreesTheSlot(void)
{
   si_sendRet = -ENOTCONN;
   sv_CmdRaw(1U, eFSOP_LS, NULL, 0U);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("REPLY seq 1 not sent"));
   TEST_ASSERT_EQUAL_INT(0, atomic_get(&st_busy));
}

int main(void)
{
   (void)setvbuf(stdout, NULL, _IONBF, 0);
   UNITY_BEGIN();
   RUN_TEST(test_DefinesMatchVectors);
   RUN_TEST(test_RangeRefusesTransfers);
   RUN_TEST(test_WriteReadSession);
   RUN_TEST(test_CdNotFound);
   RUN_TEST(test_ListGivesEntriesThenReply);
   RUN_TEST(test_DeleteDirWithSubdirNotSupported);
   RUN_TEST(test_WriteWithoutOpenIsBadState);
   RUN_TEST(test_AbortClosesAndResets);
   RUN_TEST(test_NotMounted);
   RUN_TEST(test_EmptyArgumentFromLibrary);
   RUN_TEST(test_UnknownOps);
   RUN_TEST(test_EmptyWriteRefusedAndFileStaysOpen);
   RUN_TEST(test_ReadCounts);
   RUN_TEST(test_LongestArguments);
   RUN_TEST(test_MalformedOrForeignShortsIgnored);
   RUN_TEST(test_BusyWhileACommandRuns);
   RUN_TEST(test_BusyWhileUploadIsStored);
#if defined(CONFIG_UDS)
   RUN_TEST(test_BusyWhileFlashing);
#endif // CONFIG_UDS
   RUN_TEST(test_BusyWhenManagerQueueFull);
   RUN_TEST(test_LongEntryPathIsCut);
   RUN_TEST(test_SendFailureStillFreesTheSlot);
   return UNITY_END();
}
#else
/** Without CONFIG_FS_CMD nothing is registered: the range stays free. */
static void test_DisabledRegistersNothing(void)
{
   TEST_ASSERT_EQUAL_UINT8(0U, su8_routeCnt);
   TEST_ASSERT_NULL(gcpt_SimLogFind("file commands ready"));
}

int main(void)
{
   (void)setvbuf(stdout, NULL, _IONBF, 0);
   UNITY_BEGIN();
   RUN_TEST(test_DisabledRegistersNothing);
   return UNITY_END();
}
#endif // CONFIG_FS_CMD
