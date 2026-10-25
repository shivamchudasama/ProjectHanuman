/**
 * @file          test_router.c
 * @brief         Host unit tests for the SETU appType router
 *                (_ASW/_SETU_SVC/SETURouter.c): registration rules, dispatch of
 *                the Server callbacks by appType range, the appType filter, the
 *                gate (and the filter overriding it), and
 *                the shared Client (attach on behalf of a module, results back
 *                to it). SETURouter.c is included; the GATT service and both
 *                SETU roles are stubbed.
 *
 * @date          01/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#include "SETURouter.c"
#include "unity.h"

/******************************************************************************/
/*  Stubs of the GATT service and the SETU Server                         */
/******************************************************************************/
static struct bt_gatt_attr sst_ctrlAttr;
static SETUSrvCfg_T sst_cfg;
static int si_initRet;
static uint32_t su32_initCalls;

const struct bt_gatt_attr *gstpt_SETUSvc_Init(void)
{
   return &sst_ctrlAttr;
}

int gi_SETUS_Init(const SETUSrvCfg_T *stpt_cfg)
{
   su32_initCalls++;
   sst_cfg = *stpt_cfg;
   return si_initRet;
}

/* SETU Client: records the calls; results are scripted per call */
static SETUCliCfg_T sst_cliCfg;
static int si_cliInitRet;
static bool sb_cliReady;
static int sir_attachRet[2];
static uint32_t su32_attachCalls;
static struct bt_conn *sstpt_attachConn;
static int si_detachRet;
static uint32_t su32_detachCalls;
static struct bt_conn sst_connA = { 1 };
static struct bt_conn sst_connB = { 2 };

int gi_SETUC_Init(const SETUCliCfg_T *stpt_cfg)
{
   sst_cliCfg = *stpt_cfg;
   return si_cliInitRet;
}

bool gb_SETUC_IsReady(void) { return sb_cliReady; }

int gi_SETUC_Attach(struct bt_conn *stpt_conn)
{
   int i_ret = sir_attachRet[MIN(su32_attachCalls, 1U)];

   su32_attachCalls++;
   sstpt_attachConn = stpt_conn;
   return i_ret;
}

int gi_SETUC_Detach(void)
{
   su32_detachCalls++;
   return si_detachRet;
}

/******************************************************************************/
/*  Recording module callbacks (two modules: A and B)                         */
/******************************************************************************/
typedef struct
{
   uint32_t u32_start, u32_data, u32_done, u32_short, u32_txDone, u32_ready;
   int i_readyStatus;
   struct bt_conn *stpt_readyConn;
   uint8_t u8_lastType;
   uint32_t u32_lastLen;
   uint32_t u32_lastOffset;
   SETUStatus_E e_lastStatus;
   int i_startRet;
   int i_dataRet;
} Rec_T;

static Rec_T sst_a;
static Rec_T sst_b;

#define REC_FUNCS(X, R) \
   static int si_##X##Start(uint8_t t, uint32_t l) \
   { R.u32_start++; R.u8_lastType = t; R.u32_lastLen = l; return R.i_startRet; } \
   static int si_##X##Data(uint8_t t, uint32_t o, const uint8_t *d, uint16_t l) \
   { (void)d; R.u32_data++; R.u8_lastType = t; R.u32_lastOffset = o; R.u32_lastLen = l; return R.i_dataRet; } \
   static void sv_##X##Done(uint8_t t, SETUStatus_E s, uint32_t l) \
   { R.u32_done++; R.u8_lastType = t; R.e_lastStatus = s; R.u32_lastLen = l; } \
   static void sv_##X##Short(uint8_t t, const uint8_t *d, uint8_t l) \
   { (void)d; R.u32_short++; R.u8_lastType = t; R.u32_lastLen = l; } \
   static void sv_##X##TxDone(uint8_t t, SETUStatus_E s) \
   { R.u32_txDone++; R.u8_lastType = t; R.e_lastStatus = s; } \
   static void sv_##X##Ready(struct bt_conn *c, int i) \
   { R.u32_ready++; R.stpt_readyConn = c; R.i_readyStatus = i; }

REC_FUNCS(A, sst_a)
REC_FUNCS(B, sst_b)

static SETURoute_T st_Route(uint8_t u8_first, uint8_t u8_last, bool b_a)
{
   SETURoute_T st_r;

   st_r.u8_firstAppType = u8_first;
   st_r.u8_lastAppType = u8_last;
   st_r.fpt_onRxStart = b_a ? si_AStart : si_BStart;
   st_r.fpt_onRxData = b_a ? si_AData : si_BData;
   st_r.fpt_onRxDone = b_a ? sv_ADone : sv_BDone;
   st_r.fpt_onRxShort = b_a ? sv_AShort : sv_BShort;
   st_r.fpt_onTxDone = b_a ? sv_ATxDone : sv_BTxDone;
   st_r.fpt_onCliReady = b_a ? sv_AReady : sv_BReady;
   return st_r;
}

void setUp(void)
{
   su8_routeCnt = 0U;
   sb_isStarted = false;
   gv_SETURouter_ClearFilter();
   sfpt_admit = NULL;
   sfpt_refused = NULL;
   si_initRet = 0;
   su32_initCalls = 0U;
   (void)memset(&sst_cfg, 0, sizeof(sst_cfg));
   (void)memset(&sst_cliCfg, 0, sizeof(sst_cliCfg));
   si_cliInitRet = 0;
   sb_cliReady = false;
   sir_attachRet[0] = 0;
   sir_attachRet[1] = 0;
   su32_attachCalls = 0U;
   sstpt_attachConn = NULL;
   si_detachRet = 0;
   su32_detachCalls = 0U;
   (void)atomic_ptr_set(&st_cliConn, NULL);
   (void)memset(&sst_a, 0, sizeof(sst_a));
   (void)memset(&sst_b, 0, sizeof(sst_b));
   gv_SimLogClear();
}

void tearDown(void) {}

/** Register A = 0x10, B = 0x20..0x2F and start. */
static void sv_StartTwoModules(void)
{
   SETURoute_T st_a = st_Route(0x10U, 0x10U, true);
   SETURoute_T st_b = st_Route(0x20U, 0x2FU, false);

   TEST_ASSERT_EQUAL_INT(0, gi_SETURouter_Register(&st_a));
   TEST_ASSERT_EQUAL_INT(0, gi_SETURouter_Register(&st_b));
   TEST_ASSERT_EQUAL_INT(0, gi_SETURouter_Start());
}

/******************************************************************************/
/*  Registration                                                              */
/******************************************************************************/
static void test_RegisterRejectsInvalidRanges(void)
{
   SETURoute_T st_r = st_Route(0x20U, 0x10U, true);

   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_SETURouter_Register(NULL));
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_SETURouter_Register(&st_r));
   st_r = st_Route(0xE0U, 0xF0U, true);
   TEST_ASSERT_EQUAL_INT_MESSAGE(-EINVAL, gi_SETURouter_Register(&st_r), "0xF0.. is SETU's");
   st_r = st_Route(0xEFU, 0xEFU, true);
   TEST_ASSERT_EQUAL_INT(0, gi_SETURouter_Register(&st_r));
   st_r = st_Route(0x00U, 0x00U, false);
   TEST_ASSERT_EQUAL_INT(0, gi_SETURouter_Register(&st_r));
}

static void test_RegisterRejectsOverlaps(void)
{
   SETURoute_T st_r = st_Route(0x20U, 0x2FU, true);

   TEST_ASSERT_EQUAL_INT(0, gi_SETURouter_Register(&st_r));
   st_r = st_Route(0x2FU, 0x30U, false);
   TEST_ASSERT_EQUAL_INT(-EEXIST, gi_SETURouter_Register(&st_r));
   st_r = st_Route(0x10U, 0x20U, false);
   TEST_ASSERT_EQUAL_INT(-EEXIST, gi_SETURouter_Register(&st_r));
   st_r = st_Route(0x24U, 0x25U, false);
   TEST_ASSERT_EQUAL_INT(-EEXIST, gi_SETURouter_Register(&st_r));
   st_r = st_Route(0x00U, 0xEFU, false);
   TEST_ASSERT_EQUAL_INT(-EEXIST, gi_SETURouter_Register(&st_r));
   st_r = st_Route(0x30U, 0x30U, false);
   TEST_ASSERT_EQUAL_INT(0, gi_SETURouter_Register(&st_r));
}

static void test_RegisterTableFull(void)
{
   SETURoute_T st_r;
   uint8_t i;

   for (i = 0U; i < SETU_ROUTER_MAX_ROUTES; i++)
   {
      st_r = st_Route((uint8_t)(i * 2U), (uint8_t)(i * 2U), true);
      TEST_ASSERT_EQUAL_INT(0, gi_SETURouter_Register(&st_r));
   }
   st_r = st_Route(0x80U, 0x80U, true);
   TEST_ASSERT_EQUAL_INT(-ENOMEM, gi_SETURouter_Register(&st_r));
}

static void test_RegisterAfterStartIsRefused(void)
{
   SETURoute_T st_r = st_Route(0x40U, 0x40U, true);

   sv_StartTwoModules();
   TEST_ASSERT_EQUAL_INT(-EALREADY, gi_SETURouter_Register(&st_r));
}

static void test_RegisterCopiesTheRoute(void)
{
   SETURoute_T st_r = st_Route(0x10U, 0x10U, true);

   TEST_ASSERT_EQUAL_INT(0, gi_SETURouter_Register(&st_r));
   st_r.u8_firstAppType = 0x00U;
   st_r.fpt_onRxStart = si_BStart;
   TEST_ASSERT_EQUAL_INT(0, gi_SETURouter_Start());
   TEST_ASSERT_EQUAL_INT(0, sst_cfg.fpt_onRxStart(0x10U, 5U));
   TEST_ASSERT_EQUAL_UINT32(1U, sst_a.u32_start);
   TEST_ASSERT_EQUAL_UINT32(0U, sst_b.u32_start);
}

/******************************************************************************/
/*  Start                                                                     */
/******************************************************************************/
static void test_StartConfiguresTheServer(void)
{
   sv_StartTwoModules();
   TEST_ASSERT_EQUAL_UINT32(1U, su32_initCalls);
   TEST_ASSERT_EQUAL_PTR(&sst_ctrlAttr, sst_cfg.stpt_ctrlAttr);
   TEST_ASSERT_NOT_NULL(sst_cfg.fpt_onRxStart);
   TEST_ASSERT_NOT_NULL(sst_cfg.fpt_onRxData);
   TEST_ASSERT_NOT_NULL(sst_cfg.fpt_onRxDone);
   TEST_ASSERT_NOT_NULL(sst_cfg.fpt_onRxShort);
   TEST_ASSERT_FALSE_MESSAGE(sst_cfg.b_autoTuneLink, "_BLE negotiates the link itself");
   TEST_ASSERT_EQUAL_INT(-EALREADY, gi_SETURouter_Start());
   TEST_ASSERT_EQUAL_UINT32(1U, su32_initCalls);
}

static void test_StartFailureCanBeRetried(void)
{
   si_initRet = -EIO;
   TEST_ASSERT_EQUAL_INT(-EIO, gi_SETURouter_Start());
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("gi_SETUS_Init failed"));
   si_initRet = 0;
   TEST_ASSERT_EQUAL_INT(0, gi_SETURouter_Start());
}

/******************************************************************************/
/*  Dispatch                                                                  */
/******************************************************************************/
static void test_TransferGoesToTheOwningRange(void)
{
   uint8_t u8ar_d[3] = { 1, 2, 3 };

   sv_StartTwoModules();
   // Range boundaries of B
   TEST_ASSERT_EQUAL_INT(0, sst_cfg.fpt_onRxStart(0x20U, 100U));
   TEST_ASSERT_EQUAL_INT(0, sst_cfg.fpt_onRxStart(0x2FU, 7U));
   TEST_ASSERT_EQUAL_UINT32(2U, sst_b.u32_start);
   TEST_ASSERT_EQUAL_UINT32(7U, sst_b.u32_lastLen);
   TEST_ASSERT_EQUAL_INT(0, sst_cfg.fpt_onRxData(0x2FU, 4U, u8ar_d, 3U));
   TEST_ASSERT_EQUAL_UINT32(4U, sst_b.u32_lastOffset);
   sst_cfg.fpt_onRxDone(0x2FU, eBS_CRC_ERROR, 7U);
   TEST_ASSERT_EQUAL_UINT32(1U, sst_b.u32_done);
   TEST_ASSERT_EQUAL_INT(eBS_CRC_ERROR, sst_b.e_lastStatus);
   // A saw none of it
   TEST_ASSERT_EQUAL_UINT32(0U, sst_a.u32_start + sst_a.u32_data + sst_a.u32_done);

   TEST_ASSERT_EQUAL_INT(0, sst_cfg.fpt_onRxStart(0x10U, 9U));
   TEST_ASSERT_EQUAL_UINT32(1U, sst_a.u32_start);
}

static void test_OwnerAnswersArePassedBack(void)
{
   uint8_t u8_d = 0U;

   sv_StartTwoModules();
   sst_b.i_startRet = -EBUSY;
   sst_b.i_dataRet = -ENOSPC;
   TEST_ASSERT_EQUAL_INT(-EBUSY, sst_cfg.fpt_onRxStart(0x25U, 1U));
   TEST_ASSERT_EQUAL_INT(-ENOSPC, sst_cfg.fpt_onRxData(0x25U, 0U, &u8_d, 1U));
}

static void test_UnroutedTypesAreRejected(void)
{
   uint8_t u8_d = 0U;

   sv_StartTwoModules();
   TEST_ASSERT_EQUAL_INT(-ENOTSUP, sst_cfg.fpt_onRxStart(0x11U, 10U));
   TEST_ASSERT_EQUAL_INT(-ENOTSUP, sst_cfg.fpt_onRxStart(0x1FU, 10U));
   TEST_ASSERT_EQUAL_INT(-ENOTSUP, sst_cfg.fpt_onRxStart(0x30U, 10U));
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("rejected: unknown type 0x30"));
   // Not reachable through SETU (START was rejected), but harmless
   TEST_ASSERT_EQUAL_INT(-EIO, sst_cfg.fpt_onRxData(0x30U, 0U, &u8_d, 1U));
   sst_cfg.fpt_onRxDone(0x30U, eBS_OK, 1U);
   TEST_ASSERT_EQUAL_UINT32(0U, sst_a.u32_done + sst_b.u32_done);
}

static void test_RangeWithoutReceiverRejectsTransfers(void)
{
   SETURoute_T st_r = st_Route(0x40U, 0x41U, true);
   uint8_t u8_d = 0U;

   st_r.fpt_onRxData = NULL;
   TEST_ASSERT_EQUAL_INT(0, gi_SETURouter_Register(&st_r));
   TEST_ASSERT_EQUAL_INT(0, gi_SETURouter_Start());
   TEST_ASSERT_EQUAL_INT(-ENOTSUP, sst_cfg.fpt_onRxStart(0x40U, 1U));
   TEST_ASSERT_EQUAL_UINT32(0U, sst_a.u32_start);
   TEST_ASSERT_EQUAL_INT(-EIO, sst_cfg.fpt_onRxData(0x40U, 0U, &u8_d, 1U));
}

static void test_RangeWithoutStartAcceptsEverything(void)
{
   SETURoute_T st_r = st_Route(0x40U, 0x41U, true);

   st_r.fpt_onRxStart = NULL;
   st_r.fpt_onRxDone = NULL;
   TEST_ASSERT_EQUAL_INT(0, gi_SETURouter_Register(&st_r));
   TEST_ASSERT_EQUAL_INT(0, gi_SETURouter_Start());
   TEST_ASSERT_EQUAL_INT(0, sst_cfg.fpt_onRxStart(0x41U, 1U));
   sst_cfg.fpt_onRxDone(0x41U, eBS_OK, 1U);
   TEST_ASSERT_EQUAL_UINT32(0U, sst_a.u32_done);
}

static void test_ShortMessagesAreRoutedOrLogged(void)
{
   uint8_t u8ar_p[2] = { 9, 9 };
   SETURoute_T st_c = st_Route(0x40U, 0x40U, true);

   st_c.fpt_onRxShort = NULL;
   TEST_ASSERT_EQUAL_INT(0, gi_SETURouter_Register(&st_c));
   sv_StartTwoModules();

   sst_cfg.fpt_onRxShort(0x22U, u8ar_p, 2U);
   TEST_ASSERT_EQUAL_UINT32(1U, sst_b.u32_short);
   TEST_ASSERT_EQUAL_HEX8(0x22U, sst_b.u8_lastType);

   // No range, and a range without a short handler: logged and dropped
   sst_cfg.fpt_onRxShort(0x05U, u8ar_p, 2U);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("short message type 0x05, 2 bytes ignored"));
   sst_cfg.fpt_onRxShort(0x40U, u8ar_p, 1U);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("short message type 0x40, 1 bytes ignored"));
   TEST_ASSERT_EQUAL_UINT32(0U, sst_a.u32_short);
   TEST_ASSERT_EQUAL_UINT32(1U, sst_b.u32_short);
}

/******************************************************************************/
/*  Filter                                                                    */
/******************************************************************************/
static void test_FilterRejectsOtherTransfersAtStart(void)
{
   sv_StartTwoModules();
   gv_SETURouter_SetFilter(0x20U, 0x2FU);

   // Outside: rejected before the owner is asked
   TEST_ASSERT_EQUAL_INT(-ENOTSUP, sst_cfg.fpt_onRxStart(0x10U, 5U));
   TEST_ASSERT_EQUAL_UINT32(0U, sst_a.u32_start);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("rejected: type 0x10 filtered"));

   // Inside, boundaries included: the owner decides as before
   TEST_ASSERT_EQUAL_INT(0, sst_cfg.fpt_onRxStart(0x20U, 5U));
   TEST_ASSERT_EQUAL_INT(0, sst_cfg.fpt_onRxStart(0x2FU, 5U));
   TEST_ASSERT_EQUAL_UINT32(2U, sst_b.u32_start);

   // Cleared: every range reachable again
   gv_SETURouter_ClearFilter();
   TEST_ASSERT_EQUAL_INT(0, sst_cfg.fpt_onRxStart(0x10U, 5U));
   TEST_ASSERT_EQUAL_UINT32(1U, sst_a.u32_start);
}

static void test_FilterDropsOtherShortMessages(void)
{
   uint8_t u8ar_p[2] = { 9, 9 };

   sv_StartTwoModules();
   gv_SETURouter_SetFilter(0x10U, 0x10U);
   sst_cfg.fpt_onRxShort(0x27U, u8ar_p, 2U);
   TEST_ASSERT_EQUAL_UINT32(0U, sst_b.u32_short);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("short message type 0x27 filtered"));
   sst_cfg.fpt_onRxShort(0x10U, u8ar_p, 2U);
   TEST_ASSERT_EQUAL_UINT32(1U, sst_a.u32_short);

   // A new filter replaces the previous one
   gv_SETURouter_SetFilter(0x20U, 0x2FU);
   sst_cfg.fpt_onRxShort(0x27U, u8ar_p, 2U);
   TEST_ASSERT_EQUAL_UINT32(1U, sst_b.u32_short);
   sst_cfg.fpt_onRxShort(0x10U, u8ar_p, 2U);
   TEST_ASSERT_EQUAL_UINT32(1U, sst_a.u32_short);
}

static void test_FilterLetsAnAcceptedTransferFinish(void)
{
   uint8_t u8_d = 0U;

   sv_StartTwoModules();
   TEST_ASSERT_EQUAL_INT(0, sst_cfg.fpt_onRxStart(0x10U, 1U));
   gv_SETURouter_SetFilter(0x20U, 0x2FU);
   TEST_ASSERT_EQUAL_INT(0, sst_cfg.fpt_onRxData(0x10U, 0U, &u8_d, 1U));
   sst_cfg.fpt_onRxDone(0x10U, eBS_OK, 1U);
   TEST_ASSERT_EQUAL_UINT32(1U, sst_a.u32_data);
   TEST_ASSERT_EQUAL_UINT32(1U, sst_a.u32_done);
}

/******************************************************************************/
/*  Gate                                                                      */
/******************************************************************************/
static uint8_t su8_gateFirst;
static uint8_t su8_gateLast;
static uint32_t su32_gateCalls;
static uint32_t su32_refusedCalls;
static uint8_t su8_lastRefused;

static bool sb_Gate(uint8_t u8_appType)
{
   su32_gateCalls++;
   return (u8_appType >= su8_gateFirst) && (u8_appType <= su8_gateLast);
}

static void sv_Refused(uint8_t u8_appType)
{
   su32_refusedCalls++;
   su8_lastRefused = u8_appType;
}

static void sv_StartGated(SETURouterRefused_F fpt_refused)
{
   su8_gateFirst = 0x20U;
   su8_gateLast = 0x2FU;
   su32_gateCalls = 0U;
   su32_refusedCalls = 0U;
   su8_lastRefused = 0U;
   TEST_ASSERT_EQUAL_INT(0, gi_SETURouter_SetGate(sb_Gate, fpt_refused));
   sv_StartTwoModules();
}

static void test_GateRefusesTransfersAndShortMessages(void)
{
   uint8_t u8ar_p[2] = { 9, 9 };

   sv_StartGated(sv_Refused);

   // Refused: neither owner asked, the refusal reported with its type
   TEST_ASSERT_EQUAL_INT(-ENOTSUP, sst_cfg.fpt_onRxStart(0x10U, 5U));
   TEST_ASSERT_EQUAL_UINT32(0U, sst_a.u32_start);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_refusedCalls);
   TEST_ASSERT_EQUAL_HEX8(0x10U, su8_lastRefused);
   sst_cfg.fpt_onRxShort(0x10U, u8ar_p, 2U);
   TEST_ASSERT_EQUAL_UINT32(0U, sst_a.u32_short);
   TEST_ASSERT_EQUAL_UINT32(2U, su32_refusedCalls);

   // Admitted: routed as before, nothing reported
   TEST_ASSERT_EQUAL_INT(0, sst_cfg.fpt_onRxStart(0x2FU, 5U));
   sst_cfg.fpt_onRxShort(0x20U, u8ar_p, 2U);
   TEST_ASSERT_EQUAL_UINT32(1U, sst_b.u32_start);
   TEST_ASSERT_EQUAL_UINT32(1U, sst_b.u32_short);
   TEST_ASSERT_EQUAL_UINT32(2U, su32_refusedCalls);

   // The gate follows its owner's state at each call
   su8_gateFirst = 0x00U;
   su8_gateLast = 0xEFU;
   TEST_ASSERT_EQUAL_INT(0, sst_cfg.fpt_onRxStart(0x10U, 5U));
   TEST_ASSERT_EQUAL_UINT32(1U, sst_a.u32_start);
}

static void test_GateWithoutRefusedHook(void)
{
   uint8_t u8ar_p[1] = { 0 };

   sv_StartGated(NULL);
   TEST_ASSERT_EQUAL_INT(-ENOTSUP, sst_cfg.fpt_onRxStart(0x10U, 5U));
   sst_cfg.fpt_onRxShort(0x10U, u8ar_p, 1U);
   TEST_ASSERT_EQUAL_UINT32(0U, sst_a.u32_start + sst_a.u32_short);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_refusedCalls);
}

static void test_FilterOverridesTheGate(void)
{
   uint8_t u8ar_p[1] = { 0 };

   sv_StartGated(sv_Refused);
   gv_SETURouter_SetFilter(0x10U, 0x10U);

   // The filter alone decides: the gate is not asked, its refusals not reported
   TEST_ASSERT_EQUAL_INT(0, sst_cfg.fpt_onRxStart(0x10U, 5U));
   TEST_ASSERT_EQUAL_INT(-ENOTSUP, sst_cfg.fpt_onRxStart(0x20U, 5U));
   sst_cfg.fpt_onRxShort(0x20U, u8ar_p, 1U);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_gateCalls);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_refusedCalls);
   TEST_ASSERT_EQUAL_UINT32(0U, sst_b.u32_start + sst_b.u32_short);

   // Cleared: the gate applies again
   gv_SETURouter_ClearFilter();
   TEST_ASSERT_EQUAL_INT(-ENOTSUP, sst_cfg.fpt_onRxStart(0x10U, 5U));
   TEST_ASSERT_EQUAL_UINT32(1U, su32_refusedCalls);
}

static void test_GateLetsAnAcceptedTransferFinish(void)
{
   uint8_t u8_d = 0U;

   sv_StartGated(sv_Refused);
   su8_gateFirst = 0x10U;
   TEST_ASSERT_EQUAL_INT(0, sst_cfg.fpt_onRxStart(0x10U, 1U));
   // The gate closes mid-transfer: data and result still reach the owner
   su8_gateFirst = 0x20U;
   TEST_ASSERT_EQUAL_INT(0, sst_cfg.fpt_onRxData(0x10U, 0U, &u8_d, 1U));
   sst_cfg.fpt_onRxDone(0x10U, eBS_OK, 1U);
   TEST_ASSERT_EQUAL_UINT32(1U, sst_a.u32_data);
   TEST_ASSERT_EQUAL_UINT32(1U, sst_a.u32_done);
}

static void test_SetGateAfterStartIsRefused(void)
{
   sv_StartTwoModules();
   TEST_ASSERT_EQUAL_INT(-EALREADY, gi_SETURouter_SetGate(sb_Gate, sv_Refused));
   // No gate installed: everything routed
   TEST_ASSERT_EQUAL_INT(0, sst_cfg.fpt_onRxStart(0x10U, 1U));
}

/******************************************************************************/
/*  Shared Client                                                             */
/******************************************************************************/
static void test_StartInitialisesTheClient(void)
{
   sv_StartTwoModules();
   TEST_ASSERT_NOT_NULL(sst_cliCfg.fpt_onReady);
   TEST_ASSERT_NOT_NULL(sst_cliCfg.fpt_onTxDone);
   TEST_ASSERT_FALSE_MESSAGE(sst_cliCfg.b_autoTuneLink, "_BLE negotiates the link itself");
}

static void test_StartClientFailureCanBeRetried(void)
{
   SETURoute_T st_a = st_Route(0x10U, 0x10U, true);

   TEST_ASSERT_EQUAL_INT(0, gi_SETURouter_Register(&st_a));
   si_cliInitRet = -EINVAL;
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_SETURouter_Start());
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("gi_SETUC_Init failed"));
   TEST_ASSERT_FALSE(sb_isStarted);
   // The Server is up already: its -EALREADY on the retry is fine
   si_initRet = -EALREADY;
   si_cliInitRet = 0;
   TEST_ASSERT_EQUAL_INT(0, gi_SETURouter_Start());
}

static void test_TxResultGoesToTheOwningRange(void)
{
   sv_StartTwoModules();
   sst_cliCfg.fpt_onTxDone(0x23U, eBS_CRC_ERROR);
   TEST_ASSERT_EQUAL_UINT32(1U, sst_b.u32_txDone);
   TEST_ASSERT_EQUAL_HEX8(0x23U, sst_b.u8_lastType);
   TEST_ASSERT_EQUAL_INT(eBS_CRC_ERROR, sst_b.e_lastStatus);
   TEST_ASSERT_EQUAL_UINT32(0U, sst_a.u32_txDone);

   // No range: logged
   sst_cliCfg.fpt_onTxDone(0x31U, eBS_OK);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("transfer 0x31 ended (0), no owner"));
}

static void test_ClientAttachArguments(void)
{
   SETURoute_T st_c = st_Route(0x40U, 0x40U, true);

   TEST_ASSERT_EQUAL_INT(-EPERM, gi_SETURouter_ClientAttach(&sst_connA, 0x10U));
   st_c.fpt_onCliReady = NULL;
   TEST_ASSERT_EQUAL_INT(0, gi_SETURouter_Register(&st_c));
   sv_StartTwoModules();
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_SETURouter_ClientAttach(NULL, 0x10U));
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_SETURouter_ClientAttach(&sst_connA, 0x05U));
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_SETURouter_ClientAttach(&sst_connA, 0x40U));
   TEST_ASSERT_EQUAL_UINT32(0U, su32_attachCalls);
}

static void test_ClientAttachResultGoesToTheAsker(void)
{
   sv_StartTwoModules();
   TEST_ASSERT_EQUAL_INT(0, gi_SETURouter_ClientAttach(&sst_connA, 0x22U));
   TEST_ASSERT_EQUAL_PTR(&sst_connA, sstpt_attachConn);
   sst_cliCfg.fpt_onReady(&sst_connA, 0);
   TEST_ASSERT_EQUAL_UINT32(1U, sst_b.u32_ready);
   TEST_ASSERT_EQUAL_PTR(&sst_connA, sst_b.stpt_readyConn);
   TEST_ASSERT_EQUAL_UINT32(0U, sst_a.u32_ready);

   // Ready on that link: the asker may send at once, no callback follows
   sb_cliReady = true;
   TEST_ASSERT_EQUAL_INT(-EALREADY, gi_SETURouter_ClientAttach(&sst_connA, 0x10U));
   TEST_ASSERT_EQUAL_UINT32(1U, su32_attachCalls);

   // An attach still running for that link continues (-EALREADY below)
   sb_cliReady = false;
   sir_attachRet[0] = -EALREADY;
   su32_attachCalls = 0U;
   TEST_ASSERT_EQUAL_INT(0, gi_SETURouter_ClientAttach(&sst_connA, 0x10U));
   sst_cliCfg.fpt_onReady(&sst_connA, -ENOENT);
   TEST_ASSERT_EQUAL_UINT32(1U, sst_a.u32_ready);
   TEST_ASSERT_EQUAL_INT(-ENOENT, sst_a.i_readyStatus);
}

static void test_ClientAttachMovesTheClient(void)
{
   sv_StartTwoModules();

   // Bound to another link: detached, then attached here
   sir_attachRet[0] = -EBUSY;
   sir_attachRet[1] = 0;
   TEST_ASSERT_EQUAL_INT(0, gi_SETURouter_ClientAttach(&sst_connB, 0x10U));
   TEST_ASSERT_EQUAL_UINT32(1U, su32_detachCalls);
   TEST_ASSERT_EQUAL_UINT32(2U, su32_attachCalls);
   TEST_ASSERT_EQUAL_PTR(&sst_connB, sstpt_attachConn);

   // Released meanwhile: attached anyway
   su32_attachCalls = 0U;
   si_detachRet = -ENOTCONN;
   TEST_ASSERT_EQUAL_INT(0, gi_SETURouter_ClientAttach(&sst_connA, 0x10U));
   TEST_ASSERT_EQUAL_UINT32(2U, su32_attachCalls);

   // Busy there (attach or transfer): refused, nothing moved
   su32_attachCalls = 0U;
   si_detachRet = -EBUSY;
   TEST_ASSERT_EQUAL_INT(-EBUSY, gi_SETURouter_ClientAttach(&sst_connB, 0x10U));
   TEST_ASSERT_EQUAL_UINT32(1U, su32_attachCalls);

   // Other errors of the attach are passed back
   su32_attachCalls = 0U;
   sir_attachRet[0] = -ENOTCONN;
   TEST_ASSERT_EQUAL_INT(-ENOTCONN, gi_SETURouter_ClientAttach(&sst_connB, 0x10U));
}

int main(void)
{
   (void)setvbuf(stdout, NULL, _IONBF, 0);
   UNITY_BEGIN();
   RUN_TEST(test_RegisterRejectsInvalidRanges);
   RUN_TEST(test_RegisterRejectsOverlaps);
   RUN_TEST(test_RegisterTableFull);
   RUN_TEST(test_RegisterAfterStartIsRefused);
   RUN_TEST(test_RegisterCopiesTheRoute);
   RUN_TEST(test_StartConfiguresTheServer);
   RUN_TEST(test_StartFailureCanBeRetried);
   RUN_TEST(test_TransferGoesToTheOwningRange);
   RUN_TEST(test_OwnerAnswersArePassedBack);
   RUN_TEST(test_UnroutedTypesAreRejected);
   RUN_TEST(test_RangeWithoutReceiverRejectsTransfers);
   RUN_TEST(test_RangeWithoutStartAcceptsEverything);
   RUN_TEST(test_ShortMessagesAreRoutedOrLogged);
   RUN_TEST(test_FilterRejectsOtherTransfersAtStart);
   RUN_TEST(test_FilterDropsOtherShortMessages);
   RUN_TEST(test_FilterLetsAnAcceptedTransferFinish);
   RUN_TEST(test_GateRefusesTransfersAndShortMessages);
   RUN_TEST(test_GateWithoutRefusedHook);
   RUN_TEST(test_FilterOverridesTheGate);
   RUN_TEST(test_GateLetsAnAcceptedTransferFinish);
   RUN_TEST(test_SetGateAfterStartIsRefused);
   RUN_TEST(test_StartInitialisesTheClient);
   RUN_TEST(test_StartClientFailureCanBeRetried);
   RUN_TEST(test_TxResultGoesToTheOwningRange);
   RUN_TEST(test_ClientAttachArguments);
   RUN_TEST(test_ClientAttachResultGoesToTheAsker);
   RUN_TEST(test_ClientAttachMovesTheClient);
   return UNITY_END();
}
