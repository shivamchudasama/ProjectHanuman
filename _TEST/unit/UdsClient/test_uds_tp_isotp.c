/**
 * @file          test_uds_tp_isotp.c
 * @brief         Host unit tests for the UDS client's ISO-TP transport
 *                (_LIB/UdsClient/UdsTp_Isotp.c) against recording fakes of
 *                Zephyr's ISO-TP API (shim/zephyr/canbus/isotp.h): the addresses
 *                and flow control it binds with, physical and functional sends,
 *                whole-message receives (an oversized one is drained and refused),
 *                and the error mapping. Contract: _DOC/UdsClient/API_REFERENCE.md.
 *
 * @date          12/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#include "UdsTp_Isotp.c"
#include "unity.h"

/******************************************************************************/
/*  Fake ISO-TP                                                               */
/******************************************************************************/
static const struct device sst_can = { "can@0" };
static struct
{
   uint32_t u32_binds;
   uint32_t u32_unbinds;
   int i_bindRet;
   struct isotp_msg_id st_bindRx;
   struct isotp_msg_id st_bindTx;
   struct isotp_fc_opts st_bindFc;
   int64_t i64_bindTimeout;
   uint32_t u32_sends;
   int i_sendRet;
   struct isotp_msg_id st_sendTx;
   struct isotp_msg_id st_sendRx;
   bool b_sendCb;
   uint8_t u8ar_sent[64];
   size_t t_sentLen;
   /* receive: one queued message, read in pieces like Zephyr's */
   uint8_t u8ar_msg[2][64];
   size_t tar_msgLen[2];
   uint32_t u32_msgs;
   size_t t_msgOff;
   int i_recvErr;
} sst_iso;

int isotp_bind(struct isotp_recv_ctx *rctx, const struct device *can_dev, const struct isotp_msg_id *rx_addr,
   const struct isotp_msg_id *tx_addr, const struct isotp_fc_opts *opts, k_timeout_t timeout)
{
   (void)rctx;
   TEST_ASSERT_EQUAL_PTR(&sst_can, can_dev);
   sst_iso.u32_binds++;
   sst_iso.st_bindRx = *rx_addr;
   sst_iso.st_bindTx = *tx_addr;
   sst_iso.st_bindFc = *opts;
   sst_iso.i64_bindTimeout = timeout.ms;
   return sst_iso.i_bindRet;
}

void isotp_unbind(struct isotp_recv_ctx *rctx)
{
   (void)rctx;
   sst_iso.u32_unbinds++;
}

int isotp_send(struct isotp_send_ctx *sctx, const struct device *can_dev, const uint8_t *data, size_t len,
   const struct isotp_msg_id *tx_addr, const struct isotp_msg_id *rx_addr, isotp_tx_callback_t complete_cb,
   void *cb_arg)
{
   (void)sctx;
   (void)cb_arg;
   TEST_ASSERT_EQUAL_PTR(&sst_can, can_dev);
   sst_iso.u32_sends++;
   sst_iso.st_sendTx = *tx_addr;
   sst_iso.st_sendRx = *rx_addr;
   sst_iso.b_sendCb = (complete_cb != NULL);
   sst_iso.t_sentLen = len;
   memcpy(sst_iso.u8ar_sent, data, MIN(len, sizeof(sst_iso.u8ar_sent)));
   return sst_iso.i_sendRet;
}

int isotp_recv(struct isotp_recv_ctx *rctx, uint8_t *data, size_t len, k_timeout_t timeout)
{
   size_t t_left;
   size_t t_copy;

   (void)timeout;
   if (sst_iso.u32_msgs == 0U)
   {
      return (sst_iso.i_recvErr != 0) ? sst_iso.i_recvErr : ISOTP_RECV_TIMEOUT;
   }
   t_left = sst_iso.tar_msgLen[0] - sst_iso.t_msgOff;
   t_copy = MIN(len, t_left);
   memcpy(data, &sst_iso.u8ar_msg[0][sst_iso.t_msgOff], t_copy);
   sst_iso.t_msgOff += t_copy;
   if (sst_iso.t_msgOff == sst_iso.tar_msgLen[0])
   {
      // Message done: the next one moves up
      memcpy(sst_iso.u8ar_msg[0], sst_iso.u8ar_msg[1], sizeof(sst_iso.u8ar_msg[0]));
      sst_iso.tar_msgLen[0] = sst_iso.tar_msgLen[1];
      sst_iso.u32_msgs--;
      sst_iso.t_msgOff = 0U;
      rctx->recv_buf = NULL;
   }
   else
   {
      rctx->recv_buf = (struct net_buf *)&sst_iso;
   }
   return (int)t_copy;
}

static void sv_Msg(const uint8_t *u8pt_data, size_t t_len)
{
   memcpy(sst_iso.u8ar_msg[sst_iso.u32_msgs], u8pt_data, t_len);
   sst_iso.tar_msgLen[sst_iso.u32_msgs] = t_len;
   sst_iso.u32_msgs++;
}

/******************************************************************************/
/*  Helpers                                                                   */
/******************************************************************************/
static UdsTp_T sst_tpIf;
static UdsTpIsotp_T sst_ctx;

static const UdsTarget_T scst_classic = { 0x7E0U, 0x7E8U, 0x7DFU, UDS_TGT_PAD | UDS_TGT_FUNC, 8U, 0U, 0U };

static int si_TestBind(const UdsTarget_T *stpt_target)
{
   return sst_tpIf.fpt_bind(sst_tpIf.vpt_ctx, stpt_target);
}

void setUp(void)
{
   memset(&sst_iso, 0, sizeof(sst_iso));
   gv_SimLogClear();
   gv_UdsTpIsotp_Init(&sst_tpIf, &sst_ctx, &sst_can);
}

void tearDown(void) {}

/******************************************************************************/
/*  Bind                                                                      */
/******************************************************************************/
static void test_BindClassic11Bit(void)
{
   TEST_ASSERT_EQUAL_PTR(&sst_ctx, sst_tpIf.vpt_ctx);
   TEST_ASSERT_EQUAL_INT(0, si_TestBind(&scst_classic));
   TEST_ASSERT_EQUAL_UINT32(1U, sst_iso.u32_binds);
   TEST_ASSERT_EQUAL_HEX32(0x7E8U, sst_iso.st_bindRx.std_id);
   TEST_ASSERT_EQUAL_HEX8(0U, sst_iso.st_bindRx.flags);
   TEST_ASSERT_EQUAL_UINT8(0U, sst_iso.st_bindRx.dl);
   TEST_ASSERT_EQUAL_HEX32_MESSAGE(0x7E0U, sst_iso.st_bindTx.std_id, "flow control goes out on the request ID");
   TEST_ASSERT_EQUAL_UINT8(8U, sst_iso.st_bindTx.dl);
   TEST_ASSERT_EQUAL_UINT8(0U, sst_iso.st_bindFc.bs);
   TEST_ASSERT_EQUAL_UINT8(0U, sst_iso.st_bindFc.stmin);
   TEST_ASSERT_EQUAL_INT64(0, sst_iso.i64_bindTimeout);
}

static void test_BindFd29BitAndRebind(void)
{
   UdsTarget_T st_fd = { 0x18DA10F1U, 0x18DAF110U, 0U, UDS_TGT_EXT_ID | UDS_TGT_FD | UDS_TGT_BRS, 64U, 0U, 0U };

   TEST_ASSERT_EQUAL_INT(0, si_TestBind(&scst_classic));
   TEST_ASSERT_EQUAL_INT(0, si_TestBind(&st_fd));
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(1U, sst_iso.u32_unbinds, "the old binding goes first");
   TEST_ASSERT_EQUAL_HEX32(0x18DAF110U, sst_iso.st_bindRx.ext_id);
   TEST_ASSERT_EQUAL_HEX8(ISOTP_MSG_IDE | ISOTP_MSG_FDF | ISOTP_MSG_BRS, sst_iso.st_bindRx.flags);
   TEST_ASSERT_EQUAL_HEX32(0x18DA10F1U, sst_iso.st_bindTx.ext_id);
   TEST_ASSERT_EQUAL_UINT8(64U, sst_iso.st_bindTx.dl);
}

static void test_BindErrors(void)
{
   uint8_t u8ar_buf[8];
   UdsTp_T st_tp;
   UdsTpIsotp_T st_ctx;

   sst_iso.i_bindRet = ISOTP_NO_FREE_FILTER;
   TEST_ASSERT_EQUAL_INT(-ENOSPC, si_TestBind(&scst_classic));
   TEST_ASSERT_EQUAL_INT(ISOTP_NO_FREE_FILTER, sst_ctx.i_lastIsotpErr);
   TEST_ASSERT_EQUAL_INT(-ENOTCONN, sst_tpIf.fpt_send(sst_tpIf.vpt_ctx, u8ar_buf, 2U, false));
   TEST_ASSERT_EQUAL_INT(-ENOTCONN, sst_tpIf.fpt_recv(sst_tpIf.vpt_ctx, u8ar_buf, 8U, K_NO_WAIT));
   sst_tpIf.fpt_unbind(sst_tpIf.vpt_ctx);
   TEST_ASSERT_EQUAL_UINT32_MESSAGE(0U, sst_iso.u32_unbinds, "nothing bound");

   gv_UdsTpIsotp_Init(&st_tp, &st_ctx, NULL);
   TEST_ASSERT_EQUAL_INT(-ENODEV, st_tp.fpt_bind(st_tp.vpt_ctx, &scst_classic));
}

/******************************************************************************/
/*  Send                                                                      */
/******************************************************************************/
static void test_SendPhysicalAndFunctional(void)
{
   static const uint8_t scu8ar_req[] = { 0x22U, 0xF1U, 0x90U };
   UdsTarget_T st_noFunc = scst_classic;

   TEST_ASSERT_EQUAL_INT(0, si_TestBind(&scst_classic));
   TEST_ASSERT_EQUAL_INT(0, sst_tpIf.fpt_send(sst_tpIf.vpt_ctx, scu8ar_req, 3U, false));
   TEST_ASSERT_EQUAL_HEX32(0x7E0U, sst_iso.st_sendTx.std_id);
   TEST_ASSERT_EQUAL_HEX32(0x7E8U, sst_iso.st_sendRx.std_id);
   TEST_ASSERT_FALSE_MESSAGE(sst_iso.b_sendCb, "blocking send");
   TEST_ASSERT_EQUAL_MEMORY(scu8ar_req, sst_iso.u8ar_sent, 3U);

   TEST_ASSERT_EQUAL_INT(0, sst_tpIf.fpt_send(sst_tpIf.vpt_ctx, scu8ar_req, 3U, true));
   TEST_ASSERT_EQUAL_HEX32(0x7DFU, sst_iso.st_sendTx.std_id);
   TEST_ASSERT_EQUAL_INT(-EMSGSIZE, sst_tpIf.fpt_send(sst_tpIf.vpt_ctx, sst_iso.u8ar_sent, 8U, true));

   st_noFunc.u8_flags = UDS_TGT_PAD;
   TEST_ASSERT_EQUAL_INT(0, si_TestBind(&st_noFunc));
   TEST_ASSERT_EQUAL_INT(-EINVAL, sst_tpIf.fpt_send(sst_tpIf.vpt_ctx, scu8ar_req, 3U, true));

   sst_iso.i_sendRet = ISOTP_N_TIMEOUT_BS;
   TEST_ASSERT_EQUAL_INT(-ETIMEDOUT, sst_tpIf.fpt_send(sst_tpIf.vpt_ctx, scu8ar_req, 3U, false));
   TEST_ASSERT_EQUAL_INT(ISOTP_N_TIMEOUT_BS, sst_ctx.i_lastIsotpErr);
}

/******************************************************************************/
/*  Receive                                                                   */
/******************************************************************************/
static void test_ReceiveWholeMessages(void)
{
   static const uint8_t scu8ar_long[20] = { 0x62U, 0xF1U, 0x90U, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 };
   static const uint8_t scu8ar_short[3] = { 0x6EU, 0xF1U, 0x5AU };
   uint8_t u8ar_buf[8];

   TEST_ASSERT_EQUAL_INT(0, si_TestBind(&scst_classic));
   TEST_ASSERT_EQUAL_INT(-EAGAIN, sst_tpIf.fpt_recv(sst_tpIf.vpt_ctx, u8ar_buf, sizeof(u8ar_buf), K_MSEC(50)));

   sv_Msg(scu8ar_short, sizeof(scu8ar_short));
   TEST_ASSERT_EQUAL_INT(3, sst_tpIf.fpt_recv(sst_tpIf.vpt_ctx, u8ar_buf, sizeof(u8ar_buf), K_MSEC(50)));
   TEST_ASSERT_EQUAL_MEMORY(scu8ar_short, u8ar_buf, 3U);

   // Too long for the buffer: refused, and its rest does not pass for the next message
   sv_Msg(scu8ar_long, sizeof(scu8ar_long));
   sv_Msg(scu8ar_short, sizeof(scu8ar_short));
   TEST_ASSERT_EQUAL_INT(-EMSGSIZE, sst_tpIf.fpt_recv(sst_tpIf.vpt_ctx, u8ar_buf, sizeof(u8ar_buf), K_MSEC(50)));
   TEST_ASSERT_NULL(sst_ctx.st_recv.recv_buf);
   TEST_ASSERT_EQUAL_INT(3, sst_tpIf.fpt_recv(sst_tpIf.vpt_ctx, u8ar_buf, sizeof(u8ar_buf), K_MSEC(50)));
   TEST_ASSERT_EQUAL_HEX8(0x6EU, u8ar_buf[0]);

   sst_iso.i_recvErr = ISOTP_N_WRONG_SN;
   TEST_ASSERT_EQUAL_INT(-EIO, sst_tpIf.fpt_recv(sst_tpIf.vpt_ctx, u8ar_buf, sizeof(u8ar_buf), K_MSEC(50)));
}

static void test_ErrnoMapping(void)
{
   TEST_ASSERT_EQUAL_INT(0, gi_UdsTpIsotp_Errno(ISOTP_N_OK));
   TEST_ASSERT_EQUAL_INT(-ETIMEDOUT, gi_UdsTpIsotp_Errno(ISOTP_N_TIMEOUT_A));
   TEST_ASSERT_EQUAL_INT(-ETIMEDOUT, gi_UdsTpIsotp_Errno(ISOTP_N_TIMEOUT_CR));
   TEST_ASSERT_EQUAL_INT(-ENOSPC, gi_UdsTpIsotp_Errno(ISOTP_NO_FREE_FILTER));
   TEST_ASSERT_EQUAL_INT(-ENOMEM, gi_UdsTpIsotp_Errno(ISOTP_NO_NET_BUF_LEFT));
   TEST_ASSERT_EQUAL_INT(-ENOMEM, gi_UdsTpIsotp_Errno(ISOTP_NO_CTX_LEFT));
   TEST_ASSERT_EQUAL_INT(-EMSGSIZE, gi_UdsTpIsotp_Errno(ISOTP_N_BUFFER_OVERFLW));
   TEST_ASSERT_EQUAL_INT(-EIO, gi_UdsTpIsotp_Errno(ISOTP_N_UNEXP_PDU));
   TEST_ASSERT_EQUAL_INT(-EIO, gi_UdsTpIsotp_Errno(ISOTP_N_ERROR));
}

int main(void)
{
   (void)setvbuf(stdout, NULL, _IONBF, 0);
   UNITY_BEGIN();
   RUN_TEST(test_BindClassic11Bit);
   RUN_TEST(test_BindFd29BitAndRebind);
   RUN_TEST(test_BindErrors);
   RUN_TEST(test_SendPhysicalAndFunctional);
   RUN_TEST(test_ReceiveWholeMessages);
   RUN_TEST(test_ErrnoMapping);
   return UNITY_END();
}
