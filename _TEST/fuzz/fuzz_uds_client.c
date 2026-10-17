/**
 * @file          fuzz_uds_client.c
 * @brief         libFuzzer target: the UDS client (_LIB/UdsClient) parsing
 *                what an ECU answers on the CAN bus. The transport is the
 *                scripted one of unit/UdsClient/sim_uds_tp.h; a responder takes
 *                the ECU's answers to each request from the fuzz input.
 *
 *                Input: a header byte picking the target timing (P2 fixed or
 *                learned), then a script: one byte picks the next client call
 *                (session, reset, comm control, DTC setting, security access,
 *                read/write DID, routine, request download, transfer data,
 *                transfer exit, tester present, keep-alive, raw request); every
 *                request it sends is answered with 0..3 responses taken from
 *                the input: [delay in 10 ms][length][bytes], or a transport
 *                error when the length byte is 0xFF.
 *
 *                Oracles: ASan/UBSan, __ASSERT, and the contract checks below:
 *                lengths the client reports never exceed the buffers it was
 *                given, a positive return is an NRC (1..255).
 *
 * @date          18/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#include "UdsClient.c"
#include "sim_uds_tp.h"
#include "unity.h"

void setUp(void) {}
void tearDown(void) {}

static const uint8_t *su8pt_in;
static size_t st_inLen;
static size_t st_inPos;
static UdsClient_T sst_client;

static uint8_t su8_Next(void)
{
   return (st_inPos < st_inLen) ? su8pt_in[st_inPos++] : 0U;
}

/** The ECU: answers each request with responses from the input. */
static void sv_Ecu(const uint8_t *u8pt_req, size_t t_len, bool b_functional)
{
   uint8_t u8_n;
   uint8_t i;

   (void)u8pt_req; (void)t_len; (void)b_functional;
   if (st_inPos >= st_inLen) { return; }
   u8_n = su8_Next() % 4U;
   for (i = 0U; (i < u8_n) && (st_inPos < st_inLen); i++)
   {
      int64_t i64_delay = (int64_t)su8_Next() * 10;
      uint8_t u8_len = su8_Next();
      if (sst_tp.u32_count >= SIM_TP_QUEUE) { break; }
      if (u8_len == 0xFFU)
      {
         sv_SimTpQueueBytes(sst_tp.u32_sends, i64_delay, NULL, 0U, -EIO);
         continue;
      }
      if (u8_len > (st_inLen - st_inPos)) { u8_len = (uint8_t)(st_inLen - st_inPos); }
      if (sst_tp.u32_count >= SIM_TP_QUEUE) { break; }
      sv_SimTpQueueBytes(sst_tp.u32_sends, i64_delay, &su8pt_in[st_inPos], u8_len, 0);
      st_inPos += u8_len;
   }
}

static int si_Key(uint8_t u8_level, const uint8_t *u8pt_seed, size_t t_seedLen, uint8_t *u8pt_key,
   size_t t_keyMax, size_t *tpt_keyLen, void *vpt_user)
{
   size_t t_n = su8_Next() % 8U;
   volatile uint8_t u8_sum = 0U;
   size_t i;

   (void)u8_level; (void)vpt_user;
   for (i = 0U; i < t_seedLen; i++) { u8_sum ^= u8pt_seed[i]; }   /* ASan checks the seed */
   if (t_n > t_keyMax) { t_n = t_keyMax; }
   for (i = 0U; i < t_n; i++) { u8pt_key[i] = (uint8_t)(u8_sum + i); }
   *tpt_keyLen = t_n;
   return (su8_Next() == 0xEEU) ? -EINVAL : 0;
}

static void sv_CheckRet(int i_ret)
{
   if (i_ret > 255)
   {
      printf("return %d is neither 0, an NRC nor an errno\n", i_ret);
      abort();
   }
}

static void sv_CheckLen(size_t t_len, size_t t_max, const char *cpt_what)
{
   if (t_len > t_max)
   {
      printf("%s: length %u beyond the buffer of %u\n", cpt_what, (unsigned)t_len, (unsigned)t_max);
      abort();
   }
}

int LLVMFuzzerTestOneInput(const uint8_t *u8pt_data, size_t t_size)
{
   UdsTarget_T st_target = { 0x7E0U, 0x7E8U, 0x7DFU, UDS_TGT_PAD | UDS_TGT_FUNC, 8U, 0U, 0U };
   uint8_t u8ar_buf[300];
   uint8_t u8ar_xfer[2U + 64U];
   size_t t_len;
   uint32_t u32_block;
   uint32_t u32_ops = 0U;

   if (t_size < 1U) { return 0; }
   su8pt_in = u8pt_data;
   st_inLen = t_size;
   st_inPos = 0U;
   sv_SimTpReset();
   sst_tp.fpt_responder = sv_Ecu;
   gi64_simNowMs = 1000;

   if ((su8_Next() & 1U) != 0U)
   {
      st_target.u16_p2Ms = 50U;           /* fixed by the target, not learned */
      st_target.u16_p2StarMs = 500U;
   }
   if ((gi_UdsClient_Init(&sst_client, &sst_simTp) != 0) || (gi_UdsClient_SetTarget(&sst_client, &st_target) != 0))
   {
      abort();
   }

   while ((st_inPos < st_inLen) && (u32_ops++ < 64U))
   {
      uint8_t u8_op = su8_Next();
      int i_ret = 0;

      t_len = 0U;
      switch (u8_op % 13U)
      {
         case 0: i_ret = gi_UdsClient_Session(&sst_client, su8_Next()); break;
         case 1: i_ret = gi_UdsClient_EcuReset(&sst_client, su8_Next()); break;
         case 2: i_ret = gi_UdsClient_CommControl(&sst_client, su8_Next(), su8_Next()); break;
         case 3: i_ret = gi_UdsClient_DtcSetting(&sst_client, su8_Next()); break;
         case 4: i_ret = gi_UdsClient_SecurityAccess(&sst_client, su8_Next(), si_Key, NULL); break;
         case 5:
         {
            size_t t_max = su8_Next() % sizeof(u8ar_buf);
            i_ret = gi_UdsClient_ReadDid(&sst_client, 0xF190U, u8ar_buf, t_max, &t_len);
            if (i_ret == 0) { sv_CheckLen(t_len, t_max, "ReadDid"); }
            break;
         }
         case 6:
            i_ret = gi_UdsClient_WriteDid(&sst_client, 0xF15AU, u8ar_buf, su8_Next() % 32U);
            break;
         case 7:
         {
            size_t t_max = su8_Next() % 16U;
            i_ret = gi_UdsClient_Routine(&sst_client, 1U, 0xFF00U, u8ar_buf, su8_Next() % 16U,
               u8ar_buf + 100, t_max, &t_len);
            if (i_ret == 0) { sv_CheckLen(t_len, t_max, "Routine"); }
            break;
         }
         case 8:
            u32_block = 0U;
            i_ret = gi_UdsClient_RequestDownload(&sst_client, 0U, su8_Next(), 0x00010000UL, 0x1000UL, &u32_block);
            break;
         case 9:
            i_ret = gi_UdsClient_TransferData(&sst_client, su8_Next(), u8ar_xfer, su8_Next() % 64U);
            break;
         case 10: i_ret = gi_UdsClient_TransferExit(&sst_client); break;
         case 11: i_ret = gi_UdsClient_TesterPresent(&sst_client); break;
         default:
         {
            uint8_t u8ar_req[8];
            size_t t_reqLen = 1U + (su8_Next() % 7U);
            size_t t_max = su8_Next() % sizeof(u8ar_buf);
            size_t i;
            for (i = 0U; i < t_reqLen; i++) { u8ar_req[i] = su8_Next(); }
            if ((su8_Next() & 3U) == 0U)
            {
               (void)gi32_UdsClient_KeepAlive(&sst_client);
               break;
            }
            i_ret = gi_UdsClient_Request(&sst_client, u8ar_req, t_reqLen, false, u8ar_buf, t_max, &t_len);
            if (i_ret >= 0) { sv_CheckLen(t_len, t_max, "Request"); }
            break;
         }
      }
      sv_CheckRet(i_ret);
   }

   gv_UdsClient_EndSession(&sst_client);
   gv_UdsClient_Close(&sst_client);
   return 0;
}
