/**
 * @file          fuzz_uds_cmd.c
 * @brief         libFuzzer target: UDS over BLE (_ASW/_UDS/UdsCmd.c) on the
 *                real SETU router. Reuses the stubs of unit/Uds/test_uds_cmd.c
 *                (SETU Server and UdsJob recorded), whose main() is renamed.
 *
 *                Input: a script of operations, one opcode byte each:
 *                  op % 4 == 0..1   short message from the host: appType
 *                                   0x50 + (next byte % 16), length (next
 *                                   byte, at most SETU_MAX_SHORT_PAYLOAD),
 *                                   then the payload
 *                  op % 4 == 2      the pending job ends: result (next byte),
 *                                   response length (next 2 bytes, LE, at most
 *                                   the job's response maximum), then the
 *                                   response bytes (an ECU's answer off CAN)
 *                  op % 4 == 3      a flash job STATUS with fuzzed fields
 *
 *                Oracles: ASan/UBSan, __ASSERT, and the stub's checks that
 *                every reply fits a short message and never waits for ever.
 *
 * @date          18/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#define main uds_cmd_unit_main
#include "../unit/Uds/test_uds_cmd.c"
#undef main

/* CONFIG_UDS_RESPONSE_MAX of the firmware: the longest answer UdsJob hands over */
#define FUZZ_RSP_MAX (1024U)
static uint8_t su8ar_rsp[FUZZ_RSP_MAX];

int LLVMFuzzerTestOneInput(const uint8_t *u8pt_data, size_t t_size)
{
   size_t t_pos = 0U;

   if (TEST_PROTECT())
   {
      setUp();
      while (t_pos < t_size)
      {
         uint8_t u8_op = u8pt_data[t_pos++];

         if ((u8_op % 4U) <= 1U)
         {
            uint8_t u8_type, u8_len;
            if ((t_size - t_pos) < 2U) { break; }
            u8_type = (uint8_t)(0x50U + (u8pt_data[t_pos++] % 16U));
            u8_len = u8pt_data[t_pos++];
            if (u8_len > SETU_MAX_SHORT_PAYLOAD) { u8_len = SETU_MAX_SHORT_PAYLOAD; }
            if (u8_len > (t_size - t_pos)) { u8_len = (uint8_t)(t_size - t_pos); }
            // The job stub answers with what the first payload byte says
            sst_job.u8_ret = (u8_len > 0U) ? (uint8_t)(u8pt_data[t_pos] % 4U) : 0U;
            sst_cfg.fpt_onRxShort(u8_type, &u8pt_data[t_pos], u8_len);
            t_pos += u8_len;
         }
         else if ((u8_op % 4U) == 2U)
         {
            uint8_t u8_res;
            size_t t_len;
            if ((t_size - t_pos) < 3U) { break; }
            u8_res = u8pt_data[t_pos++];
            t_len = (size_t)u8pt_data[t_pos] | ((size_t)u8pt_data[t_pos + 1U] << 8);
            t_pos += 2U;
            if (t_len > FUZZ_RSP_MAX) { t_len = FUZZ_RSP_MAX; }
            if (t_len > (t_size - t_pos)) { t_len = t_size - t_pos; }
            memcpy(su8ar_rsp, &u8pt_data[t_pos], t_len);
            t_pos += t_len;
            if (sst_job.fpt_done != NULL)
            {
               UdsJobResult_F fpt_done = sst_job.fpt_done;
               sst_job.fpt_done = NULL;
               fpt_done(u8_res, (t_len > 0U) ? su8ar_rsp : NULL, t_len, sst_job.vpt_user);
            }
         }
         else
         {
            UdsJobStatus_T st;
            if ((t_size - t_pos) < sizeof(st)) { break; }
            memcpy(&st, &u8pt_data[t_pos], sizeof(st));
            t_pos += sizeof(st);
            if (sst_job.fpt_status != NULL)
            {
               sst_job.fpt_status(&st, sst_job.vpt_user);
            }
         }
      }
   }
   else
   {
      printf("\ncheck failed: %s\n", Unity.CurrentDetail1 ? Unity.CurrentDetail1 : "");
      abort();
   }
   return 0;
}
