/**
 * @file          fuzz_fscmd.c
 * @brief         libFuzzer target: file commands over BLE (_ASW/_FS_CMD) on the
 *                real router and the real File System Manager over the
 *                in-memory volume of shim/fs_sim.c. Reuses the stubs of
 *                unit/FsCmd/test_fscmd.c, whose main() is renamed.
 *
 *                Input: a script of operations, one opcode byte each:
 *                  op % 4 == 0..1   CMD: length (next byte, at most
 *                                   SETU_MAX_SHORT_PAYLOAD), payload
 *                                   [seq][op][arg]; the manager then runs
 *                                   until its queue is empty
 *                  op % 4 == 2      the same, without running the manager
 *                                   (the next CMD finds it busy)
 *                  op % 4 == 3      run the manager until its queue is empty
 *
 *                Oracles: ASan/UBSan, __ASSERT, and the stub's checks that
 *                every reply fits a short message and never waits for ever.
 *
 * @date          18/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#define main fscmd_unit_main
#include "../unit/FsCmd/test_fscmd.c"
#undef main

static void sv_Drain(void)
{
   while (sb_ProcessNext(K_NO_WAIT)) {}
}

int LLVMFuzzerTestOneInput(const uint8_t *u8pt_data, size_t t_size)
{
   size_t t_pos = 0U;

   if (TEST_PROTECT())
   {
      setUp();
      while (t_pos < t_size)
      {
         uint8_t u8_op = u8pt_data[t_pos++];

         if ((u8_op % 4U) <= 2U)
         {
            uint8_t u8_len;
            if (t_pos >= t_size) { break; }
            u8_len = u8pt_data[t_pos++];
            if (u8_len > SETU_MAX_SHORT_PAYLOAD) { u8_len = SETU_MAX_SHORT_PAYLOAD; }
            if (u8_len > (t_size - t_pos)) { u8_len = (uint8_t)(t_size - t_pos); }
            sst_cfg.fpt_onRxShort(FSCMD_APP_TYPE_CMD, &u8pt_data[t_pos], u8_len);
            t_pos += u8_len;
            if ((u8_op % 4U) <= 1U) { sv_Drain(); }
         }
         else
         {
            sv_Drain();
         }
      }
      sv_Drain();
   }
   else
   {
      printf("\ncheck failed: %s\n", Unity.CurrentDetail1 ? Unity.CurrentDetail1 : "");
      abort();
   }
   return 0;
}
