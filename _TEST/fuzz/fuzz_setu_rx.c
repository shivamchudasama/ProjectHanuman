/**
 * @file          fuzz_setu_rx.c
 * @brief         libFuzzer target: the device's whole receive path for frames
 *                a BLE peer writes to the SETU DATA characteristic. The real
 *                SETU Server engine, the appType router, the DataStore (hex
 *                upload, BEGIN/COMMIT) and the File System Manager on the
 *                in-memory volume of shim/fs_sim.c, over the simulated link
 *                of unit/SETU/sim_link.h, built like test_upload_e2e.c.
 *
 *                Input: a script of operations, one opcode byte each:
 *                  op % 8 in 0..3   write a frame: next byte = length (1..244,
 *                                   0 means 244), then that many bytes
 *                  op % 8 == 4      settle (next byte) ms of simulated time
 *                  op % 8 == 5      run the dump thread once
 *                  op % 8 == 6      disconnect and reconnect
 *                  op % 8 == 7      one scheduler step
 *
 *                Oracles: ASan/UBSan, the shim's __ASSERT (aborts), and the
 *                scripted peer's checks on every frame the device sends back
 *                (well-formed, within ATT_MTU - 3, receiver frames only as
 *                notifications). A failed peer check aborts.
 *
 * @date          18/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

/* Server role only, as in the firmware build of test_upload_e2e.c */
#include "SETU_Core.c"
#include "SETU_Server.c"
#include "SETU_Client.c"
#include "sim_link.h"
#include "DataStore.c"
#include "SETURouter.c"
#include "FileSysManager.c"
#include "FileSysManagerFSM.c"

/* _SETU_SVC stand-in: the CTRL attribute is the one the simulated link knows */
const struct bt_gatt_attr *gstpt_SETUSvc_Init(void)
{
   return &sst_ctrlAttr;
}

/* Unity needs these; the fuzzer runs no Unity tests */
void setUp(void) {}
void tearDown(void) {}

static void sv_RunFsmgr(void)
{
   while (sb_ProcessNext(K_NO_WAIT)) {}
}

static void sv_Reset(void)
{
   atomic_set(&st_dumpBusy, 0);
   k_msgq_purge(&sst_dsEventQ);
   atomic_set(&st_uploadOpen, 0);
   gv_SimLogClear();

   gv_SimFsReset();
   gv_SimFsFormat(false);
   k_msgq_purge(&sst_fsmgrMsgQ);
   sb_mounted = false;
   (void)memset(&sst_FSMGRContext, 0, sizeof(sst_FSMGRContext));
   gv_SimRunThread(sv_FSMGR_Thread);
   sfpt_simBlockHook = sv_RunFsmgr;

   sv_SimConnect(247U);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
   (void)argc; (void)argv;
   if ((gi_DataStore_Init() != 0) || (gi_SETURouter_Start() != 0))
   {
      printf("init failed\n");
      abort();
   }
   return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *u8pt_data, size_t t_size)
{
   size_t t_pos = 0U;

   sv_Reset();

   if (TEST_PROTECT())
   {
      while (t_pos < t_size)
      {
         uint8_t u8_op = u8pt_data[t_pos++];

         switch (u8_op % 8U)
         {
            case 0: case 1: case 2: case 3:
            {
               uint16_t u16_len;
               if (t_pos >= t_size) { break; }
               u16_len = u8pt_data[t_pos++];
               if ((u16_len == 0U) || (u16_len > SETU_MAX_FRAME_LEN)) { u16_len = SETU_MAX_FRAME_LEN; }
               if (u16_len > (t_size - t_pos)) { u16_len = (uint16_t)(t_size - t_pos); }
               if (u16_len == 0U) { break; }
               sv_PeerWrite(&u8pt_data[t_pos], u16_len);
               t_pos += u16_len;
               (void)sb_Step();
               break;
            }
            case 4:
               sv_Settle((t_pos < t_size) ? u8pt_data[t_pos++] : 1);
               break;
            case 5:
               gv_SimRunThread(sv_DumpThread);
               break;
            case 6:
               sv_Disconnect();
               sv_SimConnect(247U);
               break;
            default:
               (void)sb_Step();
               break;
         }
      }
      sv_Settle(50);
      gv_SimRunThread(sv_DumpThread);
      sv_Settle(50);
   }
   else
   {
      // A peer check failed: the device sent something it must not
      printf("\npeer check failed: %s\n", Unity.CurrentDetail1 ? Unity.CurrentDetail1 : "");
      abort();
   }

   sv_Disconnect();
   return 0;
}
