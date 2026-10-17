/**
 * @file          fuzz_uds_job.c
 * @brief         libFuzzer target: a UDS flash job (_ASW/_UDS/UdsJob.c) on a
 *                stored file whose bytes come from the fuzz input (a cut or
 *                corrupted upload), with fuzzed sequence parameters and an ECU
 *                block size. The real UDS client, seed -> key and File System
 *                Manager on shim/fs_sim.c; the generic C ECU, CanIf stub and
 *                helpers of unit/Uds/test_uds_job.c (main renamed).
 *
 *                Input: [flags LE16][security level][key algo][alfid][dfi]
 *                [ECU maxNumberOfBlockLength LE16][fingerprint length], then
 *                the file's bytes ([addr LE32][len LE32][data] records).
 *
 *                Oracles: ASan/UBSan, __ASSERT, the test's ECU checks, and
 *                after the job: exactly one final STATUS, the bus unlocked, the
 *                traffic log back on, the file closed, the engine free; and
 *                for a job that reports DONE, the image the ECU received is the
 *                records' data in file order.
 *
 * @date          18/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#define main uds_job_unit_main
#include "../unit/Uds/test_uds_job.c"
#undef main

#define FUZZ_HDR_LEN                         (9U)
#define FUZZ_FILE                            "/FLASH_DISK:/FW/FUZZ.BIN"

static uint8_t su8ar_expect[ECU_IMG_MAX];

/** The records' data in file order, as a DONE job must have sent it. */
static bool sb_ExpectedImage(const uint8_t *u8pt_file, size_t t_len, uint32_t *u32pt_imgLen)
{
   size_t t_pos = 0U;
   uint32_t u32_img = 0U;

   while ((t_len - t_pos) >= 8U)
   {
      uint32_t u32_recLen = sys_get_le32(&u8pt_file[t_pos + 4U]);
      t_pos += 8U;
      if ((u32_recLen > (t_len - t_pos)) || ((u32_img + u32_recLen) > ECU_IMG_MAX)) { return false; }
      memcpy(&su8ar_expect[u32_img], &u8pt_file[t_pos], u32_recLen);
      u32_img += u32_recLen;
      t_pos += u32_recLen;
   }
   *u32pt_imgLen = u32_img;
   return t_pos == t_len;
}

int LLVMFuzzerTestOneInput(const uint8_t *u8pt_data, size_t t_size)
{
   UdsFlashParams_T st_params;
   const uint8_t *u8pt_file;
   size_t t_fileLen;
   uint32_t u32_imgLen = 0U;

   if ((t_size < FUZZ_HDR_LEN) || ((t_size - FUZZ_HDR_LEN) > ECU_IMG_MAX)) { return 0; }

   if (TEST_PROTECT())
   {
      sv_ResetAll();
      u8pt_file = &u8pt_data[FUZZ_HDR_LEN];
      t_fileLen = t_size - FUZZ_HDR_LEN;
      if (gi_SimFsPut(FUZZ_FILE, u8pt_file, (uint32_t)t_fileLen) != 0) { return 0; }

      sv_SetTargetOk();
      sst_tp.fpt_responder = sv_EcuGeneric;
      sst_ecu.u16_max = sys_get_le16(&u8pt_data[6]);

      st_params = sst_SimParams();
      st_params.u16_flags = sys_get_le16(&u8pt_data[0]);
      st_params.u8_securityLevel = u8pt_data[2];
      st_params.u8_keyAlgo = u8pt_data[3];
      st_params.u8_alfid = u8pt_data[4];
      st_params.u8_dfi = u8pt_data[5];
      // UdsCmd caps the fingerprint length before a job sees it
      st_params.u8_fingerprintLen = (uint8_t)(u8pt_data[8] % (UDS_FP_MAX + 1U));

      if (gu8_UdsJob_Flash("FUZZ.BIN", 8U, &st_params, sv_OnStatus, USER) == eUDS_OK)
      {
         const UdsJobStatus_T *stpt_last;

         sv_JobStep();
         sv_AssertCleanedUp();
         stpt_last = sstpt_LastStatus();
         TEST_ASSERT_TRUE_MESSAGE(stpt_last->u8_state >= eUDS_STATE_DONE, "the job ended with a final STATUS");
         if (stpt_last->u8_state == eUDS_STATE_DONE)
         {
            TEST_ASSERT_TRUE_MESSAGE(sb_ExpectedImage(u8pt_file, t_fileLen, &u32_imgLen),
               "DONE on a file that is not a whole set of records");
            TEST_ASSERT_EQUAL_UINT32_MESSAGE(u32_imgLen, sst_ecu.u32_imgLen, "image length the ECU received");
            TEST_ASSERT_EQUAL_MEMORY_MESSAGE(su8ar_expect, sst_ecu.u8ar_img, u32_imgLen, "image the ECU received");
         }
      }
      tearDown();
   }
   else
   {
      printf("\ncheck failed (line %u): %s %s\n", (unsigned)Unity.CurrentTestLineNumber,
         Unity.CurrentDetail1 ? Unity.CurrentDetail1 : "", Unity.CurrentDetail2 ? Unity.CurrentDetail2 : "");
      abort();
   }
   return 0;
}
