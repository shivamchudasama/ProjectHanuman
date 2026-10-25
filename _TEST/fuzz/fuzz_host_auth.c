/**
 * @file          fuzz_host_auth.c
 * @brief         libFuzzer target: host authentication (_ASW/_HOST_AUTH/HostAuth.c),
 *                what an untrusted host sends and the link events around it.
 *                Reuses the stubs of unit/HostAuth/test_host_auth.c (BT stack,
 *                router, SETU, certificate verification and crypto recorded),
 *                whose main() is renamed.
 *
 *                Input: a script of operations, one opcode byte each:
 *                  op % 8 == 0   the host link connects
 *                  op % 8 == 1   the host link drops
 *                  op % 8 == 2   a HELLO transfer: length (next 2 bytes, LE, up
 *                                to 64 past the maximum), the certificate check's
 *                                and the FINISH check's results (next byte), then
 *                                the bytes; START may refuse it
 *                  op % 8 == 3   a short message: appType 0x60 + (next % 16),
 *                                length (next byte, at most
 *                                SETU_MAX_SHORT_PAYLOAD), then the payload
 *                  op % 8 == 4   the host link's security changes: level (next %
 *                                5), error (next byte)
 *                  op % 8 == 5   SMP on the host link: accept + passkey, then
 *                                complete (bonded or not) or failed (next byte)
 *                  op % 8 == 6   the button: press (next & 1: held) or the wipe
 *                  op % 8 == 7   time passes: (next byte) x 500 ms
 *
 *                Oracles: ASan/UBSan, __ASSERT, the stubs' checks, and after
 *                each step: the gate opens fully only for the trusted host,
 *                trust needs the bonded host at level 4, every reply fits.
 *
 * @date          25/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#define main host_auth_unit_main
#include "../unit/HostAuth/test_host_auth.c"
#undef main

static uint8_t su8ar_fuzzHello[HOST_AUTH_HELLO_MAX_LEN + 64U];

static void sv_CheckInvariants(void)
{
   bool b_trusted = (atomic_get(&st_phase) == eHAP_TRUSTED);

   // The functions behind the gate are reached by the trusted host only
   TEST_ASSERT_EQUAL(b_trusted && sb_IsProvisioned(), gb_HostAuth_Admits(0x40U));
   if (b_trusted)
   {
      TEST_ASSERT_TRUE(sb_LinkIsBondedHost((struct bt_conn *)atomic_ptr_get(&st_hostConn)));
      TEST_ASSERT_TRUE(se_security >= BT_SECURITY_L4);
   }
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

         switch (u8_op % 8U)
         {
            case 0:
               sv_Connect(&sst_host);
               break;

            case 1:
               gv_HostAuth_OnHostDisconnected(&sst_host);
               se_security = BT_SECURITY_L1;
               sv_Run();
               break;

            case 2:
            {
               size_t t_len, t_off;
               uint8_t u8_res;

               if ((t_size - t_pos) < 3U) { t_pos = t_size; break; }
               t_len = (size_t)u8pt_data[t_pos] | ((size_t)u8pt_data[t_pos + 1U] << 8);
               u8_res = u8pt_data[t_pos + 2U];
               t_pos += 3U;
               t_len %= sizeof(su8ar_fuzzHello) + 1U;
               se_hostCertRet = ((u8_res & 0x0FU) == 0U) ? eDCS_BAD_SIG : eDCS_OK;
               st_verifyRet = ((u8_res & 0xF0U) == 0U) ? PSA_ERROR_INVALID_SIGNATURE : PSA_SUCCESS;
               (void)memset(su8ar_fuzzHello, 0, sizeof(su8ar_fuzzHello));
               (void)memcpy(su8ar_fuzzHello, &u8pt_data[t_pos], MIN(t_len, t_size - t_pos));
               t_pos += MIN(t_len, t_size - t_pos);
               // The stub's checks expect Qh and Nh where the test puts them
               if (t_len > HOST_AUTH_HELLO_HDR_LEN)
               {
                  (void)memset(&su8ar_fuzzHello[1], 0x61, HOST_AUTH_NONCE_LEN);
                  (void)memset(&su8ar_fuzzHello[1U + HOST_AUTH_NONCE_LEN], 0x51, HOST_AUTH_POINT_LEN);
               }
               if (sst_route.fpt_onRxStart(HOST_AUTH_APP_TYPE_HELLO, (uint32_t)t_len) == 0)
               {
                  for (t_off = 0U; t_off < t_len; t_off += 200U)
                  {
                     TEST_ASSERT_EQUAL_INT(0, sst_route.fpt_onRxData(HOST_AUTH_APP_TYPE_HELLO,
                        (uint32_t)t_off, &su8ar_fuzzHello[t_off], (uint16_t)MIN(200U, t_len - t_off)));
                  }
                  sst_route.fpt_onRxDone(HOST_AUTH_APP_TYPE_HELLO, ((u8_res & 0x0CU) == 0x0CU) ?
                     eBS_CRC_ERROR : eBS_OK, (uint32_t)t_len);
               }
               sv_Run();
            }
            break;

            case 3:
            {
               uint8_t u8_type, u8_len;
               uint8_t u8ar_p[SETU_MAX_SHORT_PAYLOAD];

               if ((t_size - t_pos) < 2U) { t_pos = t_size; break; }
               u8_type = (uint8_t)(0x60U + (u8pt_data[t_pos++] % 16U));
               u8_len = u8pt_data[t_pos++];
               if (u8_len > SETU_MAX_SHORT_PAYLOAD) { u8_len = SETU_MAX_SHORT_PAYLOAD; }
               if (u8_len > (t_size - t_pos)) { u8_len = (uint8_t)(t_size - t_pos); }
               (void)memcpy(u8ar_p, &u8pt_data[t_pos], u8_len);
               t_pos += u8_len;
               // The verify stub's check expects SigH's first byte
               if (u8_len > 0U) { u8ar_p[0] = 0xE7U; }
               sst_route.fpt_onRxShort(u8_type, u8ar_p, u8_len);
               sv_Run();
            }
            break;

            case 4:
               if ((t_size - t_pos) < 2U) { t_pos = t_size; break; }
               se_security = (bt_security_t)(u8pt_data[t_pos] % 5U);
               gv_HostAuth_OnSecurityChanged(&sst_host, (uint8_t)se_security, u8pt_data[t_pos + 1U]);
               t_pos += 2U;
               sv_Run();
               break;

            case 5:
               if (t_pos >= t_size) { break; }
               if ((sstpt_overlay != NULL) && (atomic_ptr_get(&st_hostConn) != NULL))
               {
                  uint8_t u8_b = u8pt_data[t_pos];

                  if (sstpt_overlay->pairing_accept(&sst_host, NULL) == BT_SECURITY_ERR_SUCCESS)
                  {
                     TEST_ASSERT_TRUE(sstpt_overlay->app_passkey(&sst_host) <= HOST_AUTH_PASSKEY_MAX);
                     if ((u8_b & 1U) != 0U) { se_security = BT_SECURITY_L4; }
                  }
                  if ((u8_b & 2U) != 0U)
                  {
                     sstpt_authInfo->pairing_complete(&sst_host, (u8_b & 4U) != 0U);
                  }
                  else
                  {
                     sstpt_authInfo->pairing_failed(&sst_host, (enum bt_security_err)(u8_b >> 4));
                  }
               }
               t_pos++;
               sv_Run();
               break;

            case 6:
               if (t_pos >= t_size) { break; }
               if ((u8pt_data[t_pos] % 3U) == 0U) { gv_HostAuth_OpenWindow(); }
               else if ((u8pt_data[t_pos] % 3U) == 1U) { gv_HostAuth_ForgetHostAndOpen(); }
               else { gv_HostAuth_Forget(); }
               t_pos++;
               sv_Run();
               break;

            default:
               if (t_pos >= t_size) { break; }
               sv_AdvanceMs((int64_t)u8pt_data[t_pos++] * 500);
               break;
         }
         sv_CheckInvariants();
      }
      // Leave nothing queued for the next input
      gv_HostAuth_OnHostDisconnected(&sst_host);
      sv_Run();
   }
   else
   {
      printf("\ncheck failed: %s\n", Unity.CurrentDetail1 ? Unity.CurrentDetail1 : "");
      abort();
   }
   return 0;
}
