/**
 * @file          test_uds_key.c
 * @brief         Host unit tests for the seed -> key algorithms
 *                (_ASW/_UDS/UdsKey.c): BENCH_XOR against the uds_key vectors of
 *                wire.json (which the ECU simulator checks too), refusals, the
 *                callback form, names, and the OEM hook: built as uds_key (no
 *                OEM algorithms) and uds_key_oem (UDS_KEY_OEM, a test hook).
 *                Contract: _DOC/UDS/README.md.
 *
 * @date          12/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#include <zephyr/kernel.h>
#include "UdsKey.c"
#include "unity.h"
#include "wire_vectors.h"

#if defined(UDS_KEY_OEM)
static uint32_t su32_oemCalls;

/* The OEM hook a private _ASW/_UDS/oem/ file would provide */
int gi_UdsKey_Oem(uint8_t u8_algo, uint8_t u8_level, const uint8_t *u8pt_seed, size_t t_seedLen,
   uint8_t *u8pt_key, size_t t_keyMax, size_t *tpt_keyLen)
{
   (void)u8_level;
   (void)t_keyMax;
   su32_oemCalls++;
   if (u8_algo != 0x80U)
   {
      return -ENOTSUP;
   }
   u8pt_key[0] = (uint8_t)(u8pt_seed[0] + 1U);
   *tpt_keyLen = (t_seedLen > 0U) ? 1U : 0U;
   return 0;
}
#endif // UDS_KEY_OEM

void setUp(void) {}
void tearDown(void) {}

static void test_BenchXorMatchesTheVectors(void)
{
   uint8_t u8ar_key[8];
   size_t t_len = 0U;
   uint32_t i;

   TEST_ASSERT_EQUAL_UINT8(VEC_UDS_ALGO_BENCH_XOR, UDS_KEY_ALGO_BENCH_XOR);
   for (i = 0U; i < ARRAY_SIZE(gstar_vecUdsKeys); i++)
   {
      const UdsKeyVector_T *v = &gstar_vecUdsKeys[i];

      TEST_ASSERT_EQUAL_INT_MESSAGE(0, gi_UdsKey_Compute(v->u8_algo, v->u8_level, v->u8ar_seed, v->u8_seedLen,
         u8ar_key, sizeof(u8ar_key), &t_len), v->cpt_name);
      TEST_ASSERT_EQUAL_size_t_MESSAGE(v->u8_keyLen, t_len, v->cpt_name);
      TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(v->u8ar_key, u8ar_key, v->u8_keyLen, v->cpt_name);
   }
}

static void test_RefusedInputs(void)
{
   static const uint8_t scu8ar_seed[4] = { 1, 2, 3, 4 };
   uint8_t u8ar_key[4];
   size_t t_len = 99U;

   TEST_ASSERT_EQUAL_INT(-ENOTSUP, gi_UdsKey_Compute(UDS_KEY_ALGO_NONE, 1U, scu8ar_seed, 4U, u8ar_key, 4U, &t_len));
   TEST_ASSERT_EQUAL_size_t(0U, t_len);
   TEST_ASSERT_EQUAL_INT(-ENOTSUP, gi_UdsKey_Compute(0x02U, 1U, scu8ar_seed, 4U, u8ar_key, 4U, &t_len));
   TEST_ASSERT_EQUAL_INT(-EMSGSIZE, gi_UdsKey_Compute(UDS_KEY_ALGO_BENCH_XOR, 1U, scu8ar_seed, 4U, u8ar_key, 3U,
      &t_len));
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_UdsKey_Compute(UDS_KEY_ALGO_BENCH_XOR, 1U, scu8ar_seed, 0U, u8ar_key, 4U,
      &t_len));
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_UdsKey_Compute(UDS_KEY_ALGO_BENCH_XOR, 1U, NULL, 4U, u8ar_key, 4U, &t_len));
   TEST_ASSERT_EQUAL_INT(-EINVAL, gi_UdsKey_Compute(UDS_KEY_ALGO_BENCH_XOR, 1U, scu8ar_seed, 4U, u8ar_key, 4U, NULL));
}

static void test_CallbackCarriesTheAlgorithm(void)
{
   const UdsKeyVector_T *v = &gstar_vecUdsKeys[0];
   uint8_t u8ar_key[8];
   size_t t_len = 0U;

   TEST_ASSERT_EQUAL_INT(0, gi_UdsKey_Callback(v->u8_level, v->u8ar_seed, v->u8_seedLen, u8ar_key, sizeof(u8ar_key),
      &t_len, (void *)(uintptr_t)UDS_KEY_ALGO_BENCH_XOR));
   TEST_ASSERT_EQUAL_HEX8_ARRAY(v->u8ar_key, u8ar_key, v->u8_keyLen);
   TEST_ASSERT_EQUAL_INT(-ENOTSUP, gi_UdsKey_Callback(v->u8_level, v->u8ar_seed, v->u8_seedLen, u8ar_key,
      sizeof(u8ar_key), &t_len, (void *)(uintptr_t)UDS_KEY_ALGO_NONE));
}

static void test_OemAlgorithms(void)
{
   static const uint8_t scu8ar_seed[2] = { 0x41U, 0x42U };
   uint8_t u8ar_key[4];
   size_t t_len = 0U;

#if defined(UDS_KEY_OEM)
   TEST_ASSERT_EQUAL_INT(0, gi_UdsKey_Compute(0x80U, 1U, scu8ar_seed, 2U, u8ar_key, 4U, &t_len));
   TEST_ASSERT_EQUAL_HEX8(0x42U, u8ar_key[0]);
   TEST_ASSERT_EQUAL_INT(-ENOTSUP, gi_UdsKey_Compute(0x81U, 1U, scu8ar_seed, 2U, u8ar_key, 4U, &t_len));
   TEST_ASSERT_EQUAL_UINT32(2U, su32_oemCalls);
   TEST_ASSERT_EQUAL_INT_MESSAGE(-ENOTSUP, gi_UdsKey_Compute(0x7FU, 1U, scu8ar_seed, 2U, u8ar_key, 4U, &t_len),
      "below the OEM range: not passed on");
   TEST_ASSERT_EQUAL_UINT32(2U, su32_oemCalls);
#else
   TEST_ASSERT_EQUAL_INT_MESSAGE(-ENOTSUP, gi_UdsKey_Compute(0x80U, 1U, scu8ar_seed, 2U, u8ar_key, 4U, &t_len),
      "no OEM algorithms in this build");
#endif // UDS_KEY_OEM
}

static void test_Names(void)
{
   TEST_ASSERT_EQUAL_STRING("NONE", gcpt_UdsKey_Name(UDS_KEY_ALGO_NONE));
   TEST_ASSERT_EQUAL_STRING("BENCH_XOR", gcpt_UdsKey_Name(UDS_KEY_ALGO_BENCH_XOR));
   TEST_ASSERT_EQUAL_STRING("OEM", gcpt_UdsKey_Name(0x90U));
   TEST_ASSERT_EQUAL_STRING("?", gcpt_UdsKey_Name(0x02U));
}

int main(void)
{
   (void)setvbuf(stdout, NULL, _IONBF, 0);
   UNITY_BEGIN();
   RUN_TEST(test_BenchXorMatchesTheVectors);
   RUN_TEST(test_RefusedInputs);
   RUN_TEST(test_CallbackCarriesTheAlgorithm);
   RUN_TEST(test_OemAlgorithms);
   RUN_TEST(test_Names);
   return UNITY_END();
}
