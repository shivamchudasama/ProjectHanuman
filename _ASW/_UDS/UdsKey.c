/**
 * @file          UdsKey.c
 * @brief         Source file containing the seed -> key algorithms of
 *                SecurityAccess, selected by number: BENCH_XOR for the bench, and
 *                the OEM algorithms (0x80-0xFF) when _ASW/_UDS/oem/ is built in.
 *                Contract: _DOC/UDS/README.md.
 * @date          12/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include "UdsKey.h"
#include <errno.h>
#include <stdint.h>

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/

/******************************************************************************/
/*                                                                            */
/*                                   ENUMS                                    */
/*                                                                            */
/******************************************************************************/

/******************************************************************************/
/*                                                                            */
/*                                 STRUCTURES                                 */
/*                                                                            */
/******************************************************************************/

/******************************************************************************/
/*                                                                            */
/*                                   UNIONS                                   */
/*                                                                            */
/******************************************************************************/

/******************************************************************************/
/*                                                                            */
/*                       PRIVATE FUNCTION DECLARATIONS                        */
/*                                                                            */
/******************************************************************************/
static int si_BenchXor(uint8_t u8_level, const uint8_t *u8pt_seed, size_t t_seedLen, uint8_t *u8pt_key,
   size_t t_keyMax, size_t *tpt_keyLen);

/******************************************************************************/
/*                                                                            */
/*                              EXTERN VARIABLES                              */
/*                                                                            */
/******************************************************************************/

/******************************************************************************/
/*                                                                            */
/*                             PRIVATE VARIABLES                              */
/*                                                                            */
/******************************************************************************/
/**
 * @var           scu8ar_benchMask
 * @brief         BENCH_XOR's mask, repeated over the seed.
 */
static const uint8_t scu8ar_benchMask[4] = { 0x5AU, 0xA5U, 0x3CU, 0xC3U };

/******************************************************************************/
/*                                                                            */
/*                              EXTERN FUNCTIONS                              */
/*                                                                            */
/******************************************************************************/

/******************************************************************************/
/*                                                                            */
/*                        PRIVATE FUNCTION DEFINITIONS                        */
/*                                                                            */
/******************************************************************************/
/**
 * @private       si_BenchXor
 * @brief         BENCH_XOR: key[i] = rotl8(seed[i] ^ mask[i % 4] ^ level, 1).
 * @param[in]     u8_level requestSeed level.
 * @param[in]     u8pt_seed Seed.
 * @param[in]     t_seedLen Seed length.
 * @param[out]    u8pt_key Key (as long as the seed).
 * @param[in]     t_keyMax Size of u8pt_key.
 * @param[out]    tpt_keyLen Key length.
 * @return        0, or -EMSGSIZE if the key does not fit.
 */
static int si_BenchXor(uint8_t u8_level, const uint8_t *u8pt_seed, size_t t_seedLen, uint8_t *u8pt_key,
   size_t t_keyMax, size_t *tpt_keyLen)
{
   uint8_t u8_value;
   size_t i;

   if (t_seedLen > t_keyMax)
   {
      return -EMSGSIZE;
   }

   for (i = 0U; i < t_seedLen; i++)
   {
      u8_value = (uint8_t)(u8pt_seed[i] ^ scu8ar_benchMask[i & 3U] ^ u8_level);
      u8pt_key[i] = (uint8_t)((uint8_t)(u8_value << 1) | (uint8_t)(u8_value >> 7));
   }
   *tpt_keyLen = t_seedLen;

   return 0;
}

/******************************************************************************/
/*                                                                            */
/*                        PUBLIC FUNCTION DEFINITIONS                         */
/*                                                                            */
/******************************************************************************/
/**
 * @public        gi_UdsKey_Compute
 * @brief         Compute the key of a seed with algorithm u8_algo.
 * @param[in]     u8_algo Algorithm number (UDS_KEY_ALGO_*).
 * @param[in]     u8_level requestSeed level.
 * @param[in]     u8pt_seed Seed.
 * @param[in]     t_seedLen Seed length (at least 1).
 * @param[out]    u8pt_key Key.
 * @param[in]     t_keyMax Size of u8pt_key.
 * @param[out]    tpt_keyLen Key length.
 * @return        0; -EINVAL for NULL or an empty seed; -ENOTSUP for no algorithm,
 *                an unknown one, or an OEM one in a build without them; -EMSGSIZE
 *                if the key does not fit.
 */
int gi_UdsKey_Compute(uint8_t u8_algo, uint8_t u8_level, const uint8_t *u8pt_seed, size_t t_seedLen,
   uint8_t *u8pt_key, size_t t_keyMax, size_t *tpt_keyLen)
{
   if ((u8pt_seed == NULL) || (t_seedLen == 0U) || (u8pt_key == NULL) || (tpt_keyLen == NULL))
   {
      return -EINVAL;
   }
   *tpt_keyLen = 0U;

   if (u8_algo == UDS_KEY_ALGO_BENCH_XOR)
   {
      return si_BenchXor(u8_level, u8pt_seed, t_seedLen, u8pt_key, t_keyMax, tpt_keyLen);
   }

#if defined(UDS_KEY_OEM)
   // Check if this is an OEM algorithm, built in from _ASW/_UDS/oem/
   if (u8_algo >= UDS_KEY_ALGO_OEM_FIRST)
   {
      return gi_UdsKey_Oem(u8_algo, u8_level, u8pt_seed, t_seedLen, u8pt_key, t_keyMax, tpt_keyLen);
   }
#endif // UDS_KEY_OEM

   return -ENOTSUP;
}

/**
 * @public        gi_UdsKey_Callback
 * @brief         UdsKey_F for gi_UdsClient_SecurityAccess(): the algorithm number
 *                travels in the user pointer, (void *)(uintptr_t)algo.
 * @param[in]     u8_level requestSeed level.
 * @param[in]     u8pt_seed Seed.
 * @param[in]     t_seedLen Seed length.
 * @param[out]    u8pt_key Key.
 * @param[in]     t_keyMax Size of u8pt_key.
 * @param[out]    tpt_keyLen Key length.
 * @param[in]     vpt_user The algorithm number.
 * @return        As gi_UdsKey_Compute().
 */
int gi_UdsKey_Callback(uint8_t u8_level, const uint8_t *u8pt_seed, size_t t_seedLen, uint8_t *u8pt_key,
   size_t t_keyMax, size_t *tpt_keyLen, void *vpt_user)
{
   return gi_UdsKey_Compute((uint8_t)(uintptr_t)vpt_user, u8_level, u8pt_seed, t_seedLen, u8pt_key, t_keyMax,
      tpt_keyLen);
}

/**
 * @public        gcpt_UdsKey_Name
 * @brief         Name of an algorithm for the log.
 * @param[in]     u8_algo Algorithm number.
 * @return        "NONE", "BENCH_XOR", "OEM" or "?".
 */
const char *gcpt_UdsKey_Name(uint8_t u8_algo)
{
   if (u8_algo == UDS_KEY_ALGO_NONE)
   {
      return "NONE";
   }
   if (u8_algo == UDS_KEY_ALGO_BENCH_XOR)
   {
      return "BENCH_XOR";
   }
   return (u8_algo >= UDS_KEY_ALGO_OEM_FIRST) ? "OEM" : "?";
}

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shivam Chudasama [SC]
 */
