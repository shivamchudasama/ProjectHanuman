/**
 * @file          UdsKey.h
 * @brief         Header file containing the seed -> key algorithms of
 *                SecurityAccess (UDS 0x27), selected by number. Algorithm 0x01
 *                (BENCH_XOR) is for the bench and the ECU simulator only;
 *                0x80-0xFF are OEM algorithms, compiled in from
 *                _ASW/_UDS/oem/ when that (git-ignored) folder exists.
 *                Contract: _DOC/UDS/README.md.
 * @date          12/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#ifndef _UDS_KEY_H
#define _UDS_KEY_H

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include <stddef.h>
#include <stdint.h>

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
/**
 * @def           UDS_KEY_ALGO_NONE
 * @brief         No algorithm: every seed is refused.
 */
#define UDS_KEY_ALGO_NONE                    (0x00U)

/**
 * @def           UDS_KEY_ALGO_BENCH_XOR
 * @brief         key[i] = rotl8(seed[i] ^ mask[i % 4] ^ level, 1), mask 5A A5 3C C3.
 *                Not secure: for the bench and _TOOLS/EcuSim only.
 */
#define UDS_KEY_ALGO_BENCH_XOR               (0x01U)

/**
 * @def           UDS_KEY_ALGO_OEM_FIRST
 * @brief         First number reserved for OEM algorithms (gi_UdsKey_Oem()).
 */
#define UDS_KEY_ALGO_OEM_FIRST               (0x80U)

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
/*                              EXTERN VARIABLES                              */
/*                                                                            */
/******************************************************************************/

/******************************************************************************/
/*                                                                            */
/*                              EXTERN FUNCTIONS                              */
/*                                                                            */
/******************************************************************************/
extern int gi_UdsKey_Compute(uint8_t u8_algo, uint8_t u8_level, const uint8_t *u8pt_seed, size_t t_seedLen,
   uint8_t *u8pt_key, size_t t_keyMax, size_t *tpt_keyLen);
extern int gi_UdsKey_Callback(uint8_t u8_level, const uint8_t *u8pt_seed, size_t t_seedLen, uint8_t *u8pt_key,
   size_t t_keyMax, size_t *tpt_keyLen, void *vpt_user);
extern const char *gcpt_UdsKey_Name(uint8_t u8_algo);

/**
 * @brief         OEM algorithms (0x80-0xFF). Defined by a file in _ASW/_UDS/oem/
 *                when that folder exists (the build then defines UDS_KEY_OEM);
 *                same contract as gi_UdsKey_Compute().
 */
extern int gi_UdsKey_Oem(uint8_t u8_algo, uint8_t u8_level, const uint8_t *u8pt_seed, size_t t_seedLen,
   uint8_t *u8pt_key, size_t t_keyMax, size_t *tpt_keyLen);

#endif //!_UDS_KEY_H

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shivam Chudasama [SC]
 */
