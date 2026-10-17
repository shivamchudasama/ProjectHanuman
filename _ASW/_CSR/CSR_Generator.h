/**
 * @file          CSR_Generator.h
 * @brief         Header file containing CSR generator functionality.
 * @date          27/08/2025
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#ifndef _CSR_GENERATOR_H
#define _CSR_GENERATOR_H

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include <psa/crypto.h>
#include <zephyr/drivers/hwinfo.h>
#include <psa/internal_trusted_storage.h>

#if defined(CONFIG_HW_UNIQUE_KEY)
#include <hw_unique_key.h>
#endif // CONFIG_HW_UNIQUE_KEY

#if defined(CONFIG_SECURE_STORAGE_ITS_STORE_IMPLEMENTATION_SETTINGS)
#include <zephyr/settings/settings.h>
#endif // CONFIG_SECURE_STORAGE_ITS_STORE_IMPLEMENTATION_SETTINGS

#include "CSR_Generator_Config.h"
#include "CSR_Generator_Types.h"
#include "AppLog.h"
#include "DER.h"

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
/**
 * @def           CSR_DEVICE_SIGNING_KEY_ID
 * @brief         Device signing key ID for CSR generation. A persistent PSA key:
 *                generated once, never exported, and reused on every boot until
 *                a provisioning wipe destroys it (gt_DestroyDeviceCredentials). The
 *                certificate verification (DeviceCert_Verify.c) compares the
 *                device certificate's public key with this key.
 */
#define CSR_DEVICE_SIGNING_KEY_ID            ((psa_key_id_t)0x0001u)

/**
 * @def           CRYPTO_SHA_1_LEN
 * @brief         Length of SHA-1.
 */
#define CRYPTO_SHA_1_LEN                     (20)

/**
 * @def           UUID_LEN
 * @brief         Length of UUID.
 */
#define UUID_LEN                             (16)

/**
 * @def           UUID_STRING_LEN
 * @brief         Length of UUID string representation without terminator.
 */
#define UUID_STRING_LEN                      ((UUID_LEN * 2) + 4)

/**
 * @def           CRYPTO_EC_PUBLIC_KEY_LEN
 * @brief         Length of 256-bits EC public key (in bytes).
 */
#define CRYPTO_EC_PUBLIC_KEY_LEN             (64)

/******************************************************************************/
/*                                                                            */
/*                                   ENUMS                                    */
/*                                                                            */
/******************************************************************************/
/**
 * @enum          <Enum name>
 * @brief         <Enum details>.
 */

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
/**
 * @union         <Union name>
 * @brief         <Union details>.
 */

/******************************************************************************/
/*                                                                            */
/*                              EXTERN VARIABLES                              */
/*                                                                            */
/******************************************************************************/
extern CSRConfig_T gst_CSRConfig;
extern CSRData_T gst_CSRData;

/******************************************************************************/
/*                                                                            */
/*                              EXTERN FUNCTIONS                              */
/*                                                                            */
/******************************************************************************/
extern psa_status_t gt_CalculateSHA1(const uint8_t *u8pt_data, size_t t_len,
   uint8_t *u8pt_hash);
extern psa_status_t gt_InitCryptoStorage(void);
extern psa_status_t gt_ProbeDeviceKey(void);
extern psa_status_t gt_RemoveStoredCSR(void);
extern psa_status_t gt_DestroyDeviceCredentials(void);
extern void gv_GenerateOrLoadCSR(void);

#endif //!_CSR_GENERATOR_H

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shivam Chudasama [SC]
 */
