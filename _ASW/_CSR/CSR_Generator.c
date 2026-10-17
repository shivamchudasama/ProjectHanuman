/**
 * @file          CSR_Generator.c
 * @brief         Source file containing CSR generator functionality.
 * @date          27/08/2025
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include "CSR_Generator.h"

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
/**
 * @def           CSR_STORAGE_UID_BASE
 * @brief         Base UID for CSR storage. First 3 bytes are ASCII "CSR",
 *                last 5 bytes are for specific entries.
 */
#define CSR_STORAGE_UID_BASE                 ((psa_storage_uid_t)0x4353520000000000ULL)

/**
 * @def           CSR_PERSISTED_OUTPUT_BASE_LEN
 * @brief         Base length for persisted CSR output.
 */
#define CSR_PERSISTED_OUTPUT_BASE_LEN        (offsetof(CSRData_T, u8ar_CSR))

/**
 * @def           CSR_PERSISTED_OUTPUT_LEN
 * @brief         Output length for persisted CSR output.
 */
#define CSR_PERSISTED_OUTPUT_LEN(t_csrLen)   (CSR_PERSISTED_OUTPUT_BASE_LEN + (size_t)(t_csrLen))

/* Secure storage derives its AEAD key from the HUK; nothing in this module
   writes one, so NCS must write it during psa_crypto_init() */
#if defined(CONFIG_SECURE_STORAGE_ITS_TRANSFORM_AEAD_KEY_PROVIDER_HUK_LIBRARY) && \
   !defined(CONFIG_HW_UNIQUE_KEY_WRITE_ON_CRYPTO_INIT)
#error "Secure storage uses the HUK library: set CONFIG_HW_UNIQUE_KEY_WRITE_ON_CRYPTO_INIT=y"
#endif

/******************************************************************************/
/*                                                                            */
/*                                   ENUMS                                    */
/*                                                                            */
/******************************************************************************/
// Definition of all the enums
/**
 * @enum          <Enum name>
 * @brief         <Enum details>.
 */

// Declarations of all the enum variables
/**
 * @var           <Variable name>
 * @brief         <Variable details>.
 */

/******************************************************************************/
/*                                                                            */
/*                                 STRUCTURES                                 */
/*                                                                            */
/******************************************************************************/
// Definition of all the structures
/**
 * @struct        <Structure name>
 * @brief         <Structure details>.
 */

// Declarations of all the structure variables
/**
 * @var           <Variable name>
 * @brief         <Variable details>.
 */

/******************************************************************************/
/*                                                                            */
/*                                   UNIONS                                   */
/*                                                                            */
/******************************************************************************/
// Definition of all the unions
/**
 * @union         <Union name>
 * @brief         <Union details>.
 */

// Declarations of all the union variables
/**
 * @var           <Variable name>
 * @brief         <Variable details>.
 */

/******************************************************************************/
/*                                                                            */
/*                       PRIVATE FUNCTION DECLARATIONS                        */
/*                                                                            */
/******************************************************************************/
static int si_InitPersistentKeyStorage(void);
static psa_status_t st_GenerateDeviceKey(psa_key_id_t *tpt_signingKey);
static psa_storage_uid_t st_GetCSRStorageUID(void);
static void sv_ClearCSROutput(void);
static psa_status_t st_RemoveStoredCSR(void);
static psa_status_t st_LoadStoredCSR(void);
static psa_status_t st_StoreGeneratedCSR(void);
static psa_status_t st_GenerateUUID(uint8_t *const u8pt_UUID);
static void sv_FormatUUIDString(const uint8_t *u8pt_UUID, char *cpt_UUIDString);

/******************************************************************************/
/*                                                                            */
/*                              EXTERN VARIABLES                              */
/*                                                                            */
/******************************************************************************/

/******************************************************************************/
/*                                                                            */
/*                              PUBLIC VARIABLES                              */
/*                                                                            */
/******************************************************************************/
/**
 * @var           gst_CSRConfig
 * @brief         CSR configuration.
 */
CSRConfig_T gst_CSRConfig = {
  .b_isStaticAuth2Generated = CSR_GENERATOR_CONFIG_GENERATE_STATIC_AUTH,
  .b_isStaticAuthOnDevice = CSR_GENERATOR_CONFIG_STORE_STATIC_AUTH,
  .b_isKey2Generated = CSR_GENERATOR_CONFIG_GENERATE_SIGNING_KEY,
  .b_isKeyAvailable = CSR_GENERATOR_CONFIG_STORE_SIGNING_KEY,
  .b_isCertAvailable = CSR_GENERATOR_CONFIG_CERTIFICATE_ON_DEVICE,
  .b_isCSRAvailable = CSR_GENERATOR_CONFIG_CSR_ON_DEVICE,
  .u8_certPositionOnITS = DEVICE_CERTIFICATE_ITS_OFFSET,
  .u8_CACertPositionOnITS = DEVICE_CA_CERT_ITS_OFFSET,
  .u8_CSRPositionOnITS = DEVICE_CSR_ITS_OFFSET,
  .t_subjectNameFieldCnt = 6,
  .stpt_subjectNameField = NULL,
};

/**
 * @var           gst_CSRData
 * @brief         Instance of CSRData_T structure. The generated or loaded (from secure valut)
 *                CSR data.
 */
CSRData_T gst_CSRData = { 0 };

/******************************************************************************/
/*                                                                            */
/*                             PRIVATE VARIABLES                              */
/*                                                                            */
/******************************************************************************/
/**
 * @var           su8ar_namespace
 * @brief         UUID Namespace.
 */
static const uint8_t su8ar_namespace[16] = {
  0x70, 0x0b, 0xaf, 0xdf,
  0xd5, 0xec, 0xc3, 0x9b,
  0x37, 0x04, 0xa1, 0x2c,
  0x07, 0x67, 0x86, 0x9c,
};

/**
 * @var           sscar_commonNameUUID
 * @brief         Bluetooth Common Name UUID.
 */
static char sscar_commonNameUUID[UUID_STRING_LEN + 1] = { 0 };

/**
 * @var           sstar_subjectNameFields
 * @brief         CSR Subject name fields.
 */
static SubjectNameField_T sstar_subjectNameFields[] =
{
   [0] = {
      .t_nameLen = 1,
      .t_valueLen = (sizeof(CSR_GENERATOR_SUBJECT_COUNTRY) - 1),
      .cpt_name = "C",                       // Shorthand for "countryName"
      .cpt_value = CSR_GENERATOR_SUBJECT_COUNTRY
   },
   [1] = {
      .t_nameLen = 2,
      .t_valueLen = (sizeof(CSR_GENERATOR_SUBJECT_STATE) - 1),
      .cpt_name = "ST",                      // Shorthand for "stateOrProvinceName"
      .cpt_value = CSR_GENERATOR_SUBJECT_STATE
   },
   [2] = {
      .t_nameLen = 1,
      .t_valueLen = (sizeof(CSR_GENERATOR_SUBJECT_LOCALITY) - 1),
      .cpt_name = "L",                       // Shorthand for "locality"
      .cpt_value = CSR_GENERATOR_SUBJECT_LOCALITY
   },
   [3] = {
      .t_nameLen = 1,
      .t_valueLen = (sizeof(CSR_GENERATOR_SUBJECT_ORGANIZATION) - 1),
      .cpt_name = "O",                       // Shorthand for "organization"
      .cpt_value = CSR_GENERATOR_SUBJECT_ORGANIZATION
   },
   [4] = {
      .t_nameLen = 2,
      .t_valueLen = (sizeof(CSR_GENERATOR_SUBJECT_ORGANIZATION_UNIT) - 1),
      .cpt_name = "OU",                      // Shorthand for "organizationalUnitName"
      .cpt_value = CSR_GENERATOR_SUBJECT_ORGANIZATION_UNIT
   },
   [5] = {
      .t_nameLen = 2,
      .t_valueLen = UUID_STRING_LEN,         // 128-bit Mesh device UUID as hexes and dashes
      .cpt_name = "CN",                      // Shorthand for "commonName"
      .cpt_value = sscar_commonNameUUID// To be filled in
   },
};

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
 * @private       si_InitPersistentKeyStorage
 * @brief         Initialize the settings backend that Zephyr's secure storage
 *                (the PSA ITS) keeps its entries in. Secure storage also does
 *                this from its own SYS_INIT; settings_subsys_init() returns at
 *                once when it already ran, and doing it here makes a failure
 *                visible before the first key is used.
 * @return        0 in case of no error.
 */
static int si_InitPersistentKeyStorage(void)
{
   int i_status = 0;

#if defined(CONFIG_SECURE_STORAGE_ITS_STORE_IMPLEMENTATION_SETTINGS)
   i_status = settings_subsys_init();
   if (i_status != 0)
   {
      APP_LOG_ERR("Failed to initialize Settings backend for persistent PSA storage: %d",
         i_status);
   }
   else
   {
      APP_LOG_INF("Settings backend initialized for persistent PSA storage");
   }
#endif // CONFIG_SECURE_STORAGE_ITS_STORE_IMPLEMENTATION_SETTINGS

   return i_status;
}

/**
 * @private       st_GenerateDeviceKey
 * @brief         Generate signing key.
 * @param[in]     tpt_signingKey Pointer to the signing key ID.
 * @return        psa_status_t status of the initialization.
 *                PSA_SUCCESS in case of no error.
 */
static psa_status_t st_GenerateDeviceKey(psa_key_id_t *tpt_signingKey)
{
   psa_status_t t_status = PSA_ERROR_GENERIC_ERROR;
   psa_key_attributes_t st_signAttr = PSA_KEY_ATTRIBUTES_INIT;
   psa_key_id_t t_signKeyId;

   // Check if the signing key pointer is valid
   if (!tpt_signingKey)
   {
      APP_LOG_ERR("Invalid argument: signing key pointer is NULL");
      t_status = PSA_ERROR_INVALID_ARGUMENT;
   }
   else
   {
      // Signing key generation
      // Set key type as EC key pair with SECP256R1 curve
      psa_set_key_type(&st_signAttr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));

      // Set key size as 256 bits
      psa_set_key_bits(&st_signAttr, 256);

      // Set key usage flags for signing, verification and export
      psa_set_key_usage_flags(&st_signAttr,
         (PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH));

      // Set key algorithm as ECDSA with SHA-256
      psa_set_key_algorithm(&st_signAttr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

      // Persistent key so it survives reset/reboot.
      psa_set_key_lifetime(&st_signAttr, PSA_KEY_LIFETIME_PERSISTENT);
      psa_set_key_id(&st_signAttr, CSR_DEVICE_SIGNING_KEY_ID);

      // Generate the signing key
      t_status = psa_generate_key(&st_signAttr, &t_signKeyId);

      // Check if the signing key was generated successfully.
      if (t_status == PSA_SUCCESS)
      {
         APP_LOG_INF("Signing key generated successfully with ID: %u", t_signKeyId);
         *tpt_signingKey = t_signKeyId;
      }
      // Check if the signing key already exists
      else if (t_status == PSA_ERROR_ALREADY_EXISTS)
      {
         // PSA 1.x has no psa_open_key(): a persistent key is used directly by
         // its ID. Probe it to make sure it is readable.
         t_status = gt_ProbeDeviceKey();
         t_signKeyId = CSR_DEVICE_SIGNING_KEY_ID;

         // Check if the existing signing key is usable
         if (t_status == PSA_SUCCESS)
         {
            APP_LOG_INF("Signing key already exists. Reusing key ID: %u", t_signKeyId);
            *tpt_signingKey = t_signKeyId;
         }
         else
         {
            APP_LOG_ERR("Signing key exists but could not be opened: %d", t_status);
         }
      }
      else
      {
         // Check if the error is due to persistent key storage not being ready
         if (t_status == PSA_ERROR_BAD_STATE)
         {
            APP_LOG_ERR("Persistent key storage is not ready. Check secure storage/HUK provisioning");
         }

         APP_LOG_ERR("Failed to generate signing key: %d", t_status);
      }

      // Reset the key attributes structure to free any allocated resources
      psa_reset_key_attributes(&st_signAttr);
   }

   return t_status;
}

/**
 * @private       st_GetCSRStorageUID
 * @brief         Get the PSA storage UID used for the persisted CSR blob.
 * @return        PSA storage UID for the CSR object.
 */
static psa_storage_uid_t st_GetCSRStorageUID(void)
{
   return (CSR_STORAGE_UID_BASE |
      (psa_storage_uid_t)gst_CSRConfig.u8_CSRPositionOnITS);
}

/**
 * @private       sv_ClearCSROutput
 * @brief         Reset the in-RAM CSR output cache.
 * @return        None.
 */
static void sv_ClearCSROutput(void)
{
   memset(&gst_CSRData, 0, sizeof(gst_CSRData));
}

/**
 * @private       st_RemoveStoredCSR
 * @brief         Delete the persisted CSR object from trusted storage.
 * @return        PSA_SUCCESS if the object is removed or not present.
 */
static psa_status_t st_RemoveStoredCSR(void)
{
   psa_status_t t_status;

   t_status = psa_its_remove(st_GetCSRStorageUID());

   // Check if the stored CSR object doesn't exist
   if (t_status == PSA_ERROR_DOES_NOT_EXIST)
   {
      t_status = PSA_SUCCESS;
   }
   // Check if the stored CSR object isn't removed successfully
   else if (t_status != PSA_SUCCESS)
   {
      APP_LOG_ERR("Failed to remove stored CSR: %d", t_status);
   }

   return t_status;
}

/**
 * @private       st_LoadStoredCSR
 * @brief         Load a previously stored CSR from trusted storage into RAM.
 * @return        PSA_SUCCESS if a valid CSR is restored.
 */
static psa_status_t st_LoadStoredCSR(void)
{
   psa_status_t t_status = PSA_ERROR_GENERIC_ERROR;
   struct psa_storage_info_t st_storageInfo = { 0 };
   size_t t_bytesRead = 0;
   size_t t_expectedLen = 0;

   // Clear the in-RAM CSR output cache before loading
   sv_ClearCSROutput();

   // Get the information of the stored CSR object
   t_status = psa_its_get_info(st_GetCSRStorageUID(), &st_storageInfo);

   // Check if the stored CSR object does not exist
   if (t_status != PSA_SUCCESS)
   {
      // Remove the stored CSR object if it is corrupted or has an invalid signature
      (void)st_RemoveStoredCSR();

      return t_status;
   }

   // Check if the stored CSR size is valid
   if ((st_storageInfo.size <= CSR_PERSISTED_OUTPUT_BASE_LEN) ||
      (st_storageInfo.size > sizeof(gst_CSRData)))
   {
      APP_LOG_ERR("Stored CSR has invalid size: %u",
         (unsigned int)st_storageInfo.size);

      // Remove the stored CSR object as the size is invalid
      (void)st_RemoveStoredCSR();
      return PSA_ERROR_DATA_CORRUPT;
   }

   // Load the stored CSR object into RAM
   t_status = psa_its_get(st_GetCSRStorageUID(), 0u, st_storageInfo.size,
      &gst_CSRData, &t_bytesRead);

   // Check if the stored CSR object isn't read successfully
   if (t_status != PSA_SUCCESS)
   {
      APP_LOG_ERR("Failed to load stored CSR: %d", t_status);

      // Clear the in-RAM CSR output cache
      sv_ClearCSROutput();

      // Check if either the stored CSR is corrupted or has an invalid signature
      if ((t_status == PSA_ERROR_DATA_CORRUPT) ||
         (t_status == PSA_ERROR_INVALID_SIGNATURE))
      {
         // Remove the stored CSR object as it is corrupted or has an invalid signature
         (void)st_RemoveStoredCSR();
      }

      return t_status;
   }

   // Check if the read length doesn't match the stored CSR size
   if (t_bytesRead != st_storageInfo.size)
   {
      APP_LOG_ERR("Stored CSR read length mismatch: %u/%u",
         (unsigned int)t_bytesRead, (unsigned int)st_storageInfo.size);

      // Clear the in-RAM CSR output cache
      sv_ClearCSROutput();

      // Remove the stored CSR object as it is corrupted or has an invalid signature
      (void)st_RemoveStoredCSR();
      return PSA_ERROR_DATA_CORRUPT;
   }

   // Update the in-RAM CSR expected length
   t_expectedLen = CSR_PERSISTED_OUTPUT_LEN(gst_CSRData.u16_CSRLen);

   // Check if the loaded CSR content isn't valid
   if ((gst_CSRData.u8_isCSRGenerated != 1u) ||
      (gst_CSRData.u16_CSRLen == 0u) ||
      (gst_CSRData.u16_CSRLen > CSR_MAX_DER_LEN) ||
      (st_storageInfo.size != t_expectedLen))
   {
      APP_LOG_ERR("Stored CSR content is invalid. Removing persisted copy");

      // Clear the in-RAM CSR output cache
      sv_ClearCSROutput();

      // Remove the stored CSR object as it is corrupted or has an invalid signature
      (void)st_RemoveStoredCSR();
      return PSA_ERROR_DATA_CORRUPT;
   }

   APP_LOG_INF("CSR restored from trusted storage (%u bytes)",
      gst_CSRData.u16_CSRLen);
   LOG_HEXDUMP_INF(gst_CSRData.u8ar_CSR, gst_CSRData.u16_CSRLen, "Stored CSR: ");

   return PSA_SUCCESS;
}

/**
 * @private       st_StoreGeneratedCSR
 * @brief         Persist the generated CSR into trusted storage.
 * @return        PSA_SUCCESS if the CSR is stored successfully.
 */
static psa_status_t st_StoreGeneratedCSR(void)
{
   psa_status_t t_status = PSA_ERROR_GENERIC_ERROR;
   size_t t_storageLen = 0;

   // Check if the in-RAM CSR output is valid for storage
   if ((gst_CSRData.u8_isCSRGenerated != 1u) ||
      (gst_CSRData.u16_CSRLen == 0u) ||
      (gst_CSRData.u16_CSRLen > CSR_MAX_DER_LEN))
   {
      t_status = PSA_ERROR_INVALID_ARGUMENT;
      APP_LOG_ERR("CSR output is not valid for persistent storage");
   }
   else
   {
      t_storageLen = CSR_PERSISTED_OUTPUT_LEN(gst_CSRData.u16_CSRLen);

      // Store the CSR output in trusted storage
      t_status = psa_its_set(st_GetCSRStorageUID(), t_storageLen,
         &gst_CSRData, PSA_STORAGE_FLAG_NONE);

      // Check if the CSR was stored successfully
      if (t_status == PSA_SUCCESS)
      {
         APP_LOG_INF("CSR stored in trusted storage (%u bytes)",
            gst_CSRData.u16_CSRLen);
      }
      else
      {
         APP_LOG_ERR("Failed to store CSR in trusted storage: %d", t_status);
      }
   }

   return t_status;
}

/**
 * @private       st_GenerateUUID
 * @brief         Generate a UUID.
 * @param[out]    u8pt_UUID Pointer to generated UUID data.
 * @return        PSA_SUCCESS upon successfully generation of UUID data, or an
 *                error code otherwise.
 */
static psa_status_t st_GenerateUUID(uint8_t *const u8pt_UUID)
{
   psa_status_t t_retVal = PSA_SUCCESS;
   ssize_t t_deviceIdLen = 0;
   uint8_t u8ar_deviceId[sizeof(uint64_t)] = { 0 };
   uint8_t u8ar_temp[24] = { 0 }, u8ar_digest[CRYPTO_SHA_1_LEN] = { 0 };

   // Check if the UUID pointer is valid
   if (!u8pt_UUID)
   {
      return PSA_ERROR_INVALID_ARGUMENT;
   }

   // UUID generation procedure shall follow the standard UUID format as defined in RFC4122
   // https://www.ietf.org/rfc/rfc4122.txt

   t_deviceIdLen = hwinfo_get_device_id(u8ar_deviceId, sizeof(u8ar_deviceId));
   if (t_deviceIdLen < 0)
   {
      APP_LOG_ERR("Failed to read device identifier: %d", (int)t_deviceIdLen);
      return PSA_ERROR_HARDWARE_FAILURE;
   }

   memcpy(u8ar_temp, su8ar_namespace, 16);
   memcpy(&u8ar_temp[16], u8ar_deviceId, (size_t)t_deviceIdLen);

   t_retVal = gt_CalculateSHA1(u8ar_temp, sizeof(u8ar_temp), u8ar_digest);

   memcpy(u8pt_UUID, u8ar_digest, 16);
   // time_hi_and_version is bytes 6-7, big-endian: its four most significant
   // bits (bits 12 through 15) are the high nibble of byte 6
   u8pt_UUID[6] &= 0x0F; // Set the four most significant bits (bits 12 through 15) of the time_hi_and_version field
   u8pt_UUID[6] |= 0x50; // to the 4-bit version number (5: name-based, SHA-1)
   u8pt_UUID[8] &= 0x3F; // Set the two most significant bits (bits 6 and 7) of the clock_seq_hi_and_reserved field
   u8pt_UUID[8] |= 0x80; // to zero and one, respectively

   return t_retVal;
}

/**
 * @private       sv_FormatUUIDString
 * @brief         Format a UUID byte array as a lowercase hexadecimal string.
 * @param[in]     u8pt_UUID Pointer to the UUID bytes.
 * @param[out]    cpt_UUIDString Pointer to the destination string buffer.
 * @return        None.
 */
static void sv_FormatUUIDString(const uint8_t *u8pt_UUID, char *cpt_UUIDString)
{
   static const char slcar_hexDigits[] = "0123456789abcdef";
   uint8_t u8_lpIdx;

   for (u8_lpIdx = 0; u8_lpIdx < UUID_LEN; u8_lpIdx++)
   {
      if ((u8_lpIdx > 3) && (u8_lpIdx < 11) && ((u8_lpIdx & 1u) == 0u))
      {
         *cpt_UUIDString++ = '-';
      }

      *cpt_UUIDString++ = slcar_hexDigits[u8pt_UUID[u8_lpIdx] >> 4];
      *cpt_UUIDString++ = slcar_hexDigits[u8pt_UUID[u8_lpIdx] & 0x0Fu];
   }

   *cpt_UUIDString = '\0';
}

/******************************************************************************/
/*                                                                            */
/*                        PUBLIC FUNCTION DEFINITIONS                         */
/*                                                                            */
/******************************************************************************/
/**
 * @public        gt_InitCryptoStorage
 * @brief         Initialize the storage backend (settings) and the PSA crypto
 *                library, then check that the hardware unique key exists: secure
 *                storage encrypts every ITS entry with a key derived from it,
 *                and NCS writes a random one inside psa_crypto_init() on first
 *                boot (CONFIG_HW_UNIQUE_KEY_WRITE_ON_CRYPTO_INIT). Runs once;
 *                later calls return the first result.
 * @return        PSA_SUCCESS when all are ready, PSA_ERROR_STORAGE_FAILURE if
 *                the storage backend failed or there is no HUK after crypto
 *                init, or the psa_crypto_init() error.
 */
psa_status_t gt_InitCryptoStorage(void)
{
   static bool slb_isDone = false;
   static psa_status_t slt_status = PSA_ERROR_BAD_STATE;

   // Check if the initialization already ran
   if (slb_isDone)
   {
      return slt_status;
   }

   slb_isDone = true;

   // Check if persistent key storage initialization failed
   if (si_InitPersistentKeyStorage() != 0)
   {
      slt_status = PSA_ERROR_STORAGE_FAILURE;
      return slt_status;
   }

   // Initialize cryptographic library
   slt_status = psa_crypto_init();

   // Check if initialization was successful
   if (slt_status != PSA_SUCCESS)
   {
      APP_LOG_ERR("Failed to initialize cryptographic library: %d", slt_status);
   }
   else
   {
      APP_LOG_INF("Cryptographic library initialized successfully.");
   }

#if defined(CONFIG_HW_UNIQUE_KEY)
   // Check if crypto init left the device without the key its storage needs
   if ((slt_status == PSA_SUCCESS) && !hw_unique_key_are_any_written())
   {
      APP_LOG_ERR("No hardware unique key after crypto init: secure storage cannot work");
      slt_status = PSA_ERROR_STORAGE_FAILURE;
   }
#endif // CONFIG_HW_UNIQUE_KEY

   return slt_status;
}

/**
 * @public        gt_ProbeDeviceKey
 * @brief         Check that the persistent device signing key exists. PSA 1.x
 *                (NCS v3.x) dropped psa_open_key()/psa_close_key(): a persistent
 *                key is used directly by its ID, and reading its attributes is
 *                how its presence is tested.
 * @return        PSA_SUCCESS if the key exists, PSA_ERROR_DOES_NOT_EXIST if not,
 *                or another PSA error.
 */
psa_status_t gt_ProbeDeviceKey(void)
{
   psa_status_t t_status;
   psa_key_attributes_t st_attr = PSA_KEY_ATTRIBUTES_INIT;

   t_status = psa_get_key_attributes(CSR_DEVICE_SIGNING_KEY_ID, &st_attr);

   // Reset the key attributes structure to free any allocated resources
   psa_reset_key_attributes(&st_attr);

   return t_status;
}

/**
 * @public        gt_RemoveStoredCSR
 * @brief         Delete the CSR from trusted storage and clear its RAM copy. Called
 *                once the device is provisioned: the CSR is not needed any more.
 * @return        PSA_SUCCESS if the CSR is removed or was not stored.
 */
psa_status_t gt_RemoveStoredCSR(void)
{
   sv_ClearCSROutput();

   return st_RemoveStoredCSR();
}

/**
 * @public        gt_DestroyDeviceCredentials
 * @brief         Destroy the persistent device signing key and the CSR (trusted
 *                storage and RAM). A following gv_GenerateOrLoadCSR() then
 *                generates a fresh key and CSR, as on a chip-erased device.
 * @return        PSA_SUCCESS if both are gone (also when they did not exist),
 *                otherwise the first PSA error.
 */
psa_status_t gt_DestroyDeviceCredentials(void)
{
   psa_status_t t_keyStatus;
   psa_status_t t_csrStatus;

   t_keyStatus = psa_destroy_key(CSR_DEVICE_SIGNING_KEY_ID);

   // Check if there was no key to destroy (PSA reports a missing persistent key
   // as an invalid handle)
   if ((t_keyStatus == PSA_ERROR_INVALID_HANDLE) || (t_keyStatus == PSA_ERROR_DOES_NOT_EXIST))
   {
      t_keyStatus = PSA_SUCCESS;
   }
   // Check if the key could not be destroyed
   else if (t_keyStatus != PSA_SUCCESS)
   {
      APP_LOG_ERR("Failed to destroy the device signing key: %d", t_keyStatus);
   }
   else
   {
      APP_LOG_INF("Device signing key destroyed");
   }

   t_csrStatus = gt_RemoveStoredCSR();

   return (t_keyStatus != PSA_SUCCESS) ? t_keyStatus : t_csrStatus;
}

/**
 * @public        gv_GenerateOrLoadCSR
 * @brief         Generate a Certificate Signing Request (CSR) or load the earlier
 *                generated one from ITS memory.
 * @return        None.
 */
void gv_GenerateOrLoadCSR(void)
{
   psa_status_t t_status;
   psa_key_id_t t_signingKeyID = 0;
   uint8_t u8ar_UUID[UUID_LEN] = { 0 };
   size_t t_CSRLenDER = 0;
   bool b_isSigningKeyAvailableInStorage = false;

   // Fill in CN to subject name
   char *cpt_CN = sstar_subjectNameFields[5].cpt_value;

   sv_ClearCSROutput();

   t_status = gt_InitCryptoStorage();

   // Check if the storage backend or the cryptographic library is unavailable
   if (t_status != PSA_SUCCESS)
   {
      return;
   }
   else
   {
      // Check if a CSR is already stored into trusted storage
      if (gst_CSRConfig.b_isCSRAvailable == true)
      {
         t_status = st_LoadStoredCSR();

         // Check if the stored CSR was loaded successfully
         if (t_status == PSA_SUCCESS)
         {
            // Note: At this point, the CSR is successfully loaded from trusted
            // storage and available in gst_CSRData.

            // Check that the existing signing key is present
            t_status = gt_ProbeDeviceKey();

            // Check if the existing signing key is usable
            if (t_status == PSA_SUCCESS)
            {
               b_isSigningKeyAvailableInStorage = true;

               APP_LOG_INF("Both the signing key and CSR are available in trusted storage.");
               APP_LOG_INF("Reusing stored CSR across power cycle.");
            }
            else
            {
               APP_LOG_WRN("Stored CSR found, but signing key is unavailable: %d",
                  t_status);

               // Check if the error is due to the signing key not existing
               if (t_status == PSA_ERROR_DOES_NOT_EXIST)
               {
                  (void)st_RemoveStoredCSR();
                  sv_ClearCSROutput();
               }
            }
         }
         // Check if the error is due to the CSR not existing
         else if (t_status != PSA_ERROR_DOES_NOT_EXIST)
         {
            APP_LOG_WRN("Stored CSR could not be reused. Generating a new CSR.");
         }
      }

      // Check if signing key is not available in storage
      if (b_isSigningKeyAvailableInStorage == false)
      {
         // Generate device key
         t_status = st_GenerateDeviceKey(&t_signingKeyID);

         // Check if the device signing key was generated successfully
         if (t_status == PSA_SUCCESS)
         {
            b_isSigningKeyAvailableInStorage = true;
            APP_LOG_INF("Device signing key is ready with ID: %u", t_signingKeyID);

            t_status = st_GenerateUUID(u8ar_UUID);

            // Check if UUID generation was successful
            if (t_status == PSA_SUCCESS)
            {
               APP_LOG_INF("UUID generated successfully.");
               APP_LOG_INF("Generated UUID: %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                  u8ar_UUID[0], u8ar_UUID[1], u8ar_UUID[2], u8ar_UUID[3],
                  u8ar_UUID[4], u8ar_UUID[5],
                  u8ar_UUID[6], u8ar_UUID[7],
                  u8ar_UUID[8], u8ar_UUID[9],
                  u8ar_UUID[10], u8ar_UUID[11], u8ar_UUID[12], u8ar_UUID[13], u8ar_UUID[14], u8ar_UUID[15]);

               // Fill this generated UUID to the CN field of the subject name
               sv_FormatUUIDString(u8ar_UUID, cpt_CN);

               // Assign subject name fields
               gst_CSRConfig.stpt_subjectNameField = sstar_subjectNameFields;

               // Generate CSR (in DER format)
               t_status = gt_DER_EncodeCSR(
                  gst_CSRConfig.stpt_subjectNameField,
                                                // Subject name field
                  gst_CSRConfig.t_subjectNameFieldCnt,
                                                // Number of subject name field
                  t_signingKeyID,               // Signing key ID
                  gst_CSRData.u8ar_CSR,       // CSR buffer
                  sizeof(gst_CSRData.u8ar_CSR),
                                                // CSR buffer length
                  &t_CSRLenDER                  // CSR buffer written length
               );

               // Check if CSR generation was successful
               if (t_status == PSA_SUCCESS)
               {
                  APP_LOG_INF("CSR generated successfully in DER format.");

                  // Note: The generated CSR in DER format is now available in
                  // gst_CSRData.u8ar_CSR with length t_CSRLenDER.
                  // It can be stored or used as needed.

                  // Mark the generated CSR as available in RAM
                  gst_CSRData.u8_isCSRGenerated = 1u;
                  gst_CSRData.u16_CSRLen = (uint16_t)t_CSRLenDER;

                  // Check if the generated CSR should be stored in trusted storage
                  if (gst_CSRConfig.b_isCSRAvailable == true)
                  {
                     // Store the generated CSR in trusted storage
                     t_status = st_StoreGeneratedCSR();

                     // Check if the generated CSR was stored successfully
                     if (t_status == PSA_SUCCESS)
                     {
                        APP_LOG_INF("Generated CSR is stored in trusted storage for future reuse.");
                        LOG_HEXDUMP_INF(gst_CSRData.u8ar_CSR, gst_CSRData.u16_CSRLen, "Generated CSR: ");
                     }
                     else
                     {
                        APP_LOG_ERR("Failed to store generated CSR in trusted storage: %d", t_status);
                     }
                  }
                  else
                  {
                     APP_LOG_INF("Generated CSR is not stored in trusted storage as per configuration.");
                     LOG_HEXDUMP_INF(gst_CSRData.u8ar_CSR, gst_CSRData.u16_CSRLen, "Generated CSR: ");
                  }
               }
               else
               {
                  APP_LOG_ERR("Failed to generate CSR: %d", t_status);
               }
            }
            else
            {
               APP_LOG_ERR("Failed to generate UUID: %d", t_status);
            }
         }
         else
         {
            APP_LOG_ERR("Failed to generate device signing key: %d", t_status);
         }
      }

      // Note: PSA 1.x has no psa_close_key(). A persistent key needs no
      // closing; it stays addressable by its ID.
   }
}

/**
 * @public        gt_CalculateSHA1
 * @brief         Calculate SHA-1 u8pt_hash.
 * @param[in]     u8pt_data Pointer to input data.
 * @param[in]     t_len Length of input data.
 * @param[out]    u8pt_hash Pointer to output hash buffer.
 * @return        PSA_SUCCESS upon successful hash calculation, or an error code otherwise.
 */
psa_status_t gt_CalculateSHA1(const uint8_t *u8pt_data, size_t t_len, uint8_t *u8pt_hash)
{
   size_t t_outputLen = 0;
   uint8_t u8ar_result[CRYPTO_SHA_1_LEN] = { 0 };
   psa_status_t t_retVal = PSA_ERROR_GENERIC_ERROR;

   // Check if input parameters are valid
   if (!u8pt_data || !t_len  || !u8pt_hash)
   {
      APP_LOG_ERR("Invalid argument(s) for SHA-1 calculation");
      t_retVal = PSA_ERROR_INVALID_ARGUMENT;
   }
   else
   {
      // Set up the hash operation
      t_retVal = psa_hash_compute(PSA_ALG_SHA_1, u8pt_data, t_len, u8ar_result, CRYPTO_SHA_1_LEN, &t_outputLen);

      // Check if hash finalization was successful and output length is as expected
      if (PSA_SUCCESS == t_retVal)
      {
         memcpy(u8pt_hash, u8ar_result, CRYPTO_SHA_1_LEN);
      }
      else
      {
         APP_LOG_ERR("Failed to calculate SHA-1. Error status: %d", t_retVal);
      }
   }

   return t_retVal;
}

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shivam Chudasama [SC]
 */
