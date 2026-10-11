/**
 * @file          UdsJob.h
 * @brief         Header file containing the UDS job engine: one thread that runs
 *                one UDS job at a time against the target ECU (CAN configuration
 *                and addressing): a diagnostic request, a SecurityAccess unlock,
 *                or a flash job, which downloads a stored file
 *                (/FLASH_DISK:/FW/<name>, records [u32 addr][u32 len][data]) with
 *                one parameterised ISO 14229 programming sequence. It knows nothing
 *                about BLE: requests come in through these functions, results go
 *                out through callbacks on the job thread. Contract:
 *                _DOC/UDS/README.md.
 * @date          12/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#ifndef _UDS_JOB_H
#define _UDS_JOB_H

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "UdsClient.h"
#include "CanIf.h"

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
/**
 * @def           UDS_FF_*
 * @brief         UdsFlashParams_T.u16_flags: the optional steps of the sequence.
 */
#define UDS_FF_EXT_SESSION                   (0x0001U)   /**< 10 03 first.                     */
#define UDS_FF_DTC_OFF                       (0x0002U)   /**< 85 02.                           */
#define UDS_FF_COMM_OFF                      (0x0004U)   /**< 28 <control> <type>.             */
#define UDS_FF_SECURITY                      (0x0008U)   /**< 27 <level> / <level + 1>.        */
#define UDS_FF_FINGERPRINT                   (0x0010U)   /**< 2E <DID> <data>.                 */
#define UDS_FF_ERASE                         (0x0020U)   /**< 31 01 <erase RID>.               */
#define UDS_FF_ERASE_PER_RECORD              (0x0040U)   /**< ... per record, with addr/size.  */
#define UDS_FF_CHECK                         (0x0080U)   /**< 31 01 <check RID>.               */
#define UDS_FF_CHECK_CRC                     (0x0100U)   /**< ... with the image's CRC-32.     */
#define UDS_FF_RESET                         (0x0200U)   /**< 11 <type> at the end.            */
#define UDS_FF_ALL                           (0x03FFU)

/**
 * @def           UDS_FP_MAX
 * @brief         Longest fingerprint record.
 */
#define UDS_FP_MAX                           (16U)

/**
 * @def           UDS_FILE_NAME_MAX
 * @brief         Longest file name (as for a stored upload).
 */
#define UDS_FILE_NAME_MAX                    (32U)

/**
 * @def           UDS_FILE_DIR
 * @brief         Where flash files are, the stored uploads' folder.
 */
#define UDS_FILE_DIR                         "/FLASH_DISK:/FW/"

/**
 * @def           UDS_JOB_REQ_MAX
 * @brief         Longest diagnostic request (what fits a DIAG_REQ message).
 */
#define UDS_JOB_REQ_MAX                      (240U)

/**
 * @def           UDS_REC_MAX
 * @brief         Most records a flash file may hold.
 */
#define UDS_REC_MAX                          (255U)

/******************************************************************************/
/*                                                                            */
/*                                   ENUMS                                    */
/*                                                                            */
/******************************************************************************/
/**
 * @enum          UdsResult_E
 * @brief         Outcome of a request or job (the status codes on the wire,
 *                _DOC/UDS/PROTOCOL.md).
 */
typedef enum
{
   eUDS_OK            = 0,                   /**< Done (or accepted).                  */
   eUDS_BUSY          = 1,                   /**< Another job runs, or the file is in use. */
   eUDS_BAD_ARG       = 2,                   /**< Invalid request or parameters.       */
   eUDS_BAD_STATE     = 3,                   /**< Not possible now (e.g. no job to abort). */
   eUDS_NOT_READY     = 4,                   /**< No CAN controller, or no target set. */
   eUDS_NRC           = 5,                   /**< The ECU answered negatively.         */
   eUDS_TIMEOUT       = 6,                   /**< The ECU did not answer in time.      */
   eUDS_TRANSPORT     = 7,                   /**< ISO-TP / CAN error.                  */
   eUDS_BUS_OFF       = 8,                   /**< The CAN controller went bus-off.     */
   eUDS_FILE          = 9,                   /**< File missing, unreadable or malformed. */
   eUDS_ABORTED       = 10,                  /**< Aborted by the host.                 */
   eUDS_NOT_SUPPORTED = 11,                  /**< Unknown key algorithm, FD, padding.  */
} UdsResult_E;

/**
 * @enum          UdsJobState_E
 * @brief         State of the flash job.
 */
typedef enum
{
   eUDS_STATE_IDLE    = 0,
   eUDS_STATE_RUNNING = 1,
   eUDS_STATE_DONE    = 2,
   eUDS_STATE_FAILED  = 3,
   eUDS_STATE_ABORTED = 4,
} UdsJobState_E;

/**
 * @enum          UdsJobStep_E
 * @brief         Step of the flash job (the last one started).
 */
typedef enum
{
   eUDS_STEP_NONE         = 0,
   eUDS_STEP_EXT_SESSION  = 1,
   eUDS_STEP_DTC_OFF      = 2,
   eUDS_STEP_COMM_OFF     = 3,
   eUDS_STEP_PROG_SESSION = 4,
   eUDS_STEP_SECURITY     = 5,
   eUDS_STEP_FINGERPRINT  = 6,
   eUDS_STEP_ERASE        = 7,
   eUDS_STEP_DOWNLOAD     = 8,
   eUDS_STEP_TRANSFER     = 9,
   eUDS_STEP_EXIT         = 10,
   eUDS_STEP_CHECK        = 11,
   eUDS_STEP_RESET        = 12,
   eUDS_STEP_DONE         = 13,
} UdsJobStep_E;

/******************************************************************************/
/*                                                                            */
/*                                 STRUCTURES                                 */
/*                                                                            */
/******************************************************************************/
/**
 * @struct        UdsJobTarget_T
 * @brief         The ECU: CAN configuration (applied with gi_CanIf_Configure())
 *                and UDS addressing.
 */
typedef struct
{
   CanIfConfig_T st_can;                     /**< Mode and bitrates.                   */
   UdsTarget_T st_uds;                       /**< IDs, flags, frame length, timing.    */
} UdsJobTarget_T;

/**
 * @struct        UdsFlashParams_T
 * @brief         Parameters of the programming sequence (_DOC/UDS/README.md).
 */
typedef struct
{
   uint16_t u16_flags;                       /**< UDS_FF_* steps.                      */
   uint8_t u8_securityLevel;                 /**< requestSeed level (odd).             */
   uint8_t u8_keyAlgo;                       /**< UDS_KEY_ALGO_*.                      */
   uint8_t u8_commControl;                   /**< 0x28 controlType.                    */
   uint8_t u8_commType;                      /**< 0x28 communicationType.              */
   uint8_t u8_resetType;                     /**< 0x11 resetType.                      */
   uint8_t u8_alfid;                         /**< addressAndLengthFormatIdentifier.    */
   uint8_t u8_dfi;                           /**< dataFormatIdentifier.                */
   uint16_t u16_eraseRid;                    /**< Erase routine identifier.            */
   uint16_t u16_checkRid;                    /**< Check routine identifier.            */
   uint16_t u16_maxBlock;                    /**< Cap on TransferData request length
                                                  (0: the ECU's).                      */
   uint16_t u16_fingerprintDid;              /**< Fingerprint DID.                     */
   uint8_t u8_fingerprintLen;                /**< Fingerprint length (1..16).          */
   uint8_t u8ar_fingerprint[UDS_FP_MAX];     /**< Fingerprint record.                  */
} UdsFlashParams_T;

/**
 * @struct        UdsJobStatus_T
 * @brief         Progress of the flash job.
 */
typedef struct
{
   uint8_t u8_state;                         /**< UdsJobState_E.                       */
   uint8_t u8_step;                          /**< UdsJobStep_E.                        */
   uint8_t u8_recIdx;                        /**< Record being written (0-based).      */
   uint8_t u8_recCnt;                        /**< Records in the file.                 */
   uint32_t u32_done;                        /**< Data bytes transferred.              */
   uint32_t u32_total;                       /**< Data bytes in the file.              */
   uint8_t u8_lastSid;                       /**< SID of the last request.             */
   uint8_t u8_lastNrc;                       /**< NRC of the last request (0: none).   */
   uint8_t u8_result;                        /**< UdsResult_E (eUDS_OK while running). */
} UdsJobStatus_T;

/**
 * @typedef       UdsJobResult_F
 * @brief         Result of a target, diagnostic or unlock request, on the job
 *                thread.
 * @param[in]     u8_result UdsResult_E.
 * @param[in]     u8pt_data Diagnostic: the ECU's response (positive, or 7F SID
 *                NRC); unlock: the NRC; NULL otherwise. Valid during the call.
 * @param[in]     t_len Its length.
 * @param[in]     vpt_user The user pointer of the request.
 */
typedef void (*UdsJobResult_F)(uint8_t u8_result, const uint8_t *u8pt_data, size_t t_len, void *vpt_user);

/**
 * @typedef       UdsJobStatus_F
 * @brief         Progress of a flash job, on the job thread: at every step, at most
 *                every UDS_STATUS_PERIOD_MS during a transfer, and at the end.
 * @param[in]     stpt_status Status (valid during the call).
 * @param[in]     vpt_user The user pointer of gu8_UdsJob_Flash().
 */
typedef void (*UdsJobStatus_F)(const UdsJobStatus_T *stpt_status, void *vpt_user);

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
extern int gi_UdsJob_Init(void);
extern uint8_t gu8_UdsJob_SetTarget(const UdsJobTarget_T *stpt_target, UdsJobResult_F fpt_done, void *vpt_user);
extern uint8_t gu8_UdsJob_Diag(const uint8_t *u8pt_req, size_t t_len, bool b_functional, UdsJobResult_F fpt_done,
   void *vpt_user);
extern uint8_t gu8_UdsJob_Unlock(uint8_t u8_level, uint8_t u8_algo, UdsJobResult_F fpt_done, void *vpt_user);
extern uint8_t gu8_UdsJob_Flash(const char *cpt_name, size_t t_nameLen, const UdsFlashParams_T *stpt_params,
   UdsJobStatus_F fpt_status, void *vpt_user);
extern uint8_t gu8_UdsJob_Abort(void);
extern void gv_UdsJob_GetStatus(UdsJobStatus_T *stpt_status);
extern bool gb_UdsJob_FileOpen(void);

#endif //!_UDS_JOB_H

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shivam Chudasama [SC]
 */
