/**
 * @file          UdsJob.c
 * @brief         Source file containing the UDS job engine. One thread runs one job
 *                at a time: applying a target (CAN configuration through CanIf, then
 *                UDS addressing), a diagnostic request, a SecurityAccess unlock, or
 *                a flash job. Between jobs it keeps a non-default session alive.
 *
 *                A flash job first reads the whole file (/FLASH_DISK:/FW/<name>) to
 *                check its records and compute the image's CRC-32, so a bad file
 *                never reaches the ECU. It then locks the bus (CanIf), turns the
 *                traffic log off, and runs the programming sequence of its
 *                parameters, reading the file again block by block. Bus-off and an
 *                abort from the host stop it between requests. At the end the bus
 *                is restored, and after a failure the session is no longer kept
 *                alive. Contract: _DOC/UDS/README.md.
 * @date          12/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include "UdsJob.h"
#include <errno.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/crc.h>
#include "UdsTp_Isotp.h"
#include "UdsKey.h"
#include "FileSysManager.h"
#include "DataStore.h"
#include "AppLog.h"

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
#ifndef CONFIG_UDS_RESPONSE_MAX
#define CONFIG_UDS_RESPONSE_MAX              (1024)
#endif // CONFIG_UDS_RESPONSE_MAX
#ifndef CONFIG_UDS_FLASH_BLOCK_MAX
#define CONFIG_UDS_FLASH_BLOCK_MAX           (2048)
#endif // CONFIG_UDS_FLASH_BLOCK_MAX
#ifndef CONFIG_UDS_JOB_STACK_SIZE
#define CONFIG_UDS_JOB_STACK_SIZE            (3072)
#endif // CONFIG_UDS_JOB_STACK_SIZE
#ifndef CONFIG_UDS_JOB_PRIORITY
#define CONFIG_UDS_JOB_PRIORITY              (7)
#endif // CONFIG_UDS_JOB_PRIORITY

/**
 * @def           UDS_STATUS_PERIOD_MS
 * @brief         Most often the progress is reported during a transfer.
 */
#define UDS_STATUS_PERIOD_MS                 (250)

/**
 * @def           UDS_JOB_QUEUE_LEN
 * @brief         Requests the job thread queues (one runs at a time).
 */
#define UDS_JOB_QUEUE_LEN                    (2U)

/**
 * @def           UDS_REC_HDR_LEN
 * @brief         [u32 LE address][u32 LE length] in front of each record's data.
 */
#define UDS_REC_HDR_LEN                      (8U)

/**
 * @def           UDS_PATH_MAX
 * @brief         Longest path of a flash file.
 */
#define UDS_PATH_MAX                         (sizeof(UDS_FILE_DIR) - 1U + UDS_FILE_NAME_MAX)

BUILD_ASSERT(CONFIG_UDS_FLASH_BLOCK_MAX >= 16, "UDS_FLASH_BLOCK_MAX too small");

/******************************************************************************/
/*                                                                            */
/*                                   ENUMS                                    */
/*                                                                            */
/******************************************************************************/
/**
 * @enum          UdsJobType_E
 * @brief         What a queued request asks for.
 */
typedef enum
{
   eUDS_JOB_TARGET = 0,
   eUDS_JOB_DIAG   = 1,
   eUDS_JOB_UNLOCK = 2,
   eUDS_JOB_FLASH  = 3,
} UdsJobType_E;

/******************************************************************************/
/*                                                                            */
/*                                 STRUCTURES                                 */
/*                                                                            */
/******************************************************************************/
/**
 * @struct        UdsJobMsg_T
 * @brief         A request for the job thread.
 */
typedef struct
{
   uint8_t u8_type;                          /**< UdsJobType_E.                        */
   bool b_functional;                        /**< Diagnostic: functional request.      */
   uint8_t u8_level;                         /**< Unlock: requestSeed level.           */
   uint8_t u8_algo;                          /**< Unlock: key algorithm.               */
   uint16_t u16_len;                         /**< Diagnostic: request length.          */
   union
   {
      UdsJobTarget_T st_target;              /**< Target.                              */
      uint8_t u8ar_req[UDS_JOB_REQ_MAX];     /**< Diagnostic request.                  */
      struct
      {
         UdsFlashParams_T st_params;         /**< Flash: sequence parameters.          */
         char car_name[UDS_FILE_NAME_MAX + 1U]; /**< Flash: file name.                 */
      } st_flash;
   } u;
   UdsJobResult_F fpt_done;                  /**< Result (target, diagnostic, unlock). */
   UdsJobStatus_F fpt_status;                /**< Progress (flash).                    */
   void *vpt_user;                           /**< For the callback.                    */
} UdsJobMsg_T;

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
static void sv_OnCanState(enum can_state e_state, const struct can_bus_err_cnt *stpt_errCnt, void *vpt_user);
static uint8_t su8_MapClient(int i_ret, bool b_job);
static uint8_t su8_Post(const UdsJobMsg_T *stpt_msg);
static bool sb_ValidName(const char *cpt_name, size_t t_len);
static bool sb_PutField(uint8_t *u8pt_dst, uint32_t u32_value, uint8_t u8_bytes);
static void sv_OnFsResult(const FsmgrResult_T *stpt_result, void *vpt_user);
static uint8_t su8_FileOpen(const char *cpt_name);
static void sv_FileClose(void);
static int si_FileRead(uint8_t *u8pt_dst, uint32_t u32_len);
static void sv_SetStep(UdsJobStep_E e_step);
static void sv_Report(bool b_force);
static uint8_t su8_Check(int i_ret);
static uint8_t su8_ScanFile(const char *cpt_name, uint8_t *u8pt_recCnt, uint32_t *u32pt_total, uint32_t *u32pt_crc);
static uint8_t su8_Download(const UdsFlashParams_T *stpt_params, const char *cpt_name, uint8_t u8_recCnt);
static uint8_t su8_Sequence(const UdsFlashParams_T *stpt_params, const char *cpt_name, uint8_t u8_recCnt,
   uint32_t u32_crc);
static void sv_RunFlash(const UdsJobMsg_T *stpt_msg);
static uint8_t su8_ApplyTarget(const UdsJobTarget_T *stpt_target);
static void sv_HandleMsg(const UdsJobMsg_T *stpt_msg);
static void sv_JobStep(void);
static void sv_UdsJobThread(void *vpt_p1, void *vpt_p2, void *vpt_p3);

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
 * @var           sst_jobTp / sst_jobTpCtx / sst_client
 * @brief         The ISO-TP transport and the UDS client (job thread only).
 */
static UdsTp_T sst_jobTp;
static UdsTpIsotp_T sst_jobTpCtx;
static UdsClient_T sst_client;

/**
 * @var           sb_clientReady
 * @brief         The transport and client are set up (on the first target).
 */
static bool sb_clientReady = false;

/**
 * @var           sb_targetSet
 * @brief         A target is applied.
 */
static bool sb_targetSet = false;

/**
 * @var           st_busy
 * @brief         Set from accepting a request until its result is out.
 */
static atomic_t st_busy = ATOMIC_INIT(0);

/**
 * @var           st_abort
 * @brief         The host asked the flash job to stop.
 */
static atomic_t st_abort = ATOMIC_INIT(0);

/**
 * @var           st_busOff
 * @brief         The CAN controller is bus-off (CanIf state listener).
 */
static atomic_t st_busOff = ATOMIC_INIT(0);

/**
 * @var           st_fileOpen
 * @brief         The flash job holds the File System Manager's open file.
 */
static atomic_t st_fileOpen = ATOMIC_INIT(0);

/**
 * @var           sst_status
 * @brief         Progress of the flash job. Guarded by sst_statusMutex.
 */
static UdsJobStatus_T sst_status;

/**
 * @var           sfpt_status / svpt_statusUser / si64_lastReportMs
 * @brief         Where and when the progress was last reported.
 */
static UdsJobStatus_F sfpt_status = NULL;
static void *svpt_statusUser = NULL;
static int64_t si64_lastReportMs = 0;

/**
 * @var           su8ar_rsp
 * @brief         A diagnostic response.
 */
static uint8_t su8ar_rsp[CONFIG_UDS_RESPONSE_MAX];

/**
 * @var           su8ar_block
 * @brief         One TransferData request: 2 header bytes, then data.
 */
static uint8_t su8ar_block[CONFIG_UDS_FLASH_BLOCK_MAX];

/**
 * @var           sst_fsMsg
 * @brief         File System Manager message (job thread only).
 */
static FileSysMessage_T sst_fsMsg;

/**
 * @var           su8pt_readDst / su32_readMax / su32_readLen / si_readStatus
 * @brief         The read in progress and its result.
 */
static uint8_t *su8pt_readDst = NULL;
static uint32_t su32_readMax = 0U;
static uint32_t su32_readLen = 0U;
static int si_readStatus = 0;

/**
 * @var           sst_readSem
 * @brief         Given when a read's result is in.
 */
static K_SEM_DEFINE(sst_readSem, 0, 1);

/**
 * @var           sst_statusMutex
 * @brief         Guards sst_status.
 */
static K_MUTEX_DEFINE(sst_statusMutex);

/**
 * @var           sst_udsJobQ
 * @brief         Requests for the job thread.
 */
K_MSGQ_DEFINE(sst_udsJobQ, sizeof(UdsJobMsg_T), UDS_JOB_QUEUE_LEN, 4);

/**
 * @var           sst_udsJobThread
 * @brief         The job thread.
 */
K_THREAD_DEFINE(sst_udsJobThread, CONFIG_UDS_JOB_STACK_SIZE, sv_UdsJobThread, NULL, NULL, NULL,
   CONFIG_UDS_JOB_PRIORITY, 0, 0);

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
 * @private       sv_OnCanState
 * @brief         CanIfState_F: follow bus-off (a running flash job stops).
 * @param[in]     e_state New state.
 * @param[in]     stpt_errCnt Unused.
 * @param[in]     vpt_user Unused.
 * @return        None.
 */
static void sv_OnCanState(enum can_state e_state, const struct can_bus_err_cnt *stpt_errCnt, void *vpt_user)
{
   ARG_UNUSED(stpt_errCnt);
   ARG_UNUSED(vpt_user);

   (void)atomic_set(&st_busOff, (e_state == CAN_STATE_BUS_OFF) ? 1 : 0);
}

/**
 * @private       su8_MapClient
 * @brief         The result for a UDS client return value.
 * @param[in]     i_ret 0, an NRC, or a negative errno.
 * @param[in]     b_job Inside a flash job (an abort counts).
 * @return        UdsResult_E.
 */
static uint8_t su8_MapClient(int i_ret, bool b_job)
{
   if (i_ret == 0)
   {
      return eUDS_OK;
   }
   if (b_job && (atomic_get(&st_abort) != 0))
   {
      return eUDS_ABORTED;
   }
   if (atomic_get(&st_busOff) != 0)
   {
      return eUDS_BUS_OFF;
   }
   if (i_ret > 0)
   {
      return eUDS_NRC;
   }

   switch (i_ret)
   {
      case -ETIMEDOUT: return eUDS_TIMEOUT;
      case -EINVAL:    return eUDS_BAD_ARG;
      case -ENOTCONN:  return eUDS_NOT_READY;
      case -ENOTSUP:   return eUDS_NOT_SUPPORTED;
      default:         return eUDS_TRANSPORT;
   }
}

/**
 * @private       su8_Post
 * @brief         Hand a request to the job thread, unless one is in progress.
 * @param[in]     stpt_msg Request.
 * @return        eUDS_OK (accepted) or eUDS_BUSY.
 */
static uint8_t su8_Post(const UdsJobMsg_T *stpt_msg)
{
   if (!atomic_cas(&st_busy, 0, 1))
   {
      return eUDS_BUSY;
   }
   if (k_msgq_put(&sst_udsJobQ, stpt_msg, K_NO_WAIT) != 0)
   {
      (void)atomic_set(&st_busy, 0);
      return eUDS_BUSY;
   }
   return eUDS_OK;
}

/**
 * @private       sb_ValidName
 * @brief         Whether a flash file name is valid: 1..32 characters from
 *                A-Z a-z 0-9 . _ -, not "." or "..".
 * @param[in]     cpt_name Name (not terminated).
 * @param[in]     t_len Its length.
 * @return        true if valid.
 */
static bool sb_ValidName(const char *cpt_name, size_t t_len)
{
   size_t i;
   char c;

   if ((cpt_name == NULL) || (t_len == 0U) || (t_len > UDS_FILE_NAME_MAX)
      || ((t_len == 1U) && (cpt_name[0] == '.')) || ((t_len == 2U) && (cpt_name[0] == '.') && (cpt_name[1] == '.')))
   {
      return false;
   }
   for (i = 0U; i < t_len; i++)
   {
      c = cpt_name[i];
      if (!(((c >= 'A') && (c <= 'Z')) || ((c >= 'a') && (c <= 'z')) || ((c >= '0') && (c <= '9'))
         || (c == '.') || (c == '_') || (c == '-')))
      {
         return false;
      }
   }
   return true;
}

/**
 * @private       sb_PutField
 * @brief         Write a value big-endian in u8_bytes bytes, if it fits.
 * @param[out]    u8pt_dst Destination.
 * @param[in]     u32_value Value.
 * @param[in]     u8_bytes 1..4.
 * @return        false if the value needs more bytes.
 */
static bool sb_PutField(uint8_t *u8pt_dst, uint32_t u32_value, uint8_t u8_bytes)
{
   uint8_t i;

   if ((u8_bytes < 4U) && ((u32_value >> (8U * u8_bytes)) != 0U))
   {
      return false;
   }
   for (i = 0U; i < u8_bytes; i++)
   {
      u8pt_dst[i] = (uint8_t)(u32_value >> (8U * (u8_bytes - 1U - i)));
   }
   return true;
}

/**
 * @private       sv_OnFsResult
 * @brief         FsmgrResult_F of a read: copy the data, wake the job thread.
 * @param[in]     stpt_result Result.
 * @param[in]     vpt_user Unused.
 * @return        None.
 */
static void sv_OnFsResult(const FsmgrResult_T *stpt_result, void *vpt_user)
{
   ARG_UNUSED(vpt_user);

   if (!stpt_result->b_final)
   {
      return;
   }
   si_readStatus = stpt_result->i_status;
   su32_readLen = 0U;
   if ((stpt_result->i_status == 0) && (stpt_result->u8pt_data != NULL))
   {
      su32_readLen = MIN(stpt_result->u32_len, su32_readMax);
      memcpy(su8pt_readDst, stpt_result->u8pt_data, su32_readLen);
   }
   k_sem_give(&sst_readSem);
}

/**
 * @private       su8_FileOpen
 * @brief         Open UDS_FILE_DIR<name> for reading.
 * @param[in]     cpt_name Name (checked, terminated).
 * @return        eUDS_OK; eUDS_BUSY if the File System Manager has another file
 *                open or is busy; eUDS_FILE otherwise (missing, not mounted, …).
 */
static uint8_t su8_FileOpen(const char *cpt_name)
{
   size_t t_dirLen = sizeof(UDS_FILE_DIR) - 1U;
   size_t t_nameLen = strlen(cpt_name);
   uint8_t u8_code;
   int i_ret;

   memset(&sst_fsMsg, 0, sizeof(sst_fsMsg));
   sst_fsMsg.e_command = eFSC_OPEN_FILE_READ;
   memcpy(sst_fsMsg.u8_data, UDS_FILE_DIR, t_dirLen);
   memcpy(&sst_fsMsg.u8_data[t_dirLen], cpt_name, t_nameLen);
   sst_fsMsg.u32_sizeOfData = (uint32_t)(t_dirLen + t_nameLen);

   i_ret = gi_FSMGR_Call(&sst_fsMsg);
   if (i_ret == 0)
   {
      (void)atomic_set(&st_fileOpen, 1);
      return eUDS_OK;
   }

   APP_LOG_WRN("%s%s not opened (%d)", UDS_FILE_DIR, cpt_name, i_ret);
   u8_code = gu8_FSMGR_StatusCode(i_ret);
   return ((u8_code == (uint8_t)eFSS_BAD_STATE) || (u8_code == (uint8_t)eFSS_BUSY)) ? eUDS_BUSY : eUDS_FILE;
}

/**
 * @private       sv_FileClose
 * @brief         Close the file (if open).
 * @return        None.
 */
static void sv_FileClose(void)
{
   if (atomic_get(&st_fileOpen) == 0)
   {
      return;
   }
   memset(&sst_fsMsg, 0, sizeof(sst_fsMsg));
   sst_fsMsg.e_command = eFSC_CLOSE_FILE;
   (void)gi_FSMGR_Call(&sst_fsMsg);
   (void)atomic_set(&st_fileOpen, 0);
}

/**
 * @private       si_FileRead
 * @brief         Read up to u32_len bytes from the open file, a File System Manager
 *                read (at most FS_MAX_CHUNK_SIZE) at a time.
 * @param[out]    u8pt_dst Destination.
 * @param[in]     u32_len Bytes wanted.
 * @return        Bytes read (fewer at the end of the file), or a negative errno.
 */
static int si_FileRead(uint8_t *u8pt_dst, uint32_t u32_len)
{
   uint32_t u32_got = 0U;
   uint32_t u32_chunk;
   int i_ret;

   while (u32_got < u32_len)
   {
      u32_chunk = MIN(u32_len - u32_got, FS_MAX_CHUNK_SIZE);
      memset(&sst_fsMsg, 0, sizeof(sst_fsMsg));
      sst_fsMsg.e_command = eFSC_READ_FILE;
      sst_fsMsg.u32_sizeOfData = u32_chunk;
      su8pt_readDst = &u8pt_dst[u32_got];
      su32_readMax = u32_chunk;
      k_sem_reset(&sst_readSem);

      i_ret = gi_FSMGR_Submit(&sst_fsMsg, sv_OnFsResult, NULL, K_FOREVER);
      if (i_ret != 0)
      {
         return i_ret;
      }
      (void)k_sem_take(&sst_readSem, K_FOREVER);
      if (si_readStatus != 0)
      {
         return si_readStatus;
      }

      // Check if the end of the file was reached
      if (su32_readLen == 0U)
      {
         break;
      }
      u32_got += su32_readLen;
   }

   return (int)u32_got;
}

/**
 * @private       sv_SetStep
 * @brief         Enter a step and report it.
 * @param[in]     e_step Step.
 * @return        None.
 */
static void sv_SetStep(UdsJobStep_E e_step)
{
   (void)k_mutex_lock(&sst_statusMutex, K_FOREVER);
   sst_status.u8_step = (uint8_t)e_step;
   (void)k_mutex_unlock(&sst_statusMutex);
   sv_Report(true);
}

/**
 * @private       sv_Report
 * @brief         Report the progress: always when forced, else at most every
 *                UDS_STATUS_PERIOD_MS.
 * @param[in]     b_force Report now.
 * @return        None.
 */
static void sv_Report(bool b_force)
{
   UdsJobStatus_T st_copy;
   int64_t i64_now = k_uptime_get();

   if (!b_force && ((i64_now - si64_lastReportMs) < UDS_STATUS_PERIOD_MS))
   {
      return;
   }
   si64_lastReportMs = i64_now;

   (void)k_mutex_lock(&sst_statusMutex, K_FOREVER);
   sst_status.u8_lastSid = gu8_UdsClient_LastSid(&sst_client);
   sst_status.u8_lastNrc = gu8_UdsClient_LastNrc(&sst_client);
   st_copy = sst_status;
   (void)k_mutex_unlock(&sst_statusMutex);

   if (sfpt_status != NULL)
   {
      sfpt_status(&st_copy, svpt_statusUser);
   }
}

/**
 * @private       su8_Check
 * @brief         The result of a UDS step inside the flash job; an abort asked for
 *                meanwhile wins over success, so the job stops between requests.
 * @param[in]     i_ret The client's return value.
 * @return        UdsResult_E.
 */
static uint8_t su8_Check(int i_ret)
{
   if ((i_ret == 0) && (atomic_get(&st_abort) != 0))
   {
      return eUDS_ABORTED;
   }
   return su8_MapClient(i_ret, true);
}

/**
 * @private       su8_ScanFile
 * @brief         Read the whole file: check its records, count them and their
 *                data, and compute the CRC-32 of the data.
 * @param[in]     cpt_name File name.
 * @param[out]    u8pt_recCnt Records.
 * @param[out]    u32pt_total Data bytes.
 * @param[out]    u32pt_crc CRC-32 (IEEE) of the records' data in order.
 * @return        eUDS_OK; as su8_FileOpen(); eUDS_FILE for no records, a cut
 *                header or record, an empty record, more than UDS_REC_MAX records
 *                or a read error.
 */
static uint8_t su8_ScanFile(const char *cpt_name, uint8_t *u8pt_recCnt, uint32_t *u32pt_total, uint32_t *u32pt_crc)
{
   uint8_t u8ar_hdr[UDS_REC_HDR_LEN];
   uint8_t u8_result;
   uint32_t u32_count = 0U;
   uint32_t u32_left;
   uint32_t u32_chunk;
   int i_ret;

   *u8pt_recCnt = 0U;
   *u32pt_total = 0U;
   *u32pt_crc = 0U;

   u8_result = su8_FileOpen(cpt_name);
   if (u8_result != eUDS_OK)
   {
      return u8_result;
   }

   while (u8_result == eUDS_OK)
   {
      i_ret = si_FileRead(u8ar_hdr, UDS_REC_HDR_LEN);
      if (i_ret == 0)
      {
         break;
      }
      u32_left = (i_ret == (int)UDS_REC_HDR_LEN) ? sys_get_le32(&u8ar_hdr[4]) : 0U;
      if ((u32_left == 0U) || (u32_count >= UDS_REC_MAX))
      {
         APP_LOG_WRN("record %u: bad header (%d)", u32_count, i_ret);
         u8_result = eUDS_FILE;
         break;
      }
      *u32pt_total += u32_left;

      while (u32_left > 0U)
      {
         u32_chunk = MIN(u32_left, (uint32_t)sizeof(su8ar_block));
         i_ret = si_FileRead(su8ar_block, u32_chunk);
         if (i_ret != (int)u32_chunk)
         {
            APP_LOG_WRN("record %u: data cut short (%d)", u32_count, i_ret);
            u8_result = eUDS_FILE;
            break;
         }
         *u32pt_crc = crc32_ieee_update(*u32pt_crc, su8ar_block, u32_chunk);
         u32_left -= u32_chunk;
      }
      u32_count++;
   }
   sv_FileClose();

   if ((u8_result == eUDS_OK) && (u32_count == 0U))
   {
      APP_LOG_WRN("%s holds no record", cpt_name);
      u8_result = eUDS_FILE;
   }
   *u8pt_recCnt = (uint8_t)u32_count;

   return u8_result;
}

/**
 * @private       su8_Download
 * @brief         Per record: optional erase, RequestDownload, TransferData blocks,
 *                RequestTransferExit. The file was checked by su8_ScanFile().
 * @param[in]     stpt_params Parameters.
 * @param[in]     cpt_name File name.
 * @param[in]     u8_recCnt Records.
 * @return        UdsResult_E.
 */
static uint8_t su8_Download(const UdsFlashParams_T *stpt_params, const char *cpt_name, uint8_t u8_recCnt)
{
   uint8_t u8_addrLen = (uint8_t)(stpt_params->u8_alfid & 0x0FU);
   uint8_t u8_sizeLen = (uint8_t)(stpt_params->u8_alfid >> 4);
   uint8_t u8ar_hdr[UDS_REC_HDR_LEN];
   uint8_t u8ar_args[1U + 4U + 4U];
   uint8_t u8_result;
   uint8_t u8_rec;
   uint8_t u8_bsc;
   uint32_t u32_address;
   uint32_t u32_left;
   uint32_t u32_max = 0U;
   uint32_t u32_block;
   uint32_t u32_chunk;
   int i_ret;

   u8_result = su8_FileOpen(cpt_name);
   for (u8_rec = 0U; (u8_rec < u8_recCnt) && (u8_result == eUDS_OK); u8_rec++)
   {
      (void)k_mutex_lock(&sst_statusMutex, K_FOREVER);
      sst_status.u8_recIdx = u8_rec;
      (void)k_mutex_unlock(&sst_statusMutex);

      if (si_FileRead(u8ar_hdr, UDS_REC_HDR_LEN) != (int)UDS_REC_HDR_LEN)
      {
         u8_result = eUDS_FILE;
         break;
      }
      u32_address = sys_get_le32(u8ar_hdr);
      u32_left = sys_get_le32(&u8ar_hdr[4]);

      // Erase this record's memory: 31 01 <RID> <ALFID> <address> <size>
      if (((stpt_params->u16_flags & UDS_FF_ERASE) != 0U) && ((stpt_params->u16_flags & UDS_FF_ERASE_PER_RECORD) != 0U))
      {
         u8ar_args[0] = stpt_params->u8_alfid;
         if (!sb_PutField(&u8ar_args[1], u32_address, u8_addrLen)
            || !sb_PutField(&u8ar_args[1U + u8_addrLen], u32_left, u8_sizeLen))
         {
            u8_result = eUDS_BAD_ARG;
            break;
         }
         sv_SetStep(eUDS_STEP_ERASE);
         u8_result = su8_Check(gi_UdsClient_Routine(&sst_client, 0x01U, stpt_params->u16_eraseRid, u8ar_args,
            1U + u8_addrLen + u8_sizeLen, NULL, 0U, NULL));
         if (u8_result != eUDS_OK)
         {
            break;
         }
      }

      sv_SetStep(eUDS_STEP_DOWNLOAD);
      u8_result = su8_Check(gi_UdsClient_RequestDownload(&sst_client, stpt_params->u8_dfi, stpt_params->u8_alfid,
         u32_address, u32_left, &u32_max));
      if (u8_result != eUDS_OK)
      {
         break;
      }

      // Block: the ECU's maximum, capped by the parameters and the buffer
      u32_block = MIN(u32_max, (uint32_t)sizeof(su8ar_block));
      if (stpt_params->u16_maxBlock != 0U)
      {
         u32_block = MIN(u32_block, stpt_params->u16_maxBlock);
      }
      if (u32_block < 3U)
      {
         u8_result = eUDS_BAD_ARG;
         break;
      }

      sv_SetStep(eUDS_STEP_TRANSFER);
      u8_bsc = 1U;
      while ((u32_left > 0U) && (u8_result == eUDS_OK))
      {
         u32_chunk = MIN(u32_left, u32_block - 2U);
         i_ret = si_FileRead(&su8ar_block[2], u32_chunk);
         if (i_ret != (int)u32_chunk)
         {
            u8_result = eUDS_FILE;
            break;
         }
         u8_result = su8_Check(gi_UdsClient_TransferData(&sst_client, u8_bsc, su8ar_block, u32_chunk));
         u8_bsc++;
         u32_left -= u32_chunk;
         (void)k_mutex_lock(&sst_statusMutex, K_FOREVER);
         sst_status.u32_done += u32_chunk;
         (void)k_mutex_unlock(&sst_statusMutex);
         sv_Report(false);
      }
      if (u8_result != eUDS_OK)
      {
         break;
      }

      sv_SetStep(eUDS_STEP_EXIT);
      u8_result = su8_Check(gi_UdsClient_TransferExit(&sst_client));
   }
   sv_FileClose();

   return u8_result;
}

/**
 * @private       su8_Sequence
 * @brief         The programming sequence (see UdsJob.h, UDS_FF_*).
 * @param[in]     stpt_params Parameters.
 * @param[in]     cpt_name File name.
 * @param[in]     u8_recCnt Records in the file.
 * @param[in]     u32_crc CRC-32 of the image.
 * @return        UdsResult_E.
 */
static uint8_t su8_Sequence(const UdsFlashParams_T *stpt_params, const char *cpt_name, uint8_t u8_recCnt,
   uint32_t u32_crc)
{
   uint16_t u16_flags = stpt_params->u16_flags;
   uint8_t u8ar_crc[4];
   uint8_t u8_result = eUDS_OK;

   if ((u16_flags & UDS_FF_EXT_SESSION) != 0U)
   {
      sv_SetStep(eUDS_STEP_EXT_SESSION);
      u8_result = su8_Check(gi_UdsClient_Session(&sst_client, 0x03U));
   }
   if ((u8_result == eUDS_OK) && ((u16_flags & UDS_FF_DTC_OFF) != 0U))
   {
      sv_SetStep(eUDS_STEP_DTC_OFF);
      u8_result = su8_Check(gi_UdsClient_DtcSetting(&sst_client, 0x02U));
   }
   if ((u8_result == eUDS_OK) && ((u16_flags & UDS_FF_COMM_OFF) != 0U))
   {
      sv_SetStep(eUDS_STEP_COMM_OFF);
      u8_result = su8_Check(gi_UdsClient_CommControl(&sst_client, stpt_params->u8_commControl,
         stpt_params->u8_commType));
   }
   if (u8_result == eUDS_OK)
   {
      sv_SetStep(eUDS_STEP_PROG_SESSION);
      u8_result = su8_Check(gi_UdsClient_Session(&sst_client, 0x02U));
   }
   if ((u8_result == eUDS_OK) && ((u16_flags & UDS_FF_SECURITY) != 0U))
   {
      sv_SetStep(eUDS_STEP_SECURITY);
      u8_result = su8_Check(gi_UdsClient_SecurityAccess(&sst_client, stpt_params->u8_securityLevel,
         gi_UdsKey_Callback, (void *)(uintptr_t)stpt_params->u8_keyAlgo));
   }
   if ((u8_result == eUDS_OK) && ((u16_flags & UDS_FF_FINGERPRINT) != 0U))
   {
      sv_SetStep(eUDS_STEP_FINGERPRINT);
      u8_result = su8_Check(gi_UdsClient_WriteDid(&sst_client, stpt_params->u16_fingerprintDid,
         stpt_params->u8ar_fingerprint, stpt_params->u8_fingerprintLen));
   }
   if ((u8_result == eUDS_OK) && ((u16_flags & UDS_FF_ERASE) != 0U) && ((u16_flags & UDS_FF_ERASE_PER_RECORD) == 0U))
   {
      sv_SetStep(eUDS_STEP_ERASE);
      u8_result = su8_Check(gi_UdsClient_Routine(&sst_client, 0x01U, stpt_params->u16_eraseRid, NULL, 0U, NULL, 0U,
         NULL));
   }
   if (u8_result == eUDS_OK)
   {
      u8_result = su8_Download(stpt_params, cpt_name, u8_recCnt);
   }
   if (u8_result == eUDS_OK)
   {
      (void)k_mutex_lock(&sst_statusMutex, K_FOREVER);
      sst_status.u8_recIdx = u8_recCnt;
      (void)k_mutex_unlock(&sst_statusMutex);
   }
   if ((u8_result == eUDS_OK) && ((u16_flags & UDS_FF_CHECK) != 0U))
   {
      sv_SetStep(eUDS_STEP_CHECK);
      sys_put_be32(u32_crc, u8ar_crc);
      u8_result = su8_Check(gi_UdsClient_Routine(&sst_client, 0x01U, stpt_params->u16_checkRid, u8ar_crc,
         ((u16_flags & UDS_FF_CHECK_CRC) != 0U) ? sizeof(u8ar_crc) : 0U, NULL, 0U, NULL));
   }
   if ((u8_result == eUDS_OK) && ((u16_flags & UDS_FF_RESET) != 0U))
   {
      sv_SetStep(eUDS_STEP_RESET);
      u8_result = su8_Check(gi_UdsClient_EcuReset(&sst_client, stpt_params->u8_resetType));
   }

   return u8_result;
}

/**
 * @private       sv_RunFlash
 * @brief         A flash job: check the file, take the bus, run the sequence, give
 *                the bus back, report the outcome.
 * @param[in]     stpt_msg Request.
 * @return        None.
 */
static void sv_RunFlash(const UdsJobMsg_T *stpt_msg)
{
   const UdsFlashParams_T *stpt_params = &stpt_msg->u.st_flash.st_params;
   const char *cpt_name = stpt_msg->u.st_flash.car_name;
   CanIfStatus_T st_can;
   bool b_locked = false;
   bool b_monitor = false;
   uint8_t u8_recCnt = 0U;
   uint32_t u32_total = 0U;
   uint32_t u32_crc = 0U;
   uint8_t u8_result;

   sfpt_status = stpt_msg->fpt_status;
   svpt_statusUser = stpt_msg->vpt_user;
   APP_LOG_INF("flash %s%s", UDS_FILE_DIR, cpt_name);

   u8_result = su8_ScanFile(cpt_name, &u8_recCnt, &u32_total, &u32_crc);
   if (u8_result == eUDS_OK)
   {
      (void)k_mutex_lock(&sst_statusMutex, K_FOREVER);
      sst_status.u8_recCnt = u8_recCnt;
      sst_status.u32_total = u32_total;
      (void)k_mutex_unlock(&sst_statusMutex);
      APP_LOG_INF("%u records, %u bytes, CRC-32 %08x", u8_recCnt, u32_total, u32_crc);

      // The bus stays as it is for the whole job, and quiet
      if (gi_CanIf_Lock(&sst_client) != 0)
      {
         u8_result = eUDS_BUSY;
      }
      else
      {
         b_locked = true;
         if ((gi_CanIf_GetStatus(&st_can) == 0) && st_can.b_monitor)
         {
            b_monitor = true;
            gv_CanIf_SetMonitor(false);
         }
      }
   }

   if (u8_result == eUDS_OK)
   {
      u8_result = su8_Sequence(stpt_params, cpt_name, u8_recCnt, u32_crc);
   }

   // A failed job leaves the ECU to fall back to its default session
   if (u8_result != eUDS_OK)
   {
      gv_UdsClient_EndSession(&sst_client);
   }
   if (b_monitor)
   {
      gv_CanIf_SetMonitor(true);
   }
   if (b_locked)
   {
      (void)gi_CanIf_Unlock(&sst_client);
   }

   (void)k_mutex_lock(&sst_statusMutex, K_FOREVER);
   sst_status.u8_result = u8_result;
   if (u8_result == eUDS_OK)
   {
      sst_status.u8_state = (uint8_t)eUDS_STATE_DONE;
      sst_status.u8_step = (uint8_t)eUDS_STEP_DONE;
   }
   else
   {
      sst_status.u8_state = (uint8_t)((u8_result == eUDS_ABORTED) ? eUDS_STATE_ABORTED : eUDS_STATE_FAILED);
   }
   (void)k_mutex_unlock(&sst_statusMutex);

   if (u8_result == eUDS_OK)
   {
      APP_LOG_INF("flash %s done", cpt_name);
   }
   else
   {
      APP_LOG_WRN("flash %s failed: result %u, SID 0x%02x, NRC 0x%02x", cpt_name, u8_result,
         gu8_UdsClient_LastSid(&sst_client), gu8_UdsClient_LastNrc(&sst_client));
   }

   // Free the engine first: the host may start the next request on the final status
   (void)atomic_set(&st_abort, 0);
   (void)atomic_set(&st_busy, 0);
   sv_Report(true);
}

/**
 * @private       su8_ApplyTarget
 * @brief         Configure the CAN controller and point the client at the ECU.
 * @param[in]     stpt_target Target.
 * @return        eUDS_OK; eUDS_NOT_READY without a CAN controller; eUDS_BAD_ARG
 *                for a bad configuration or addressing; eUDS_NOT_SUPPORTED for a
 *                mode the controller lacks, extended addressing, or padding that
 *                differs from the build's; eUDS_BUSY if a session locked the bus;
 *                eUDS_TRANSPORT otherwise.
 */
static uint8_t su8_ApplyTarget(const UdsJobTarget_T *stpt_target)
{
   const struct device *stpt_can = gstpt_CanIf_GetDevice();
   bool b_pad = ((stpt_target->st_uds.u8_flags & UDS_TGT_PAD) != 0U);
   bool b_udsFd = ((stpt_target->st_uds.u8_flags & UDS_TGT_FD) != 0U);
   int i_ret;

   // A refused target leaves none
   sb_targetSet = false;
   if (stpt_can == NULL)
   {
      return eUDS_NOT_READY;
   }
   // ISO-TP pads (with 0xCC) exactly when the build says so
   if (b_pad != IS_ENABLED(CONFIG_ISOTP_ENABLE_TX_PADDING))
   {
      return eUDS_NOT_SUPPORTED;
   }
   if (b_udsFd && !stpt_target->st_can.b_fd)
   {
      return eUDS_BAD_ARG;
   }

   if (!sb_clientReady)
   {
      gv_UdsTpIsotp_Init(&sst_jobTp, &sst_jobTpCtx, stpt_can);
      (void)gi_UdsClient_Init(&sst_client, &sst_jobTp);
      sb_clientReady = true;
   }

   i_ret = gi_CanIf_Configure(&stpt_target->st_can, NULL);
   switch (i_ret)
   {
      case 0:         break;
      case -EBUSY:    return eUDS_BUSY;
      case -EINVAL:   return eUDS_BAD_ARG;
      case -ENOTSUP:  return eUDS_NOT_SUPPORTED;
      case -ENODEV:   return eUDS_NOT_READY;
      default:        return eUDS_TRANSPORT;
   }

   i_ret = gi_UdsClient_SetTarget(&sst_client, &stpt_target->st_uds);
   if (i_ret != 0)
   {
      APP_LOG_WRN("target refused (%d)", i_ret);
      return (i_ret == -EINVAL) ? eUDS_BAD_ARG : ((i_ret == -ENOTSUP) ? eUDS_NOT_SUPPORTED : eUDS_TRANSPORT);
   }

   sb_targetSet = true;
   APP_LOG_INF("target tx 0x%x rx 0x%x%s", stpt_target->st_uds.u32_txId, stpt_target->st_uds.u32_rxId,
      b_udsFd ? ", CAN FD" : "");
   return eUDS_OK;
}

/**
 * @private       sv_HandleMsg
 * @brief         Run one request and deliver its result.
 * @param[in]     stpt_msg Request.
 * @return        None.
 */
static void sv_HandleMsg(const UdsJobMsg_T *stpt_msg)
{
   uint8_t u8_result = eUDS_OK;
   size_t t_len = 0U;
   uint8_t u8_nrc;
   int i_ret;

   switch (stpt_msg->u8_type)
   {
      case eUDS_JOB_TARGET:
         u8_result = su8_ApplyTarget(&stpt_msg->u.st_target);
         (void)atomic_set(&st_busy, 0);
         stpt_msg->fpt_done(u8_result, NULL, 0U, stpt_msg->vpt_user);
         break;

      case eUDS_JOB_DIAG:
         if (!sb_targetSet)
         {
            u8_result = eUDS_NOT_READY;
         }
         else
         {
            i_ret = gi_UdsClient_Request(&sst_client, stpt_msg->u.u8ar_req, stpt_msg->u16_len, stpt_msg->b_functional,
               su8ar_rsp, sizeof(su8ar_rsp), &t_len);
            u8_result = su8_MapClient(i_ret, false);
         }
         (void)atomic_set(&st_busy, 0);
         stpt_msg->fpt_done(u8_result, (t_len > 0U) ? su8ar_rsp : NULL, t_len, stpt_msg->vpt_user);
         break;

      case eUDS_JOB_UNLOCK:
         if (!sb_targetSet)
         {
            u8_result = eUDS_NOT_READY;
         }
         else
         {
            i_ret = gi_UdsClient_SecurityAccess(&sst_client, stpt_msg->u8_level, gi_UdsKey_Callback,
               (void *)(uintptr_t)stpt_msg->u8_algo);
            u8_result = su8_MapClient(i_ret, false);
         }
         u8_nrc = gu8_UdsClient_LastNrc(&sst_client);
         (void)atomic_set(&st_busy, 0);
         stpt_msg->fpt_done(u8_result, (u8_result == eUDS_NRC) ? &u8_nrc : NULL, (u8_result == eUDS_NRC) ? 1U : 0U,
            stpt_msg->vpt_user);
         break;

      case eUDS_JOB_FLASH:
         sv_RunFlash(stpt_msg);
         break;

      default:
         (void)atomic_set(&st_busy, 0);
         break;
   }
}

/**
 * @private       sv_JobStep
 * @brief         One turn of the job thread: wait for a request (no longer than
 *                the keep-alive allows), run it.
 * @return        None.
 */
static void sv_JobStep(void)
{
   UdsJobMsg_T st_msg;
   int32_t i32_wait = sb_clientReady ? gi32_UdsClient_KeepAlive(&sst_client) : UDS_KEEPALIVE_NONE;

   if (k_msgq_get(&sst_udsJobQ, &st_msg, (i32_wait < 0) ? K_FOREVER : K_MSEC(i32_wait)) == 0)
   {
      sv_HandleMsg(&st_msg);
   }
}

/**
 * @private       sv_UdsJobThread
 * @brief         The job thread.
 * @param[in]     vpt_p1 Unused.
 * @param[in]     vpt_p2 Unused.
 * @param[in]     vpt_p3 Unused.
 * @return        None.
 */
static void sv_UdsJobThread(void *vpt_p1, void *vpt_p2, void *vpt_p3)
{
   ARG_UNUSED(vpt_p1);
   ARG_UNUSED(vpt_p2);
   ARG_UNUSED(vpt_p3);

   while (true)
   {
      sv_JobStep();
   }
}

/******************************************************************************/
/*                                                                            */
/*                        PUBLIC FUNCTION DEFINITIONS                         */
/*                                                                            */
/******************************************************************************/
/**
 * @public        gi_UdsJob_Init
 * @brief         Follow the CAN controller's state (bus-off stops a flash job).
 *                Call once, after gi_CanIf_Init().
 * @return        0, or gi_CanIf_AddStateListener()'s error.
 */
int gi_UdsJob_Init(void)
{
   int i_ret = gi_CanIf_AddStateListener(sv_OnCanState, NULL);

   if (i_ret != 0)
   {
      APP_LOG_ERR("gi_CanIf_AddStateListener failed (%d)", i_ret);
   }
   return i_ret;
}

/**
 * @public        gu8_UdsJob_SetTarget
 * @brief         Apply a target (CAN configuration, then addressing). The result
 *                comes through fpt_done on the job thread.
 * @param[in]     stpt_target Target (copied).
 * @param[in]     fpt_done Result callback.
 * @param[in]     vpt_user For the callback.
 * @return        eUDS_OK (accepted), eUDS_BAD_ARG for NULL, eUDS_BUSY while a
 *                request or job is in progress.
 */
uint8_t gu8_UdsJob_SetTarget(const UdsJobTarget_T *stpt_target, UdsJobResult_F fpt_done, void *vpt_user)
{
   UdsJobMsg_T st_msg;

   if ((stpt_target == NULL) || (fpt_done == NULL))
   {
      return eUDS_BAD_ARG;
   }
   memset(&st_msg, 0, sizeof(st_msg));
   st_msg.u8_type = eUDS_JOB_TARGET;
   st_msg.u.st_target = *stpt_target;
   st_msg.fpt_done = fpt_done;
   st_msg.vpt_user = vpt_user;
   return su8_Post(&st_msg);
}

/**
 * @public        gu8_UdsJob_Diag
 * @brief         Send a diagnostic request to the target; the ECU's response comes
 *                through fpt_done on the job thread.
 * @param[in]     u8pt_req Request (SID first, copied).
 * @param[in]     t_len 1..UDS_JOB_REQ_MAX bytes.
 * @param[in]     b_functional To the functional identifier.
 * @param[in]     fpt_done Result callback.
 * @param[in]     vpt_user For the callback.
 * @return        eUDS_OK (accepted), eUDS_BAD_ARG, eUDS_BUSY.
 */
uint8_t gu8_UdsJob_Diag(const uint8_t *u8pt_req, size_t t_len, bool b_functional, UdsJobResult_F fpt_done,
   void *vpt_user)
{
   UdsJobMsg_T st_msg;

   if ((u8pt_req == NULL) || (t_len == 0U) || (t_len > UDS_JOB_REQ_MAX) || (fpt_done == NULL))
   {
      return eUDS_BAD_ARG;
   }
   memset(&st_msg, 0, sizeof(st_msg));
   st_msg.u8_type = eUDS_JOB_DIAG;
   st_msg.b_functional = b_functional;
   st_msg.u16_len = (uint16_t)t_len;
   memcpy(st_msg.u.u8ar_req, u8pt_req, t_len);
   st_msg.fpt_done = fpt_done;
   st_msg.vpt_user = vpt_user;
   return su8_Post(&st_msg);
}

/**
 * @public        gu8_UdsJob_Unlock
 * @brief         SecurityAccess at a level with an on-device key algorithm; the
 *                result (with the NRC, if any) comes through fpt_done.
 * @param[in]     u8_level requestSeed level (odd, 0x01..0x7D).
 * @param[in]     u8_algo UDS_KEY_ALGO_*.
 * @param[in]     fpt_done Result callback.
 * @param[in]     vpt_user For the callback.
 * @return        eUDS_OK (accepted), eUDS_BAD_ARG, eUDS_NOT_SUPPORTED for an
 *                algorithm this build lacks, eUDS_BUSY.
 */
uint8_t gu8_UdsJob_Unlock(uint8_t u8_level, uint8_t u8_algo, UdsJobResult_F fpt_done, void *vpt_user)
{
   UdsJobMsg_T st_msg;
   uint8_t u8_probe = 1U;
   uint8_t u8_key;
   size_t t_keyLen;

   if (((u8_level & 1U) == 0U) || (u8_level > 0x7DU) || (fpt_done == NULL))
   {
      return eUDS_BAD_ARG;
   }
   if (gi_UdsKey_Compute(u8_algo, u8_level, &u8_probe, 1U, &u8_key, 1U, &t_keyLen) == -ENOTSUP)
   {
      return eUDS_NOT_SUPPORTED;
   }
   memset(&st_msg, 0, sizeof(st_msg));
   st_msg.u8_type = eUDS_JOB_UNLOCK;
   st_msg.u8_level = u8_level;
   st_msg.u8_algo = u8_algo;
   st_msg.fpt_done = fpt_done;
   st_msg.vpt_user = vpt_user;
   return su8_Post(&st_msg);
}

/**
 * @public        gu8_UdsJob_Flash
 * @brief         Start a flash job: download UDS_FILE_DIR<name> to the target with
 *                the programming sequence of the parameters. Progress comes through
 *                fpt_status on the job thread, the last one with the outcome.
 * @param[in]     cpt_name File name (not terminated).
 * @param[in]     t_nameLen Its length.
 * @param[in]     stpt_params Parameters (copied).
 * @param[in]     fpt_status Progress callback.
 * @param[in]     vpt_user For the callback.
 * @return        eUDS_OK (accepted, the state is RUNNING); eUDS_NOT_READY without
 *                a target; eUDS_BUSY while a request runs or a hex upload is being
 *                stored; eUDS_BAD_ARG for a bad name or inconsistent parameters;
 *                eUDS_NOT_SUPPORTED for a key algorithm this build lacks.
 */
uint8_t gu8_UdsJob_Flash(const char *cpt_name, size_t t_nameLen, const UdsFlashParams_T *stpt_params,
   UdsJobStatus_F fpt_status, void *vpt_user)
{
   UdsJobMsg_T st_msg;
   uint8_t u8_probe = 1U;
   uint8_t u8_key;
   size_t t_keyLen;
   uint16_t u16_flags;
   uint8_t u8_alfid;
   uint8_t u8_result;

   if ((stpt_params == NULL) || (fpt_status == NULL) || !sb_ValidName(cpt_name, t_nameLen))
   {
      return eUDS_BAD_ARG;
   }
   u16_flags = stpt_params->u16_flags;
   u8_alfid = stpt_params->u8_alfid;
   if (((u16_flags & (uint16_t)~UDS_FF_ALL) != 0U)
      || ((u8_alfid & 0x0FU) == 0U) || ((u8_alfid & 0x0FU) > 4U) || ((u8_alfid >> 4) == 0U) || ((u8_alfid >> 4) > 4U)
      || (((u16_flags & UDS_FF_ERASE_PER_RECORD) != 0U) && ((u16_flags & UDS_FF_ERASE) == 0U))
      || (((u16_flags & UDS_FF_CHECK_CRC) != 0U) && ((u16_flags & UDS_FF_CHECK) == 0U))
      || (((u16_flags & UDS_FF_FINGERPRINT) != 0U)
         && ((stpt_params->u8_fingerprintLen == 0U) || (stpt_params->u8_fingerprintLen > UDS_FP_MAX)))
      || (((u16_flags & UDS_FF_SECURITY) != 0U)
         && (((stpt_params->u8_securityLevel & 1U) == 0U) || (stpt_params->u8_securityLevel > 0x7DU))))
   {
      return eUDS_BAD_ARG;
   }
   if (((u16_flags & UDS_FF_SECURITY) != 0U)
      && (gi_UdsKey_Compute(stpt_params->u8_keyAlgo, stpt_params->u8_securityLevel, &u8_probe, 1U, &u8_key, 1U,
         &t_keyLen) == -ENOTSUP))
   {
      return eUDS_NOT_SUPPORTED;
   }
   if (!sb_targetSet)
   {
      return eUDS_NOT_READY;
   }
   if (gb_DataStore_UploadOpen())
   {
      return eUDS_BUSY;
   }

   memset(&st_msg, 0, sizeof(st_msg));
   st_msg.u8_type = eUDS_JOB_FLASH;
   st_msg.u.st_flash.st_params = *stpt_params;
   memcpy(st_msg.u.st_flash.car_name, cpt_name, t_nameLen);
   st_msg.fpt_status = fpt_status;
   st_msg.vpt_user = vpt_user;

   // RUNNING from now on, so a status request right after sees it
   (void)k_mutex_lock(&sst_statusMutex, K_FOREVER);
   if (atomic_get(&st_busy) != 0)
   {
      (void)k_mutex_unlock(&sst_statusMutex);
      return eUDS_BUSY;
   }
   (void)atomic_set(&st_abort, 0);
   u8_result = su8_Post(&st_msg);
   if (u8_result == eUDS_OK)
   {
      memset(&sst_status, 0, sizeof(sst_status));
      sst_status.u8_state = (uint8_t)eUDS_STATE_RUNNING;
   }
   (void)k_mutex_unlock(&sst_statusMutex);

   return u8_result;
}

/**
 * @public        gu8_UdsJob_Abort
 * @brief         Stop the running flash job at its next request.
 * @return        eUDS_OK, or eUDS_BAD_STATE if no flash job runs.
 */
uint8_t gu8_UdsJob_Abort(void)
{
   uint8_t u8_result = eUDS_BAD_STATE;

   (void)k_mutex_lock(&sst_statusMutex, K_FOREVER);
   if (sst_status.u8_state == (uint8_t)eUDS_STATE_RUNNING)
   {
      (void)atomic_set(&st_abort, 1);
      u8_result = eUDS_OK;
   }
   (void)k_mutex_unlock(&sst_statusMutex);

   return u8_result;
}

/**
 * @public        gv_UdsJob_GetStatus
 * @brief         The flash job's progress (the last job's outcome when none runs).
 * @param[out]    stpt_status Status.
 * @return        None.
 */
void gv_UdsJob_GetStatus(UdsJobStatus_T *stpt_status)
{
   if (stpt_status == NULL)
   {
      return;
   }
   (void)k_mutex_lock(&sst_statusMutex, K_FOREVER);
   *stpt_status = sst_status;
   (void)k_mutex_unlock(&sst_statusMutex);
}

/**
 * @public        gb_UdsJob_FileOpen
 * @brief         Whether a flash job holds the File System Manager's open file
 *                (the file commands and the hex upload's BEGIN answer BUSY then).
 * @return        true while it does.
 */
bool gb_UdsJob_FileOpen(void)
{
   return atomic_get(&st_fileOpen) != 0;
}

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shivam Chudasama [SC]
 */
