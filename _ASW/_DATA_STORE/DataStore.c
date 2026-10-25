/**
 * @file          DataStore.c
 * @brief         Source file containing the receive-side data store.
 *
 *                Each hex segment arrives as one SETU transfer of type
 *                DS_APP_TYPE_SEGMENT whose object is [u32 LE start address][data].
 *                The data is collected in su8ar_segBuf. Once the transfer ends with
 *                eBS_OK (CRC-32 verified), the dump thread logs it, stores it in the
 *                upload file if one is open, and then tells the client with a
 *                DS_APP_TYPE_STORED short message. New transfers are rejected until
 *                then. With CONFIG_DS_HEX_DUMP the dump prints every byte as
 *                "0xAAAAAAAA: xx xx ..." lines (slow, for debugging); without it, a
 *                single summary line with the CRC-32.
 *
 *                An upload is stored as a file when the client frames it with BEGIN
 *                (file name) and COMMIT: the segments are written, as records
 *                [u32 LE address][u32 LE length][data], to DS_FILE_DIR/DS_TEMP_NAME,
 *                which COMMIT renames to DS_FILE_DIR/<name>. Both are answered with
 *                DS_APP_TYPE_FILE. File system work runs on the dump thread through
 *                the File System Manager (_LIB/FileSysManager).
 * @date          25/09/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include "DataStore.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/crc.h>
#include <zephyr/logging/log_ctrl.h>
#include "SETU.h"
#include "SETURouter.h"
#include "FileSysManager.h"
#if defined(CONFIG_UDS)
#include "UdsJob.h"
#endif // CONFIG_UDS
#include "AppLog.h"

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
/**
 * @def           DS_BYTES_PER_LINE
 * @brief         Data bytes printed per dump line.
 */
#define DS_BYTES_PER_LINE                    (16U)

/**
 * @def           DS_REPORT_LEN
 * @brief         Payload length of the RESULT and STORED short messages:
 *                [u8 status][u32 LE address][u32 LE length].
 */
#define DS_REPORT_LEN                        (9U)

/**
 * @def           DS_SHORT_TIMEOUT_MS
 * @brief         Maximum wait for a CTRL credit when sending a short message.
 */
#define DS_SHORT_TIMEOUT_MS                  (100)

/**
 * @def           DS_LOG_BACKLOG_MAX
 * @brief         The dump thread waits while more log messages than this are pending,
 *                so the deferred log buffer never overflows and drops lines.
 */
#define DS_LOG_BACKLOG_MAX                   (8U)

/**
 * @def           DS_DUMP_STACK_SIZE
 * @brief         Stack size of the dump thread. It also submits file system
 *                messages and notifies RESULT/STORED/FILE through the BT host,
 *                about 1.8 KiB on its deepest static path (audit F4).
 */
#define DS_DUMP_STACK_SIZE                   (3072)

/**
 * @def           DS_DUMP_PRIORITY
 * @brief         Priority of the dump thread. Below the SETU engine thread
 *                (SETU_THREAD_PRIORITY) so that dumping never delays the link.
 */
#define DS_DUMP_PRIORITY                     (10)

/**
 * @def           DS_EVENT_QUEUE_DEPTH
 * @brief         Events (segment, BEGIN, COMMIT) waiting for the dump thread.
 */
#define DS_EVENT_QUEUE_DEPTH                 (4)

/**
 * @def           DS_TEMP_PATH
 * @brief         Path of the file an upload is written to until COMMIT.
 */
#define DS_TEMP_PATH                         DS_FILE_DIR "/" DS_TEMP_NAME

/******************************************************************************/
/*                                                                            */
/*                                   ENUMS                                    */
/*                                                                            */
/******************************************************************************/
/**
 * @enum          DsEventType_E
 * @brief         Work for the dump thread.
 */
typedef enum
{
   eDSE_SEGMENT,                             /**< A verified segment is in su8ar_segBuf. */
   eDSE_BEGIN,                               /**< BEGIN with a file name.              */
   eDSE_COMMIT,                              /**< COMMIT.                              */
} DsEventType_E;

/******************************************************************************/
/*                                                                            */
/*                                 STRUCTURES                                 */
/*                                                                            */
/******************************************************************************/
/**
 * @struct        DsEvent_T
 * @brief         One event for the dump thread.
 */
typedef struct
{
   uint8_t u8_type;                          /**< DsEventType_E.                       */
   uint8_t u8_nameLen;                       /**< BEGIN: name length.                  */
   char car_name[DS_NAME_MAX + 1U];          /**< BEGIN: file name.                    */
} DsEvent_T;

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
static int si_OnRxStart(uint8_t u8_appType, uint32_t u32_totalLen);
static int si_OnRxData(uint8_t u8_appType, uint32_t u32_offset,
   const uint8_t *u8pt_data, uint16_t u16_len);
static void sv_OnRxDone(uint8_t u8_appType, SETUStatus_E e_status, uint32_t u32_totalLen);
static void sv_OnRxShort(uint8_t u8_appType, const uint8_t *u8pt_data, uint8_t u8_len);
static void sv_SendReport(uint8_t u8_appType, uint8_t u8_status, uint32_t u32_addr,
   uint32_t u32_len);
static void sv_SendFile(uint8_t u8_op, int i_status, uint32_t u32_size, uint32_t u32_crc);
static bool sb_ValidName(const char *cpt_name, uint32_t u32_len);
static int si_Fs(FileSysCommand_E e_cmd, const void *vpt_data, uint32_t u32_len, uint8_t u8_flags);
static int si_FsPath(FileSysCommand_E e_cmd, const char *cpt_path, uint8_t u8_flags);
static int si_WriteToFile(const uint8_t *u8pt_data, uint32_t u32_len);
static void sv_DumpSegment(void);
static void sv_StoreSegment(void);
static void sv_Begin(const DsEvent_T *stpt_event);
static void sv_Commit(void);
static void sv_DumpThread(void *vpt_p1, void *vpt_p2, void *vpt_p3);

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
 * @var           su8ar_segBuf
 * @brief         Data bytes of the segment being received or dumped.
 */
static uint8_t su8ar_segBuf[DS_BUF_SIZE];

/**
 * @var           su8ar_addrHdr
 * @brief         Little-endian start address received in front of the segment data.
 */
static uint8_t su8ar_addrHdr[DS_ADDR_HDR_LEN];

/**
 * @var           su32_segAddr
 * @brief         Start address of the segment handed to the dump thread.
 */
static uint32_t su32_segAddr = 0U;

/**
 * @var           su32_segLen
 * @brief         Number of data bytes of the segment handed to the dump thread.
 */
static uint32_t su32_segLen = 0U;

/**
 * @var           st_dumpBusy
 * @brief         Set from a verified segment until it has been dumped and stored. While
 *                set, su8ar_segBuf belongs to the dump thread and new transfers are
 *                rejected.
 */
static atomic_t st_dumpBusy = ATOMIC_INIT(0);

/**
 * @var           st_uploadOpen
 * @brief         Set from a successful BEGIN until COMMIT (or the next BEGIN): the
 *                upload file is open and segments are written to it.
 */
static atomic_t st_uploadOpen = ATOMIC_INIT(0);

/**
 * @var           si_uploadErr
 * @brief         First error while writing the open upload, 0 if none. COMMIT then
 *                discards the file and reports it. Dump thread only.
 */
static int si_uploadErr = 0;

/**
 * @var           su32_fileSize
 * @brief         Bytes written to the open upload file. Dump thread only.
 */
static uint32_t su32_fileSize = 0U;

/**
 * @var           su32_fileCrc
 * @brief         CRC-32 (IEEE) of the bytes written to the open upload file.
 */
static uint32_t su32_fileCrc = 0U;

/**
 * @var           scar_uploadName
 * @brief         File name given by BEGIN.
 */
static char scar_uploadName[DS_NAME_MAX + 1U];

/**
 * @var           sst_fsMsg
 * @brief         File system message built by the dump thread (kept off its stack).
 */
static FileSysMessage_T sst_fsMsg;

/**
 * @var           sst_dsEventQ
 * @brief         Wakes the dump thread with a verified segment, BEGIN or COMMIT.
 */
K_MSGQ_DEFINE(sst_dsEventQ, sizeof(DsEvent_T), DS_EVENT_QUEUE_DEPTH, 4);

/**
 * @var           sst_dumpThread
 * @brief         Low-priority thread that prints and stores received segments.
 */
K_THREAD_DEFINE(sst_dumpThread, DS_DUMP_STACK_SIZE, sv_DumpThread, NULL, NULL, NULL,
   DS_DUMP_PRIORITY, 0, 0);

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
 * @private       si_OnRxStart
 * @brief         SETURxStart_F: accept a hex segment that fits the buffer while the
 *                buffer is free.
 * @param[in]     u8_appType Application type announced by the client.
 * @param[in]     u32_totalLen Object size (address header + data).
 * @return        0 to accept, non-zero to reject (client sees eBS_REJECTED).
 */
static int si_OnRxStart(uint8_t u8_appType, uint32_t u32_totalLen)
{
   int i_ret = 0;

   // Check if the transfer is a hex segment
   if (u8_appType != DS_APP_TYPE_SEGMENT)
   {
      APP_LOG_WRN("rejected: unknown type 0x%02x", u8_appType);
      i_ret = -ENOTSUP;
   }
   // Check if the object holds an address and at least one data byte, and fits the buffer
   else if ((u32_totalLen <= DS_ADDR_HDR_LEN) ||
      (u32_totalLen > (DS_ADDR_HDR_LEN + DS_BUF_SIZE)))
   {
      APP_LOG_WRN("rejected: length %u outside %u..%u", u32_totalLen,
         DS_ADDR_HDR_LEN + 1U, DS_ADDR_HDR_LEN + DS_BUF_SIZE);
      i_ret = -EMSGSIZE;
   }
   // Check if the previous segment is still being dumped or stored
   else if (atomic_get(&st_dumpBusy) != 0)
   {
      APP_LOG_WRN("rejected: previous segment still being dumped");
      i_ret = -EBUSY;
   }
   else
   {
      APP_LOG_INF("segment announced: %u bytes", u32_totalLen - DS_ADDR_HDR_LEN);
   }

   return i_ret;
}

/**
 * @private       si_OnRxData
 * @brief         SETURxData_F: store an in-order chunk. Object bytes 0..3 are the address
 *                header, the rest goes into su8ar_segBuf. The first chunk usually carries
 *                both, so it is split.
 * @param[in]     u8_appType Application type (unused, checked at START).
 * @param[in]     u32_offset Object offset of the chunk.
 * @param[in]     u8pt_data Chunk data, valid only during the call.
 * @param[in]     u16_len Chunk length.
 * @return        0 to continue, non-zero aborts with eBS_SINK_ERROR.
 */
static int si_OnRxData(uint8_t u8_appType, uint32_t u32_offset,
   const uint8_t *u8pt_data, uint16_t u16_len)
{
   uint32_t u32_hdrBytes = 0U;
   uint32_t u32_bufOffset = 0U;

   ARG_UNUSED(u8_appType);

   // Check if the chunk starts inside the address header
   if (u32_offset < DS_ADDR_HDR_LEN)
   {
      u32_hdrBytes = MIN(DS_ADDR_HDR_LEN - u32_offset, (uint32_t)u16_len);
      memcpy(&su8ar_addrHdr[u32_offset], u8pt_data, u32_hdrBytes);
      u32_offset += u32_hdrBytes;
      u8pt_data += u32_hdrBytes;
      u16_len -= (uint16_t)u32_hdrBytes;
   }

   // Check if data bytes remain after the header part
   if (u16_len > 0U)
   {
      u32_bufOffset = u32_offset - DS_ADDR_HDR_LEN;

      // Check if the chunk fits the buffer (guaranteed by the length check at START)
      if ((u32_bufOffset + u16_len) > DS_BUF_SIZE)
      {
         APP_LOG_ERR("chunk at %u + %u overflows the buffer", u32_bufOffset, u16_len);
         return -ENOSPC;
      }

      memcpy(&su8ar_segBuf[u32_bufOffset], u8pt_data, u16_len);
   }

   APP_LOG_DBG("chunk offset %u, %u bytes", u32_offset, u16_len);

   return 0;
}

/**
 * @private       sv_OnRxDone
 * @brief         SETURxDone_F: hand a verified segment to the dump thread, or discard a
 *                failed one. Reports the result to the client either way.
 * @param[in]     u8_appType Application type.
 * @param[in]     e_status Result of the incoming transfer.
 * @param[in]     u32_totalLen Object size (address header + data).
 * @return        None.
 */
static void sv_OnRxDone(uint8_t u8_appType, SETUStatus_E e_status, uint32_t u32_totalLen)
{
   DsEvent_T st_event = { 0 };
   uint32_t u32_addr = 0U;
   uint32_t u32_len = 0U;

   // Check if the segment is complete and CRC-verified
   if (e_status == eBS_OK)
   {
      u32_addr = sys_get_le32(su8ar_addrHdr);
      u32_len = u32_totalLen - DS_ADDR_HDR_LEN;

      APP_LOG_INF("segment received: addr 0x%08x, %u bytes", u32_addr, u32_len);

      su32_segAddr = u32_addr;
      su32_segLen = u32_len;
      atomic_set(&st_dumpBusy, 1);

      st_event.u8_type = (uint8_t)eDSE_SEGMENT;
      // Check if the dump thread could not take it (cannot happen: only one segment
      // is in flight and the queue has room for it and a BEGIN/COMMIT pair)
      if (k_msgq_put(&sst_dsEventQ, &st_event, K_NO_WAIT) != 0)
      {
         APP_LOG_ERR("event queue full, segment dropped");
         atomic_set(&st_dumpBusy, 0);
         sv_SendReport(DS_APP_TYPE_RESULT, (uint8_t)eBS_SINK_ERROR, 0U, 0U);
         return;
      }
   }
   else
   {
      APP_LOG_WRN("transfer type 0x%02x failed, status %u, data discarded", u8_appType,
         (unsigned int)e_status);
   }

   // Best effort: the link may already be gone (eBS_DISCONNECTED)
   sv_SendReport(DS_APP_TYPE_RESULT, (uint8_t)e_status, u32_addr, u32_len);
}

/**
 * @private       sv_OnRxShort
 * @brief         SETURxShort_F: queue BEGIN (with its file name) and COMMIT for the dump
 *                thread. A BEGIN without a name or with a longer one than DS_NAME_MAX is
 *                answered at once; other types of the range are ignored.
 * @param[in]     u8_appType Application type.
 * @param[in]     u8pt_data Payload (valid only during the call).
 * @param[in]     u8_len Payload length.
 * @return        None.
 */
static void sv_OnRxShort(uint8_t u8_appType, const uint8_t *u8pt_data, uint8_t u8_len)
{
   DsEvent_T st_event = { 0 };

   if (u8_appType == DS_APP_TYPE_BEGIN)
   {
      // Check if the name length is valid (its characters are checked by the thread)
      if ((u8_len == 0U) || (u8_len > DS_NAME_MAX))
      {
         APP_LOG_WRN("BEGIN refused: name length %u", u8_len);
         sv_SendFile(DS_APP_TYPE_BEGIN, -EINVAL, 0U, 0U);
         return;
      }
      st_event.u8_type = (uint8_t)eDSE_BEGIN;
      st_event.u8_nameLen = u8_len;
      memcpy(st_event.car_name, u8pt_data, u8_len);
   }
   else if (u8_appType == DS_APP_TYPE_COMMIT)
   {
      st_event.u8_type = (uint8_t)eDSE_COMMIT;
   }
   else
   {
      APP_LOG_WRN("short message 0x%02x ignored", u8_appType);
      return;
   }

   // Check if the dump thread can take it
   if (k_msgq_put(&sst_dsEventQ, &st_event, K_NO_WAIT) != 0)
   {
      APP_LOG_WRN("0x%02x refused: busy", u8_appType);
      sv_SendFile(u8_appType, -EBUSY, 0U, 0U);
   }
}

/**
 * @private       sv_SendReport
 * @brief         Send a [u8 status][u32 LE address][u32 LE length] short message on CTRL.
 * @param[in]     u8_appType DS_APP_TYPE_RESULT or DS_APP_TYPE_STORED.
 * @param[in]     u8_status SETUStatus_E value (0 = OK).
 * @param[in]     u32_addr Segment start address.
 * @param[in]     u32_len Segment data length.
 * @return        None.
 */
static void sv_SendReport(uint8_t u8_appType, uint8_t u8_status, uint32_t u32_addr,
   uint32_t u32_len)
{
   uint8_t u8ar_report[DS_REPORT_LEN];
   int i_ret = 0;

   u8ar_report[0] = u8_status;
   sys_put_le32(u32_addr, &u8ar_report[1]);
   sys_put_le32(u32_len, &u8ar_report[5]);

   i_ret = gi_SETUS_SendShort(u8_appType, u8ar_report, sizeof(u8ar_report),
      K_MSEC(DS_SHORT_TIMEOUT_MS));

   // Check if the report could not be sent (no link, not subscribed, no credit)
   if (i_ret != 0)
   {
      APP_LOG_DBG("report 0x%02x not sent (%d)", u8_appType, i_ret);
   }
}

/**
 * @private       sv_SendFile
 * @brief         Send FILE: [u8 op][u8 status][u32 LE file size][u32 LE file CRC-32].
 * @param[in]     u8_op DS_APP_TYPE_BEGIN or DS_APP_TYPE_COMMIT.
 * @param[in]     i_status 0 or a negative errno (sent as an FsmgrStatus_E code).
 * @param[in]     u32_size File size.
 * @param[in]     u32_crc File CRC-32.
 * @return        None.
 */
static void sv_SendFile(uint8_t u8_op, int i_status, uint32_t u32_size, uint32_t u32_crc)
{
   uint8_t u8ar_reply[DS_FILE_REPLY_LEN];
   int i_ret = 0;

   u8ar_reply[0] = u8_op;
   u8ar_reply[1] = gu8_FSMGR_StatusCode(i_status);
   sys_put_le32(u32_size, &u8ar_reply[2]);
   sys_put_le32(u32_crc, &u8ar_reply[6]);

   i_ret = gi_SETUS_SendShort(DS_APP_TYPE_FILE, u8ar_reply, sizeof(u8ar_reply),
      K_MSEC(DS_SHORT_TIMEOUT_MS));

   // Check if the reply could not be sent (no link, not subscribed, no credit)
   if (i_ret != 0)
   {
      APP_LOG_DBG("FILE not sent (%d)", i_ret);
   }
}

/**
 * @private       sb_ValidName
 * @brief         Whether a BEGIN name is a plain file name: 1..DS_NAME_MAX characters
 *                from A-Z a-z 0-9 . _ -, not "." or "..", and not the temporary name.
 * @param[in]     cpt_name Name (terminated).
 * @param[in]     u32_len Name length.
 * @return        true if valid.
 */
static bool sb_ValidName(const char *cpt_name, uint32_t u32_len)
{
   static const char sscar_temp[] = DS_TEMP_NAME;
   bool b_isTemp = (u32_len == (sizeof(sscar_temp) - 1U));
   uint32_t u32_idx;
   char c_ch;

   // Check if the length is valid and the name is not a directory reference
   if ((u32_len == 0U) || (u32_len > DS_NAME_MAX) || (strcmp(cpt_name, ".") == 0) ||
      (strcmp(cpt_name, "..") == 0))
   {
      return false;
   }

   for (u32_idx = 0U; u32_idx < u32_len; u32_idx++)
   {
      c_ch = cpt_name[u32_idx];
      // Check if the character is allowed
      if (!(((c_ch >= 'A') && (c_ch <= 'Z')) || ((c_ch >= 'a') && (c_ch <= 'z')) ||
         ((c_ch >= '0') && (c_ch <= '9')) || (c_ch == '.') || (c_ch == '_') || (c_ch == '-')))
      {
         return false;
      }
      // FAT names compare without case: compare upper case with the temporary name
      if (b_isTemp && ((((c_ch >= 'a') && (c_ch <= 'z')) ? (char)(c_ch - 32) : c_ch) !=
         sscar_temp[u32_idx]))
      {
         b_isTemp = false;
      }
   }

   return !b_isTemp;
}

/**
 * @private       si_Fs
 * @brief         Execute one file system command and wait for its result.
 * @param[in]     e_cmd Command.
 * @param[in]     vpt_data Payload, or NULL.
 * @param[in]     u32_len Payload length (at most FS_MAX_CHUNK_SIZE).
 * @param[in]     u8_flags FSMGR_MSG_* flags.
 * @return        0 or a negative errno.
 */
static int si_Fs(FileSysCommand_E e_cmd, const void *vpt_data, uint32_t u32_len, uint8_t u8_flags)
{
   sst_fsMsg.e_command = e_cmd;
   sst_fsMsg.u8_flags = u8_flags;
   sst_fsMsg.u32_sizeOfData = u32_len;
   if (u32_len > 0U)
   {
      memcpy(sst_fsMsg.u8_data, vpt_data, u32_len);
   }

   return gi_FSMGR_Call(&sst_fsMsg);
}

/**
 * @private       si_FsPath
 * @brief         si_Fs() with a path as payload.
 * @param[in]     e_cmd Command.
 * @param[in]     cpt_path Path.
 * @param[in]     u8_flags FSMGR_MSG_* flags.
 * @return        0 or a negative errno.
 */
static int si_FsPath(FileSysCommand_E e_cmd, const char *cpt_path, uint8_t u8_flags)
{
   return si_Fs(e_cmd, cpt_path, (uint32_t)strlen(cpt_path), u8_flags);
}

/**
 * @private       si_WriteToFile
 * @brief         Append bytes to the open upload file, FS_MAX_CHUNK_SIZE at a time,
 *                and add them to its size and CRC-32.
 * @param[in]     u8pt_data Data.
 * @param[in]     u32_len Data length.
 * @return        0 or the first write error.
 */
static int si_WriteToFile(const uint8_t *u8pt_data, uint32_t u32_len)
{
   uint32_t u32_chunk;
   int i_ret = 0;

   while ((u32_len > 0U) && (i_ret == 0))
   {
      u32_chunk = MIN(u32_len, FS_MAX_CHUNK_SIZE);
      i_ret = si_Fs(eFSC_WRITE_DATA, u8pt_data, u32_chunk, 0U);
      if (i_ret == 0)
      {
         su32_fileCrc = crc32_ieee_update(su32_fileCrc, u8pt_data, u32_chunk);
         su32_fileSize += u32_chunk;
      }
      u8pt_data += u32_chunk;
      u32_len -= u32_chunk;
   }

   return i_ret;
}

/**
 * @private       sv_DumpSegment
 * @brief         Log the segment in su8ar_segBuf. With CONFIG_DS_HEX_DUMP, print it as
 *                "0xAAAAAAAA: xx xx ..." lines, DS_BYTES_PER_LINE bytes each, framed by
 *                start and end lines; otherwise print one summary line.
 * @return        None.
 */
static void sv_DumpSegment(void)
{
   static const char sscar_hexDigits[] = "0123456789abcdef";
   char car_line[(DS_BYTES_PER_LINE * 3U) + 1U];
   uint32_t u32_crc = 0U;
   uint32_t u32_pos = 0U;
   uint32_t u32_lineLen = 0U;
   uint32_t u32_idx = 0U;

   // CRC over the whole object, equal to the CRC-32 in the client's START frame
   u32_crc = crc32_ieee(su8ar_addrHdr, sizeof(su8ar_addrHdr));
   u32_crc = crc32_ieee_update(u32_crc, su8ar_segBuf, su32_segLen);

   // Check if the full hex dump is disabled: the summary line is all that is printed
   if (!IS_ENABLED(CONFIG_DS_HEX_DUMP))
   {
      LOG_INF("SEG addr=0x%08x len=%u crc=0x%08x", su32_segAddr, su32_segLen, u32_crc);
      return;
   }

   LOG_INF("SEG start addr=0x%08x len=%u crc=0x%08x", su32_segAddr, su32_segLen, u32_crc);

   for (u32_pos = 0U; u32_pos < su32_segLen; u32_pos += DS_BYTES_PER_LINE)
   {
      u32_lineLen = MIN(DS_BYTES_PER_LINE, su32_segLen - u32_pos);

      for (u32_idx = 0U; u32_idx < u32_lineLen; u32_idx++)
      {
         car_line[(u32_idx * 3U)] = sscar_hexDigits[su8ar_segBuf[u32_pos + u32_idx] >> 4];
         car_line[(u32_idx * 3U) + 1U] = sscar_hexDigits[su8ar_segBuf[u32_pos + u32_idx] & 0x0FU];
         car_line[(u32_idx * 3U) + 2U] = ' ';
      }

      // Replace the trailing space with the terminator
      car_line[(u32_lineLen * 3U) - 1U] = '\0';

      // Wait for the log thread to drain, so no line is dropped
      while (log_buffered_cnt() > DS_LOG_BACKLOG_MAX)
      {
         k_msleep(1);
      }

      LOG_INF("0x%08x: %s", su32_segAddr + u32_pos, car_line);
   }

   LOG_INF("SEG end addr=0x%08x len=%u", su32_segAddr, su32_segLen);
}

/**
 * @private       sv_StoreSegment
 * @brief         Dump the segment, write it as a record to the open upload file (if
 *                any), then free the buffer and send STORED: status OK, or
 *                eBS_SINK_ERROR once writing the upload file has failed.
 * @return        None.
 */
static void sv_StoreSegment(void)
{
   uint8_t u8ar_hdr[DS_RECORD_HDR_LEN];
   uint8_t u8_status = (uint8_t)eBS_OK;
   uint32_t u32_addr = 0U;
   uint32_t u32_len = 0U;
   int i_ret = 0;

   sv_DumpSegment();

   // Check if the upload is being stored in a file
   if (atomic_get(&st_uploadOpen) != 0)
   {
      // Check if the file is still good: once a write failed, the rest is not written
      if (si_uploadErr == 0)
      {
         sys_put_le32(su32_segAddr, &u8ar_hdr[0]);
         sys_put_le32(su32_segLen, &u8ar_hdr[4]);
         i_ret = si_WriteToFile(u8ar_hdr, sizeof(u8ar_hdr));
         if (i_ret == 0)
         {
            i_ret = si_WriteToFile(su8ar_segBuf, su32_segLen);
         }
         if (i_ret != 0)
         {
            APP_LOG_ERR("writing %s failed (%d)", DS_TEMP_PATH, i_ret);
            si_uploadErr = i_ret;
         }
      }
      if (si_uploadErr != 0)
      {
         u8_status = (uint8_t)eBS_SINK_ERROR;
      }
   }

   // Copy before freeing the buffer: the next segment overwrites these
   u32_addr = su32_segAddr;
   u32_len = su32_segLen;
   atomic_set(&st_dumpBusy, 0);

   sv_SendReport(DS_APP_TYPE_STORED, u8_status, u32_addr, u32_len);
}

/**
 * @private       sv_Begin
 * @brief         BEGIN: discard an unfinished upload, create DS_FILE_DIR, and open a
 *                fresh DS_TEMP_PATH for the segments. Refused while another user of
 *                the file system has a file open. Answers FILE.
 * @param[in]     stpt_event The BEGIN event with the file name.
 * @return        None.
 */
static void sv_Begin(const DsEvent_T *stpt_event)
{
   int i_ret = 0;

   // Check if the name is a plain file name
   if (!sb_ValidName(stpt_event->car_name, stpt_event->u8_nameLen))
   {
      APP_LOG_WRN("BEGIN refused: bad name");
      sv_SendFile(DS_APP_TYPE_BEGIN, -EINVAL, 0U, 0U);
      return;
   }

   // Check if an upload is still open (its COMMIT never came): discard it
   if (atomic_get(&st_uploadOpen) != 0)
   {
      APP_LOG_WRN("unfinished upload %s discarded", scar_uploadName);
      (void)si_Fs(eFSC_ABORT, NULL, 0U, 0U);
      atomic_set(&st_uploadOpen, 0);
   }
   // Check if someone else holds the file system's one open file, or a flash job
   // runs (it opens its file twice)
   else if (gb_FSMGR_IsFileOpen()
#if defined(CONFIG_UDS)
      || gb_UdsJob_FlashRunning()
#endif // CONFIG_UDS
      )
   {
      APP_LOG_WRN("BEGIN refused: a file is open");
      sv_SendFile(DS_APP_TYPE_BEGIN, -EBUSY, 0U, 0U);
      return;
   }

   i_ret = si_FsPath(eFSC_MAKE_DIR, DS_FILE_DIR, FSMGR_MSG_KEEP_DIR);

   // A temporary file left by a lost upload goes first: opening does not truncate
   if (i_ret == 0)
   {
      i_ret = si_FsPath(eFSC_DELETE_FILE, DS_TEMP_PATH, 0U);
      if (i_ret == -ENOENT)
      {
         i_ret = 0;
      }
   }
   if (i_ret == 0)
   {
      i_ret = si_FsPath(eFSC_OPEN_FILE_WRITE, DS_TEMP_PATH, 0U);
   }

   if (i_ret != 0)
   {
      APP_LOG_ERR("BEGIN %s failed (%d)", stpt_event->car_name, i_ret);
      sv_SendFile(DS_APP_TYPE_BEGIN, i_ret, 0U, 0U);
      return;
   }

   memcpy(scar_uploadName, stpt_event->car_name, (size_t)stpt_event->u8_nameLen + 1U);
   si_uploadErr = 0;
   su32_fileSize = 0U;
   su32_fileCrc = 0U;
   atomic_set(&st_uploadOpen, 1);

   APP_LOG_INF("storing upload as %s/%s", DS_FILE_DIR, scar_uploadName);
   sv_SendFile(DS_APP_TYPE_BEGIN, 0, 0U, 0U);
}

/**
 * @private       sv_Commit
 * @brief         COMMIT: close the upload file and rename it to its name, replacing
 *                an older file of that name. A failed upload is deleted instead.
 *                Answers FILE with the file's size and CRC-32.
 * @return        None.
 */
static void sv_Commit(void)
{
   char car_path[sizeof(DS_FILE_DIR) + DS_NAME_MAX + 1U];
   uint8_t u8ar_rename[sizeof(DS_TEMP_PATH) + sizeof(car_path)];
   uint32_t u32_tempLen = sizeof(DS_TEMP_PATH);
   int i_ret = 0;

   // Check if an upload is open
   if (atomic_get(&st_uploadOpen) == 0)
   {
      APP_LOG_WRN("COMMIT without BEGIN");
      sv_SendFile(DS_APP_TYPE_COMMIT, -EPERM, 0U, 0U);
      return;
   }
   atomic_set(&st_uploadOpen, 0);

   // Check if writing failed: the file is dropped and the first error reported
   if (si_uploadErr != 0)
   {
      i_ret = si_uploadErr;
      (void)si_Fs(eFSC_ABORT, NULL, 0U, 0U);
   }
   else
   {
      i_ret = si_Fs(eFSC_CLOSE_FILE, NULL, 0U, 0U);
   }

   (void)snprintf(car_path, sizeof(car_path), "%s/%s", DS_FILE_DIR, scar_uploadName);

   // An older file of the same name is replaced
   if (i_ret == 0)
   {
      i_ret = si_FsPath(eFSC_DELETE_FILE, car_path, 0U);
      if (i_ret == -ENOENT)
      {
         i_ret = 0;
      }
   }

   // Rename "temp\0name"
   if (i_ret == 0)
   {
      memcpy(u8ar_rename, DS_TEMP_PATH, u32_tempLen);
      memcpy(&u8ar_rename[u32_tempLen], car_path, strlen(car_path));
      i_ret = si_Fs(eFSC_RENAME, u8ar_rename, u32_tempLen + (uint32_t)strlen(car_path), 0U);
   }

   if (i_ret != 0)
   {
      APP_LOG_ERR("upload %s failed (%d), discarded", scar_uploadName, i_ret);
      (void)si_FsPath(eFSC_DELETE_FILE, DS_TEMP_PATH, 0U);
      sv_SendFile(DS_APP_TYPE_COMMIT, i_ret, 0U, 0U);
      return;
   }

   LOG_INF("FILE %s size=%u crc=0x%08x", car_path, su32_fileSize, su32_fileCrc);
   sv_SendFile(DS_APP_TYPE_COMMIT, 0, su32_fileSize, su32_fileCrc);
}

/**
 * @private       sv_DumpThread
 * @brief         Execute the events in order: dump and store verified segments
 *                (then STORED), BEGIN and COMMIT.
 * @param[in]     vpt_p1 Unused.
 * @param[in]     vpt_p2 Unused.
 * @param[in]     vpt_p3 Unused.
 * @return        None.
 */
static void sv_DumpThread(void *vpt_p1, void *vpt_p2, void *vpt_p3)
{
   DsEvent_T st_event;

   ARG_UNUSED(vpt_p1);
   ARG_UNUSED(vpt_p2);
   ARG_UNUSED(vpt_p3);

   while (true)
   {
      (void)k_msgq_get(&sst_dsEventQ, &st_event, K_FOREVER);

      switch (st_event.u8_type)
      {
         case eDSE_SEGMENT:
            sv_StoreSegment();
            break;

         case eDSE_BEGIN:
            sv_Begin(&st_event);
            break;

         case eDSE_COMMIT:
            sv_Commit();
            break;

         default:
            break;
      }
   }
}

/******************************************************************************/
/*                                                                            */
/*                        PUBLIC FUNCTION DEFINITIONS                         */
/*                                                                            */
/******************************************************************************/
/**
 * @public        gi_DataStore_Init
 * @brief         Register the data store's appType range (DS_APP_TYPE_SEGMENT to
 *                DS_APP_TYPE_LAST) and its callbacks with the SETU router. Call
 *                once, before gi_SETURouter_Start().
 * @return        0 on success, otherwise the error from gi_SETURouter_Register().
 */
int gi_DataStore_Init(void)
{
   SETURoute_T st_route = { 0 };
   int i_ret = 0;

   st_route.u8_firstAppType = DS_APP_TYPE_SEGMENT;
   st_route.u8_lastAppType = DS_APP_TYPE_LAST;
   st_route.fpt_onRxStart = si_OnRxStart;
   st_route.fpt_onRxData = si_OnRxData;
   st_route.fpt_onRxDone = sv_OnRxDone;
   st_route.fpt_onRxShort = sv_OnRxShort;

   i_ret = gi_SETURouter_Register(&st_route);

   // Check if the route was registered
   if (i_ret != 0)
   {
      APP_LOG_ERR("gi_SETURouter_Register failed (%d)", i_ret);
   }
   else
   {
      APP_LOG_INF("hex upload ready, segment buffer %u bytes", DS_BUF_SIZE);
   }

   return i_ret;
}

/**
 * @public        gb_DataStore_UploadOpen
 * @brief         Whether an upload is being stored (from a successful BEGIN until
 *                COMMIT or the next BEGIN): it holds the file system's open file.
 * @return        true while an upload file is open.
 */
bool gb_DataStore_UploadOpen(void)
{
   return atomic_get(&st_uploadOpen) != 0;
}

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shivam Chudasama [SC]
 */
