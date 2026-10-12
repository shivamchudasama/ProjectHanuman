/**
 * @file          FsCmd.c
 * @brief         Source file containing the file commands over BLE. A CMD short
 *                message from the host becomes one File System Manager message; its
 *                result comes back as a REPLY (and, for LS, one ENTRY per listed
 *                entry first), sent from the File System Manager thread. One command
 *                runs at a time; another, or any while a hex upload is being stored
 *                (DataStore), is answered BUSY. Contract:
 *                _DOC/FileSysManager/PROTOCOL.md.
 * @date          07/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include "FsCmd.h"
#include <errno.h>
#include <string.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/byteorder.h>
#include "SETU.h"
#include "SETURouter.h"
#include "DataStore.h"
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
 * @def           FSCMD_SHORT_TIMEOUT_MS
 * @brief         Maximum wait for a CTRL credit when sending a REPLY or ENTRY.
 */
#define FSCMD_SHORT_TIMEOUT_MS               (200)

/**
 * @def           FSCMD_CMD_HDR_LEN
 * @brief         [u8 seq][u8 op] in front of a CMD's argument.
 */
#define FSCMD_CMD_HDR_LEN                    (2U)

/**
 * @def           FSCMD_REPLY_HDR_LEN
 * @brief         [u8 seq][u8 op][u8 status] in front of a REPLY's data.
 */
#define FSCMD_REPLY_HDR_LEN                  (3U)

/**
 * @def           FSCMD_ENTRY_HDR_LEN
 * @brief         [u8 seq][u8 type][u32 LE size] in front of an ENTRY's path.
 */
#define FSCMD_ENTRY_HDR_LEN                  (6U)

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
static void sv_SendReply(uint8_t u8_seq, uint8_t u8_op, uint8_t u8_status,
   const uint8_t *u8pt_data, uint32_t u32_len);
static int si_BuildMessage(uint8_t u8_op, const uint8_t *u8pt_arg, uint32_t u32_argLen,
   FileSysMessage_T *stpt_msg);
static void sv_OnResult(const FsmgrResult_T *stpt_result, void *vpt_user);
static void sv_OnRxShort(uint8_t u8_appType, const uint8_t *u8pt_data, uint8_t u8_len);

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
 * @var           st_busy
 * @brief         Set while a command is with the File System Manager.
 */
static atomic_t st_busy = ATOMIC_INIT(0);

/**
 * @var           su8_seq
 * @brief         Sequence number of the command in progress.
 */
static uint8_t su8_seq = 0U;

/**
 * @var           su8_op
 * @brief         Op of the command in progress.
 */
static uint8_t su8_op = 0U;

/**
 * @var           sst_msg
 * @brief         Message built from a CMD (SETU engine thread only).
 */
static FileSysMessage_T sst_msg;

/**
 * @var           su8ar_tx
 * @brief         REPLY and ENTRY payload (File System Manager thread only, apart
 *                from the immediate refusals on the engine thread, which use their
 *                own buffer).
 */
static uint8_t su8ar_tx[SETU_MAX_SHORT_PAYLOAD];

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
 * @private       sv_SendReply
 * @brief         Send REPLY [u8 seq][u8 op][u8 status][data].
 * @param[in]     u8_seq Sequence number of the command.
 * @param[in]     u8_op Op of the command.
 * @param[in]     u8_status FsmgrStatus_E code.
 * @param[in]     u8pt_data Data, or NULL.
 * @param[in]     u32_len Data length (at most FSCMD_READ_MAX).
 * @return        None.
 */
static void sv_SendReply(uint8_t u8_seq, uint8_t u8_op, uint8_t u8_status,
   const uint8_t *u8pt_data, uint32_t u32_len)
{
   uint8_t u8ar_reply[FSCMD_REPLY_HDR_LEN + FSCMD_READ_MAX];
   int i_ret = 0;

   u32_len = MIN(u32_len, FSCMD_READ_MAX);
   u8ar_reply[0] = u8_seq;
   u8ar_reply[1] = u8_op;
   u8ar_reply[2] = u8_status;
   if (u32_len > 0U)
   {
      memcpy(&u8ar_reply[FSCMD_REPLY_HDR_LEN], u8pt_data, u32_len);
   }

   i_ret = gi_SETUS_SendShort(FSCMD_APP_TYPE_REPLY, u8ar_reply,
      (uint8_t)(FSCMD_REPLY_HDR_LEN + u32_len), K_MSEC(FSCMD_SHORT_TIMEOUT_MS));

   // Check if the reply could not be sent (no link, not subscribed, no credit)
   if (i_ret != 0)
   {
      APP_LOG_WRN("REPLY seq %u not sent (%d)", u8_seq, i_ret);
   }
}

/**
 * @private       si_BuildMessage
 * @brief         Turn a CMD's op and argument into a File System Manager message.
 * @param[in]     u8_op FsCmdOp_E.
 * @param[in]     u8pt_arg Argument.
 * @param[in]     u32_argLen Argument length.
 * @param[out]    stpt_msg Message.
 * @return        0, or -EINVAL for an unknown op or a bad argument.
 */
static int si_BuildMessage(uint8_t u8_op, const uint8_t *u8pt_arg, uint32_t u32_argLen,
   FileSysMessage_T *stpt_msg)
{
   uint32_t u32_count = FSCMD_READ_MAX;
   bool b_pathArg = true;

   memset(stpt_msg, 0, sizeof(*stpt_msg));

   switch (u8_op)
   {
      case eFSOP_MKDIR:   stpt_msg->e_command = eFSC_MAKE_DIR;        break;
      case eFSOP_CD:      stpt_msg->e_command = eFSC_OPEN_DIR;        break;
      case eFSOP_OPENR:   stpt_msg->e_command = eFSC_OPEN_FILE_READ;  break;
      case eFSOP_OPENW:   stpt_msg->e_command = eFSC_OPEN_FILE_WRITE; break;
      case eFSOP_DELFILE: stpt_msg->e_command = eFSC_DELETE_FILE;     break;
      case eFSOP_DELDIR:  stpt_msg->e_command = eFSC_DELETE_DIR;      break;

      case eFSOP_WRITE:
         // An empty write would close the file (FAILED): refuse it here
         if (u32_argLen == 0U)
         {
            return -EINVAL;
         }
         stpt_msg->e_command = eFSC_WRITE_DATA;
         break;

      case eFSOP_READ:
         // No argument: as much as fits; a u16 count of 0 means the same
         if (u32_argLen == 2U)
         {
            u32_count = sys_get_le16(u8pt_arg);
            u32_count = ((u32_count == 0U) || (u32_count > FSCMD_READ_MAX)) ? FSCMD_READ_MAX : u32_count;
         }
         else if (u32_argLen != 0U)
         {
            return -EINVAL;
         }
         stpt_msg->e_command = eFSC_READ_FILE;
         stpt_msg->u32_sizeOfData = u32_count;
         b_pathArg = false;
         break;

      case eFSOP_LS:    stpt_msg->e_command = eFSC_DEBUG_LIST_DRIVE; b_pathArg = false; break;
      case eFSOP_CLOSE: stpt_msg->e_command = eFSC_CLOSE_FILE;       b_pathArg = false; break;
      case eFSOP_ABORT: stpt_msg->e_command = eFSC_ABORT;            b_pathArg = false; break;

      default:
         return -EINVAL;
   }

   // Check if the argument goes into the message (a path or the data of a write)
   if (b_pathArg)
   {
      if (u32_argLen > FSCMD_ARG_MAX)
      {
         return -EINVAL;
      }
      stpt_msg->u32_sizeOfData = u32_argLen;
      if (u32_argLen > 0U)
      {
         memcpy(stpt_msg->u8_data, u8pt_arg, u32_argLen);
      }
   }

   return 0;
}

/**
 * @private       sv_OnResult
 * @brief         FsmgrResult_F, on the File System Manager thread: an ENTRY per
 *                listed entry, then the REPLY, which frees the command slot.
 * @param[in]     stpt_result Result.
 * @param[in]     vpt_user Unused.
 * @return        None.
 */
static void sv_OnResult(const FsmgrResult_T *stpt_result, void *vpt_user)
{
   uint32_t u32_len = 0U;
   uint8_t u8_seq = su8_seq;
   uint8_t u8_op = su8_op;
   int i_ret = 0;

   ARG_UNUSED(vpt_user);

   // Check if this is a listing entry
   if (!stpt_result->b_final)
   {
      u32_len = stpt_result->u32_len;
      if (u32_len > FSCMD_ENTRY_PATH_MAX)
      {
         APP_LOG_WRN("path of %u bytes cut to %u", u32_len, FSCMD_ENTRY_PATH_MAX);
         u32_len = FSCMD_ENTRY_PATH_MAX;
      }
      su8ar_tx[0] = u8_seq;
      su8ar_tx[1] = stpt_result->u8_entryType;
      sys_put_le32(stpt_result->u32_entrySize, &su8ar_tx[2]);
      memcpy(&su8ar_tx[FSCMD_ENTRY_HDR_LEN], stpt_result->u8pt_data, u32_len);
      i_ret = gi_SETUS_SendShort(FSCMD_APP_TYPE_ENTRY, su8ar_tx,
         (uint8_t)(FSCMD_ENTRY_HDR_LEN + u32_len), K_MSEC(FSCMD_SHORT_TIMEOUT_MS));
      if (i_ret != 0)
      {
         APP_LOG_WRN("ENTRY seq %u not sent (%d)", u8_seq, i_ret);
      }
      return;
   }

   // The data of a successful command: a path, a byte count or read data
   if (stpt_result->i_status == 0)
   {
      switch (u8_op)
      {
         case eFSOP_MKDIR:
         case eFSOP_CD:
         case eFSOP_OPENR:
         case eFSOP_OPENW:
         case eFSOP_READ:
            u32_len = MIN(stpt_result->u32_len, FSCMD_READ_MAX);
            if (u32_len > 0U)
            {
               memcpy(su8ar_tx, stpt_result->u8pt_data, u32_len);
            }
            break;

         case eFSOP_WRITE:
         case eFSOP_CLOSE:
            sys_put_le32(stpt_result->u32_total, su8ar_tx);
            u32_len = 4U;
            break;

         case eFSOP_LS:
            sys_put_le16((uint16_t)MIN(stpt_result->u32_total, 0xFFFFU), su8ar_tx);
            u32_len = 2U;
            break;

         default:
            break;
      }
   }
   else
   {
      APP_LOG_INF("op %u seq %u failed (%d)", u8_op, u8_seq, stpt_result->i_status);
   }

   // Free the slot first: the host may send its next CMD as soon as it has the REPLY
   atomic_set(&st_busy, 0);
   sv_SendReply(u8_seq, u8_op, gu8_FSMGR_StatusCode(stpt_result->i_status), su8ar_tx, u32_len);
}

/**
 * @private       sv_OnRxShort
 * @brief         SETURxShort_F, on the SETU engine thread: hand a CMD to the File
 *                System Manager, or answer it at once (bad op or argument, busy).
 * @param[in]     u8_appType Application type.
 * @param[in]     u8pt_data Payload (valid only during the call).
 * @param[in]     u8_len Payload length.
 * @return        None.
 */
static void sv_OnRxShort(uint8_t u8_appType, const uint8_t *u8pt_data, uint8_t u8_len)
{
   uint8_t u8_seq;
   uint8_t u8_op;
   int i_ret = 0;

   // Check if this is a command with its sequence number and op
   if ((u8_appType != FSCMD_APP_TYPE_CMD) || (u8_len < FSCMD_CMD_HDR_LEN))
   {
      APP_LOG_WRN("short message 0x%02x (%u bytes) ignored", u8_appType, u8_len);
      return;
   }

   u8_seq = u8pt_data[0];
   u8_op = u8pt_data[1];

   // Check if another command, the hex upload or a flash job holds the file system
   if ((atomic_get(&st_busy) != 0) || gb_DataStore_UploadOpen()
#if defined(CONFIG_UDS)
      || gb_UdsJob_FlashRunning()
#endif // CONFIG_UDS
      )
   {
      APP_LOG_WRN("op %u seq %u refused: busy", u8_op, u8_seq);
      sv_SendReply(u8_seq, u8_op, (uint8_t)eFSS_BUSY, NULL, 0U);
      return;
   }

   i_ret = si_BuildMessage(u8_op, &u8pt_data[FSCMD_CMD_HDR_LEN], (uint32_t)u8_len - FSCMD_CMD_HDR_LEN,
      &sst_msg);
   if (i_ret != 0)
   {
      APP_LOG_WRN("op %u seq %u refused: bad op or argument", u8_op, u8_seq);
      sv_SendReply(u8_seq, u8_op, (uint8_t)eFSS_BAD_ARG, NULL, 0U);
      return;
   }

   su8_seq = u8_seq;
   su8_op = u8_op;
   atomic_set(&st_busy, 1);

   i_ret = gi_FSMGR_Submit(&sst_msg, sv_OnResult, NULL, K_NO_WAIT);
   if (i_ret != 0)
   {
      atomic_set(&st_busy, 0);
      APP_LOG_WRN("op %u seq %u refused: queue full (%d)", u8_op, u8_seq, i_ret);
      sv_SendReply(u8_seq, u8_op, (uint8_t)eFSS_BUSY, NULL, 0U);
      return;
   }

   APP_LOG_DBG("op %u seq %u queued", u8_op, u8_seq);
}

/******************************************************************************/
/*                                                                            */
/*                        PUBLIC FUNCTION DEFINITIONS                         */
/*                                                                            */
/******************************************************************************/
/**
 * @public        gi_FsCmd_Init
 * @brief         Register the file commands' appType range (0x40-0x4F) with the
 *                SETU router (short messages only: transfers are refused). Call
 *                once, before gi_SETURouter_Start(). Does nothing without
 *                CONFIG_FS_CMD.
 * @return        0 on success, otherwise the error from gi_SETURouter_Register().
 */
int gi_FsCmd_Init(void)
{
   SETURoute_T st_route = { 0 };
   int i_ret = 0;

   // Check if the file commands are built in
   if (!IS_ENABLED(CONFIG_FS_CMD))
   {
      return 0;
   }

   st_route.u8_firstAppType = FSCMD_APP_TYPE_CMD;
   st_route.u8_lastAppType = FSCMD_APP_TYPE_LAST;
   st_route.fpt_onRxShort = sv_OnRxShort;

   i_ret = gi_SETURouter_Register(&st_route);

   // Check if the route was registered
   if (i_ret != 0)
   {
      APP_LOG_ERR("gi_SETURouter_Register failed (%d)", i_ret);
   }
   else
   {
      APP_LOG_INF("file commands ready");
   }

   return i_ret;
}

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shivam Chudasama [SC]
 */
