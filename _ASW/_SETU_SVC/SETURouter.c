/**
 * @file          SETURouter.c
 * @brief         Source file containing the appType router of the SETU Server.
 *
 *                Registration happens at start-up, before gi_SETURouter_Start(),
 *                so the route table is read-only once callbacks can arrive and
 *                needs no lock. Dispatch is stateless: every SETU callback
 *                carries the appType, and a rejected START never reaches
 *                fpt_onRxDone, so each call goes to the range it belongs to.
 * @date          01/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include "SETURouter.h"
#include <zephyr/sys/atomic.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include "SETUSvc.h"
#include "AppLog.h"

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
/**
 * @def           ROUTER_FILTER_ON
 * @brief         Set in st_filter while a filter applies; bits 15..8 hold the
 *                first allowed appType, bits 7..0 the last.
 */
#define ROUTER_FILTER_ON                     (0x10000)

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
static const SETURoute_T *sstpt_FindRoute(uint8_t u8_appType);
static bool sb_IsAllowed(uint8_t u8_appType);
static int si_RouteRxStart(uint8_t u8_appType, uint32_t u32_totalLen);
static int si_RouteRxData(uint8_t u8_appType, uint32_t u32_offset,
   const uint8_t *u8pt_data, uint16_t u16_len);
static void sv_RouteRxDone(uint8_t u8_appType, SETUStatus_E e_status, uint32_t u32_totalLen);
static void sv_RouteRxShort(uint8_t u8_appType, const uint8_t *u8pt_data, uint8_t u8_len);
#if SETU_ENABLE_CLIENT
static void sv_RouteTxDone(uint8_t u8_appType, SETUStatus_E e_status);
static void sv_RouteCliReady(struct bt_conn *stpt_conn, int i_status);
#endif // SETU_ENABLE_CLIENT

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
 * @var           sstar_routes
 * @brief         Registered appType ranges (copies of the callers' structures).
 */
static SETURoute_T sstar_routes[SETU_ROUTER_MAX_ROUTES];

/**
 * @var           su8_routeCnt
 * @brief         Number of entries used in sstar_routes.
 */
static uint8_t su8_routeCnt = 0U;

/**
 * @var           sb_isStarted
 * @brief         Set once the SETU Server runs with the router callbacks.
 */
static bool sb_isStarted = false;

/**
 * @var           st_filter
 * @brief         appType filter for new transfers and short messages
 *                (ROUTER_FILTER_ON | first << 8 | last), 0 when none applies.
 *                Written by an application thread, read on the engine thread.
 */
static atomic_t st_filter = ATOMIC_INIT(0);

/**
 * @var           sfpt_admit
 * @brief         Gate consulted while no filter applies (NULL: admit all). Set
 *                before gi_SETURouter_Start(), read-only afterwards.
 */
static SETURouterAdmit_F sfpt_admit = NULL;

/**
 * @var           sfpt_refused
 * @brief         Told about each appType the gate refused (may be NULL).
 */
static SETURouterRefused_F sfpt_refused = NULL;

#if SETU_ENABLE_CLIENT
/**
 * @var           st_cliOwner
 * @brief         appType (inside its range) of the module whose Client attach
 *                is pending or done: it gets fpt_onCliReady.
 */
static atomic_t st_cliOwner = ATOMIC_INIT(0);

/**
 * @var           st_cliConn
 * @brief         Connection the Client was last asked to attach to (only
 *                compared, never dereferenced).
 */
static atomic_ptr_t st_cliConn = ATOMIC_PTR_INIT(NULL);
#endif // SETU_ENABLE_CLIENT

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
 * @private       sstpt_FindRoute
 * @brief         Find the registered range an appType belongs to.
 * @param[in]     u8_appType Application type.
 * @return        The route, or NULL if no range holds the appType.
 */
static const SETURoute_T *sstpt_FindRoute(uint8_t u8_appType)
{
   uint8_t u8_idx = 0U;

   for (u8_idx = 0U; u8_idx < su8_routeCnt; u8_idx++)
   {
      // Check if the appType lies in this range
      if ((u8_appType >= sstar_routes[u8_idx].u8_firstAppType) &&
         (u8_appType <= sstar_routes[u8_idx].u8_lastAppType))
      {
         return &sstar_routes[u8_idx];
      }
   }

   return NULL;
}

/**
 * @private       sb_IsAllowed
 * @brief         Whether the current filter, or the gate when no filter
 *                applies, lets an appType through. A gate refusal is reported
 *                to sfpt_refused.
 * @param[in]     u8_appType Application type.
 * @return        true if the type is inside the filter, or no filter applies
 *                and the gate (if any) admits it.
 */
static bool sb_IsAllowed(uint8_t u8_appType)
{
   atomic_val_t t_filter = atomic_get(&st_filter);

   // Check if a filter applies: it alone decides
   if ((t_filter & ROUTER_FILTER_ON) != 0)
   {
      return (u8_appType >= (uint8_t)((t_filter >> 8) & 0xFF)) &&
         (u8_appType <= (uint8_t)(t_filter & 0xFF));
   }

   // Check if a gate applies and refuses the type
   if ((sfpt_admit != NULL) && !sfpt_admit(u8_appType))
   {
      // Check if the gate's owner wants to know
      if (sfpt_refused != NULL)
      {
         sfpt_refused(u8_appType);
      }
      return false;
   }

   return true;
}

/**
 * @private       si_RouteRxStart
 * @brief         SETURxStart_F: forward to the owning range, reject unrouted types.
 * @param[in]     u8_appType Application type announced by the client.
 * @param[in]     u32_totalLen Object size.
 * @return        The owner's answer, or -ENOTSUP when the filter excludes the
 *                type or no range accepts transfers of this type.
 */
static int si_RouteRxStart(uint8_t u8_appType, uint32_t u32_totalLen)
{
   const SETURoute_T *stpt_route = sstpt_FindRoute(u8_appType);

   // Check if the filter or the gate lets this type through on the current link
   if (!sb_IsAllowed(u8_appType))
   {
      APP_LOG_WRN("rejected: type 0x%02x filtered", u8_appType);
      return -ENOTSUP;
   }

   // Check if a module receives transfers of this type
   if ((stpt_route == NULL) || (stpt_route->fpt_onRxData == NULL))
   {
      APP_LOG_WRN("rejected: unknown type 0x%02x", u8_appType);
      return -ENOTSUP;
   }

   // Check if the owner wants to decide (no fpt_onRxStart accepts everything)
   if (stpt_route->fpt_onRxStart != NULL)
   {
      return stpt_route->fpt_onRxStart(u8_appType, u32_totalLen);
   }

   return 0;
}

/**
 * @private       si_RouteRxData
 * @brief         SETURxData_F: forward to the owning range.
 * @param[in]     u8_appType Application type.
 * @param[in]     u32_offset Object offset of the chunk.
 * @param[in]     u8pt_data Chunk data, valid only during the call.
 * @param[in]     u16_len Chunk length.
 * @return        The owner's answer, or -EIO if the type has no receiver (not
 *                reachable: such a START is rejected).
 */
static int si_RouteRxData(uint8_t u8_appType, uint32_t u32_offset,
   const uint8_t *u8pt_data, uint16_t u16_len)
{
   const SETURoute_T *stpt_route = sstpt_FindRoute(u8_appType);

   // Check if the transfer still has a receiver
   if ((stpt_route == NULL) || (stpt_route->fpt_onRxData == NULL))
   {
      return -EIO;
   }

   return stpt_route->fpt_onRxData(u8_appType, u32_offset, u8pt_data, u16_len);
}

/**
 * @private       sv_RouteRxDone
 * @brief         SETURxDone_F: forward to the owning range.
 * @param[in]     u8_appType Application type.
 * @param[in]     e_status Result of the transfer.
 * @param[in]     u32_totalLen Size announced in START.
 * @return        None.
 */
static void sv_RouteRxDone(uint8_t u8_appType, SETUStatus_E e_status, uint32_t u32_totalLen)
{
   const SETURoute_T *stpt_route = sstpt_FindRoute(u8_appType);

   // Check if the owner wants the result
   if ((stpt_route != NULL) && (stpt_route->fpt_onRxDone != NULL))
   {
      stpt_route->fpt_onRxDone(u8_appType, e_status, u32_totalLen);
   }
}

/**
 * @private       sv_RouteRxShort
 * @brief         SETURxShort_F: forward to the owning range, log and drop others
 *                (filtered types included).
 * @param[in]     u8_appType Application type.
 * @param[in]     u8pt_data Payload, valid only during the call.
 * @param[in]     u8_len Payload length.
 * @return        None.
 */
static void sv_RouteRxShort(uint8_t u8_appType, const uint8_t *u8pt_data, uint8_t u8_len)
{
   const SETURoute_T *stpt_route = sstpt_FindRoute(u8_appType);

   // Check if the filter or the gate lets this type through on the current link
   if (!sb_IsAllowed(u8_appType))
   {
      APP_LOG_WRN("short message type 0x%02x filtered", u8_appType);
   }
   // Check if a module handles short messages of this type
   else if ((stpt_route != NULL) && (stpt_route->fpt_onRxShort != NULL))
   {
      stpt_route->fpt_onRxShort(u8_appType, u8pt_data, u8_len);
   }
   else
   {
      APP_LOG_INF("short message type 0x%02x, %u bytes ignored", u8_appType, u8_len);
   }
}

#if SETU_ENABLE_CLIENT
/**
 * @private       sv_RouteTxDone
 * @brief         SETUTxDone_F: hand a Client transfer's result to the range that
 *                owns its appType.
 * @param[in]     u8_appType Application type of the transfer.
 * @param[in]     e_status Result of the transfer.
 * @return        None.
 */
static void sv_RouteTxDone(uint8_t u8_appType, SETUStatus_E e_status)
{
   const SETURoute_T *stpt_route = sstpt_FindRoute(u8_appType);

   // Check if the owner wants the result
   if ((stpt_route != NULL) && (stpt_route->fpt_onTxDone != NULL))
   {
      stpt_route->fpt_onTxDone(u8_appType, e_status);
   }
   else
   {
      APP_LOG_WRN("transfer 0x%02x ended (%d), no owner", u8_appType, (int)e_status);
   }
}

/**
 * @private       sv_RouteCliReady
 * @brief         SETUCliReady_F: hand the attach result to the module that asked
 *                for the attach.
 * @param[in]     stpt_conn Connection the Client attached to.
 * @param[in]     i_status 0 when ready, negative errno otherwise.
 * @return        None.
 */
static void sv_RouteCliReady(struct bt_conn *stpt_conn, int i_status)
{
   const SETURoute_T *stpt_route = sstpt_FindRoute((uint8_t)atomic_get(&st_cliOwner));

   // Check if the owner wants the result
   if ((stpt_route != NULL) && (stpt_route->fpt_onCliReady != NULL))
   {
      stpt_route->fpt_onCliReady(stpt_conn, i_status);
   }
}
#endif // SETU_ENABLE_CLIENT

/******************************************************************************/
/*                                                                            */
/*                        PUBLIC FUNCTION DEFINITIONS                         */
/*                                                                            */
/******************************************************************************/
/**
 * @public        gi_SETURouter_Register
 * @brief         Register an appType range and its callbacks (copied). Call at
 *                start-up, before gi_SETURouter_Start().
 * @param[in]     stpt_route Range and callbacks.
 * @return        0 on success; -EINVAL for NULL, an inverted range or a range
 *                reaching above SETU_APP_TYPE_MAX; -EEXIST if it overlaps a
 *                registered range; -ENOMEM if SETU_ROUTER_MAX_ROUTES are used;
 *                -EALREADY after gi_SETURouter_Start().
 */
int gi_SETURouter_Register(const SETURoute_T *stpt_route)
{
   uint8_t u8_idx = 0U;

   // Check if the route table is still open
   if (sb_isStarted)
   {
      return -EALREADY;
   }

   // Check if the range is valid
   if ((stpt_route == NULL) ||
      (stpt_route->u8_firstAppType > stpt_route->u8_lastAppType) ||
      (stpt_route->u8_lastAppType > SETU_APP_TYPE_MAX))
   {
      return -EINVAL;
   }

   for (u8_idx = 0U; u8_idx < su8_routeCnt; u8_idx++)
   {
      // Check if the range overlaps a registered one
      if ((stpt_route->u8_firstAppType <= sstar_routes[u8_idx].u8_lastAppType) &&
         (stpt_route->u8_lastAppType >= sstar_routes[u8_idx].u8_firstAppType))
      {
         return -EEXIST;
      }
   }

   // Check if there is room for another range
   if (su8_routeCnt >= SETU_ROUTER_MAX_ROUTES)
   {
      return -ENOMEM;
   }

   sstar_routes[su8_routeCnt] = *stpt_route;
   su8_routeCnt++;

   return 0;
}

/**
 * @public        gi_SETURouter_Start
 * @brief         Initialise the SETU GATT service, the SETU Server and
 *                (when SETU_ENABLE_CLIENT) the SETU Client with the router
 *                callbacks. Call once, after
 *                every module has registered and before advertising starts. A
 *                failed start can be retried.
 * @return        0 on success, -EALREADY if already started, otherwise the error
 *                from gi_SETUS_Init() or gi_SETUC_Init().
 */
int gi_SETURouter_Start(void)
{
   SETUSrvCfg_T st_cfg = { 0 };
#if SETU_ENABLE_CLIENT
   SETUCliCfg_T st_cliCfg = { 0 };
#endif // SETU_ENABLE_CLIENT
   int i_ret = 0;

   // Check if the Server already runs
   if (sb_isStarted)
   {
      return -EALREADY;
   }

   st_cfg.stpt_ctrlAttr = gstpt_SETUSvc_Init();
   st_cfg.fpt_onRxStart = si_RouteRxStart;
   st_cfg.fpt_onRxData = si_RouteRxData;
   st_cfg.fpt_onRxDone = sv_RouteRxDone;
   st_cfg.fpt_onRxShort = sv_RouteRxShort;
   // ConnectionHandling.c already negotiates PHY, data length and MTU
   st_cfg.b_autoTuneLink = false;

   i_ret = gi_SETUS_Init(&st_cfg);

   // Check if the SETU Server started (-EALREADY: a retried start)
   if ((i_ret != 0) && (i_ret != -EALREADY))
   {
      APP_LOG_ERR("gi_SETUS_Init failed (%d)", i_ret);
      return i_ret;
   }

#if SETU_ENABLE_CLIENT
   st_cliCfg.fpt_onReady = sv_RouteCliReady;
   st_cliCfg.fpt_onTxDone = sv_RouteTxDone;
   // ConnectionHandling.c already negotiates PHY, data length and MTU
   st_cliCfg.b_autoTuneLink = false;

   i_ret = gi_SETUC_Init(&st_cliCfg);

   // Check if the SETU Client started
   if ((i_ret != 0) && (i_ret != -EALREADY))
   {
      APP_LOG_ERR("gi_SETUC_Init failed (%d)", i_ret);
      return i_ret;
   }
#endif // SETU_ENABLE_CLIENT

   sb_isStarted = true;
   APP_LOG_INF("SETU server and client ready, %u appType range(s)", su8_routeCnt);

   return 0;
}

/**
 * @public        gi_SETURouter_SetGate
 * @brief         Install the gate consulted for new transfers and short
 *                messages while no filter applies: a refused transfer is
 *                rejected at START (as an unknown type), a refused short
 *                message is dropped, and fpt_refused hears of both. A filter
 *                (gv_SETURouter_SetFilter()) overrides the gate while it
 *                applies. Call at start-up, before gi_SETURouter_Start().
 * @param[in]     fpt_admit Gate, or NULL to admit everything.
 * @param[in]     fpt_refused Told about refusals (may be NULL).
 * @return        0 on success, -EALREADY after gi_SETURouter_Start().
 */
int gi_SETURouter_SetGate(SETURouterAdmit_F fpt_admit, SETURouterRefused_F fpt_refused)
{
   // Check if the router is still being set up
   if (sb_isStarted)
   {
      return -EALREADY;
   }

   sfpt_admit = fpt_admit;
   sfpt_refused = fpt_refused;

   return 0;
}

#if SETU_ENABLE_CLIENT
/**
 * @public        gi_SETURouter_ClientAttach
 * @brief         Attach the shared SETU Client to a connection on behalf of
 *                a module, moving it off another connection if needed. Thread
 *                context only.
 *
 *                - Already attached and ready on stpt_conn: -EALREADY, the
 *                  module may send at once (no fpt_onCliReady follows).
 *                - Otherwise the attach starts (or, if it is already running
 *                  for stpt_conn, continues) and its result goes to the
 *                  owner's fpt_onCliReady. A Client bound to another
 *                  connection is detached first (gi_SETUC_Detach()), which is
 *                  refused while an attach or a transfer runs there.
 * @param[in]     stpt_conn Connection to attach to.
 * @param[in]     u8_ownerAppType Any appType of the asking module's range; the
 *                range must have fpt_onCliReady.
 * @return        0 if the attach started or is running (fpt_onCliReady
 *                follows), -EALREADY if ready on this connection already,
 *                -EPERM if the router has not started, -EINVAL for a NULL
 *                connection or an owner without fpt_onCliReady, -EBUSY if the
 *                Client is busy on another connection, otherwise the error of
 *                gi_SETUC_Attach().
 */
int gi_SETURouter_ClientAttach(struct bt_conn *stpt_conn, uint8_t u8_ownerAppType)
{
   const SETURoute_T *stpt_owner = sstpt_FindRoute(u8_ownerAppType);
   int i_ret;

   // Check if the Client runs and the request is valid
   if (!sb_isStarted)
   {
      return -EPERM;
   }
   if ((stpt_conn == NULL) || (stpt_owner == NULL) || (stpt_owner->fpt_onCliReady == NULL))
   {
      return -EINVAL;
   }

   // The owner is set first: the result may arrive before this call returns
   (void)atomic_set(&st_cliOwner, u8_ownerAppType);

   // Check if the Client is ready on this connection already
   if (gb_SETUC_IsReady() && (atomic_ptr_get(&st_cliConn) == stpt_conn))
   {
      return -EALREADY;
   }

   i_ret = gi_SETUC_Attach(stpt_conn);

   // Check if the Client is bound to another connection: move it
   if (i_ret == -EBUSY)
   {
      i_ret = gi_SETUC_Detach();

      // Check if it could be released (-ENOTCONN: released meanwhile)
      if ((i_ret != 0) && (i_ret != -ENOTCONN))
      {
         return -EBUSY;
      }

      i_ret = gi_SETUC_Attach(stpt_conn);
   }

   // -EALREADY from gi_SETUC_Attach(): an attach is running for this connection
   if (i_ret == -EALREADY)
   {
      i_ret = 0;
   }

   // Check if the attach started
   if (i_ret == 0)
   {
      (void)atomic_ptr_set(&st_cliConn, stpt_conn);
   }

   return i_ret;
}
#endif // SETU_ENABLE_CLIENT

/**
 * @public        gv_SETURouter_SetFilter
 * @brief         Accept only appTypes u8_first..u8_last (inclusive) from now
 *                on: other transfers are rejected at START (as unknown
 *                types) and other short messages are dropped. A transfer
 *                already accepted runs to its end. For a link whose peer may
 *                reach only one module, e.g. a peer device that may only
 *                pair. Any thread; replaces the previous filter.
 * @param[in]     u8_first First allowed appType.
 * @param[in]     u8_last Last allowed appType (inclusive).
 * @return        None.
 */
void gv_SETURouter_SetFilter(uint8_t u8_first, uint8_t u8_last)
{
   (void)atomic_set(&st_filter,
      ROUTER_FILTER_ON | ((atomic_val_t)u8_first << 8) | (atomic_val_t)u8_last);
}

/**
 * @public        gv_SETURouter_ClearFilter
 * @brief         Remove the filter: every registered range is reachable
 *                again. Any thread.
 * @return        None.
 */
void gv_SETURouter_ClearFilter(void)
{
   (void)atomic_set(&st_filter, 0);
}

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shivam Chudasama [SC]
 */
