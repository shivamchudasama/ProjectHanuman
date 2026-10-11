/**
 * @file          UdsClient_Config.h
 * @brief         Tunables of the UDS client. Each takes its Kconfig value (_DI/Kconfig,
 *                menu "UDS") when the build defines it, otherwise the default below,
 *                so the library also builds without the application's Kconfig (host
 *                tests).
 *
 * @date          12/10/2026
 * @author        Shivam Chudasama [SC]
 * @license       MIT
 */

/* SPDX-License-Identifier: MIT */

#ifndef _UDS_CLIENT_CONFIG_H
#define _UDS_CLIENT_CONFIG_H

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
/**
 * @def           UDS_P2_MS
 * @brief         Default wait for a response (P2 client), until the ECU's
 *                DiagnosticSessionControl response gives its own P2.
 */
#ifndef UDS_P2_MS
#ifdef CONFIG_UDS_P2_MS
#define UDS_P2_MS                            CONFIG_UDS_P2_MS
#else
#define UDS_P2_MS                            (150)
#endif // CONFIG_UDS_P2_MS
#endif // UDS_P2_MS

/**
 * @def           UDS_P2STAR_MS
 * @brief         Default wait after NRC 0x78 (P2* client), until the ECU gives its
 *                own.
 */
#ifndef UDS_P2STAR_MS
#ifdef CONFIG_UDS_P2STAR_MS
#define UDS_P2STAR_MS                        CONFIG_UDS_P2STAR_MS
#else
#define UDS_P2STAR_MS                        (5000)
#endif // CONFIG_UDS_P2STAR_MS
#endif // UDS_P2STAR_MS

/**
 * @def           UDS_P2_MARGIN_MS
 * @brief         Added to the ECU's P2 and P2* (server values) for the network
 *                and the tester's own latency.
 */
#ifndef UDS_P2_MARGIN_MS
#define UDS_P2_MARGIN_MS                     (50)
#endif // UDS_P2_MARGIN_MS

/**
 * @def           UDS_TESTER_PRESENT_MS
 * @brief         Keep-alive period in a non-default session (S3 server is 5 s).
 */
#ifndef UDS_TESTER_PRESENT_MS
#ifdef CONFIG_UDS_TESTER_PRESENT_MS
#define UDS_TESTER_PRESENT_MS                CONFIG_UDS_TESTER_PRESENT_MS
#else
#define UDS_TESTER_PRESENT_MS                (2000)
#endif // CONFIG_UDS_TESTER_PRESENT_MS
#endif // UDS_TESTER_PRESENT_MS

/**
 * @def           UDS_BUSY_RETRIES
 * @brief         Times a request is repeated after NRC 0x21 busyRepeatRequest.
 */
#ifndef UDS_BUSY_RETRIES
#ifdef CONFIG_UDS_BUSY_RETRIES
#define UDS_BUSY_RETRIES                     CONFIG_UDS_BUSY_RETRIES
#else
#define UDS_BUSY_RETRIES                     (3)
#endif // CONFIG_UDS_BUSY_RETRIES
#endif // UDS_BUSY_RETRIES

/**
 * @def           UDS_BUSY_DELAY_MS
 * @brief         Pause before repeating a request after NRC 0x21.
 */
#ifndef UDS_BUSY_DELAY_MS
#define UDS_BUSY_DELAY_MS                    (20)
#endif // UDS_BUSY_DELAY_MS

/**
 * @def           UDS_PENDING_MAX
 * @brief         NRC 0x78 answers accepted for one request before it times out
 *                (ISO 14229 sets no limit; this keeps a broken ECU from holding the
 *                tester for ever).
 */
#ifndef UDS_PENDING_MAX
#define UDS_PENDING_MAX                      (100)
#endif // UDS_PENDING_MAX

/**
 * @def           UDS_CLIENT_BUF_SIZE
 * @brief         The client's own request and response buffers (service helpers):
 *                bounds seeds, keys, WriteDataByIdentifier data and routine
 *                arguments and status records.
 */
#ifndef UDS_CLIENT_BUF_SIZE
#define UDS_CLIENT_BUF_SIZE                  (64)
#endif // UDS_CLIENT_BUF_SIZE

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

#endif //!_UDS_CLIENT_CONFIG_H
