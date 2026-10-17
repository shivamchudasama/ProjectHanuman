/**
 * @file          DeviceCert.h
 * @brief         Header file containing the CA and device certificate buffers and
 *                their storage in PSA ITS.
 * @date          05/09/2025
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#ifndef _DEVICE_CERT_H
#define _DEVICE_CERT_H

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include <psa/crypto.h>
#include <zephyr/drivers/hwinfo.h>
#include <psa/internal_trusted_storage.h>

#include "CSR_Generator.h"
#include "DeviceCert_Types.h"
#include "DeviceCert_Config.h"
#include "AppLog.h"

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
/**
 * @struct        <Structure name>
 * @brief         <Structure details>.
 */

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
extern DeviceCertData_T gst_deviceCertData;
extern CACertData_T gst_CACertData;

/******************************************************************************/
/*                                                                            */
/*                              EXTERN FUNCTIONS                              */
/*                                                                            */
/******************************************************************************/
extern psa_status_t gt_StoreCACert(void);
extern psa_status_t gt_StoreDeviceCert(void);
extern psa_status_t gt_LoadStoredCerts(void);
extern psa_status_t gt_RemoveStoredCerts(void);
extern void gv_ClearCertData(void);

#endif //!_DEVICE_CERT_H

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shivam Chudasama [SC]
 */
