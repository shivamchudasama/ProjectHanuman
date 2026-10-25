/**
 * @file          DeviceCert_Verify.h
 * @brief         Header file containing X.509 certificate verification for device
 *                provisioning: the CA certificate, this device's own certificate,
 *                and (for pairing) a remote device's certificate.
 * @date          01/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#ifndef _DEVICE_CERT_VERIFY_H
#define _DEVICE_CERT_VERIFY_H

/******************************************************************************/
/*                                                                            */
/*                                  INCLUDES                                  */
/*                                                                            */
/******************************************************************************/
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <psa/crypto.h>
#include "DeviceCert_Types.h"

/******************************************************************************/
/*                                                                            */
/*                                  DEFINES                                   */
/*                                                                            */
/******************************************************************************/
/**
 * @def           DEVICE_CERT_P256_PUB_KEY_LEN
 * @brief         Length of an uncompressed P-256 public key (0x04 || X || Y).
 */
#define DEVICE_CERT_P256_PUB_KEY_LEN         (65)

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
// All functions are blocking (ECDSA verify) and not thread safe: one caller at a
// time. Their callers exclude each other by state: provisioning needs an
// unprovisioned device, host authentication a provisioned device with an
// untrusted host link, pairing a run started by the trusted host. None of them
// checks the validity period, as the device has no wall clock.
extern DeviceCertStatus_E ge_VerifyCACertificate(const uint8_t *u8pt_der, size_t t_len);
extern DeviceCertStatus_E ge_VerifyOwnDeviceCertificate(const uint8_t *u8pt_der,
   size_t t_len);
extern DeviceCertStatus_E ge_VerifyStoredDeviceCertificate(const uint8_t *u8pt_der,
   size_t t_len);
extern DeviceCertStatus_E ge_VerifyRemoteDeviceCertificate(const uint8_t *u8pt_der,
   size_t t_len, psa_key_id_t *tpt_remotePubKeyID);
extern DeviceCertStatus_E ge_VerifyHostCertificate(const uint8_t *u8pt_der,
   size_t t_len, psa_key_id_t *tpt_hostPubKeyID);
extern bool gb_IsTrustAnchorSet(void);
extern void gv_ClearTrustAnchor(void);

#endif //!_DEVICE_CERT_VERIFY_H

/**
 * Copyright(c) Bajaj Auto Technology Limited (BATL) as an unpublished work.
 * THIS SOFTWARE AND/OR MATERIAL IS THE PROPERTY OF BATL.
 * ALL USE, DISCLOSURE, AND/OR REPRODUCTION NOT SPECIFICALLY AUTHORIZED BY
 * BATL IS PROHIBITED.
 *
 * @author:Shivam Chudasama [SC]
 */
