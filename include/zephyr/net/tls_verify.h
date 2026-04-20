/*
 * Copyright (c) 2025 wolfSSL Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file
 * @brief mbedTLS-compatible flag-bit constants for the wolfSSL backend's
 *        TLS_CERT_VERIFY_RESULT getsockopt bitmask.
 *
 * The wolfSSL TLS backend accumulates certificate verification errors
 * into a tls_context field that backs the TLS_CERT_VERIFY_RESULT
 * socket option. The bit layout matches mbedtls/x509.h so that
 * application code inspecting the result stays portable across the
 * two backends.
 *
 * Under CONFIG_MBEDTLS this file is inert; applications pull real
 * mbedTLS types and macros from mbedtls/x509.h.
 */

#ifndef ZEPHYR_INCLUDE_NET_TLS_VERIFY_H_
#define ZEPHYR_INCLUDE_NET_TLS_VERIFY_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(CONFIG_WOLFSSL)

/* Same hex values as mbedtls/x509.h */
#define MBEDTLS_X509_BADCERT_EXPIRED          0x01
#define MBEDTLS_X509_BADCERT_REVOKED          0x02
#define MBEDTLS_X509_BADCERT_CN_MISMATCH      0x04
#define MBEDTLS_X509_BADCERT_NOT_TRUSTED      0x08
#define MBEDTLS_X509_BADCRL_NOT_TRUSTED       0x10
#define MBEDTLS_X509_BADCRL_EXPIRED           0x20
#define MBEDTLS_X509_BADCERT_MISSING          0x40
#define MBEDTLS_X509_BADCERT_SKIP_VERIFY      0x80
#define MBEDTLS_X509_BADCERT_OTHER            0x0100
#define MBEDTLS_X509_BADCERT_FUTURE           0x0200
#define MBEDTLS_X509_BADCRL_FUTURE            0x0400
#define MBEDTLS_X509_BADCERT_KEY_USAGE        0x0800
#define MBEDTLS_X509_BADCERT_EXT_KEY_USAGE    0x1000
#define MBEDTLS_X509_BADCERT_NS_CERT_TYPE     0x2000
#define MBEDTLS_X509_BADCERT_BAD_MD           0x4000
#define MBEDTLS_X509_BADCERT_BAD_PK           0x8000
#define MBEDTLS_X509_BADCERT_BAD_KEY          0x010000
#define MBEDTLS_X509_BADCRL_BAD_MD            0x020000
#define MBEDTLS_X509_BADCRL_BAD_PK            0x040000
#define MBEDTLS_X509_BADCRL_BAD_KEY           0x080000

/* Error code for verify failure (used in callback return values) */
#define MBEDTLS_ERR_X509_CERT_VERIFY_FAILED   -0x2700

#endif /* CONFIG_WOLFSSL */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_NET_TLS_VERIFY_H_ */
