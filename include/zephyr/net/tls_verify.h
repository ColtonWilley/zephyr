/*
 * Copyright (c) 2025 wolfSSL Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file
 * @brief mbedTLS-compat types and constants for the wolfSSL backend's
 *        cert-verify callback path.
 *
 * The Zephyr TLS socket layer exposes TWO cert-verify callback socket
 * options. Know which one you are using — this header is only needed
 * for option #1:
 *
 *   1. TLS_CERT_VERIFY_CALLBACK — mbedTLS-style callback.
 *      Signature:  int cb(void *data, mbedtls_x509_crt *crt,
 *                         int depth, uint32_t *flags);
 *      Under CONFIG_WOLFSSL, tls_wolfssl_verify_cb_shim() in
 *      sockets_tls.c populates a ztls_x509_crt (aliased to
 *      mbedtls_x509_crt below) from the wolfSSL cert, then invokes
 *      the customer's function. The struct definitions and
 *      MBEDTLS_X509_BADCERT_* constants below let an mbedTLS-shaped
 *      callback compile against a wolfSSL build.
 *
 *   2. TLS_CERT_VERIFY_CALLBACK_WOLFSSL — wolfSSL-style callback.
 *      Signature:  int cb(int preverify_ok,
 *                         WOLFSSL_X509_STORE_CTX *store);
 *      The customer sees raw wolfSSL types. NO struct translation
 *      happens. The struct definitions and typedefs in this file are
 *      NOT used on this path. Only the MBEDTLS_X509_BADCERT_* bit
 *      constants still matter — they back the TLS_CERT_VERIFY_RESULT
 *      getsockopt bitmask, which is populated regardless of which
 *      callback path is active.
 *
 * Under CONFIG_MBEDTLS this file is inert — the customer pulls real
 * mbedTLS types from mbedtls/x509.h and the typedefs / constants
 * below do not activate.
 *
 * Struct population tiers used by path #1 only (see sockets_tls.c
 * tls_wolfssl_populate_ztls_crt):
 *   Tier 1 — always populated (cheap fields: raw, version, serial,
 *            validity, ca_istrue).
 *   Tier 2 — populated only with CONFIG_WOLFSSL_X509_VERIFY_EXTENDED
 *            (issuer / subject DN lists, SAN list, signature OID,
 *            pk_raw).
 *   Stub   — emitted zeroed for compile-compat with mbedTLS callbacks
 *            that reference them; not meaningful data.
 */

#ifndef ZEPHYR_INCLUDE_NET_TLS_VERIFY_H_
#define ZEPHYR_INCLUDE_NET_TLS_VERIFY_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ztls_asn1_buf {
	int tag;
	size_t len;
	unsigned char *p;
};

struct ztls_x509_time {
	int year, mon, day;
	int hour, min, sec;
};

struct ztls_asn1_sequence {
	struct ztls_asn1_buf buf;
	struct ztls_asn1_sequence *next;
};

/*
 * Distinguished name component (matches mbedtls_asn1_named_data).
 * Linked list: one node per RDN (CN, O, OU, C, ST, etc.).
 * oid.p and val.p borrow directly from the certificate DER buffer
 * (the raw Name SEQUENCE). All pointers are valid only for the
 * verify callback duration. No separate allocations for the data,
 * only for the list node structs (first node is embedded in the crt).
 */
struct ztls_asn1_named_data {
	struct ztls_asn1_buf oid;
	struct ztls_asn1_buf val;
	struct ztls_asn1_named_data *next;
	unsigned char next_merged;
};

/*
 * Authority Key Identifier container (matches mbedtls_x509_authority).
 * All fields zeroed — populated in a future tier if needed.
 */
struct ztls_x509_authority {
	struct ztls_asn1_buf keyIdentifier;
	struct ztls_asn1_sequence authorityCertIssuer;
	struct ztls_asn1_buf authorityCertSerialNumber;
	struct ztls_asn1_buf raw;
};

struct ztls_x509_crt {
	/* --- Tier 1: always populated --- */
	struct ztls_asn1_buf raw;
	struct ztls_asn1_buf tbs;             /* zeroed (derivable from raw; future) */
	int version;
	struct ztls_asn1_buf serial;
	struct ztls_x509_time valid_from;
	struct ztls_x509_time valid_to;
	int ca_istrue;

	/* --- Tier 2: populated only with X509_VERIFY_EXTENDED --- */
	struct ztls_asn1_buf issuer_raw;
	struct ztls_asn1_buf subject_raw;
	struct ztls_asn1_named_data issuer;
	struct ztls_asn1_named_data subject;
	struct ztls_asn1_sequence subject_alt_names;
	struct ztls_asn1_buf sig_oid;
	struct ztls_asn1_buf pk_raw;

	/* --- Stub fields: zeroed for compile-compatibility --- */
	struct ztls_asn1_buf issuer_id;
	struct ztls_asn1_buf subject_id;
	struct ztls_asn1_buf v3_ext;
	struct ztls_asn1_buf subject_key_id;
	struct ztls_x509_authority authority_key_id;
	struct ztls_asn1_sequence certificate_policies;
	struct ztls_asn1_sequence ext_key_usage;

	/* pk (mbedtls_pk_context) is OMITTED — would require full
	 * pk-context emulation. Use pk_raw instead. */

	struct ztls_x509_crt *next;
};

#if defined(CONFIG_WOLFSSL)

typedef struct ztls_asn1_buf         mbedtls_asn1_buf;
typedef struct ztls_asn1_buf         mbedtls_x509_buf;
typedef struct ztls_x509_time        mbedtls_x509_time;
typedef struct ztls_asn1_sequence    mbedtls_asn1_sequence;
typedef struct ztls_asn1_sequence    mbedtls_x509_sequence;
typedef struct ztls_asn1_named_data  mbedtls_asn1_named_data;
typedef struct ztls_asn1_named_data  mbedtls_x509_name;
typedef struct ztls_x509_authority   mbedtls_x509_authority;
typedef struct ztls_x509_crt         mbedtls_x509_crt;

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
