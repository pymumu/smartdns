/*************************************************************************
 *
 * Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
 *
 * smartdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * smartdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _SMARTDNS_OPENSSL_COMPAT_H_
#define _SMARTDNS_OPENSSL_COMPAT_H_

/*
 * Single point of truth for OpenSSL version handling.
 *
 * smartdns must build and behave identically with OpenSSL 1.0.x through 4.x.
 * Every version check in the tree MUST go through the macros below instead of
 * open-coding OPENSSL_VERSION_NUMBER / OPENSSL_API_COMPAT / OSSL_QUIC1_VERSION.
 *
 * Rationale for not using OPENSSL_API_COMPAT: it describes the API level the
 * caller asked to *hide*, not the version of the library being compiled
 * against, and it is overridable from the command line. Using it to decide
 * whether to call SSL_library_init() or CRYPTO_set_locking_callback() produced
 * declarations without definitions (link failure) and, in the other direction,
 * an uninitialised and non-thread-safe OpenSSL 1.0.x.
 */

#include <openssl/opensslv.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <stdint.h>
#include <time.h>

#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 4
/* OpenSSL 4.0 removed the low level RSA/DSA/DH interfaces entirely. */
#include <openssl/core_names.h>
#endif

/* ------------------------------------------------------------------ */
/* Identity normalisation                                             */
/* ------------------------------------------------------------------ */

#if defined(LIBRESSL_VERSION_NUMBER)
# define SMARTDNS_OPENSSL_IS_LIBRESSL 1
#else
# define SMARTDNS_OPENSSL_IS_LIBRESSL 0
#endif

/*
 * LibreSSL and BoringSSL report an OPENSSL_VERSION_NUMBER of their own
 * (0x20000000L / 0x1010007fL), which is exactly what the feature checks below
 * have to be based on -- do NOT substitute LIBRESSL_VERSION_NUMBER here.
 */
#define SMARTDNS_OPENSSL_VERSION_NUMBER OPENSSL_VERSION_NUMBER

#define SMARTDNS_OPENSSL_V_1_0_0 0x10000000L
#define SMARTDNS_OPENSSL_V_1_0_2 0x10002000L
#define SMARTDNS_OPENSSL_V_1_1_0 0x10100000L
#define SMARTDNS_OPENSSL_V_1_1_1 0x10101000L
#define SMARTDNS_OPENSSL_V_3_0_0 0x30000000L
#define SMARTDNS_OPENSSL_V_3_2_0 0x30200000L
#define SMARTDNS_OPENSSL_V_4_0_0 0x40000000L

#define SMARTDNS_OPENSSL_AT_LEAST(v) (SMARTDNS_OPENSSL_VERSION_NUMBER >= (v))
#define SMARTDNS_OPENSSL_BEFORE(v)   (SMARTDNS_OPENSSL_VERSION_NUMBER <  (v))

/* ------------------------------------------------------------------ */
/* Capability macros                                                  */
/* ------------------------------------------------------------------ */

/*
 * QUIC: one single probe. Replaces the eight open-coded
 * `defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)` tests and the
 * competing `OPENSSL_VERSION_NUMBER >= 0x30200000L` test, which could disagree.
 */
#if !SMARTDNS_OPENSSL_IS_LIBRESSL && defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC) && \
	SMARTDNS_OPENSSL_AT_LEAST(SMARTDNS_OPENSSL_V_3_2_0)
# define SMARTDNS_OPENSSL_HAVE_QUIC 1
#else
# define SMARTDNS_OPENSSL_HAVE_QUIC 0
#endif

/* ASN1_TIME_cmp_time_t() / TLS 1.3 / SSL_CTX_set_ciphersuites() */
#define SMARTDNS_HAVE_TLS13              SMARTDNS_OPENSSL_AT_LEAST(SMARTDNS_OPENSSL_V_1_1_1)
/* SSL_CTX_set_min_proto_version() / SSL_CTX_set_max_proto_version() */
#define SMARTDNS_HAVE_PROTO_VERSION_API  SMARTDNS_OPENSSL_AT_LEAST(SMARTDNS_OPENSSL_V_1_1_0)
/* SSL_set1_host() -- hostname verification via X509_VERIFY_PARAM */
#define SMARTDNS_HAVE_SSL_SET1_HOST      SMARTDNS_OPENSSL_AT_LEAST(SMARTDNS_OPENSSL_V_1_0_2)
/* SSL_CTX_set_ecdh_auto() -- only needed on 1.0.2, 1.1.0+ does it implicitly */
#define SMARTDNS_HAVE_ECDH_AUTO          SMARTDNS_OPENSSL_AT_LEAST(SMARTDNS_OPENSSL_V_1_0_2)
/*
 * OpenSSL < 1.1.0 requires explicit library initialisation and locking
 * callbacks. Those entry points were removed in 1.1.0.
 */
#define SMARTDNS_NEED_LEGACY_INIT        SMARTDNS_OPENSSL_BEFORE(SMARTDNS_OPENSSL_V_1_1_0)
#define SMARTDNS_NEED_LEGACY_THREAD_CB   SMARTDNS_OPENSSL_BEFORE(SMARTDNS_OPENSSL_V_1_1_0)

/* ------------------------------------------------------------------ */
/* Peer certificate                                                   */
/* ------------------------------------------------------------------ */

/*
 * SSL_get_peer_certificate() was deprecated in 3.0 and removed in 4.0.
 * Both spellings return a certificate with an incremented reference count,
 * so the caller's X509_free() obligation is identical.
 */
#if SMARTDNS_OPENSSL_AT_LEAST(SMARTDNS_OPENSSL_V_3_0_0)
# define dns_SSL_get1_peer_certificate(s) SSL_get1_peer_certificate(s)
#else
# define dns_SSL_get1_peer_certificate(s) SSL_get_peer_certificate(s)
#endif

/* ------------------------------------------------------------------ */
/* X509 notBefore / notAfter accessors                                */
/* ------------------------------------------------------------------ */

/*
 * Three different spellings exist:
 *   1.0.x: X509_get_notAfter()        -> mutable ASN1_TIME *
 *   1.1.0+: X509_getm_notAfter()     -> mutable ASN1_TIME *
 *           X509_get0_notAfter()     -> const ASN1_TIME *
 *   4.0:  X509_get_notAfter()        -> removed
 *
 * X509_gmtime_adj() needs the mutable form, everything else should use the
 * const form. Getting this wrong is a hard compile error on 4.0 for the
 * X509_gmtime_adj() call sites.
 */
#if SMARTDNS_OPENSSL_AT_LEAST(SMARTDNS_OPENSSL_V_1_1_0)
# define dns_X509_getm_notAfter(c)  X509_getm_notAfter(c)
# define dns_X509_getm_notBefore(c) X509_getm_notBefore(c)
# define dns_X509_get0_notAfter(c)  X509_get0_notAfter(c)
# define dns_X509_get0_notBefore(c) X509_get0_notBefore(c)
#else
# define dns_X509_getm_notAfter(c)  X509_get_notAfter(c)
# define dns_X509_getm_notBefore(c) X509_get_notBefore(c)
# define dns_X509_get0_notAfter(c)  X509_get_notAfter(c)
# define dns_X509_get0_notBefore(c) X509_get_notBefore(c)
#endif

/* ------------------------------------------------------------------ */
/* SSL_METHOD selection                                               */
/* ------------------------------------------------------------------ */

/*
 * TLS_*_method() (version flexible, "any supported protocol") replaced
 * SSLv23_*_method() in 1.1.0; the old names survive but are deprecated.
 */
#if SMARTDNS_OPENSSL_AT_LEAST(SMARTDNS_OPENSSL_V_1_1_0)
# define dns_TLS_client_method() TLS_client_method()
# define dns_TLS_server_method() TLS_server_method()
#else
# define dns_TLS_client_method() SSLv23_client_method()
# define dns_TLS_server_method() SSLv23_server_method()
#endif

/* ------------------------------------------------------------------ */
/* const qualifiers                                                   */
/* ------------------------------------------------------------------ */

/*
 * X509_NAME_get_index_by_NID(), X509_NAME_get_entry(),
 * X509_NAME_ENTRY_get_data(), i2d_X509_PUBKEY() and X509_set_issuer_name() only
 * gained const parameters in OpenSSL 3.0 -- both 1.0.x and 1.1.x declare them
 * without. Passing a const pointer to them triggers -Wdiscarded-qualifiers on
 * everything below 3.0, which is why the cutoff here is 3.0.0 and not 1.1.0.
 *
 * dns_unconst() drops the qualifier where the library really lacks it and is a
 * plain identity on 3.0+, so call sites keep a single spelling and stay
 * const-correct on modern OpenSSL.
 */
#if SMARTDNS_OPENSSL_BEFORE(SMARTDNS_OPENSSL_V_3_0_0)
# define dns_unconst(type, p) ((type)(uintptr_t)(const void *)(p))
#else
# define dns_unconst(type, p) (p)
#endif

/* ------------------------------------------------------------------ */
/* ASN1_STRING data pointer                                           */
/* ------------------------------------------------------------------ */

#if SMARTDNS_OPENSSL_AT_LEAST(SMARTDNS_OPENSSL_V_1_1_0)
# define dns_ASN1_STRING_get0_data(s) ASN1_STRING_get0_data(s)
#else
# define dns_ASN1_STRING_get0_data(s) ASN1_STRING_data(dns_unconst(ASN1_STRING *, s))
#endif

/* ------------------------------------------------------------------ */
/* EVP_MD_CTX lifecycle                                               */
/* ------------------------------------------------------------------ */

#if SMARTDNS_OPENSSL_AT_LEAST(SMARTDNS_OPENSSL_V_1_1_0)
# define dns_EVP_MD_CTX_new()    EVP_MD_CTX_new()
# define dns_EVP_MD_CTX_free(c)  EVP_MD_CTX_free(c)
# define dns_EVP_MD_CTX_reset(c) EVP_MD_CTX_reset(c)
#else
# define dns_EVP_MD_CTX_new()    EVP_MD_CTX_create()
# define dns_EVP_MD_CTX_free(c)  EVP_MD_CTX_destroy(c)
# define dns_EVP_MD_CTX_reset(c) EVP_MD_CTX_init(c)
#endif

/* ------------------------------------------------------------------ */
/* Certificate time comparison                                        */
/* ------------------------------------------------------------------ */

/*
 * Returns < 0 when `t` is in the past, > 0 when in the future, 0 on error --
 * identical for both implementations, so the call site does not need to care.
 */
#if SMARTDNS_OPENSSL_AT_LEAST(SMARTDNS_OPENSSL_V_1_1_1)
static inline int dns_ASN1_TIME_cmp_now(const ASN1_TIME *t)
{
	return ASN1_TIME_cmp_time_t(t, time(NULL));
}
#else
static inline int dns_ASN1_TIME_cmp_now(const ASN1_TIME *t)
{
	return X509_cmp_current_time(t);
}
#endif

/* ------------------------------------------------------------------ */
/* Upstream hostname verification                                     */
/* ------------------------------------------------------------------ */

#if SMARTDNS_OPENSSL_AT_LEAST(SMARTDNS_OPENSSL_V_4_0_0)
# define dns_SSL_set1_peer_dnsname(s, h) SSL_set1_dnsname((s), (h))
#elif SMARTDNS_HAVE_SSL_SET1_HOST
# define dns_SSL_set1_peer_dnsname(s, h) SSL_set1_host((s), (h))
#else
/* 1.0.1 has no such API; callers must fall back to the built-in SAN/CN check. */
# define dns_SSL_set1_peer_dnsname(s, h) (0)
#endif

/* ------------------------------------------------------------------ */
/* ECDH                                                               */
/* ------------------------------------------------------------------ */

#if SMARTDNS_OPENSSL_AT_LEAST(SMARTDNS_OPENSSL_V_1_1_0)
/* Implicit since 1.1.0. */
# define dns_SSL_CTX_set_ecdh_auto(ctx) ((void)0)
#elif SMARTDNS_HAVE_ECDH_AUTO
# define dns_SSL_CTX_set_ecdh_auto(ctx) SSL_CTX_set_ecdh_auto((ctx), 1)
#else
# define dns_SSL_CTX_set_ecdh_auto(ctx) ((void)0)
#endif

/* ------------------------------------------------------------------ */
/* Private key PEM output format                                      */
/* ------------------------------------------------------------------ */

/*
 * Always emit PKCS#8 ("BEGIN PRIVATE KEY").
 *
 * PEM_write_bio_PrivateKey() already defaults to PKCS#8 on both 1.0.x (RSA has
 * ameth->priv_encode, so it routes to PEM_write_bio_PKCS8PrivateKey) and 3.x,
 * but the default is an implementation detail that OpenSSL is free to change --
 * and pinning the other direction is worse: PEM_write_bio_PrivateKey_traditional()
 * only exists from 3.0, so using it would make 1.0.x emit PKCS#8 while 3.x
 * emitted PKCS#1, i.e. output that depends on the build.
 *
 * PEM_write_bio_PKCS8PrivateKey() exists in every supported release, so naming
 * the format outright is both explicit and version independent.
 */
# define dns_PEM_write_bio_PrivateKey(bp, pkey) \
	PEM_write_bio_PKCS8PrivateKey((bp), (pkey), NULL, NULL, 0, NULL, NULL)

/* ------------------------------------------------------------------ */
/* TLS write                                                          */
/* ------------------------------------------------------------------ */

/*
 * QUIC needs SSL_write_ex2() to carry stream flags; 1.1.0+ can report partial
 * writes via SSL_write_ex(); anything older has to use SSL_write().
 * All three report the number of bytes consumed in `written`.
 */
static inline int dns_SSL_write(SSL *ssl, const void *buff, int num, uint64_t flags, size_t *written)
{
#if SMARTDNS_OPENSSL_HAVE_QUIC
	(void)flags;
	return SSL_write_ex2(ssl, buff, (size_t)num, flags, written);
#elif SMARTDNS_OPENSSL_AT_LEAST(SMARTDNS_OPENSSL_V_1_1_1)
	int ret = 0;

	(void)flags;
	ret = SSL_write_ex(ssl, buff, (size_t)num, written);
	if (ret > 0) {
		return ret;
	}
	return ret;
#else
	int ret = 0;

	(void)flags;
	ret = (int)SSL_write(ssl, buff, num);
	*written = (ret > 0) ? (size_t)ret : 0;
	return ret;
#endif
}

/* ------------------------------------------------------------------ */
/* Version independent SSL_CTX defaults                               */
/* ------------------------------------------------------------------ */

/*
 * Applies the fixed protocol range, cipher list and ECDH setup to a freshly
 * created SSL_CTX. Declared here rather than in util.h so that util.h keeps not
 * exposing any OpenSSL type.
 */
void dns_ssl_ctx_setup_defaults(SSL_CTX *ssl_ctx);

#endif /* _SMARTDNS_OPENSSL_COMPAT_H_ */
