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

#include "smartdns/util.h"

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <sys/stat.h>
#include <pthread.h>

int generate_cert_key(const char *key_path, const char *cert_path, const char *san, int days)
{
	int ret = -1;
#if (OPENSSL_VERSION_NUMBER <= 0x30000000L)
	RSA *rsa = NULL;
	BIGNUM *bn = NULL;
#endif
	X509_EXTENSION *cert_ext = NULL;
	BIO *cert_file = NULL;
	BIO *key_file = NULL;
	X509 *cert = NULL;
	EVP_PKEY *pkey = NULL;
	const int RSA_KEY_LENGTH = 2048;

	if (key_path == NULL || cert_path == NULL) {
		return ret;
	}

	key_file = BIO_new_file(key_path, "wb");
	cert_file = BIO_new_file(cert_path, "wb");
	cert = X509_new();
	if (cert == NULL) {
		goto out;
	}

	X509_set_version(cert, 2);

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
	pkey = EVP_RSA_gen(RSA_KEY_LENGTH);
#else
	bn = BN_new();
	rsa = RSA_new();
	pkey = EVP_PKEY_new();
	if (rsa == NULL || pkey == NULL || bn == NULL) {
		goto out;
	}

	EVP_PKEY_assign(pkey, EVP_PKEY_RSA, rsa);
	BN_set_word(bn, RSA_F4);
	if (RSA_generate_key_ex(rsa, RSA_KEY_LENGTH, bn, NULL) != 1) {
		goto out;
	}
#endif

	if (key_file == NULL || cert_file == NULL || cert == NULL || pkey == NULL) {
		goto out;
	}

	ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);           // serial number
	X509_gmtime_adj(X509_get_notBefore(cert), 0);               // now
	X509_gmtime_adj(X509_get_notAfter(cert), days * 24 * 3600); // accepts secs

	X509_set_pubkey(cert, pkey);

	X509_NAME *name = X509_get_subject_name(cert);

	const unsigned char *country = (unsigned char *)"smartdns";
	const unsigned char *company = (unsigned char *)"smartdns";
	const unsigned char *common_name = (unsigned char *)"smartdns";

	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, country, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, company, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, common_name, -1, -1, 0);

	if (san != NULL) {
		cert_ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, san);
		if (cert_ext == NULL) {
			goto out;
		}
		ret = X509_add_ext(cert, cert_ext, -1);
	}

	X509_set_issuer_name(cert, name);

	// Add X509v3 extensions
	cert_ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "CA:FALSE");
	ret = X509_add_ext(cert, cert_ext, -1);
	X509_EXTENSION_free(cert_ext);

	cert_ext = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, "digitalSignature,keyEncipherment");
	X509_add_ext(cert, cert_ext, -1);
	X509_EXTENSION_free(cert_ext);

	cert_ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_key_identifier, "hash");
	X509_add_ext(cert, cert_ext, -1);
	X509_EXTENSION_free(cert_ext);

	X509_sign(cert, pkey, EVP_sha256());

	ret = PEM_write_bio_PrivateKey(key_file, pkey, NULL, NULL, 0, NULL, NULL);
	if (ret != 1) {
		goto out;
	}

	ret = PEM_write_bio_X509(cert_file, cert);
	if (ret != 1) {
		goto out;
	}

	chmod(key_path, S_IRUSR);
	chmod(cert_path, S_IRUSR);

	ret = 0;
out:
	if (cert_ext) {
		X509_EXTENSION_free(cert_ext);
	}

	if (pkey) {
		EVP_PKEY_free(pkey);
	}

#if (OPENSSL_VERSION_NUMBER <= 0x30000000L)
	if (rsa && pkey == NULL) {
		RSA_free(rsa);
	}

	if (bn) {
		BN_free(bn);
	}
#endif

	if (cert_file) {
		BIO_free_all(cert_file);
	}

	if (key_file) {
		BIO_free_all(key_file);
	}

	if (cert) {
		X509_free(cert);
	}

	return ret;
}

#if OPENSSL_API_COMPAT < 0x10100000
#define THREAD_STACK_SIZE (16 * 1024)
static pthread_mutex_t *lock_cs;
static long *lock_count;

static __attribute__((unused)) void _pthreads_locking_callback(int mode, int type, const char *file, int line)
{
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&(lock_cs[type]));
		lock_count[type]++;
	} else {
		pthread_mutex_unlock(&(lock_cs[type]));
	}
}

static __attribute__((unused)) unsigned long _pthreads_thread_id(void)
{
	unsigned long ret = 0;

	ret = (unsigned long)pthread_self();
	return (ret);
}

void SSL_CRYPTO_thread_setup(void)
{
	int i = 0;

	if (lock_cs != NULL) {
		return;
	}

	lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
	if (!lock_cs || !lock_count) {
		/* Nothing we can do about this...void function! */
		if (lock_cs) {
			OPENSSL_free(lock_cs);
		}
		if (lock_count) {
			OPENSSL_free(lock_count);
		}
		return;
	}
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		lock_count[i] = 0;
		pthread_mutex_init(&(lock_cs[i]), NULL);
	}

#if OPENSSL_API_COMPAT < 0x10000000
	CRYPTO_set_id_callback(_pthreads_thread_id);
#else
	CRYPTO_THREADID_set_callback(_pthreads_thread_id);
#endif
	CRYPTO_set_locking_callback(_pthreads_locking_callback);
}

void SSL_CRYPTO_thread_cleanup(void)
{
	int i = 0;

	if (lock_cs == NULL) {
		return;
	}

	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_mutex_destroy(&(lock_cs[i]));
	}
	OPENSSL_free(lock_cs);
	OPENSSL_free(lock_count);
	lock_cs = NULL;
	lock_count = NULL;
}
#endif

unsigned char *SSL_SHA256(const unsigned char *d, size_t n, unsigned char *md)
{
	static unsigned char m[SHA256_DIGEST_LENGTH];

	if (md == NULL) {
		md = m;
	}

	EVP_MD_CTX *ctx = EVP_MD_CTX_create();
	if (ctx == NULL) {
		return NULL;
	}

	EVP_MD_CTX_init(ctx);
	EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(ctx, d, n);
	EVP_DigestFinal_ex(ctx, m, NULL);
	EVP_MD_CTX_destroy(ctx);

	return (md);
}

int SSL_base64_decode_ext(const char *in, unsigned char *out, int max_outlen, int url_safe, int auto_padding)
{
	size_t inlen = strlen(in);
	char *in_padding_data = NULL;
	int padding_len = 0;
	const char *in_data = in;
	int outlen = 0;

	if (inlen == 0) {
		return 0;
	}

	if (inlen % 4 == 0) {
		auto_padding = 0;
	}

	if (auto_padding == 1 || url_safe == 1) {
		padding_len = 4 - inlen % 4;
		in_padding_data = (char *)malloc(inlen + padding_len + 1);
		if (in_padding_data == NULL) {
			goto errout;
		}

		if (url_safe) {
			for (size_t i = 0; i < inlen; i++) {
				if (in[i] == '-') {
					in_padding_data[i] = '+';
				} else if (in[i] == '_') {
					in_padding_data[i] = '/';
				} else {
					in_padding_data[i] = in[i];
				}
			}
		} else {
			memcpy(in_padding_data, in, inlen);
		}

		if (auto_padding) {
			memset(in_padding_data + inlen, '=', padding_len);
		} else {
			padding_len = 0;
		}

		in_padding_data[inlen + padding_len] = '\0';
		in_data = in_padding_data;
		inlen += padding_len;
	}

	if (max_outlen < (int)inlen / 4 * 3) {
		goto errout;
	}

	outlen = EVP_DecodeBlock(out, (unsigned char *)in_data, inlen);
	if (outlen < 0) {
		goto errout;
	}

	/* Subtract padding bytes from |outlen| */
	while (in[--inlen] == '=') {
		--outlen;
	}

	if (in_padding_data) {
		free(in_padding_data);
	}

	outlen -= padding_len;

	return outlen;
errout:

	if (in_padding_data) {
		free(in_padding_data);
	}

	return -1;
}

int SSL_base64_decode(const char *in, unsigned char *out, int max_outlen)
{
	return SSL_base64_decode_ext(in, out, max_outlen, 0, 0);
}

int SSL_base64_encode(const void *in, int in_len, char *out)
{
	int outlen = 0;

	if (in_len == 0) {
		return 0;
	}

	outlen = EVP_EncodeBlock((unsigned char *)out, in, in_len);
	if (outlen < 0) {
		goto errout;
	}

	return outlen;
errout:
	return -1;
}

int dns_is_quic_supported(void)
{
#ifdef OSSL_QUIC1_VERSION
	return 1;
#else
	return 0;
#endif
}