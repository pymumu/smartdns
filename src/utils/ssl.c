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

#include "smartdns/dns_conf.h"
#include "smartdns/tlog.h"
#include "smartdns/util.h"

#include <ifaddrs.h>
#include <linux/limits.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <pthread.h>
#include <sys/stat.h>

#define DNS_MAX_HOSTNAME_LEN 256

struct DNS_EVP_PKEY_CTX {
	EVP_PKEY *pkey;
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
	RSA *rsa;
	BIGNUM *bn;
#endif
};

int is_cert_valid(const char *cert_file_path)
{
	struct stat st;
	BIO *cert_file = NULL;
	X509 *cert = NULL;
	int ret = 0;

	if (stat(cert_file_path, &st) != 0) {
		return 0;
	}

	if (st.st_size <= 0) {
		return 0;
	}

	cert_file = BIO_new_file(cert_file_path, "r");
	if (cert_file == NULL) {
		return 0;
	}

	cert = PEM_read_bio_X509_AUX(cert_file, NULL, NULL, NULL);
	if (cert == NULL) {
		goto out;
	}

	if (X509_get_notAfter(cert) == NULL) {
		goto out;
	}

	if (X509_get_notBefore(cert) == NULL) {
		goto out;
	}

	if (X509_cmp_current_time(X509_get_notAfter(cert)) < 0) {
		tlog(TLOG_WARN, "cert %s expired", cert_file_path);
		goto out;
	}

	if (X509_cmp_current_time(X509_get_notBefore(cert)) > 0) {
		tlog(TLOG_WARN, "cert %s not valid yet", cert_file_path);
		goto out;
	}

	ret = 1;
out:
	if (cert) {
		X509_free(cert);
	}

	if (cert_file) {
		BIO_free(cert_file);
	}

	return ret;
}

int generate_cert_san(char *san, int max_san_len)
{
	char hostname[DNS_MAX_HOSTNAME_LEN];
	char domainname[DNS_MAX_HOSTNAME_LEN];
	int san_len = 0;
	struct ifaddrs *ifaddr = NULL;
	struct ifaddrs *ifa = NULL;
	uint8_t addr[16] = {0};
	int addr_len = 0;

	hostname[0] = '\0';
	domainname[0] = '\0';

	if (san == NULL || max_san_len <= 0) {
		return -1;
	}

	int len = snprintf(san, max_san_len - san_len, "DNS:%s", "smartdns");
	if (len < 0 || len >= max_san_len - san_len) {
		return -1;
	}
	san_len += len;

	len = snprintf(san + san_len, max_san_len - san_len, ",DNS:%s", "localhost");
	if (len < 0 || len >= max_san_len - san_len) {
		return -1;
	}
	san_len += len;

	/* get local domain name */
	if (getdomainname(domainname, DNS_MAX_HOSTNAME_LEN - 1) == 0) {
		/* check domain is valid */
		if (strncmp(domainname, "(none)", DNS_MAX_HOSTNAME_LEN - 1) == 0) {
			domainname[0] = '\0';
		}

		if (domainname[0] != '\0') {
			len = snprintf(san + san_len, max_san_len - san_len, ",DNS:%s", domainname);
			if (len < 0 || len >= max_san_len - san_len) {
				return -1;
			}
			san_len += len;
		}
	}

	if (gethostname(hostname, DNS_MAX_HOSTNAME_LEN - 1) == 0) {
		/* check hostname is valid */
		if (strncmp(hostname, "(none)", DNS_MAX_HOSTNAME_LEN - 1) == 0) {
			hostname[0] = '\0';
		}

		if (hostname[0] != '\0') {
			len = snprintf(san + san_len, max_san_len - san_len, ",DNS:%s", hostname);
			if (len < 0 || len >= max_san_len - san_len) {
				return -1;
			}
			san_len += len;
		}
	}

	if (dns_conf.server_name[0] != '\0' &&
		strncmp(dns_conf.server_name, "smartdns", DNS_MAX_SERVER_NAME_LEN - 1) != 0) {
		len = snprintf(san + san_len, max_san_len - san_len, ",DNS:%s", dns_conf.server_name);
		if (len < 0 || len >= max_san_len - san_len) {
			return -1;
		}
		san_len += len;
	}

	if (getifaddrs(&ifaddr) == -1) {
		return -1;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) {
			continue;
		}

		switch (ifa->ifa_addr->sa_family) {
		case AF_INET: {
			struct sockaddr_in *addr_in = NULL;
			addr_in = (struct sockaddr_in *)ifa->ifa_addr;
			memcpy(addr, &(addr_in->sin_addr.s_addr), 4);
			addr_len = 4;
		} break;
		case AF_INET6: {
			struct sockaddr_in6 *addr_in6 = NULL;
			addr_in6 = (struct sockaddr_in6 *)ifa->ifa_addr;
			if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
				memcpy(addr, &(addr_in6->sin6_addr.s6_addr[12]), 4);
				addr_len = 4;
			} else {
				memcpy(addr, addr_in6->sin6_addr.s6_addr, 16);
				addr_len = 16;
				// TODO
				// SKIP local IPV6;
				continue;
			}
		} break;
		default:
			continue;
			break;
		}

		if (is_private_addr(addr, addr_len) == 0) {
			continue;
		}

		if (addr_len == 4) {
			len = snprintf(san + san_len, max_san_len - san_len, ",IP:%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);
		} else if (addr_len == 16) {
			len = snprintf(san + san_len, max_san_len - san_len, ",IP:%x:%x:%x:%x:%x:%x:%x:%x",
						   ntohs(((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr.s6_addr[0]),
						   ntohs(((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr.s6_addr[1]),
						   ntohs(((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr.s6_addr[2]),
						   ntohs(((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr.s6_addr[3]),
						   ntohs(((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr.s6_addr[4]),
						   ntohs(((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr.s6_addr[5]),
						   ntohs(((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr.s6_addr[6]),
						   ntohs(((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr.s6_addr[7]));
		} else {
			continue;
		}
		if (len < 0 || len >= max_san_len - san_len) {
			goto errout;
		}
		san_len += len;
	}

	freeifaddrs(ifaddr);
	return 0;

errout:
	if (ifaddr) {
		freeifaddrs(ifaddr);
	}
	return -1;
}

static void _free_key(struct DNS_EVP_PKEY_CTX *ctx)
{
	if (ctx) {
		if (ctx->pkey) {
			EVP_PKEY_free(ctx->pkey);
		}
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
		if (ctx->rsa) {
			RSA_free(ctx->rsa);
		}
		if (ctx->bn) {
			BN_free(ctx->bn);
		}
		free(ctx);
#endif
	}
}

static struct DNS_EVP_PKEY_CTX *_read_key_from_file(const char *key_path)
{
	struct DNS_EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	BIO *key_file = NULL;

	ctx = malloc(sizeof(struct DNS_EVP_PKEY_CTX));
	if (ctx == NULL) {
		return NULL;
	}
	memset(ctx, 0, sizeof(struct DNS_EVP_PKEY_CTX));

	key_file = BIO_new_file(key_path, "rb");
	if (key_file == NULL) {
		tlog(TLOG_ERROR, "read root key file %s failed.", key_path);
		goto errout;
	}

	pkey = PEM_read_bio_PrivateKey(key_file, NULL, NULL, NULL);
	if (pkey == NULL) {
		tlog(TLOG_ERROR, "read root key data failed.");
		goto errout;
	}

	BIO_free(key_file);
	ctx->pkey = pkey;
	return ctx;
errout:
	if (key_file) {
		BIO_free(key_file);
	}
	if (ctx) {
		_free_key(ctx);
	}
	return NULL;
}

static struct DNS_EVP_PKEY_CTX *_generate_key(void)
{
	struct DNS_EVP_PKEY_CTX *ctx = NULL;
	ctx = malloc(sizeof(struct DNS_EVP_PKEY_CTX));
	if (ctx == NULL) {
		return NULL;
	}
	memset(ctx, 0, sizeof(struct DNS_EVP_PKEY_CTX));

	const int RSA_KEY_LENGTH = 2048;
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
	ctx->pkey = EVP_RSA_gen(RSA_KEY_LENGTH);
#else
	ctx->pkey = EVP_PKEY_new();
	ctx->rsa = RSA_new();
	ctx->bn = BN_new();

	BN_set_word(ctx->bn, RSA_F4);
	RSA_generate_key_ex(ctx->rsa, RSA_KEY_LENGTH, ctx->bn, NULL);
	EVP_PKEY_assign_RSA(ctx->pkey, ctx->rsa);
#endif
	return ctx;
}

static X509 *_generate_smartdns_cert(EVP_PKEY *pkey, X509 *issuer_cert, EVP_PKEY *issuer_key, const char *san, int days)
{
	X509 *cert = NULL;
	X509_EXTENSION *cert_ext = NULL;
	int is_ca = 0;

	if (pkey == NULL) {
		goto errout;
	}

	cert = X509_new();
	if (cert == NULL) {
		goto errout;
	}

	if (issuer_cert == NULL || issuer_key == NULL) {
		is_ca = 1;
	}

	X509_set_version(cert, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(cert), rand());
	X509_gmtime_adj(X509_get_notBefore(cert), 0);
	X509_gmtime_adj(X509_get_notAfter(cert), days * 24 * 3600);

	X509_set_pubkey(cert, pkey);

	X509_NAME *name = X509_get_subject_name(cert);
	X509_NAME *issuer_name = name;

	const unsigned char *country = (unsigned char *)"smartdns";
	const unsigned char *company = (unsigned char *)"smartdns";
	const unsigned char *common_name = (unsigned char *)(is_ca ? "SmartDNS Root" : "smartdns");
	const char *BASIC_CONSTRAINTS = is_ca ? "CA:TRUE" : "CA:FALSE";
	const char *KEY_USAGE = is_ca ? "keyCertSign,cRLSign" : "digitalSignature,keyEncipherment";
	const char *EXT_KEY_USAGE = is_ca ? "clientAuth,serverAuth,codeSigning,timeStamping" : "serverAuth";

	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, country, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, common_name, -1, -1, 0);
	if (is_ca) {
		X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, company, -1, -1, 0);
	} else {
		issuer_name = X509_get_subject_name(issuer_cert);
	}
	X509_set_subject_name(cert, name);
	X509_set_issuer_name(cert, issuer_name);

	if (san != NULL) {
		cert_ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, san);
		if (cert_ext == NULL) {
			goto errout;
		}
		X509_add_ext(cert, cert_ext, -1);
		X509_EXTENSION_free(cert_ext);
	}

	// Add X509v3 extensions
	cert_ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, BASIC_CONSTRAINTS);
	X509_add_ext(cert, cert_ext, -1);
	X509_EXTENSION_free(cert_ext);

	cert_ext = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, KEY_USAGE);
	X509_add_ext(cert, cert_ext, -1);
	X509_EXTENSION_free(cert_ext);

	if (EXT_KEY_USAGE != NULL) {
		cert_ext = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, EXT_KEY_USAGE);
		X509_add_ext(cert, cert_ext, -1);
		X509_EXTENSION_free(cert_ext);
	}

	cert_ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_key_identifier, "hash");
	X509_add_ext(cert, cert_ext, -1);
	X509_EXTENSION_free(cert_ext);

	X509_sign(cert, is_ca ? pkey : issuer_key, EVP_sha256());
	return cert;

errout:
	if (cert) {
		X509_free(cert);
	}

	return NULL;
}

int generate_cert_key(const char *key_path, const char *cert_path, const char *root_key_path, const char *san, int days)
{
	char root_key_path_buff[PATH_MAX * 2] = {0};
	char server_key_path[PATH_MAX] = {0};
	BIO *server_key_file = NULL;
	BIO *server_cert_file = NULL;
	BIO *root_key_file = NULL;
	int create_root_key = 0;
	X509 *ca_cert = NULL;
	X509 *server_cert = NULL;
	struct DNS_EVP_PKEY_CTX *server_key_ctx = NULL;
	struct DNS_EVP_PKEY_CTX *ca_key_ctx = NULL;

	if (key_path == NULL || cert_path == NULL) {
		return -1;
	}

	if (root_key_path == NULL || root_key_path[0] == '\0') {
		safe_strncpy(server_key_path, key_path, sizeof(server_key_path));
		if (dir_name(server_key_path) == NULL) {
			tlog(TLOG_ERROR, "get server key path failed.");
			return -1;
		}

		snprintf(root_key_path_buff, sizeof(root_key_path_buff), "%s/root-ca.key", server_key_path);
		root_key_path = root_key_path_buff;
	}

	if (access(root_key_path, F_OK) == 0) {
		ca_key_ctx = _read_key_from_file(root_key_path);
		if (ca_key_ctx == NULL) {
			tlog(TLOG_ERROR, "read root ca key failed.");
			goto errout;
		}
		create_root_key = 1;
	} else {
		ca_key_ctx = _generate_key();
		create_root_key = 0;
	}

	if (ca_key_ctx == NULL) {
		tlog(TLOG_ERROR, "generate root ca key failed.");
		goto errout;
	}

	ca_cert = _generate_smartdns_cert(ca_key_ctx->pkey, NULL, NULL, NULL, 365 * 10);
	if (ca_cert == NULL) {
		tlog(TLOG_ERROR, "generate root ca cert failed.");
		goto errout;
	}

	server_key_ctx = _generate_key();
	if (server_key_ctx == NULL) {
		tlog(TLOG_ERROR, "generate server key failed.");
		goto errout;
	}
	server_cert = _generate_smartdns_cert(server_key_ctx->pkey, ca_cert, ca_key_ctx->pkey, san, days);
	if (server_cert == NULL) {
		tlog(TLOG_ERROR, "generate server cert failed.");
		goto errout;
	}

	server_key_file = BIO_new_file(key_path, "wb");
	server_cert_file = BIO_new_file(cert_path, "wb");
	if (server_key_file == NULL || server_cert_file == NULL) {
		tlog(TLOG_ERROR, "create key/cert file failed.");
		return -1;
	}

	if (PEM_write_bio_PrivateKey(server_key_file, server_key_ctx->pkey, NULL, NULL, 0, NULL, NULL) != 1) {
		return -1;
	}

	if (PEM_write_bio_X509(server_cert_file, server_cert) != 1) {
		return -1;
	}

	if (PEM_write_bio_X509(server_cert_file, ca_cert) != 1) {
		return -1;
	}

	if (create_root_key == 0) {
		root_key_file = BIO_new_file(root_key_path, "wb");
		if (root_key_file == NULL) {
			tlog(TLOG_ERROR, "create root ca key file failed.");
			goto errout;
		}

		if (PEM_write_bio_PrivateKey(root_key_file, ca_key_ctx->pkey, NULL, NULL, 0, NULL, NULL) != 1) {
			goto errout;
		}
		BIO_free_all(root_key_file);
		chmod(root_key_path, S_IRUSR);
	}

	chmod(key_path, S_IRUSR);
	chmod(cert_path, S_IRUSR);

	BIO_free_all(server_key_file);
	BIO_free_all(server_cert_file);

	X509_free(ca_cert);
	X509_free(server_cert);
	_free_key(ca_key_ctx);
	_free_key(server_key_ctx);
	return 0;

errout:
	if (server_key_file) {
		BIO_free_all(server_key_file);
	}

	if (server_cert_file) {
		BIO_free_all(server_cert_file);
	}

	if (root_key_file) {
		BIO_free_all(root_key_file);
	}

	if (ca_cert) {
		X509_free(ca_cert);
	}

	if (server_cert) {
		X509_free(server_cert);
	}

	if (ca_key_ctx) {
		_free_key(ca_key_ctx);
	}

	if (server_key_ctx) {
		_free_key(server_key_ctx);
	}

	return -1;
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