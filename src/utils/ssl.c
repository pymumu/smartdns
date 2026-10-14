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

#include "smartdns/lib/openssl_compat.h"

#include <ifaddrs.h>
#include <linux/limits.h>
#include <pthread.h>
#include <sys/stat.h>
#include <time.h>

#define DNS_MAX_HOSTNAME_LEN 256

/*
 * Default TLS settings applied to every SSL_CTX we create. Without them the
 * protocol range, the cipher list and even the availability of ECDHE follow
 * whatever the linked OpenSSL happens to default to, which means the same
 * smartdns build negotiates different TLS depending on the host.
 */
#define DNS_SSL_DEFAULT_CIPHER_LIST                                                                                    \
	"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"                         \
	"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"                           \
	"HIGH:!aNULL:!eNULL:!EXPORT:!DES:!3DES:!MD5:!RC4:!PSK"

#define DNS_SSL_DEFAULT_CIPHERSUITES "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"

struct DNS_EVP_PKEY_CTX {
	EVP_PKEY *pkey;
#if SMARTDNS_OPENSSL_BEFORE(SMARTDNS_OPENSSL_V_3_0_0)
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

	if (dns_X509_get0_notAfter(cert) == NULL) {
		goto out;
	}

	if (dns_X509_get0_notBefore(cert) == NULL) {
		goto out;
	}

	if (dns_ASN1_TIME_cmp_now(dns_X509_get0_notAfter(cert)) < 0) {
		tlog(TLOG_WARN, "cert %s expired", cert_file_path);
		goto out;
	}

	if (dns_ASN1_TIME_cmp_now(dns_X509_get0_notBefore(cert)) > 0) {
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

int generate_cert_san(char *san, int max_san_len, const char *append_san)
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

	if (append_san != NULL && append_san[0] != '\0') {
		len = snprintf(san + san_len, max_san_len - san_len, ",%s", append_san);
		if (len < 0 || len >= max_san_len - san_len) {
			return -1;
		}
		san_len += len;
	}

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
	if (ctx == NULL) {
		return;
	}

	if (ctx->pkey) {
		EVP_PKEY_free(ctx->pkey);
	}
#if SMARTDNS_OPENSSL_BEFORE(SMARTDNS_OPENSSL_V_3_0_0)
	/*
	 * Only frees the RSA when ownership was *not* handed to pkey by
	 * EVP_PKEY_assign_RSA(); _generate_key() clears the pointer on success to
	 * avoid a double free.
	 */
	if (ctx->rsa) {
		RSA_free(ctx->rsa);
	}
	if (ctx->bn) {
		BN_free(ctx->bn);
	}
#endif
	free(ctx);
}

static struct DNS_EVP_PKEY_CTX *_read_key_from_file(const char *key_path)
{
	struct DNS_EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	BIO *key_file = NULL;

	ctx = zalloc(1, sizeof(struct DNS_EVP_PKEY_CTX));
	if (ctx == NULL) {
		return NULL;
	}

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
	ctx = zalloc(1, sizeof(struct DNS_EVP_PKEY_CTX));
	if (ctx == NULL) {
		return NULL;
	}

	const int RSA_KEY_LENGTH = 2048;
#if SMARTDNS_OPENSSL_AT_LEAST(SMARTDNS_OPENSSL_V_3_0_0)
	ctx->pkey = EVP_RSA_gen(RSA_KEY_LENGTH);
#else
	ctx->pkey = EVP_PKEY_new();
	if (ctx->pkey == NULL) {
		goto errout;
	}

	ctx->rsa = RSA_new();
	if (ctx->rsa == NULL) {
		goto errout;
	}

	ctx->bn = BN_new();
	if (ctx->bn == NULL) {
		goto errout;
	}

	if (BN_set_word(ctx->bn, RSA_F4) != 1) {
		goto errout;
	}

	if (RSA_generate_key_ex(ctx->rsa, RSA_KEY_LENGTH, ctx->bn, NULL) != 1) {
		goto errout;
	}

	/* Transfers ownership of rsa to pkey. */
	if (EVP_PKEY_assign_RSA(ctx->pkey, ctx->rsa) != 1) {
		goto errout;
	}
	ctx->rsa = NULL;
#endif

	if (ctx->pkey == NULL) {
		goto errout;
	}

	return ctx;
errout:
	_free_key(ctx);
	return NULL;
}

static X509 *_generate_smartdns_cert(EVP_PKEY *pkey, X509 *issuer_cert, EVP_PKEY *issuer_key, const char *san, int days)
{
	X509 *cert = NULL;
	X509_EXTENSION *cert_ext = NULL;
	X509_NAME *name = NULL;
	const X509_NAME *issuer_name = NULL;
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
	/* The mutable accessor is required here: OpenSSL 4.0 made the const one read-only. */
	X509_gmtime_adj(dns_X509_getm_notBefore(cert), 0);
	X509_gmtime_adj(dns_X509_getm_notAfter(cert), (long)days * 24 * 3600);

	X509_set_pubkey(cert, pkey);

	name = X509_NAME_new();
	if (name == NULL) {
		goto errout;
	}
	issuer_name = name;

	const unsigned char *country = (unsigned char *)"smartdns";
	const unsigned char *company = (unsigned char *)"smartdns";
	const unsigned char *common_name = (unsigned char *)(is_ca ? "SmartDNS Root" : "smartdns");

	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, country, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, common_name, -1, -1, 0);
	if (is_ca) {
		X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, company, -1, -1, 0);
	} else {
		if (issuer_cert != NULL) {
			issuer_name = X509_get_subject_name(issuer_cert);
		}
	}
	X509_set_subject_name(cert, name);
	X509_set_issuer_name(cert, dns_unconst(X509_NAME *, issuer_name));

	if (san != NULL && san[0] != '\0') {
		cert_ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, dns_unconst(char *, san));
		if (cert_ext == NULL) {
			goto errout;
		}
		X509_add_ext(cert, cert_ext, -1);
		X509_EXTENSION_free(cert_ext);
		cert_ext = NULL;
	}

	const char *basic_constraints = is_ca ? "critical,CA:TRUE" : "CA:FALSE";
	cert_ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, dns_unconst(char *, basic_constraints));
	if (cert_ext == NULL) {
		tlog(TLOG_ERROR, "Failed to create basicConstraints extension");
		goto errout;
	}
	X509_add_ext(cert, cert_ext, -1);
	X509_EXTENSION_free(cert_ext);
	cert_ext = NULL;

	const char *key_usage = is_ca ? "critical,keyCertSign,cRLSign" : "digitalSignature,keyEncipherment";
	cert_ext = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, dns_unconst(char *, key_usage));
	if (cert_ext == NULL) {
		tlog(TLOG_ERROR, "Failed to create keyUsage extension");
		goto errout;
	}
	X509_add_ext(cert, cert_ext, -1);
	X509_EXTENSION_free(cert_ext);
	cert_ext = NULL;

	if (!is_ca) {
		cert_ext = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, "serverAuth");
		if (cert_ext == NULL) {
			tlog(TLOG_ERROR, "Failed to create extKeyUsage extension");
			goto errout;
		}
		X509_add_ext(cert, cert_ext, -1);
		X509_EXTENSION_free(cert_ext);
		cert_ext = NULL;
	}

	X509V3_CTX ext_ctx;
	X509V3_set_ctx(&ext_ctx, issuer_cert ? issuer_cert : cert, cert, NULL, NULL, 0);
	cert_ext = X509V3_EXT_conf_nid(NULL, &ext_ctx, NID_subject_key_identifier, "hash");
	if (cert_ext != NULL) {
		X509_add_ext(cert, cert_ext, -1);
		X509_EXTENSION_free(cert_ext);
	} else {
		tlog(TLOG_WARN, "Failed to create subjectKeyIdentifier extension, continuing");
	}

	if (X509_sign(cert, is_ca ? pkey : issuer_key, EVP_sha256()) <= 0) {
		goto errout;
	}

	X509_NAME_free(name);
	return cert;

errout:
	if (name) {
		X509_NAME_free(name);
	}

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

	if (dns_PEM_write_bio_PrivateKey(server_key_file, server_key_ctx->pkey) != 1) {
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

		if (dns_PEM_write_bio_PrivateKey(root_key_file, ca_key_ctx->pkey) != 1) {
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

/*
 * Keyed on the library version, not on OPENSSL_API_COMPAT: the latter describes
 * which API level the caller wants hidden and can be set from the command line,
 * which previously produced a declaration in util.h with no matching definition.
 */
#if SMARTDNS_NEED_LEGACY_THREAD_CB
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

/*
 * Separate callback for CRYPTO_THREADID_set_callback(): it wants
 * void (*)(CRYPTO_THREADID *), not unsigned long (*)(void). The mismatch only
 * surfaces on OpenSSL 1.0.x, because 1.1.0 dropped these callbacks entirely.
 */
static __attribute__((unused)) void _pthreads_thread_id_crypto(CRYPTO_THREADID *id)
{
	CRYPTO_THREADID_set_numeric(id, (unsigned long)pthread_self());
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

#if SMARTDNS_OPENSSL_BEFORE(SMARTDNS_OPENSSL_V_1_0_0)
	CRYPTO_set_id_callback(_pthreads_thread_id);
#else
	CRYPTO_THREADID_set_callback(_pthreads_thread_id_crypto);
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
#else
/*
 * OpenSSL 1.1.0+ is thread safe by construction and removed the locking
 * callbacks. Both entry points remain defined because util.h declares them
 * unconditionally and smartdns.c calls them on every build.
 */
void SSL_CRYPTO_thread_setup(void)
{
}

void SSL_CRYPTO_thread_cleanup(void)
{
}
#endif

unsigned char *SSL_SHA256(const unsigned char *d, size_t n, unsigned char *md)
{
	static unsigned char m[SHA256_DIGEST_LENGTH];
	unsigned int digest_len = 0;

	if (md == NULL) {
		md = m;
	}

	EVP_MD_CTX *ctx = dns_EVP_MD_CTX_new();
	if (ctx == NULL) {
		return NULL;
	}

	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 || EVP_DigestUpdate(ctx, d, n) != 1 ||
		EVP_DigestFinal_ex(ctx, md, &digest_len) != 1) {
		dns_EVP_MD_CTX_free(ctx);
		return NULL;
	}
	dns_EVP_MD_CTX_free(ctx);

	return md;
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

	/* Adjust output length by counting '=' in in_data (not 'in') */
	int pos = inlen;
	while (pos > 0 && in_data[--pos] == '=') {
		--outlen;
	}

	if (in_padding_data) {
		free(in_padding_data);
	}

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
#if SMARTDNS_OPENSSL_HAVE_QUIC
	return 1;
#else
	return 0;
#endif
}

void dns_ssl_ctx_setup_defaults(SSL_CTX *ssl_ctx)
{
	long options = 0;

	if (ssl_ctx == NULL) {
		return;
	}

	options = SSL_OP_ALL | SSL_OP_CIPHER_SERVER_PREFERENCE | SSL_OP_SINGLE_DH_USE;
#ifdef SSL_OP_NO_COMPRESSION
	options |= SSL_OP_NO_COMPRESSION;
#endif
#ifdef SSL_OP_NO_SSLv2
	options |= SSL_OP_NO_SSLv2;
#endif
	options |= SSL_OP_NO_SSLv3;
#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
	options |= SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
#endif

#if SMARTDNS_HAVE_PROTO_VERSION_API
	/*
	 * Pin the negotiated range. Without it the lower bound follows whatever the
	 * linked OpenSSL defaults to (TLS 1.0 on 1.0.x, TLS 1.2 on 3.x) plus any
	 * distro crypto policy, so the same smartdns config behaves per-host.
	 */
	SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
#ifdef TLS1_3_VERSION
	SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
#else
	SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_2_VERSION);
#endif
#else
	/* 1.0.x has no *_proto_version API, so express the same floor as options. */
#ifdef SSL_OP_NO_TLSv1
	options |= SSL_OP_NO_TLSv1;
#endif
#ifdef SSL_OP_NO_TLSv1_1
	options |= SSL_OP_NO_TLSv1_1;
#endif
#endif

	SSL_CTX_set_options(ssl_ctx, options);

	if (SSL_CTX_set_cipher_list(ssl_ctx, DNS_SSL_DEFAULT_CIPHER_LIST) != 1) {
		tlog(TLOG_WARN, "set default cipher list failed.");
	}

#if SMARTDNS_HAVE_TLS13
	if (SSL_CTX_set_ciphersuites(ssl_ctx, DNS_SSL_DEFAULT_CIPHERSUITES) != 1) {
		tlog(TLOG_DEBUG, "set default TLS 1.3 ciphersuites failed.");
	}
#endif

	/* 1.0.x needs ECDH enabled explicitly, otherwise ECDHE cannot be negotiated. */
	dns_SSL_CTX_set_ecdh_auto(ssl_ctx);
}
