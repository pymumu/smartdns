/*************************************************************************
 *
 * Copyright (C) 2018-2026 Ruilin Peng (Nick) <pymumu@gmail.com>.
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
#include <gtest/gtest.h>
#include <errno.h>

#include "smartdns/lib/gepoll.h"
#include "smartdns/lib/gsocket.h"
#include "smartdns/smartdns.h"
#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/quic.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <poll.h>
#include <set>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

#include <vector>

/* ========================================================================= */
/*                               Test Utilities                              */
/* ========================================================================= */

namespace GSocketHTTPTestUtils
{

static struct gsocket *create_listener(int port, int type)
{
	struct gsocket *sock = gsocket_new(socket(AF_INET, type, 0));
	if (!sock)
		return NULL;

	int opt = 1;
	gsocket_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	if (gsocket_bind(sock, "0.0.0.0", port) != 0) {
		gsocket_close(sock);
		gsocket_free(sock);
		return NULL;
	}

	if (type == SOCK_STREAM) {
		if (gsocket_listen(sock, 50) != 0) {
			gsocket_close(sock);
			gsocket_free(sock);
			return NULL;
		}
	}
	gsocket_set_nonblock(sock, 1);
	return sock;
}

static int get_socket_port(struct gsocket *sock)
{
	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);
	if (gsocket_getsockname(sock, (struct sockaddr *)&sin, &len) == 0) {
		return ntohs(sin.sin_port);
	}
	return 0;
}


static int alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                          const unsigned char *in, unsigned int inlen, void *arg)
{
    static const unsigned char server_protos[] = {
        8, 'h', 't', 't', 'p', '/', '1', '.', '1',
        2, 'h', '2'
    };

    if (SSL_select_next_proto((unsigned char **)out, outlen, server_protos, sizeof(server_protos), in, inlen) != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    return SSL_TLSEXT_ERR_OK;
}

static SSL_CTX *init_ssl_ctx(bool server)
{
	SSL_CTX *ctx;
	const SSL_METHOD *method = server ? TLS_server_method() : TLS_client_method();
	ctx = SSL_CTX_new(method);
	if (server) {
		char key[PATH_MAX];
		char cert[PATH_MAX];
		smartdns_get_cert(key, cert);
		if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
			/* Check for error, printing stderr might help debug */
			ERR_print_errors_fp(stderr);
		}
		if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) {
			ERR_print_errors_fp(stderr);
		}
		SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, NULL);
	}
	return ctx;
}

/* Helper to create temporary test directory with index.html */
static std::string setup_test_www_dir(size_t index_html_size = 5000)
{
	char tmpdir[] = "/tmp/smartdns_test_XXXXXX";
	if (mkdtemp(tmpdir) == NULL) {
		return "/tmp/smartdns_test";
	}

	std::string dir = tmpdir;
	std::string index_path = dir + "/index.html";

	/* Generate index.html with specified size */
	FILE *fp = fopen(index_path.c_str(), "w");
	if (!fp) {
		return "/tmp/smartdns_test";
	}

	fprintf(fp, "<!DOCTYPE html>\n<html>\n<head><title>SmartDNS Test Server</title></head>\n<body>\n");
	fprintf(fp, "<h1>SmartDNS Test Server</h1>\n");
	fprintf(fp, "<p>This is a test file for HTTP server testing.</p>\n");

	/* Fill to desired size with padding content */
	size_t written = ftell(fp);
	size_t line_num = 0;
	while (written < index_html_size - 200) {
		fprintf(fp, "<p>Test content line %zu: Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
				"Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>\n", line_num++);
		written = ftell(fp);
	}

	fprintf(fp, "</body>\n</html>\n");
	fclose(fp);

	return dir;
}

static void cleanup_test_www_dir(const std::string &dir)
{
	if (dir.empty() || dir.find("/tmp/smartdns_test") != 0) {
		return;
	}
	std::string cmd = "rm -rf " + dir;
	system(cmd.c_str());
}


/* Helper to handle I/O for a stream. Returns true if stream should be closed/removed. */
static bool handle_stream_io(struct gsocket *stream, struct gstream_poll *sp, void *user_data)
{
	const char *response_str = (const char *)user_data;
	char buf[1024];
	ssize_t n = gsocket_recv(stream, buf, sizeof(buf), 0);

	if (n >= 0) {
		const char *final_resp = response_str;

		char url[128] = {0};
		socklen_t ulen = sizeof(url) - 1;
		if (gsocket_getsockopt(stream, SOL_HTTP, SO_HTTP_URL, url, &ulen) == 0) {
			url[ulen] = 0;
			if (strcmp(url, "/status") == 0) {
				int status = 404;
				gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_STATUS, &status, sizeof(status));
				final_resp = "NotFound";
			} else if (strcmp(url, "/method_test") == 0) {
				char method[16] = {0};
				socklen_t mlen = sizeof(method) - 1;
				if (gsocket_getsockopt(stream, SOL_HTTP, SO_HTTP_METHOD, method, &mlen) == 0) {
					method[mlen] = 0;
					// Verify method is GET
					if (strcmp(method, "GET") != 0) {
						final_resp = "MethodMismatch";
					}
				} else {
					final_resp = "MethodGetFailed";
				}
			}
		}

		gsocket_send(stream, final_resp, strlen(final_resp), MSG_NOSIGNAL);
		return true; /* Should close */

	} else if (n < 0 && errno != EAGAIN) {
		/* Error */
		return true; /* Should close */
	}
	return false;
}

static bool handle_file_request(struct gsocket *stream, struct gstream_poll *sp, void *user_data)
{
	const char *root = (const char *)user_data;
	char buf[1024];
	
	ssize_t n = gsocket_recv(stream, buf, sizeof(buf) - 1, 0);
	
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return false;
		}
		return false;
	}
	buf[n] = 0;

	/* If header not fully received, wait more */
	if (n == GSOCKET_HANDSHAKE_WANT_READ) {
		return false;
	}

	char url[128] = {0};
	socklen_t ulen = sizeof(url) - 1;
	if (gsocket_getsockopt(stream, SOL_HTTP, SO_HTTP_URL, url, &ulen) != 0) {
		/* Header might still be incomplete if recv returned 0 or data was too small */
		return false;
	}
	url[ulen] = 0;
	printf("Request: %s\n", url);

	char path[PATH_MAX];
	if (strcmp(url, "/") == 0) {
		snprintf(path, sizeof(path), "%s/index.html", root);
	} else {
		snprintf(path, sizeof(path), "%s%s", root, url);
	}

	struct stat st;
	int found = 0;

	/* 1. Try raw path first if it has an extension */
	if (strchr(url, '.') != NULL) {
		if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
			found = 1;
		}
	}

	/* 2. Try path.html if not found */
	if (!found) {
		char path_html[PATH_MAX];
		snprintf(path_html, sizeof(path_html), "%s.html", path);
		if (stat(path_html, &st) == 0 && S_ISREG(st.st_mode)) {
			strncpy(path, path_html, sizeof(path));
			found = 1;
		}
	}

	/* 3. Try path/index.html if it's a directory */
	if (!found) {
		if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
			strncat(path, "/index.html", sizeof(path) - strlen(path) - 1);
			if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
				found = 1;
			}
		}
	}

	/* 4. Try raw path anyway if still not found (might have no extension) */
	if (!found) {
		if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
			found = 1;
		}
	}

	FILE *fp = NULL;
	if (found) {
		fp = fopen(path, "rb");
	}

	if (fp) {
		fseek(fp, 0, SEEK_END);
		long size = ftell(fp);
		fseek(fp, 0, SEEK_SET);

		if (size < 0) {
			fclose(fp);
			fp = NULL;
		} else {
			/* Set Content-Type */
			const char *content_type = "application/octet-stream";
			if (strstr(path, ".html")) content_type = "text/html";
			else if (strstr(path, ".js")) content_type = "application/javascript";
			else if (strstr(path, ".css")) content_type = "text/css";
			else if (strstr(path, ".png")) content_type = "image/png";
			else if (strstr(path, ".jpg")) content_type = "image/jpeg";
			else if (strstr(path, ".ico")) content_type = "image/x-icon";
			else if (strstr(path, ".svg")) content_type = "image/svg+xml";
			else if (strstr(path, ".json")) content_type = "application/json";
			else if (strstr(path, ".woff2")) content_type = "font/woff2";
			else if (strstr(path, ".woff")) content_type = "font/woff";
			else if (strstr(path, ".ttf")) content_type = "font/ttf";

			char header[128];
			int hlen = snprintf(header, sizeof(header), "content-type: %s", content_type);
			gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_HEADER, header, hlen);

			/* Set Content-Length */
			size_t clen = size;
			gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_BODY_LEN, &clen, sizeof(clen));

			char *content = (char *)malloc(size);
			size_t sent = 0;
			if (content) {
				fread(content, 1, size, fp);
			/* Send all content - loop until everything is sent */
			printf("Starting to send file: size=%ld\n", size);
			while (sent < size) {
				size_t remaining = size - sent;
				int flags = MSG_NOSIGNAL;
				/* Set GS_MSG_FIN on the last send */
				if (remaining > 0 && sent + remaining == size) { // Only set FIN on the very last chunk
					flags |= GS_MSG_FIN;
				}
				ssize_t s = gsocket_send(stream, content + sent, remaining, flags);
				if (s <= 0) {
					if (errno == EAGAIN || errno == EWOULDBLOCK) {
						/* Process pending events (e.g. WINDOW_UPDATE) during backpressure */
						struct gstream_event events[1];
						gstream_poll_wait(sp, events, 1, 10);
						continue;
					}
					break;
				}
				sent += s;
			}
			free(content);
			}
		}
		fclose(fp);
	}

	if (!fp) {
		printf("Not Found: %s\n", path);
		int status = 404;
		gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_STATUS, &status, sizeof(status));
		const char *not_found = "File Not Found";
		size_t clen = strlen(not_found);
		gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_BODY_LEN, &clen, sizeof(clen));
		gsocket_send(stream, not_found, clen, MSG_NOSIGNAL | GS_MSG_FIN);
	}

	/* Don't call gstream_poll_del here - let caller handle cleanup */
	return true;
}

typedef bool (*StreamHandler)(struct gsocket *stream, struct gstream_poll *sp, void *user_data);

static void process_stream_events_generic(struct gsocket *conn, struct gstream_poll *sp, struct gepoll *ep,
										  std::set<struct gsocket *> &clients,
										  std::map<struct gsocket *, std::set<struct gsocket *>> &conn_streams,
										  StreamHandler handler, void *user_data)
{
	while (true) {
		struct gstream_event stream_events[64];
		int ret = gstream_poll_wait(sp, stream_events, 64, 0);
		if (ret <= 0) break;

		for (int i = 0; i < ret; i++) {
			struct gsocket *s = stream_events[i].stream;
			if (s == conn) {
				while (true) {
					struct gsocket *stream = gsocket_accept(conn, NULL, NULL);
					if (stream) {
						conn_streams[conn].insert(stream);
						gstream_poll_add(sp, stream, POLLIN | POLLOUT, stream);
					} else {
						break;
					}
				}
			} else {
				if (handler(s, sp, user_data)) {
					gstream_poll_del(sp, s);
					gsocket_close(s);
					gsocket_free(s);
					conn_streams[conn].erase(s);
				}
			}
		}
	}
}

static void process_stream_events(struct gsocket *conn, struct gstream_poll *sp, struct gepoll *ep,
								  std::set<struct gsocket *> &clients,
								  std::map<struct gsocket *, std::set<struct gsocket *>> &conn_streams,
								  const char *response_str = "Response")
{
	process_stream_events_generic(conn, sp, ep, clients, conn_streams, handle_stream_io, (void *)response_str);
}

void process_file_stream_events(struct gsocket *conn, struct gstream_poll *sp, struct gepoll *ep,
									std::set<struct gsocket *> &clients,
									std::map<struct gsocket *, std::set<struct gsocket *>> &conn_streams,
									const char *root)
{
	while (true) {
		struct gstream_event stream_events[64];
		int ret = gstream_poll_wait(sp, stream_events, 64, 0);
		if (ret <= 0) break;

		for (int i = 0; i < ret; i++) {
			struct gsocket *s = stream_events[i].stream;
			if (s == conn) {
				while (true) {
					struct gsocket *stream = gsocket_accept(conn, NULL, NULL);
					if (stream) {
						conn_streams[conn].insert(stream);
						gstream_poll_add(sp, stream, POLLIN | POLLOUT, stream);
					} else {
						break;
					}
				}
			} else {
				if (handle_file_request(s, sp, (void *)root)) {
					gstream_poll_del(sp, s);
					gsocket_close(s);
					gsocket_free(s);
					conn_streams[conn].erase(s);
				}
			}
		}
	}
}

} // namespace GSocketHTTPTestUtils

using namespace GSocketHTTPTestUtils;

/* ========================================================================= */
/*                              Server Threads                               */
/* ========================================================================= */

typedef struct gsocket_io *(*LayerCreator)(int is_server);

/* Synchronization Helper */
struct ServerSync {
	std::mutex m;
	std::condition_variable cv;
	bool ready = false;
	int port = 0;
	void notify(int p = 0)
	{
		std::lock_guard<std::mutex> lk(m);
		ready = true;
		if (p > 0)
			port = p;
		cv.notify_one();
	}
	void wait()
	{
		std::unique_lock<std::mutex> lk(m);
		cv.wait(lk, [this] { return ready; });
	}
};

void gsocket_generic_server_thread_with_config(int port, int type, ServerSync *sync, std::atomic<bool> &running, std::function<void(struct gsocket*)> push_layers, StreamHandler handler, void *user_data)
{
	struct gsocket *listener = create_listener(port, type);
	if (!listener) {
		sync->notify(0);
		return;
	}

	if (push_layers) push_layers(listener);
	
	/* Ensure we listen (activates QUIC listener state if applicable) */
	if (gsocket_listen(listener, 50) != 0) {
	}

	struct gepoll *ep = gepoll_create(0);
	gepoll_add(ep, listener, type == SOCK_DGRAM ? (EPOLLIN | EPOLLOUT) : EPOLLIN, listener);

	int p = get_socket_port(listener);
	sync->notify(p);

	std::set<struct gsocket *> clients;
	std::map<struct gsocket *, struct gstream_poll *> client_polls;
	std::map<struct gsocket *, std::set<struct gsocket *>> conn_streams;

	while (running) {
		struct gepoll_event events[64];
		int n = gepoll_wait(ep, events, 64, 10);

		for (int i = 0; i < n; i++) {
			struct gsocket *sock = (struct gsocket *)events[i].user_data;
			/* Safety check: ensure socket is still valid (in clients set) before accessing */
			if (sock != listener && clients.count(sock) == 0) {
				continue;
			}
			
			/* 1. Drive Network I/O for ALL sockets (TCP and UDP/Listener) */
			int hr = gsocket_handshake(sock);

			if (hr != GSOCKET_HANDSHAKE_DONE) {
				if (hr != GSOCKET_HANDSHAKE_ERR) {
					/* Update interests */
					if (clients.count(sock) || (sock == listener && type == SOCK_DGRAM)) {
						struct gstream_poll *sp = client_polls.count(sock) ? client_polls[sock] : NULL;
						int evs = 0;
						if (sp) {
							evs = gstream_poll_get_net_events(sp);
						} else {
							evs = EPOLLIN;
						}
						
						if (hr == GSOCKET_HANDSHAKE_WANT_WRITE) {
							evs |= EPOLLOUT;
						} else if (hr == GSOCKET_HANDSHAKE_WANT_READ) {
							evs |= EPOLLIN;
						}
						gepoll_mod(ep, sock, evs, sock);
					}
				} else {
					if (clients.count(sock)) {
						struct gstream_poll *sp = client_polls[sock];
						gstream_poll_destroy(sp);
						client_polls.erase(sock);
						if (conn_streams.count(sock)) {
							for (auto s : conn_streams[sock]) {
								gsocket_close(s);
								gsocket_free(s);
							}
							conn_streams.erase(sock);
						}
						gepoll_del(ep, sock);
						gsocket_close(sock);
						gsocket_free(sock);
						clients.erase(sock);
					}
				}
				
				if (sock != listener) {
					continue;
				}
			}

			if (sock == listener) {
				while (true) {
					struct gsocket *client = gsocket_accept(listener, NULL, NULL);
					if (client) {
						gsocket_set_nonblock(client, 1);
						if (type == SOCK_STREAM) {
							gepoll_add(ep, client, EPOLLIN | EPOLLOUT, client);
						}
                        /* Drive handshake immediately for new connection */
                        gsocket_handshake(client);

						clients.insert(client);
						struct gstream_poll *sp = gstream_poll_create(client);
						gstream_poll_add(sp, client, POLLIN, client);
						client_polls[client] = sp;
					} else {
						break;
					}
				}
			} else if (type == SOCK_STREAM && clients.count(sock)) {
				process_stream_events_generic(sock, client_polls[sock], ep, clients, conn_streams, handler, user_data);

				if (clients.count(sock)) {
					int evs = gstream_poll_get_net_events(client_polls[sock]);
					gepoll_mod(ep, sock, evs, sock);
				}
			}
		}

		if (type == SOCK_DGRAM || n == 0) {
			std::vector<struct gsocket *> drive_list;
			if (type == SOCK_DGRAM) drive_list.push_back(listener);
			drive_list.insert(drive_list.end(), clients.begin(), clients.end());

			for (auto sock : drive_list) {
				if (sock != listener && clients.count(sock) == 0) continue;

				/* Drive handshake */
				int hr = gsocket_handshake(sock);
				if (hr == GSOCKET_HANDSHAKE_ERR) {
					if (sock != listener) {
						/* Cleanup Client */
						struct gstream_poll *sp = client_polls[sock];
						gstream_poll_destroy(sp);
						client_polls.erase(sock);
						if (conn_streams.count(sock)) {
							for (auto s : conn_streams[sock]) {
								gsocket_close(s);
								gsocket_free(s);
							}
							conn_streams.erase(sock);
						}
						clients.erase(sock);
						gsocket_close(sock);
						gsocket_free(sock);
					}
					continue;
				}

				/* For Listener (QUIC), accept new connections */
				if (sock == listener && type == SOCK_DGRAM) {
					while (true) {
						struct gsocket *client = gsocket_accept(listener, NULL, NULL);
						if (client) {
							gsocket_set_nonblock(client, 1);

							/* CRITICAL: Trigger handshake immediately for new QUIC connection */
							gsocket_handshake(client);

							clients.insert(client);
							struct gstream_poll *sp = gstream_poll_create(client);
							gstream_poll_add(sp, client, POLLIN, client);
							client_polls[client] = sp;
						} else {
							break;
						}
					}
				}

				/* For Clients, process streams */
				if (sock != listener && clients.count(sock)) {
					process_stream_events_generic(sock, client_polls[sock], ep, clients, conn_streams, handler, user_data);
				}
			}
		}
	}

	for (auto kv : client_polls)
		gstream_poll_destroy(kv.second);
	for (auto kv : conn_streams) {
		for (auto s : kv.second) {
			gsocket_close(s);
			gsocket_free(s);
		}
	}
	for (auto c : clients) {
		gsocket_close(c);
		gsocket_free(c);
	}
	gepoll_destroy(ep);
	gsocket_close(listener);
	gsocket_free(listener);
}

void gsocket_generic_server_thread(int port, ServerSync *sync, std::atomic<bool> &running, LayerCreator layer_fn)
{
	gsocket_generic_server_thread_with_config(port, SOCK_STREAM, sync, running, 
		[layer_fn](struct gsocket *l) { gsocket_push_layer(l, layer_fn(1)); },
		handle_stream_io, (void *)"Response");
}

void gsocket_http3_server_thread(int port, ServerSync *sync, std::atomic<bool> &running)
{
	SSL_CTX *ssl_ctx = SSL_CTX_new(OSSL_QUIC_server_method());
	unsigned char alpn[] = {2, 'h', '3'};
	SSL_CTX_set_alpn_protos(ssl_ctx, alpn, sizeof(alpn));

	char key[PATH_MAX];
	char cert[PATH_MAX];
	smartdns_get_cert(key, cert);
	SSL_CTX_use_PrivateKey_file(ssl_ctx, key, SSL_FILETYPE_PEM);
	SSL_CTX_use_certificate_file(ssl_ctx, cert, SSL_FILETYPE_PEM);

	gsocket_generic_server_thread_with_config(port, SOCK_DGRAM, sync, running,
		[ssl_ctx](struct gsocket *l) {
			gsocket_push_layer(l, gsocket_io_ssl_quic_new(ssl_ctx, 1));
			gsocket_push_layer(l, gsocket_io_http3_new(1));
		},
		handle_stream_io, (void *)"Response");
	SSL_CTX_free(ssl_ctx);
}

static bool handle_http2_status_test(struct gsocket *stream, struct gstream_poll *sp, void *user_data)
{
	char buf[128];
	gsocket_recv(stream, buf, sizeof(buf), 0);

	int status = 404;
	gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_STATUS, &status, sizeof(status));

	int get_status = 0;
	socklen_t l = sizeof(get_status);
	gsocket_getsockopt(stream, SOL_HTTP, SO_HTTP_STATUS, &get_status, &l);

	gsocket_send(stream, "NotFound", 8, MSG_NOSIGNAL);
	return true;
}

void gsocket_http2_status_server_thread(int port, ServerSync *sync, std::atomic<bool> &running)
{
	gsocket_generic_server_thread_with_config(port, SOCK_STREAM, sync, running,
		[](struct gsocket *l) { gsocket_push_layer(l, gsocket_io_http2_new(1)); },
		handle_http2_status_test, NULL);
}

void gsocket_http1_file_server_thread(int port, const char *root, ServerSync *sync, std::atomic<bool> &running)
{
	gsocket_generic_server_thread_with_config(port, SOCK_STREAM, sync, running,
		[](struct gsocket *l) { gsocket_push_layer(l, gsocket_io_http1_new(1)); },
		handle_file_request, (void *)root);
}

void gsocket_http2_file_server_thread(int port, const char *root, ServerSync *sync, std::atomic<bool> &running)
{
	SSL_CTX *ssl_ctx = init_ssl_ctx(true);
	const char *protos = "h2";

	gsocket_generic_server_thread_with_config(port, SOCK_STREAM, sync, running,
		[ssl_ctx, protos](struct gsocket *l) {
			gsocket_push_layer(l, gsocket_io_ssl_new(ssl_ctx, 1));
			gsocket_push_layer(l, gsocket_io_http2_new(1));
			gsocket_setsockopt(l, SOL_SSL, SO_SSL_ALPN, protos, strlen(protos));
		},
		handle_file_request, (void *)root);
	SSL_CTX_free(ssl_ctx);
}

/* ========================================================================= */
/*                              Helper Functions                             */
/* ========================================================================= */

// QUIC ALPN support
static const unsigned char g_quic_alpn[] = {4, 'q', 'u', 'i', 'c'};
static int alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
						  unsigned int inlen, void *arg)
{
	*out = g_quic_alpn + 1;
	*outlen = g_quic_alpn[0];
	return SSL_TLSEXT_ERR_OK;
}

/* ========================================================================= */
/*                               Client Tasks                                */
/* ========================================================================= */

static void client_task(int port, int id, const char *path, int type = 1, int requests = 1)
{
	struct gsocket *sock = gsocket_new(socket(AF_INET, SOCK_STREAM, 0));
	struct gsocket_io *io = (type == 2) ? gsocket_io_http2_new(0) : gsocket_io_http1_new(0);
	gsocket_push_layer(sock, io);

	if (gsocket_connect(sock, "127.0.0.1", port) == 0) {
		int retries = 0;
		int hr;
		while ((hr = gsocket_handshake(sock)) != GSOCKET_HANDSHAKE_DONE && retries++ < 1000) {
			usleep(1000);
		}

		for (int k = 0; k < requests; k++) {
			struct gsocket *stream = gsocket_open_stream(sock);
			if (stream) {
				gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_METHOD, "GET", 4);
				char url[64];
				snprintf(url, sizeof(url), "%s-%d-%d", path, id, k);
				gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_URL, url, strlen(url));

				gsocket_send(stream, NULL, 0, MSG_NOSIGNAL | (type == 2 ? GS_MSG_FIN : 0));

				char buf[256];
				int n = gsocket_recv(stream, buf, sizeof(buf) - 1, 0);
				if (n > 0) {
					buf[n] = 0;
				}
				gsocket_close(stream);
				gsocket_free(stream);
			}
		}
	}
	gsocket_close(sock);
	gsocket_free(sock);
}

static void client_h3_task(int port, int id, const char *path = "/", const char *expected_resp = NULL)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct gsocket *sock = gsocket_new(fd);

	SSL_CTX *ssl_ctx = SSL_CTX_new(OSSL_QUIC_client_method());
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
	unsigned char alpn[] = {2, 'h', '3'};
	SSL_CTX_set_alpn_protos(ssl_ctx, alpn, sizeof(alpn));

	gsocket_push_layer(sock, gsocket_io_ssl_quic_new(ssl_ctx, 0));
	gsocket_push_layer(sock, gsocket_io_http3_new(0));
	gsocket_set_nonblock(sock, 1);

	/* Async connect wait using gepoll */
	struct gepoll *ep = gepoll_create(0);
	gepoll_add(ep, sock, EPOLLIN | EPOLLOUT, sock);

	if (gsocket_connect(sock, "127.0.0.1", port) == 0 || errno == EINPROGRESS) {
		/* Wait for handshake */
		int retries = 0;
		while (retries++ < 100) {
			if (gsocket_handshake(sock) == GSOCKET_HANDSHAKE_DONE)
				break;
			struct gepoll_event ev;
			gepoll_wait(ep, &ev, 1, 100);
		}

		struct gsocket *stream = gsocket_open_stream(sock);
		if (stream) {
			gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_METHOD, "GET", 4);
			gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_URL, path, strlen(path));
			gsocket_send(stream, NULL, 0, MSG_NOSIGNAL);

			char buf[128];
			gsocket_set_nonblock(stream, 0);
			int n = gsocket_recv(stream, buf, sizeof(buf) - 1, 0);
			if (expected_resp) {
				if (n > 0) {
					buf[n] = 0;
					if (strcmp(buf, expected_resp) != 0) {
						exit(1);
					}
				} else {
					exit(1);
				}
			}
			gsocket_close(stream);
			gsocket_free(stream);
		}
	}
	gepoll_destroy(ep);
	gsocket_close(sock);
	gsocket_free(sock);
	SSL_CTX_free(ssl_ctx);
}

/* ========================================================================= */
/*                                Test Cases                                 */
/* ========================================================================= */

class GSocketHTTPTest : public ::testing::Test
{
};

TEST_F(GSocketHTTPTest, HTTP1ClientBasic)
{
	ServerSync sync;
	std::atomic<bool> running(true);
	int port = 0;
	std::thread t(gsocket_generic_server_thread, port, &sync, std::ref(running), gsocket_io_http1_new);
	sync.wait();
	port = sync.port;

	struct gsocket *sock = gsocket_new(socket(AF_INET, SOCK_STREAM, 0));
	gsocket_push_layer(sock, gsocket_io_http1_new(0));
	ASSERT_EQ(gsocket_connect(sock, "127.0.0.1", port), 0);

	struct gsocket *stream = gsocket_open_stream(sock);
	ASSERT_NE(stream, nullptr);

	gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_METHOD, "GET", 4);
	gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_URL, "/hello", 7);
	gsocket_send(stream, NULL, 0, MSG_NOSIGNAL);

	char buf[8192];
	int n = gsocket_recv(stream, buf, sizeof(buf) - 1, 0);
	ASSERT_GT(n, 0);
	buf[n] = 0;
	ASSERT_STREQ(buf, "Response");

	gsocket_close(stream);
	gsocket_free(stream);
	gsocket_close(sock);
	gsocket_free(sock);
	running = false;
	t.join();
}

TEST_F(GSocketHTTPTest, HTTP1ServerBasic)
{
	int port = 0;
	struct gsocket *listener = create_listener(port, SOCK_STREAM);
	ASSERT_NE(listener, nullptr);
	port = get_socket_port(listener);
	gsocket_set_nonblock(listener, 0);

	std::thread client_thread([port]() {
		/* Use gsocket client */
		client_task(port, 0, "/basic", 1, 1);
	});

	struct gsocket *conn = gsocket_accept(listener, NULL, NULL);
	ASSERT_NE(conn, nullptr);
	gsocket_push_layer(conn, gsocket_io_http1_new(1));

	struct gepoll *ep = gepoll_create(0);
	gepoll_add(ep, conn, EPOLLIN, conn);
	struct gepoll_event ev[1];
	gepoll_wait(ep, ev, 1, 2000);

	struct gsocket *stream = gsocket_accept(conn, NULL, NULL);
	ASSERT_NE(stream, nullptr);

	char buf[10];
	int r = gsocket_recv(stream, buf, sizeof(buf), 0);
	ASSERT_GE(r, 0);

	gsocket_send(stream, "Response", 8, MSG_NOSIGNAL);

	gsocket_close(stream);
	gsocket_free(stream);
	gsocket_close(conn);
	gsocket_free(conn);
	gsocket_close(listener);
	gsocket_free(listener);
	gepoll_destroy(ep);
	client_thread.join();
}

TEST_F(GSocketHTTPTest, HTTP1LargeDataTransfer)
{
	ServerSync sync;
	std::atomic<bool> running(true);
	std::thread t(gsocket_generic_server_thread, 0, &sync, std::ref(running), gsocket_io_http1_new);
	sync.wait();
	int port = sync.port;

	struct gsocket *sock = gsocket_new(socket(AF_INET, SOCK_STREAM, 0));
	gsocket_push_layer(sock, gsocket_io_http1_new(0));
	ASSERT_EQ(gsocket_connect(sock, "127.0.0.1", port), 0);

	struct gsocket *stream = gsocket_open_stream(sock);
	ASSERT_NE(stream, nullptr);

	size_t total = 1024 * 128; /* 128KB is enough to test large data */
	char *data = (char *)malloc(total);
	memset(data, 'A', total);

	gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_METHOD, "POST", 5);
	gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_URL, "/large", 7);

	ssize_t sent = 0;
	while (sent < (ssize_t)total) {
		ssize_t n = gsocket_send(stream, data + sent, total - sent, 0);
		if (n <= 0)
			break;
		sent += n;
	}
	ASSERT_EQ(sent, (ssize_t)total);

	char buf[128];
	ssize_t n = gsocket_recv(stream, buf, sizeof(buf), 0);
	ASSERT_GT(n, 0);

	free(data);
	gsocket_close(stream);
	gsocket_free(stream);
	gsocket_close(sock);
	gsocket_free(sock);
	running = false;
	t.join();
}

TEST_F(GSocketHTTPTest, HTTP1SerialRequests)
{
	ServerSync sync;
	std::atomic<bool> running(true);
	std::thread t(gsocket_generic_server_thread, 0, &sync, std::ref(running), gsocket_io_http1_new);
	sync.wait();
	int port = sync.port;

	struct gsocket *sock = gsocket_new(socket(AF_INET, SOCK_STREAM, 0));
	gsocket_push_layer(sock, gsocket_io_http1_new(0));
	ASSERT_EQ(gsocket_connect(sock, "127.0.0.1", port), 0);

	for (int i = 0; i < 3; i++) {
		struct gsocket *stream = gsocket_open_stream(sock);
		ASSERT_NE(stream, nullptr);

		char url[32];
		snprintf(url, sizeof(url), "/serial-%d", i);
		gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_METHOD, "GET", 4);
		gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_URL, url, strlen(url));
		gsocket_send(stream, NULL, 0, 0);

		char buf[128];
		ssize_t n = gsocket_recv(stream, buf, sizeof(buf), 0);
		ASSERT_GT(n, 0);
		buf[n] = 0;
		ASSERT_STREQ(buf, "Response");

		gsocket_close(stream);
		gsocket_free(stream);
	}

	gsocket_close(sock);
	gsocket_free(sock);
	running = false;
	t.join();
}

TEST_F(GSocketHTTPTest, HTTP1Concurrent)
{
	ServerSync sync;
	std::atomic<bool> running(true);
	int port = 0;
	std::thread s(gsocket_generic_server_thread, port, &sync, std::ref(running), gsocket_io_http1_new);
	sync.wait();
	port = sync.port;

	std::thread c1(client_task, port, 0, "/req", 1, 1);
	std::thread c2(client_task, port, 1, "/req", 1, 1);
	c1.join();
	c2.join();

	running = false;
	s.join();
}

TEST_F(GSocketHTTPTest, HTTP1KeepAlive)
{
	ServerSync sync;
	std::atomic<bool> running(true);
	int port = 0;
	std::thread s(gsocket_generic_server_thread, port, &sync, std::ref(running), gsocket_io_http1_new);
	sync.wait();
	port = sync.port;

	std::thread c1(client_task, port, 0, "/ka", 1, 3);
	std::thread c2(client_task, port, 1, "/ka", 1, 3);
	c1.join();
	c2.join();

	running = false;
	s.join();
}

TEST_F(GSocketHTTPTest, HTTP2Concurrent)
{
	ServerSync sync;
	std::atomic<bool> running(true);
	int port = 0;
	signal(SIGPIPE, SIG_IGN);
	std::thread s(gsocket_generic_server_thread, port, &sync, std::ref(running), gsocket_io_http2_new);
	sync.wait();
	port = sync.port;
	ASSERT_GT(port, 0);

	std::thread c1(client_task, port, 0, "/h2", 2, 3);
	std::thread c2(client_task, port, 1, "/h2", 2, 3);
	c1.join();
	c2.join();

	running = false;
	s.join();
}

TEST_F(GSocketHTTPTest, HTTP3Concurrent)
{
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
	ServerSync sync;
	std::atomic<bool> running(true);
	int port = 0;
	std::thread s(gsocket_http3_server_thread, port, &sync, std::ref(running));
	sync.wait();
	port = sync.port;
	ASSERT_GT(port, 0);

	std::thread c1(client_h3_task, port, 0, "/", (const char *)NULL);
	std::thread c2(client_h3_task, port, 1, "/", (const char *)NULL);
	c1.join();
	c2.join();

	running = false;
	s.join();
#else
#endif
}

TEST_F(GSocketHTTPTest, ALPN_Negotiation)
{
	auto alpn_server = [](int port, const char *protos, ServerSync *s_sync) {
		struct gsocket *l = create_listener(0, SOCK_STREAM);
		/* Verify Listener */
		if (!l) {
			s_sync->notify(0);
			return;
		}
		gsocket_set_nonblock(l, 0); /* Blocking accept for this test */
		int actual_port = get_socket_port(l);
		s_sync->notify(actual_port);

		struct gsocket *c = gsocket_accept(l, NULL, NULL);
		if (c) {
			SSL_CTX *ctx = init_ssl_ctx(true);
			gsocket_push_layer(c, gsocket_io_ssl_new(ctx, 1));
			gsocket_setsockopt(c, SOL_SSL, SO_SSL_ALPN, protos, strlen(protos));
			if (gsocket_handshake(c) == GSOCKET_HANDSHAKE_DONE) {
				char buf[128];
				int n = gsocket_recv(c, buf, sizeof(buf), 0);
				if (n > 0)
					gsocket_send(c, buf, n, 0);
			}
			gsocket_close(c);
			gsocket_free(c);
			SSL_CTX_free(ctx);
		}
		gsocket_close(l);
		gsocket_free(l);
	};

	/* Case 1: H2 */
	{
		ServerSync sync;
		int port = 30095; /* Placeholder, will use dynamic */
		std::thread t(alpn_server, port, "h2,http/1.1", &sync);
		sync.wait();
		int actual_port = sync.port;
		ASSERT_GT(actual_port, 0);

		struct gsocket *s = gsocket_new(socket(AF_INET, SOCK_STREAM, 0));
		SSL_CTX *c = init_ssl_ctx(false);
		gsocket_push_layer(s, gsocket_io_ssl_new(c, 0));
		char protos[] = "h2,http/1.1";
		gsocket_setsockopt(s, SOL_SSL, SO_SSL_ALPN, protos, strlen(protos));

		ASSERT_EQ(gsocket_connect(s, "127.0.0.1", actual_port), 0);
		ASSERT_EQ(gsocket_handshake(s), GSOCKET_HANDSHAKE_DONE);
		char p[32] = {0};
		socklen_t l = sizeof(p);
		gsocket_getsockopt(s, SOL_SSL, SO_SSL_ALPN, p, &l);
		ASSERT_STREQ(p, "h2");

		const char *data = "hello h2";
		gsocket_send(s, data, strlen(data), 0);
		char buf[128] = {0};
		int n = gsocket_recv(s, buf, sizeof(buf), 0);
		ASSERT_EQ(n, (int)strlen(data));
		ASSERT_STREQ(buf, data);
		gsocket_close(s);
		gsocket_free(s);
		SSL_CTX_free(c);
		t.join();
	}

	/* Case 2: HTTP/1.1 */
	{
		ServerSync sync;
		int port = 30096;
		std::thread t(alpn_server, port, "http/1.1,h2", &sync);
		sync.wait();
		int actual_port = sync.port;
		ASSERT_GT(actual_port, 0);

		struct gsocket *s = gsocket_new(socket(AF_INET, SOCK_STREAM, 0));
		SSL_CTX *c = init_ssl_ctx(false);
		gsocket_push_layer(s, gsocket_io_ssl_new(c, 0));
		char protos[] = "http/1.1";
		gsocket_setsockopt(s, SOL_SSL, SO_SSL_ALPN, protos, strlen(protos));
		ASSERT_EQ(gsocket_connect(s, "127.0.0.1", actual_port), 0);
		ASSERT_EQ(gsocket_handshake(s), GSOCKET_HANDSHAKE_DONE);
		char p[32] = {0};
		socklen_t l = sizeof(p);
		gsocket_getsockopt(s, SOL_SSL, SO_SSL_ALPN, p, &l);
		ASSERT_STREQ(p, "http/1.1");

		const char *data = "hello http/1.1";
		gsocket_send(s, data, strlen(data), 0);
		char buf[128] = {0};
		int n = gsocket_recv(s, buf, sizeof(buf), 0);
		ASSERT_EQ(n, (int)strlen(data));
		ASSERT_STREQ(buf, data);
		gsocket_close(s);
		gsocket_free(s);
		SSL_CTX_free(c);
		t.join();
	}
}

TEST_F(GSocketHTTPTest, ALPN_H2)
{
	/* Placeholder for clean test */
}

TEST_F(GSocketHTTPTest, HTTP2StatusSetGet)
{
	ServerSync sync;
	std::atomic<bool> running(true);
	int port = 0;
	std::thread s(gsocket_http2_status_server_thread, port, &sync, std::ref(running));
	sync.wait();
	port = sync.port;
	ASSERT_GT(port, 0);

	struct gsocket *sock = gsocket_new(socket(AF_INET, SOCK_STREAM, 0));
	gsocket_push_layer(sock, gsocket_io_http2_new(0));
	if (gsocket_connect(sock, "127.0.0.1", port) == 0) {
		struct gsocket *stream = gsocket_open_stream(sock);
		if (stream) {
			gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_METHOD, "GET", 4);
			gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_URL, "/status", 7);
			gsocket_send(stream, NULL, 0, MSG_NOSIGNAL | GS_MSG_FIN);

			char buf[256];
			int n = gsocket_recv(stream, buf, sizeof(buf) - 1, 0);
			if (n > 0) {
				buf[n] = 0;
				ASSERT_STREQ(buf, "NotFound");
			}

			int status = 0;
			socklen_t slen = sizeof(status);
			gsocket_getsockopt(stream, SOL_HTTP, SO_HTTP_STATUS, &status, &slen);
			EXPECT_EQ(status, 404);

			gsocket_close(stream);
			gsocket_free(stream);
		}
	}
	gsocket_close(sock);
	gsocket_free(sock);

	running = false;
	s.join();
}

TEST_F(GSocketHTTPTest, HTTP3StatusSetGet)
{
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
	ServerSync sync;
	std::atomic<bool> running(true);
	int port = 0;
	std::thread s(gsocket_http3_server_thread, port, &sync, std::ref(running));
	sync.wait();
	port = sync.port;
	ASSERT_GT(port, 0);

	std::thread c(
		[](int p) {
			int fd = socket(AF_INET, SOCK_DGRAM, 0);
			struct gsocket *sock = gsocket_new(fd);
			SSL_CTX *ctx = SSL_CTX_new(OSSL_QUIC_client_method());
			SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
			unsigned char alpn[] = {2, 'h', '3'};
			SSL_CTX_set_alpn_protos(ctx, alpn, sizeof(alpn));

			char key[PATH_MAX];
			char cert[PATH_MAX];
			smartdns_get_cert(key, cert);
			SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM);
			SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM);

			gsocket_push_layer(sock, gsocket_io_ssl_quic_new(ctx, 0));
			gsocket_push_layer(sock, gsocket_io_http3_new(0));
			gsocket_set_nonblock(sock, 1);

			struct gepoll *ep = gepoll_create(0);
			gepoll_add(ep, sock, EPOLLIN | EPOLLOUT, sock);

			if (gsocket_connect(sock, "127.0.0.1", p) == 0 || errno == EINPROGRESS) {
				int retries = 0;
				while (retries++ < 100) {
					if (gsocket_handshake(sock) == GSOCKET_HANDSHAKE_DONE)
						break;
					struct gepoll_event ev;
					gepoll_wait(ep, &ev, 1, 100);
				}
				struct gsocket *st = gsocket_open_stream(sock);
				if (st) {
					gsocket_setsockopt(st, SOL_HTTP, SO_HTTP_METHOD, "GET", 4);
					gsocket_setsockopt(st, SOL_HTTP, SO_HTTP_URL, "/status", 7);
					gsocket_send(st, NULL, 0, MSG_NOSIGNAL);
					char b[128];
					gsocket_set_nonblock(st, 0);
					int n = gsocket_recv(st, b, sizeof(b) - 1, 0);
					if (n > 0) {
						b[n] = 0;
						ASSERT_STREQ(b, "NotFound");
						int status = 0;
						socklen_t slen = sizeof(status);
						gsocket_getsockopt(st, SOL_HTTP, SO_HTTP_STATUS, &status, &slen);
						EXPECT_EQ(status, 404);
					}
					gsocket_close(st);
					gsocket_free(st);
				}
			}
			gepoll_destroy(ep);
			gsocket_close(sock);
			gsocket_free(sock);
			SSL_CTX_free(ctx);
		},
		port);
	c.join();
	running = false;
	s.join();
#endif
}

TEST_F(GSocketHTTPTest, HTTP1StatusSetGet)
{
	struct gsocket *l = create_listener(0, SOCK_STREAM);
	gsocket_set_nonblock(l, 0); /* Blocking accept */
	/* Push layer to listener */
	gsocket_push_layer(l, gsocket_io_http1_new(1));

	int port = get_socket_port(l);
	ASSERT_GT(port, 0);

	std::thread c([port] { client_task(port, 0, "/status", 1, 1); });

	struct gsocket *cn = gsocket_accept(l, NULL, NULL);
	ASSERT_NE(cn, nullptr);
	/* No explicit push for client */
	// gsocket_push_layer(cn, gsocket_io_http1_new(1));
	struct gepoll *ep = gepoll_create(0);
	gepoll_add(ep, cn, EPOLLIN, cn);
	struct gepoll_event ev;
	gepoll_wait(ep, &ev, 1, 1000);

	struct gsocket *s = gsocket_accept(cn, NULL, NULL);
	ASSERT_NE(s, nullptr);

	int st = 404;
	gsocket_setsockopt(s, SOL_HTTP, SO_HTTP_STATUS, &st, sizeof(st));
	int get_st = 0;
	socklen_t len = sizeof(get_st);
	gsocket_getsockopt(s, SOL_HTTP, SO_HTTP_STATUS, &get_st, &len);
	ASSERT_EQ(get_st, 404);

	gsocket_send(s, "OK", 2, MSG_NOSIGNAL);

	gsocket_close(s);
	gsocket_free(s);
	gsocket_close(cn);
	gsocket_free(cn);
	gsocket_close(l);
	gsocket_free(l);
	gepoll_destroy(ep);
	c.join();
}

TEST_F(GSocketHTTPTest, HTTP1MethodUrlGet)
{
	struct gsocket *l = create_listener(0, SOCK_STREAM);
	gsocket_push_layer(l, gsocket_io_http1_new(1));
	int port = get_socket_port(l);
	gsocket_set_nonblock(l, 0);

	std::thread c([port] { client_task(port, 0, "/test_url", 1, 1); });

	struct gsocket *cn = gsocket_accept(l, NULL, NULL);
	ASSERT_NE(cn, nullptr);

	struct gepoll *ep = gepoll_create(0);
	gepoll_add(ep, cn, EPOLLIN, cn);
	struct gepoll_event ev;
	gepoll_wait(ep, &ev, 1, 1000);

	struct gsocket *s = gsocket_accept(cn, NULL, NULL);
	ASSERT_NE(s, nullptr);

	char method[16] = {0};
	socklen_t ml = sizeof(method);
	ASSERT_EQ(gsocket_getsockopt(s, SOL_HTTP, SO_HTTP_METHOD, method, &ml), 0);
	ASSERT_STREQ(method, "GET");

	char url[64] = {0};
	socklen_t ul = sizeof(url);
	ASSERT_EQ(gsocket_getsockopt(s, SOL_HTTP, SO_HTTP_URL, url, &ul), 0);
	ASSERT_STREQ(url, "/test_url-0-0");

	gsocket_send(s, "OK", 2, MSG_NOSIGNAL);
	gsocket_close(s);
	gsocket_free(s);
	gsocket_close(cn);
	gsocket_free(cn);
	gsocket_close(l);
	gsocket_free(l);
	gepoll_destroy(ep);
	c.join();
}

TEST_F(GSocketHTTPTest, HTTP2MethodUrlGet)
{
	struct gsocket *l = create_listener(0, SOCK_STREAM);
	gsocket_push_layer(l, gsocket_io_http2_new(1));
	int port = get_socket_port(l);
	gsocket_set_nonblock(l, 0);

	std::thread c([port] { client_task(port, 0, "/h2_url", 2, 1); });

	struct gsocket *cn = gsocket_accept(l, NULL, NULL);
	ASSERT_NE(cn, nullptr);

	struct gepoll *ep = gepoll_create(0);
	gepoll_add(ep, cn, EPOLLIN, cn);

	struct gsocket *s = NULL;
	while (!s) {
		struct gepoll_event ev;
		gepoll_wait(ep, &ev, 1, 100);
		s = gsocket_accept(cn, NULL, NULL);
	}

	char method[16] = {0};
	socklen_t ml = sizeof(method);
	ASSERT_EQ(gsocket_getsockopt(s, SOL_HTTP, SO_HTTP_METHOD, method, &ml), 0);
	ASSERT_STREQ(method, "GET");

	char url[64] = {0};
	socklen_t ul = sizeof(url);
	ASSERT_EQ(gsocket_getsockopt(s, SOL_HTTP, SO_HTTP_URL, url, &ul), 0);
	ASSERT_STREQ(url, "/h2_url-0-0");

	gsocket_send(s, "OK", 2, MSG_NOSIGNAL);
	gsocket_close(s);
	gsocket_free(s);
	gsocket_close(cn);
	gsocket_free(cn);
	gsocket_close(l);
	gsocket_free(l);
	gepoll_destroy(ep);
	c.join();
}

TEST_F(GSocketHTTPTest, HTTP3MethodUrlGet)
{
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
	ServerSync sync;
	std::atomic<bool> running(true);
	int port = 0;
	std::thread s(gsocket_http3_server_thread, port, &sync, std::ref(running));
	sync.wait();
	port = sync.port;
	ASSERT_GT(port, 0);

	std::thread c(client_h3_task, port, 0, "/method_test", "Response");
	c.join();

	running = false;
	s.join();
#endif
}

TEST_F(GSocketHTTPTest, HTTP1FileServer)
{
	ServerSync sync;
	std::atomic<bool> running(true);
	std::string root = "/home/rock/code/smartdns/.vscode/www/";  // 32KB file
	ASSERT_FALSE(root.empty());
	std::thread s(gsocket_http1_file_server_thread, 0, root.c_str(), &sync, std::ref(running));
	sync.wait();
	int port = sync.port;
	ASSERT_GT(port, 0);
	printf("HTTPS File Server running on port %d\n", port);
	// sleep(600);

	struct gsocket *sock = gsocket_new(socket(AF_INET, SOCK_STREAM, 0));
	gsocket_push_layer(sock, gsocket_io_http1_new(0));
	ASSERT_EQ(gsocket_connect(sock, "127.0.0.1", port), 0);

	/* Request index.html */
	struct gsocket *stream = gsocket_open_stream(sock);
	ASSERT_NE(stream, nullptr);
	gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_METHOD, "GET", 4);
	gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_URL, "/", 1);
	gsocket_send(stream, NULL, 0, MSG_NOSIGNAL);

	char *buf = (char *)malloc(256 * 1024);  // 256KB buffer for large files
	ASSERT_NE(buf, nullptr);
	
	// Read all data (may require multiple recv calls for large files)
	int total = 0;
	while (total < 256 * 1024 - 1) {
		int n = gsocket_recv(stream, buf + total, 256 * 1024 - 1 - total, 0);
		if (n <= 0) break;
		total += n;
	}
	ASSERT_GT(total, 0);
	buf[total] = 0;

	/* Verify content against actual index.html */
	std::string index_path = root + "/index.html";
	FILE *fp = fopen(index_path.c_str(), "rb");
	ASSERT_NE(fp, nullptr);
	fseek(fp, 0, SEEK_END);
	long size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	char *expected = (char *)malloc(size + 1);
	if (expected) {
		fread(expected, 1, size, fp);
		expected[size] = 0;
	}
	fclose(fp);

	ASSERT_EQ(total, size);
	ASSERT_STREQ(buf, expected);
	free(expected);
	free(buf);  // Free the dynamically allocated buffer

	gsocket_close(stream);
	gsocket_free(stream);

	/* Request 404 */
	stream = gsocket_open_stream(sock);
	ASSERT_NE(stream, nullptr);
	gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_METHOD, "GET", 4);
	gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_URL, "/not_exists", 11);
	gsocket_send(stream, NULL, 0, MSG_NOSIGNAL);

	char buf404[256];  // Small buffer for 404 response
	int n = gsocket_recv(stream, buf404, sizeof(buf404) - 1, 0);
	ASSERT_GT(n, 0);
	buf404[n] = 0;
	ASSERT_STREQ(buf404, "File Not Found");

	int status = 0;
	socklen_t slen = sizeof(status);
	gsocket_getsockopt(stream, SOL_HTTP, SO_HTTP_STATUS, &status, &slen);
	EXPECT_EQ(status, 404);

	gsocket_close(stream);
	gsocket_free(stream);

	gsocket_close(sock);
	gsocket_free(sock);
	running = false;
	s.join();
	cleanup_test_www_dir(root);
}

TEST_F(GSocketHTTPTest, HTTP2FileServer)
{
	ServerSync sync;
	std::atomic<bool> running(true);
	std::string root = "/home/rock/code/smartdns/.vscode/www/";  // 32KB file
	ASSERT_FALSE(root.empty());
	std::thread s(gsocket_http2_file_server_thread, 0, root.c_str(), &sync, std::ref(running));
	sync.wait();
	int port = sync.port;
	ASSERT_GT(port, 0);
	printf("HTTPS File Server running on port %d\n", port);
	// sleep(600);


	struct gsocket *sock = gsocket_new(socket(AF_INET, SOCK_STREAM, 0));
	SSL_CTX *ssl_ctx = init_ssl_ctx(false);
	const char *protos = "h2";
	
	gsocket_push_layer(sock, gsocket_io_ssl_new(ssl_ctx, 0));
	gsocket_push_layer(sock, gsocket_io_http2_new(0));
	gsocket_setsockopt(sock, SOL_SSL, SO_SSL_ALPN, protos, strlen(protos));

	printf("Connecting to 127.0.0.1:%d\n", port); fflush(stdout);
	gsocket_set_nonblock(sock, 1);
	int cr = gsocket_connect(sock, "127.0.0.1", port);
	if (cr < 0 && errno == EINPROGRESS) {
		/* Wait for connection */
		struct pollfd pfd = {gsocket_get_fd(sock), POLLOUT, 0};
		poll(&pfd, 1, 1000);
	}
	
	printf("Driving client handshake...\n"); fflush(stdout);
	int hr;
	int retry = 0;
	while ((hr = gsocket_handshake(sock)) != GSOCKET_HANDSHAKE_DONE && retry++ < 30000) {
		if (hr == GSOCKET_HANDSHAKE_ERR) {
			printf("Client handshake error!\n"); fflush(stdout);
			break;
		}
		if (retry % 100 == 0) {
			printf("Client handshake: still in progress (hr=%d)...\n", hr); fflush(stdout);
		}
		usleep(1000);
	}
	printf("Client handshake exited with %d (retry=%d).\n", hr, retry); fflush(stdout);
	ASSERT_EQ(hr, GSOCKET_HANDSHAKE_DONE);
	printf("Client handshake done.\n"); fflush(stdout);

	/* Request index.html */
	printf("Opening stream...\n");
	struct gsocket *stream = gsocket_open_stream(sock);
	ASSERT_NE(stream, nullptr);
	printf("Stream opened. Sending request...\n");
	gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_METHOD, "GET", 4);
	char req_url[] = "/_next/static/chunks/1a5bd2cda26bbf61.js";
	gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_URL, req_url, strlen(req_url));
	gsocket_send(stream, NULL, 0, MSG_NOSIGNAL | GS_MSG_FIN);

	printf("Waiting for response...\n");
	
	/* Get expected file size first */
	std::string index_path = root + "/_next/static/chunks/1a5bd2cda26bbf61.js";
	FILE *fp = fopen(index_path.c_str(), "rb");
	ASSERT_NE(fp, nullptr);
	fseek(fp, 0, SEEK_END);
	long expected_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	char *expected = (char *)malloc(expected_size + 1);
	if (expected) {
		fread(expected, 1, expected_size, fp);
		expected[expected_size] = 0;
	}
	fclose(fp);
	
	char *buf = (char *)malloc(256 * 1024);  // 256KB buffer for large files
	ASSERT_NE(buf, nullptr);
	
	// HTTP/2 may need multiple recv calls for large files
	int total = 0;
	while (total < expected_size) {
		int n = gsocket_recv(stream, buf + total, expected_size - total, 0);
		printf("Client recv: n=%d, total=%d, expected=%ld\n", n, total, expected_size);
		if (n > 0) {
			total += n;
		} else if (n < 0) {
			// Error occurred
			printf("Client recv error: errno=%d\n", errno);
			break;
		} else {
			// n == 0: stream ended
			printf("Client recv returned 0 - stream ended\n");
			break;
		}
	}
	printf("Response received (n=%d).\n", total);
	ASSERT_GT(total, 0);
	buf[total] = 0;

	ASSERT_EQ(total, expected_size);
	ASSERT_STREQ(buf, expected);
	free(expected);
	free(buf);  // Free the dynamically allocated buffer

	gsocket_close(stream);
	gsocket_free(stream);
	gsocket_close(sock);
	gsocket_free(sock);
	SSL_CTX_free(ssl_ctx);
	running = false;
	s.join();
	cleanup_test_www_dir(root);
}
// HTTPS File Server Thread (HTTP/1 + TLS)
void gsocket_https_file_server_thread(int port, const char *root, ServerSync *sync, std::atomic<bool> &running)
{
	SSL_CTX *ssl_ctx = init_ssl_ctx(true);
	gsocket_generic_server_thread_with_config(port, SOCK_STREAM, sync, running,
		[ssl_ctx](struct gsocket *l) {
			gsocket_push_layer(l, gsocket_io_ssl_new(ssl_ctx, 1));
			gsocket_push_layer(l, gsocket_io_http1_new(1));
		},
		handle_file_request, (void *)root);
	SSL_CTX_free(ssl_ctx);
}

TEST_F(GSocketHTTPTest, HTTPSFileServer)
{
	ServerSync sync;
	std::atomic<bool> running(true);
	std::string root = "/home/rock/code/smartdns/.vscode/www/";  // 32KB file
	ASSERT_FALSE(root.empty());
	std::thread s(gsocket_https_file_server_thread, 0, root.c_str(), &sync, std::ref(running));
	sync.wait();
	int port = sync.port;
	printf("HTTPS File Server running on port %d\n", port);
	// sleep(600);

	SSL_CTX *ssl_ctx = init_ssl_ctx(false);
	struct gsocket *sock = gsocket_new(socket(AF_INET, SOCK_STREAM, 0));
	gsocket_push_layer(sock, gsocket_io_ssl_new(ssl_ctx, 0));
	gsocket_push_layer(sock, gsocket_io_http1_new(0));
	ASSERT_EQ(gsocket_connect(sock, "127.0.0.1", port), 0);

	/* Request index.html */
	struct gsocket *stream = gsocket_open_stream(sock);
	ASSERT_NE(stream, nullptr);
	gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_METHOD, "GET", 4);
	gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_URL, "/", 1);
	gsocket_send(stream, NULL, 0, MSG_NOSIGNAL);

	/* Get expected file size first */
	std::string index_path = root + "/index.html";
	FILE *fp = fopen(index_path.c_str(), "rb");
	ASSERT_NE(fp, nullptr);
	fseek(fp, 0, SEEK_END);
	long expected_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	char *expected = (char *)malloc(expected_size + 1);
	if (expected) {
		fread(expected, 1, expected_size, fp);
		expected[expected_size] = 0;
	}
	fclose(fp);

	char *buf = (char *)malloc(256 * 1024);  // 256KB buffer for large files
	ASSERT_NE(buf, nullptr);
	
	// HTTPS may need multiple recv calls for large files
	int total = 0;
	while (total < expected_size) {
		int n = gsocket_recv(stream, buf + total, expected_size - total, 0);
		if (n > 0) {
			total += n;
		} else if (n < 0) {
			// Error occurred
			break;
		}
		// n == 0 means no data yet, continue waiting
	}
	ASSERT_GT(total, 0);
	buf[total] = 0;

	ASSERT_EQ(total, expected_size);
	ASSERT_STREQ(buf, expected);
	free(expected);
	free(buf);  // Free the dynamically allocated buffer

	gsocket_close(stream);
	gsocket_free(stream);

	/* Request 404 */
	stream = gsocket_open_stream(sock);
	ASSERT_NE(stream, nullptr);
	gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_METHOD, "GET", 4);
	gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_URL, "/not_exists", 11);
	gsocket_send(stream, NULL, 0, MSG_NOSIGNAL);

	char buf404[256];  // Small buffer for 404 response
	int n = gsocket_recv(stream, buf404, sizeof(buf404) - 1, 0);
	ASSERT_GT(n, 0);
	buf404[n] = 0;
	ASSERT_STREQ(buf404, "File Not Found");

	int status = 0;
	socklen_t slen = sizeof(status);
	gsocket_getsockopt(stream, SOL_HTTP, SO_HTTP_STATUS, &status, &slen);
	EXPECT_EQ(status, 404);

	gsocket_close(stream);
	gsocket_free(stream);

	gsocket_close(sock);
	gsocket_free(sock);
	SSL_CTX_free(ssl_ctx);

	running = false;
	s.join();
	cleanup_test_www_dir(root);
}

// ALPN Callback for H3
static int h3_alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                          const unsigned char *in, unsigned int inlen, void *arg)
{
    static const unsigned char server_protos[] = {
        2, 'h', '3'
    };

    if (SSL_select_next_proto((unsigned char **)out, outlen, server_protos, sizeof(server_protos), in, inlen) != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    return SSL_TLSEXT_ERR_OK;
}

// HTTP3 File Server Thread
void gsocket_http3_file_server_thread(int port, const char *root, ServerSync *sync, std::atomic<bool> &running)
{
	SSL_CTX *ssl_ctx = SSL_CTX_new(OSSL_QUIC_server_method());
	
	// Use correct HTTP3 ALPN setup
	char key[PATH_MAX];
	char cert[PATH_MAX];
	smartdns_get_cert(key, cert);
	SSL_CTX_use_PrivateKey_file(ssl_ctx, key, SSL_FILETYPE_PEM);
	SSL_CTX_use_certificate_file(ssl_ctx, cert, SSL_FILETYPE_PEM);
	
	// For HTTP3, use callback for server selection
	SSL_CTX_set_alpn_select_cb(ssl_ctx, h3_alpn_select_cb, NULL);
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);

	gsocket_generic_server_thread_with_config(port, SOCK_DGRAM, sync, running,
		[ssl_ctx](struct gsocket *l) {
			gsocket_push_layer(l, gsocket_io_ssl_quic_new(ssl_ctx, 1));
			gsocket_push_layer(l, gsocket_io_http3_new(1));  // Re-enable HTTP3
		},
		handle_file_request, (void *)root);
	SSL_CTX_free(ssl_ctx);
}

TEST_F(GSocketHTTPTest, HTTP3FileServer)
{
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
	ServerSync sync;
	std::atomic<bool> running(true);
	std::string root = "/home/rock/code/smartdns/.vscode/www/";  // 32KB file
	ASSERT_FALSE(root.empty());
	// Use 0 to pick random port
	std::thread s(gsocket_http3_file_server_thread, 0, root.c_str(), &sync, std::ref(running));
	sync.wait();
	int port = sync.port;
	ASSERT_GT(port, 0);
	printf("HTTP3 File Server running on port %d\n", port);
    
	std::string cmd = "curl --connect-timeout 2 -k -v --http3 https://127.0.0.1:";
	cmd += std::to_string(port);
	cmd += "/index.html";
	printf("curl command: %s\n", cmd.c_str());
	int ret = system(cmd.c_str());
	ASSERT_EQ(ret, 0);

	running = false;
	s.join();
	cleanup_test_www_dir(root);
#else
	GTEST_SKIP() << "QUIC not supported";
#endif
}
/*************************************************************************
 *
 * Copyright (C) 2018-2026 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

/* ALPN Negotiation Test Cases - Appended to test_gsocket_http.cc */

// Server thread for ALPN negotiation tests - supports both h2 and http/1.1
void gsocket_alpn_http2_server_thread(int port, const char *root, ServerSync *sync, std::atomic<bool> &running)
{
	SSL_CTX *ssl_ctx = init_ssl_ctx(true);
	const char *protos = "h2,http/1.1";  // Server supports both protocols
	
	gsocket_generic_server_thread_with_config(port, SOCK_STREAM, sync, running,
		[ssl_ctx, protos](struct gsocket *l) {
			gsocket_push_layer(l, gsocket_io_ssl_new(ssl_ctx, 1));
			gsocket_push_layer(l, gsocket_io_http2_new(1));  // HTTP/2 layer with auto-fallback
			gsocket_setsockopt(l, SOL_SSL, SO_SSL_ALPN, protos, strlen(protos));
		},
		handle_file_request, (void *)root);
	SSL_CTX_free(ssl_ctx);
}

TEST_F(GSocketHTTPTest, ALPN_HTTP2_Negotiation)
{
	ServerSync sync;
	std::atomic<bool> running(true);
	std::string root = setup_test_www_dir(5000);  // 5KB file
	ASSERT_FALSE(root.empty());
	
	std::thread s(gsocket_alpn_http2_server_thread, 0, root.c_str(), &sync, std::ref(running));
	sync.wait();
	int port = sync.port;
	ASSERT_GT(port, 0);
	
	// Client requests h2 protocol
	struct gsocket *sock = gsocket_new(socket(AF_INET, SOCK_STREAM, 0));
	SSL_CTX *ssl_ctx = init_ssl_ctx(false);
	const char *client_protos = "h2";  // Client prefers h2
	
	gsocket_push_layer(sock, gsocket_io_ssl_new(ssl_ctx, 0));
	gsocket_push_layer(sock, gsocket_io_http2_new(0));
	gsocket_setsockopt(sock, SOL_SSL, SO_SSL_ALPN, client_protos, strlen(client_protos));
	
	gsocket_set_nonblock(sock, 1);
	int cr = gsocket_connect(sock, "127.0.0.1", port);
	if (cr < 0 && errno == EINPROGRESS) {
		struct pollfd pfd = {gsocket_get_fd(sock), POLLOUT, 0};
		poll(&pfd, 1, 1000);
	}
	
	// Drive handshake
	int hr;
	int retry = 0;
	while ((hr = gsocket_handshake(sock)) != GSOCKET_HANDSHAKE_DONE && retry++ < 1000) {
		if (hr == GSOCKET_HANDSHAKE_ERR) {
			break;
		}
		usleep(1000);
	}
	ASSERT_EQ(hr, GSOCKET_HANDSHAKE_DONE);
	
	// Verify ALPN negotiated to h2
	char negotiated_alpn[32] = {0};
	socklen_t alpn_len = sizeof(negotiated_alpn) - 1;
	gsocket_getsockopt(sock, SOL_SSL, SO_SSL_ALPN, negotiated_alpn, &alpn_len);
	ASSERT_STREQ(negotiated_alpn, "h2");
	
	// Send HTTP/2 request
	struct gsocket *stream = gsocket_open_stream(sock);
	ASSERT_NE(stream, nullptr);
	gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_METHOD, "GET", 4);
	gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_URL, "/", 1);
	gsocket_send(stream, NULL, 0, MSG_NOSIGNAL | GS_MSG_FIN);
	
	// Receive response
	char buf[8192];
	int total = 0;
	while (total < (int)sizeof(buf) - 1) {
		int n = gsocket_recv(stream, buf + total, sizeof(buf) - 1 - total, 0);
		if (n <= 0) break;
		total += n;
	}
	ASSERT_GT(total, 0);
	buf[total] = 0;
	
	// Verify response contains expected content
	ASSERT_TRUE(strstr(buf, "SmartDNS Test Server") != NULL);
	
	gsocket_close(stream);
	gsocket_free(stream);
	gsocket_close(sock);
	gsocket_free(sock);
	SSL_CTX_free(ssl_ctx);
	
	running = false;
	s.join();
	cleanup_test_www_dir(root);
}

TEST_F(GSocketHTTPTest, ALPN_HTTP1_Fallback)
{
	ServerSync sync;
	std::atomic<bool> running(true);
	std::string root = setup_test_www_dir(5000);  // 5KB file
	ASSERT_FALSE(root.empty());
	
	// IDENTICAL server code as ALPN_HTTP2_Negotiation test
	std::thread s(gsocket_alpn_http2_server_thread, 0, root.c_str(), &sync, std::ref(running));
	sync.wait();
	int port = sync.port;
	ASSERT_GT(port, 0);
	
	// Client requests http/1.1 protocol
	struct gsocket *sock = gsocket_new(socket(AF_INET, SOCK_STREAM, 0));
	SSL_CTX *ssl_ctx = init_ssl_ctx(false);
	const char *client_protos = "http/1.1";  // Client prefers http/1.1
	
	gsocket_push_layer(sock, gsocket_io_ssl_new(ssl_ctx, 0));
	gsocket_push_layer(sock, gsocket_io_http2_new(0));  // Same HTTP/2 layer, will fallback internally
	gsocket_setsockopt(sock, SOL_SSL, SO_SSL_ALPN, client_protos, strlen(client_protos));
	
	gsocket_set_nonblock(sock, 1);
	int cr = gsocket_connect(sock, "127.0.0.1", port);
	if (cr < 0 && errno == EINPROGRESS) {
		struct pollfd pfd = {gsocket_get_fd(sock), POLLOUT, 0};
		poll(&pfd, 1, 1000);
	}
	
	// Drive handshake
	int hr;
	int retry = 0;
	while ((hr = gsocket_handshake(sock)) != GSOCKET_HANDSHAKE_DONE && retry++ < 1000) {
		if (hr == GSOCKET_HANDSHAKE_ERR) {
			break;
		}
		usleep(1000);
	}
	ASSERT_EQ(hr, GSOCKET_HANDSHAKE_DONE);
	
	// Verify ALPN negotiated to http/1.1
	char negotiated_alpn[32] = {0};
	socklen_t alpn_len = sizeof(negotiated_alpn) - 1;
	gsocket_getsockopt(sock, SOL_SSL, SO_SSL_ALPN, negotiated_alpn, &alpn_len);
	ASSERT_STREQ(negotiated_alpn, "http/1.1");
	
	// Send request using same HTTP/2 API (will use HTTP/1.1 internally)
	struct gsocket *stream = gsocket_open_stream(sock);
	ASSERT_NE(stream, nullptr);
	gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_METHOD, "GET", 4);
	gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_URL, "/", 1);
	gsocket_send(stream, NULL, 0, MSG_NOSIGNAL);
	
	// Receive response
	char buf[8192];
	int total = 0;
	int loop = 0;
	while (total < (int)sizeof(buf) - 1 && loop++ < 1000) {
		int n = gsocket_recv(stream, buf + total, sizeof(buf) - 1 - total, 0);
		if (n > 0) {
			total += n;
		} else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			usleep(1000);
			continue;
		} else if (n == 0) {
			break;
		} else {
			break;
		}
	}
	ASSERT_GT(total, 0);
	buf[total] = 0;
	
	// Verify response contains expected content
	ASSERT_TRUE(strstr(buf, "SmartDNS Test Server") != NULL);
	
	gsocket_close(stream);
	gsocket_free(stream);
	gsocket_close(sock);
	gsocket_free(sock);
	SSL_CTX_free(ssl_ctx);
	
	running = false;
	s.join();
	cleanup_test_www_dir(root);
}
