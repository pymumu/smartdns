#include "gtest/gtest.h"
extern "C" {
#include "smartdns/dns.h"
#include "smartdns/http_parse.h"
#include "smartdns/util.h"
}
#undef min
#undef max
#include "client.h"
#include "server.h"
#include "include/utils.h"
#include <atomic>
#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <functional>
#include <poll.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC) && OPENSSL_VERSION_NUMBER >= 0x30500000L
namespace {
bool WaitFor(const std::function<bool()> &ready, int milliseconds = 3000)
{
    auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
    do { if (ready()) return true; poll(nullptr, 0, 1); }
    while (std::chrono::steady_clock::now() < end);
    return ready();
}

/* A real, loopback-only DNS peer. H3 waits for the mandatory client SETTINGS;
 * DoQ can hold FIN after delivering a complete, valid DNS answer. */
class QuicDnsPeer {
public:
    ~QuicDnsPeer() {
        run = false;
        if (worker.joinable()) worker.join();
        for (auto &stream : streams) SSL_free(stream.ssl);
        SSL_free(control); SSL_free(connection); SSL_free(listener);
        SSL_CTX_free(context);
        if (fd >= 0) close(fd);
    }
    bool Start(bool http3, bool hold_fin = false) {
        h3 = http3; allow_fin = !hold_fin;
        if (!cert.Write("") || !key.Write("") ||
            generate_cert_key(key.GetPath().c_str(), cert.GetPath().c_str(), nullptr, "IP:127.0.0.1", 1)) return false;
        context = SSL_CTX_new(OSSL_QUIC_server_method());
        if (!context || SSL_CTX_use_certificate_file(context, cert.GetPath().c_str(), SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_use_PrivateKey_file(context, key.GetPath().c_str(), SSL_FILETYPE_PEM) != 1) return false;
        SSL_CTX_set_alpn_select_cb(context, [](SSL *, const unsigned char **out, unsigned char *length,
            const unsigned char *in, unsigned n, void *arg) {
            auto *self = static_cast<QuicDnsPeer *>(arg);
            static const unsigned char h3[] = {2, 'h', '3'}, doq[] = {3, 'd', 'o', 'q'};
            return SSL_select_next_proto(const_cast<unsigned char **>(out), length,
                self->h3 ? h3 : doq, self->h3 ? sizeof(h3) : sizeof(doq), in, n) == OPENSSL_NPN_NEGOTIATED
                ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_ALERT_FATAL;
        }, this);
        fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (fd < 0 || bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address))) return false;
        socklen_t size = sizeof(address);
        if (getsockname(fd, reinterpret_cast<sockaddr *>(&address), &size)) return false;
        port = ntohs(address.sin_port);
        listener = SSL_new_listener(context, 0);
        if (!listener || SSL_set_fd(listener, fd) != 1 || SSL_set_blocking_mode(listener, 0) != 1 ||
            SSL_listen(listener) != 1) return false;
        run = true;
        return true;
    }
    void StartWorker() { worker = std::thread([this] { Run(); }); }
    std::string Configuration() const {
        return "bind 127.0.0.1:60053\ncache-size 0\nspeed-check-mode none\ndualstack-ip-selection no\n" +
            std::string(h3 ? "server-http3 https://127.0.0.1:" : "server-quic quic://127.0.0.1:") +
            std::to_string(port) + (h3 ? "/dns-query" : "") + " -no-check-certificate\n";
    }
    std::atomic<bool> body_sent{false}, allow_fin{true}, settings_seen{false};
    std::atomic<int> answers{0};
private:
    struct Stream {
        SSL *ssl;
        std::vector<unsigned char> input, output;
        size_t sent = 0;
        bool finished = false;
    };
    bool MakeAnswer(const unsigned char *data, size_t length, std::vector<unsigned char> &answer) {
        unsigned char input[DNS_PACKSIZE], output[DNS_PACKSIZE], wire[DNS_PACKSIZE];
        auto *query = reinterpret_cast<dns_packet *>(input), *response = reinterpret_cast<dns_packet *>(output);
        if (dns_decode(query, sizeof(input), const_cast<unsigned char *>(data), length)) return false;
        int count = 0, type = 0, klass = 0;
        auto *question = dns_get_rrs_start(query, DNS_RRS_QD, &count);
        char name[DNS_MAX_CNAME_LEN]{};
        if (!question || count != 1 || dns_get_domain(question, name, sizeof(name), &type, &klass)) return false;
        dns_head header{}; header.id = query->head.id; header.qr = DNS_QR_ANSWER;
        header.rd = query->head.rd; header.ra = 1;
        unsigned char ip[] = {192, 0, 2, 19};
        if (dns_packet_init(response, sizeof(output), &header) || dns_add_domain(response, name, type, klass) ||
            dns_add_A(response, DNS_RRS_AN, name, 600, ip)) return false;
        int n = dns_encode(wire, sizeof(wire), response);
        if (n <= 0) return false;
        answer.assign(wire, wire + n);
        return true;
    }
    void Service(Stream &stream) {
        unsigned char bytes[4096]; size_t got = 0;
        if (SSL_read_ex(stream.ssl, bytes, sizeof(bytes), &got) == 1 && got)
            stream.input.insert(stream.input.end(), bytes, bytes + got);
        if (stream.input.size() > 8192) { run = false; return; }
        if (h3 && (SSL_get_stream_id(stream.ssl) & 3) == 2) {
            const unsigned char settings[] = {0, 4, 4, 1, 0, 7, 0};
            if (stream.input.size() >= sizeof(settings) &&
                memcmp(stream.input.data(), settings, sizeof(settings)) == 0) settings_seen = true;
            return;
        }
        if (h3 && !settings_seen.load()) return;
        if (stream.output.empty()) {
            std::vector<unsigned char> answer;
            if (h3) {
                http_head *request = http_head_init(8192, HTTP_VERSION_3_0);
                int parsed = http_head_parse(request, stream.input.data(), stream.input.size());
                bool ready = parsed >= 0 && http_head_get_data_len(request) > 0;
                if (ready) ready = MakeAnswer(static_cast<const unsigned char *>(http_head_get_data(request)),
                    http_head_get_data_len(request), answer);
                http_head_destroy(request);
                if (!ready) return;
                http_head *response = http_head_init(8192, HTTP_VERSION_3_0);
                http_head_set_head_type(response, HTTP_HEAD_RESPONSE);
                http_head_set_httpcode(response, 200, "OK");
                http_head_add_fields(response, "content-type", "application/dns-message");
                http_head_set_data(response, answer.data(), answer.size());
                unsigned char wire[8192];
                int n = http_head_serialize(response, wire, sizeof(wire));
                http_head_destroy(response);
                if (n <= 0) return;
                stream.output.assign(wire, wire + n);
            } else {
                if (stream.input.size() < 2) return;
                size_t n = (stream.input[0] << 8) | stream.input[1];
                if (stream.input.size() < n + 2 || !MakeAnswer(stream.input.data() + 2, n, answer)) return;
                stream.output = {static_cast<unsigned char>(answer.size() >> 8), static_cast<unsigned char>(answer.size())};
                stream.output.insert(stream.output.end(), answer.begin(), answer.end());
            }
        }
        if (stream.sent < stream.output.size()) {
            size_t sent = 0;
            SSL_write_ex(stream.ssl, stream.output.data() + stream.sent, stream.output.size() - stream.sent, &sent);
            stream.sent += sent;
        }
        if (stream.sent == stream.output.size()) {
            body_sent = true;
            if (allow_fin.load() && SSL_stream_conclude(stream.ssl, 0) == 1) {
                stream.finished = true;
                answers++;
            }
        }
    }
    void Run() {
        while (run.load()) {
            SSL_handle_events(listener);
            if (!connection) {
                connection = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
                if (connection) {
                    SSL_set_blocking_mode(connection, 0);
                    SSL_set_default_stream_mode(connection, SSL_DEFAULT_STREAM_MODE_NONE);
                    SSL_set_incoming_stream_policy(connection, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0);
                }
            }
            if (connection) {
                SSL_do_handshake(connection); SSL_handle_events(connection);
                if (SSL_is_init_finished(connection)) {
                    if (h3 && !control) {
                        control = SSL_new_stream(connection, SSL_STREAM_FLAG_UNI);
                        const unsigned char settings[] = {0, 4, 0}; size_t sent = 0;
                        if (control) SSL_write_ex(control, settings, sizeof(settings), &sent);
                    }
                    for (SSL *s; (s = SSL_accept_stream(connection, SSL_ACCEPT_STREAM_NO_BLOCK));)
                        streams.push_back({s});
                    for (auto &stream : streams) if (!stream.finished) Service(stream);
                }
            }
            poll(nullptr, 0, 1);
        }
    }
    bool h3 = false;
    int fd = -1, port = 0;
    SSL_CTX *context = nullptr;
    SSL *listener = nullptr, *connection = nullptr, *control = nullptr;
    std::vector<Stream> streams;
    smartdns::TempFile cert, key;
    std::atomic<bool> run{false};
    std::thread worker;
};
}

TEST(QuicEndToEnd, HttpsHttp3QueryRequiresClientSettingsAndReusesTheConnection)
{
    QuicDnsPeer upstream;
    ASSERT_TRUE(upstream.Start(true));
    smartdns::Server server;
    ASSERT_TRUE(server.Start(upstream.Configuration()));
    upstream.StartWorker(); // Fork the resolver before the peer runs OpenSSL calls.
    for (const char *name : {"first.h3.test", "second.h3.test"}) {
        smartdns::Client client;
        ASSERT_TRUE(client.Query(std::string(name) + " +time=3 +tries=1", 60053));
        EXPECT_EQ(client.GetStatus(), "NOERROR");
        ASSERT_EQ(client.GetAnswerNum(), 1);
        EXPECT_EQ(client.GetAnswer()[0].GetData(), "192.0.2.19");
    }
    EXPECT_TRUE(upstream.settings_seen.load());
    EXPECT_EQ(upstream.answers.load(), 2);
}

TEST(QuicEndToEnd, ValidDoqAnswerIsNotDeliveredUntilFin)
{
    QuicDnsPeer upstream;
    ASSERT_TRUE(upstream.Start(false, true));
    smartdns::Server server;
    ASSERT_TRUE(server.Start(upstream.Configuration()));
    upstream.StartWorker();
    smartdns::Client client;
    std::atomic<bool> done{false}; bool queried = false;
    std::thread query([&] { queried = client.Query("fin.doq.test +time=3 +tries=1", 60053); done = true; });
    Defer { upstream.allow_fin = true; if (query.joinable()) query.join(); };
    ASSERT_TRUE(WaitFor([&] { return upstream.body_sent.load(); }));
    EXPECT_FALSE(WaitFor([&] { return done.load(); }, 500));
    upstream.allow_fin = true;
    query.join();
    ASSERT_TRUE(queried);
    EXPECT_EQ(client.GetStatus(), "NOERROR");
    ASSERT_EQ(client.GetAnswerNum(), 1);
    EXPECT_EQ(client.GetAnswer()[0].GetData(), "192.0.2.19");
}
#endif
