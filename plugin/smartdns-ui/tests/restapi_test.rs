/*************************************************************************
 *
 * Copyright (C) 2018-2024 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

mod common;

use common::TestDnsRequest;
use nix::libc::c_char;
use reqwest;
use serde_json::json;
use smartdns_ui::{http_api_msg, http_jwt::JwtClaims, smartdns::LogLevel};
use std::ffi::CString;

#[tokio::test(flavor = "multi_thread")]
async fn test_rest_api_login() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let c = reqwest::Client::new();
    let body = json!({
        "username": "admin",
        "password": "password",
    });

    let res = c
        .post(server.get_url("/api/auth/login"))
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    let code = res.status();
    let body = res.text().await.unwrap();
    println!("res: {}", body);
    assert_eq!(code, 200);

    let result = http_api_msg::api_msg_parse_auth_token(&body);
    assert!(result.is_ok());
    let token = result.unwrap();
    assert!(!token.token.is_empty());
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.insecure_disable_signature_validation();
    let calims = jsonwebtoken::decode::<JwtClaims>(
        &token.token,
        &jsonwebtoken::DecodingKey::from_secret(&[]),
        &validation,
    );
    println!("calims: {:?}", calims);
    assert_eq!(token.expires_in, "600");
    assert!(calims.is_ok());
    let calims = calims.unwrap();
    let calims = calims.claims;
    assert_eq!(calims.user, "admin");
}

#[test]
fn test_rest_api_logout() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());
    client.set_with_auth_header(false);
    let res = client.login("admin", "password");
    assert!(res.is_ok());

    let c = client.get("/api/cache/count");
    assert!(c.is_ok());
    let (code, _) = c.unwrap();
    assert_eq!(code, 200);

    let ret = client.logout();
    assert!(ret.is_ok());

    let c = client.get("/api/cache/count");
    assert!(c.is_ok());
    let (code, _) = c.unwrap();
    assert_eq!(code, 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_rest_api_login_incorrect() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let c = reqwest::Client::new();
    let body = json!({
        "username": "admin",
        "password": "wrongpassword",
    });

    let res = c
        .post(server.get_url("/api/auth/login"))
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    let code = res.status();
    let body = res.text().await.unwrap();
    println!("res: {}", body);
    assert_eq!(code, 401);

    let result = http_api_msg::api_msg_parse_error(&body);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "Incorrect username or password.");
}

#[test]
fn test_rest_api_change_password() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());
    let password_msg =
        http_api_msg::api_msg_gen_auth_password_change("wrong_oldpassword", "newpassword");
    let c = client.put("/api/auth/password", password_msg.as_str());
    assert!(c.is_ok());
    let (code, _) = c.unwrap();
    assert_eq!(code, 403);

    let password_msg = http_api_msg::api_msg_gen_auth_password_change("password", "newpassword");
    let c = client.put("/api/auth/password", password_msg.as_str());
    assert!(c.is_ok());
    let (code, _) = c.unwrap();
    assert_eq!(code, 204);

    let res = client.login("admin", "password");
    assert!(!res.is_ok());
}

#[test]
fn test_rest_api_cache_count() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());
    let c = client.get("/api/cache/count");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let count = http_api_msg::api_msg_parse_cache_number(&body);
    assert!(count.is_ok());
    assert_eq!(count.unwrap(), 0);
}

#[test]
fn test_rest_api_auth_refresh() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());
    let c = client.post("/api/auth/refresh", "");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let token = http_api_msg::api_msg_parse_auth_token(&body);
    assert!(token.is_ok());
    let token = token.unwrap();
    assert!(!token.token.is_empty());
    assert_eq!(token.expires_in, "600");
    println!("token: {:?}", token);
}

#[test]
fn test_rest_api_auth_check() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());
    let c = client.get("/api/auth/check");
    assert!(c.is_ok());
    let (code, _) = c.unwrap();
    assert_eq!(code, 401);

    let res = client.login("admin", "password");
    assert!(res.is_ok());
    let c = client.get("/api/auth/check");
    assert!(c.is_ok());
    let (code, _) = c.unwrap();
    assert_eq!(code, 200);
}

#[test]
fn test_rest_api_no_permission() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let client = common::TestClient::new(&server.get_host());
    let c = client.get("/api/cache/count");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 401);
    println!("body: {}", body);
    let error_msg = http_api_msg::api_msg_parse_error(&body);
    assert!(error_msg.is_ok());
    assert_eq!(error_msg.unwrap(), "Please login.");
}

#[test]
fn test_rest_api_404() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());
    let c = client.post("/api/404", "");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 404);
    let error_msg = http_api_msg::api_msg_parse_error(&body);
    assert!(error_msg.is_ok());
    assert_eq!(error_msg.unwrap(), "API not found.");
}

#[test]
fn test_rest_api_log_stream() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());
    let socket = client.websocket("/api/log/stream");
    assert!(socket.is_ok());
    let mut socket = socket.unwrap();

    _ = socket.send(tungstenite::Message::Text("aaaa".to_string()));
    _ = socket.close(None);
}

#[test]
fn test_rest_api_log_level() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    server.set_one_instance(true);
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());

    let c = client.get("/api/log/level");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let log_level = http_api_msg::api_msg_parse_loglevel(&body);
    assert!(log_level.is_ok());
    assert_eq!(log_level.unwrap(), LogLevel::DEBUG);

    let level_msg = http_api_msg::api_msg_gen_loglevel(LogLevel::ERROR);
    let c = client.put("/api/log/level", level_msg.as_str());
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 204);
    println!("body: {}", body);

    assert_eq!(smartdns_ui::smartdns::dns_log_get_level(), LogLevel::ERROR);
}

#[test]
fn test_rest_api_get_domain() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    for i in 0..1024 {
        let mut request = TestDnsRequest::new();
        request.domain = format!("{}.com", i);
        request.id = i as u16;
        assert!(server.send_test_dnsrequest(request).is_ok());
    }

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());

    let c = client.get("/api/domain/count");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let count = http_api_msg::api_msg_parse_count(&body);
    assert!(count.is_ok());
    assert_eq!(count.unwrap(), 1024);

    let c = client.get("/api/domain?page_num=11&page_size=10&order=asc");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let result = http_api_msg::api_msg_parse_domain_list(&body);
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.len(), 10);
    assert_eq!(result[0].id, 101);
    assert_eq!(result[0].domain, "100.com");
}

#[test]
fn test_rest_api_get_by_id() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    for i in 0..1024 {
        let mut request = TestDnsRequest::new();
        request.domain = format!("{}.com", i);
        request.id = i as u16;
        assert!(server.send_test_dnsrequest(request).is_ok());
    }

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());

    let c = client.get("/api/domain/1000");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let result = http_api_msg::api_msg_parse_domain(&body);
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.id, 1000);
    assert_eq!(result.domain, "999.com");
}

#[test]
fn test_rest_api_delete_domain_by_id() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    for i in 0..1024 {
        let mut request = TestDnsRequest::new();
        request.domain = format!("{}.com", i);
        request.id = i as u16;
        assert!(server.send_test_dnsrequest(request).is_ok());
    }

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());

    let c = client.delete("/api/domain/1000");
    assert!(c.is_ok());
    let (code, _) = c.unwrap();
    assert_eq!(code, 204);

    let c = client.get("/api/domain/1000");
    assert!(c.is_ok());
    let (code, _) = c.unwrap();
    assert_eq!(code, 404);

    let c = client.get("/api/domain/count");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let count = http_api_msg::api_msg_parse_count(&body);
    assert!(count.is_ok());
    assert_eq!(count.unwrap(), 1023);
}

#[test]
fn test_rest_api_server_version() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let client = common::TestClient::new(&server.get_host());

    let c = client.get("/api/server/version");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let version = http_api_msg::api_msg_parse_version(&body);
    assert!(version.is_ok());
    let version = version.unwrap();
    assert_eq!(version.0, smartdns_ui::smartdns::smartdns_version());
    if env!("GIT_VERSION").is_empty() {
        assert_eq!(version.1, env!("CARGO_PKG_VERSION"));
        return;
    }
    let check_version = std::format!("{} ({})", env!("CARGO_PKG_VERSION"), env!("GIT_VERSION"));
    assert_eq!(version.1, check_version);
}

#[test]
fn test_rest_api_https_server() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    server.enable_mock_server();
    server.set_https(true);
    assert!(server.start().is_ok());

    let client = common::TestClient::new(&server.get_host());

    let c = client.get("/api/server/version");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let version = http_api_msg::api_msg_parse_version(&body);
    assert!(version.is_ok());
    let version = version.unwrap();
    assert_eq!(version.0, smartdns_ui::smartdns::smartdns_version());
    if env!("GIT_VERSION").is_empty() {
        assert_eq!(version.1, env!("CARGO_PKG_VERSION"));
        return;
    }
    let check_version = std::format!("{} ({})", env!("CARGO_PKG_VERSION"), env!("GIT_VERSION"));
    assert_eq!(version.1, check_version);
}

#[test]
fn test_rest_api_settings() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());

    let res = client.login("admin", "password");
    assert!(res.is_ok());

    let c = client.get("/api/config/settings");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let settings = http_api_msg::api_msg_parse_key_value(&body);
    assert!(settings.is_ok());

    let mut settings = std::collections::HashMap::new();
    settings.insert("key1".to_string(), "value1".to_string());
    settings.insert("key2".to_string(), "value2".to_string());
    let body = http_api_msg::api_msg_gen_key_value(&settings);
    let c = client.put("/api/config/settings", body.as_str());
    assert!(c.is_ok());
    let (code, _) = c.unwrap();
    assert_eq!(code, 204);

    let c = client.get("/api/config/settings");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let settings = http_api_msg::api_msg_parse_key_value(&body);
    assert!(settings.is_ok());
    let settings = settings.unwrap();
    assert_eq!(settings.len(), 7);
    assert_eq!(settings["key1"], "value1");
}

#[test]
fn test_rest_api_get_client() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::INFO);
    assert!(server.start().is_ok());

    for i in 0..1024 {
        let mut request = TestDnsRequest::new();
        request.domain = format!("{}.com", i);
        request.remote_addr = format!("client-{}", i);
        request.id = i as u16;
        assert!(server.send_test_dnsrequest(request).is_ok());
    }

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());

    let c = client.get("/api/client");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let list = http_api_msg::api_msg_parse_client_list(&body);
    assert!(list.is_ok());
    let list = list.unwrap();
    assert_eq!(list.len(), 1024);
}

#[test]
fn test_rest_api_stats_top() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    for i in 0..1024 {
        let mut request = TestDnsRequest::new();
        if i < 512 {
            request.domain = format!("a.com");
            request.remote_addr = format!("192.168.1.1");
        } else if i < 512 + 256 + 128 {
            request.domain = format!("b.com");
            request.remote_addr = format!("192.168.1.2");
        } else {
            request.domain = format!("c.com");
            request.remote_addr = format!("192.168.1.3");
        }
        assert!(server.send_test_dnsrequest(request).is_ok());
    }

    server.get_data_server().get_stat().refresh();

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());

    let c = client.get("/api/stats/top/client");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let list = http_api_msg::api_msg_parse_top_client_list(&body);
    assert!(list.is_ok());
    let list = list.unwrap();
    assert_eq!(list.len(), 3);
    assert_eq!(list[0].client_ip, "192.168.1.1");
    assert_eq!(list[0].count, 512);
    assert_eq!(list[2].client_ip, "192.168.1.3");
    assert_eq!(list[2].count, 128);

    let c = client.get("/api/stats/top/domain");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let list = http_api_msg::api_msg_parse_top_domain_list(&body);
    assert!(list.is_ok());
    let list = list.unwrap();
    assert_eq!(list.len(), 3);
    assert_eq!(list[0].domain, "a.com");
    assert_eq!(list[0].count, 512);
    assert_eq!(list[2].domain, "c.com");
    assert_eq!(list[2].count, 128);
}

#[test]
fn test_rest_api_stats_overview() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    server.enable_mock_server();
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());
    let server_name;

    unsafe {
        smartdns_ui::smartdns::smartdns_c::dns_stats
            .avg_time
            .avg_time = 22.0 as f32;
        smartdns_ui::smartdns::smartdns_c::dns_stats
            .request
            .blocked_count = 10;
        smartdns_ui::smartdns::smartdns_c::dns_stats.request.total = 15;

        server_name = smartdns_ui::smartdns::smartdns_get_server_name();
    }

    let c = client.get("/api/stats/overview");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let overview = http_api_msg::api_msg_parse_stats_overview(&body);
    assert!(overview.is_ok());
    let overview = overview.unwrap();
    assert_eq!(overview.db_size > 0, true);
    assert_eq!(overview.server_name, server_name);
}

#[test]
fn test_rest_api_stats_metrics() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    server.enable_mock_server();
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());

    unsafe {
        smartdns_ui::smartdns::smartdns_c::dns_stats
            .avg_time
            .avg_time = 22.0 as f32;
        smartdns_ui::smartdns::smartdns_c::dns_stats
            .request
            .blocked_count = 10;
        smartdns_ui::smartdns::smartdns_c::dns_stats.request.total = 15;
    }

    for i in 0..1024 {
        let mut request = TestDnsRequest::new();
        request.domain = format!("{}.com", i);
        request.remote_addr = format!("client-{}", i);
        request.is_blocked = i % 2 == 0;
        assert!(server.send_test_dnsrequest(request).is_ok());
    }

    let c = client.get("/api/stats/metrics");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let metrics = http_api_msg::api_msg_parse_metrics_data(&body);
    assert!(metrics.is_ok());
    let metrics = metrics.unwrap();
    assert_eq!(metrics.avg_query_time, 22.0 as f64);
    assert_eq!(metrics.cache_hit_rate, 0 as f64);
    assert_eq!(metrics.total_query_count, 1024);
    assert_eq!(metrics.block_query_count, 1024 / 2);
}

#[test]
fn test_rest_api_get_hourly_query_count() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    for i in 0..1024 {
        let mut request = TestDnsRequest::new();
        request.domain = format!("{}.com", i);
        request.remote_addr = format!("client-{}", i);
        assert!(server.send_test_dnsrequest(request).is_ok());
    }

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());

    let c = client.get("/api/stats/hourly-query-count");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let list = http_api_msg::api_msg_parse_hourly_query_count(&body);
    assert!(list.is_ok());
    let list = list.unwrap();
    assert_eq!(list.hourly_query_count.len(), 1);
    assert_eq!(list.hourly_query_count[0].query_count, 1024);
}

#[test]
fn test_rest_api_server_status() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    server.enable_mock_server();
    assert!(server.start().is_ok());

    let mut client = common::TestClient::new(&server.get_host());
    let res = client.login("admin", "password");
    assert!(res.is_ok());

    unsafe {
        let server_type = smartdns_ui::smartdns::smartdns_c::dns_server_type_t_DNS_SERVER_UDP;
        let mut flags: smartdns_ui::smartdns::smartdns_c::client_dns_server_flags =
            std::mem::zeroed();
        let ip = CString::new("1.2.3.4").expect("CString::new failed");
        let port = 3353;
        smartdns_ui::smartdns::smartdns_c::dns_client_add_server(
            ip.as_ptr() as *const c_char,
            port,
            server_type,
            &mut flags,
        );
    }

    let c = client.get("/api/upstream-server");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    let server_list = http_api_msg::api_msg_parse_upstream_server_list(&body);
    assert!(server_list.is_ok());
    let server_list = server_list.unwrap();
    assert!(server_list.len() > 0);
    let exists = server_list.iter().any(|server| server.ip == "1.2.3.4");
    assert!(exists);
}
