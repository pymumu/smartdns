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

use reqwest;
use serde_json::json;
use smartdns_ui::{http_api_msg, http_jwt::JwtClaims, smartdns::LogLevel};

#[tokio::test]
async fn test_rest_api_login() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let c = reqwest::Client::new();
    let body = json!({
        "user": "admin",
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

#[tokio::test]
async fn test_rest_api_login_incorrect() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let c = reqwest::Client::new();
    let body = json!({
        "user": "admin",
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

    let record = server.new_mock_domain_record();
    for i in 0..1024 {
        let mut record = record.clone();
        record.domain = format!("{}.com", i);
        assert!(server.add_domain_record(&record).is_ok());
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

    let record = server.new_mock_domain_record();
    for i in 0..1024 {
        let mut record = record.clone();
        record.domain = format!("{}.com", i);
        assert!(server.add_domain_record(&record).is_ok());
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

    let record = server.new_mock_domain_record();
    for i in 0..1024 {
        let mut record = record.clone();
        record.domain = format!("{}.com", i);
        assert!(server.add_domain_record(&record).is_ok());
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
    server.enable_mock_server();
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
    assert_eq!(version.1, env!("CARGO_PKG_VERSION"));
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
    assert_eq!(version.1, env!("CARGO_PKG_VERSION"));
}

