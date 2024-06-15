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

use smartdns_ui::smartdns::LogLevel;
use std::{fs::File, io::Write};

#[test]
fn test_http_server_indexhtml() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());
    let www_root = server.get_www_root();

    let mut index_html_file = File::create(www_root.clone() + "/index.html").unwrap();
    let content = "Hello, world!";
    index_html_file.write_all(content.as_bytes()).unwrap();

    let client = common::TestClient::new(&server.get_host());
    let c = client.get("/");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    assert_eq!(body, content);
}

#[test]
fn test_http_server_somehtml() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());
    let www_root = server.get_www_root();

    let mut index_html_file = File::create(www_root.clone() + "/index.html").unwrap();
    let content = "Hello, world!";
    index_html_file.write_all(content.as_bytes()).unwrap();

    let mut some_html_file = File::create(www_root.clone() + "/some.html").unwrap();
    let some_content = "Some index file!";
    some_html_file.write_all(some_content.as_bytes()).unwrap();

    let client = common::TestClient::new(&server.get_host());
    let c = client.get("/some.html");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    assert_eq!(body, some_content);
}

#[test]
fn test_http_server_redirect_indexhtml() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());
    let www_root = server.get_www_root();

    let mut index_html_file = File::create(www_root.clone() + "/index.html").unwrap();
    let content = "Hello, world!";
    index_html_file.write_all(content.as_bytes()).unwrap();

    let client = common::TestClient::new(&server.get_host());
    let c = client.get("/some.html");
    assert!(c.is_ok());
    let (code, body) = c.unwrap();
    assert_eq!(code, 200);
    assert_eq!(body, content);
}

#[test]
fn test_http_server_404() {
    let mut server = common::TestServer::new();
    server.set_log_level(LogLevel::DEBUG);
    assert!(server.start().is_ok());

    let client = common::TestClient::new(&server.get_host());
    let c = client.get("/index.html");
    assert!(c.is_ok());
    let (code, _) = c.unwrap();
    assert_eq!(code, 404);
}
