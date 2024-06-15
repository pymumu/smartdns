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

use http::uri;
use reqwest;
use smartdns_ui::http_api_msg;
use std::{error::Error, net::TcpStream};
use tungstenite::*;

pub struct TestClient {
    url: String,
    token: Option<http_api_msg::TokenResponse>,
}

impl TestClient {
    pub fn new(url: &String) -> Self {
        let client = TestClient {
            url: url.clone(),
            token: None,
        };

        client
    }

    pub fn login(&mut self, user: &str, password: &str) -> Result<String, Box<dyn Error>> {
        let url = self.url.clone() + "/api/auth/login";
        let body = http_api_msg::api_msg_gen_auth_login(&http_api_msg::AuthUser {
            user: user.to_string(),
            password: password.to_string(),
        });
        let client = reqwest::blocking::Client::new();
        let resp = client.post(&url).body(body).send()?;
        let text = resp.text()?;

        let token = http_api_msg::api_msg_parse_auth_token(&text)?;
        self.token = Some(token);
        Ok(text)
    }

    fn prep_request(
        &self,
        method: reqwest::Method,
        path: &str,
    ) -> Result<reqwest::blocking::RequestBuilder, Box<dyn Error>> {
        let url = self.url.clone() + path;
        let client = reqwest::blocking::ClientBuilder::new()
            .danger_accept_invalid_certs(true)
            .build()?;
        let mut req = client.request(method, url);
        if let Some(token) = &self.token {
            if self.token.is_some() {
                req = req.header("Authorization", format!("{}", token.token));
            }
        }
        Ok(req)
    }

    pub fn get(&self, path: &str) -> Result<(i32, String), Box<dyn Error>> {
        let req = self.prep_request(reqwest::Method::GET, path)?;
        let resp = req.send()?;
        let status = resp.status().as_u16();
        let text = resp.text()?;
        Ok((status as i32, text))
    }

    pub fn delete(&self, path: &str) -> Result<(i32, String), Box<dyn Error>> {
        let req = self.prep_request(reqwest::Method::DELETE, path)?;
        let resp = req.send()?;
        let status = resp.status().as_u16();
        let text = resp.text()?;
        Ok((status as i32, text))
    }

    pub fn put(&self, path: &str, body: &str) -> Result<(i32, String), Box<dyn Error>> {
        let req = self.prep_request(reqwest::Method::PUT, path)?;
        let resp = req.body(body.to_string()).send()?;
        let status = resp.status().as_u16();
        let text = resp.text()?;
        Ok((status as i32, text))
    }

    pub fn post(&self, path: &str, body: &str) -> Result<(i32, String), Box<dyn Error>> {
        let req = self.prep_request(reqwest::Method::POST, path)?;
        let resp = req.body(body.to_string()).send()?;
        let status = resp.status().as_u16();
        let text = resp.text()?;
        Ok((status as i32, text))
    }

    pub fn websocket(
        &self,
        path: &str,
    ) -> Result<WebSocket<stream::MaybeTlsStream<TcpStream>>, Box<dyn Error>> {
        let url = self.url.clone() + path;
        let uri: http::Uri = url.parse()?;
        let mut parts = uri.into_parts();
        parts.scheme = Some("ws".parse().unwrap());
        let uri = uri::Uri::from_parts(parts).unwrap();
        let mut request_builder = tungstenite::ClientRequestBuilder::new(uri);

        if let Some(token) = &self.token {
            if self.token.is_some() {
                request_builder =
                    request_builder.with_header("Authorization", format!("{}", token.token));
            }
        }

        request_builder = request_builder
            .with_header("Upgrade", "websocket")
            .with_header("Sec-WebSocket-Version", "13")
            .with_header("Connection", "keep-alive, Upgrade");

        let ret = tungstenite::connect(request_builder);
        if let Err(e) = ret {
            println!("websocket connect error: {:?}", e.to_string());
            return Err(Box::new(e));
        }
        let (socket, _) = ret.unwrap();
        Ok(socket)
    }
}

impl Drop for TestClient {
    fn drop(&mut self) {}
}
