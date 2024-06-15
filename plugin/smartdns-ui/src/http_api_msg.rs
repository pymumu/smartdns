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

use crate::db::*;
use crate::smartdns::LogLevel;
use serde_json::json;
use std::error::Error;

#[derive(Debug)]
pub struct AuthUser {
    pub user: String,
    pub password: String,
}

#[derive(Debug)]
pub struct TokenResponse {
    pub token: String,
    pub expires_in: String,
}

pub fn api_msg_parse_auth(data: &str) -> Result<AuthUser, Box<dyn Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    let user = v["user"].as_str();
    if user.is_none() {
        return Err("user not found".into());
    }
    let password = v["password"].as_str();
    if password.is_none() {
        return Err("password not found".into());
    }

    Ok(AuthUser {
        user: user.unwrap().to_string(),
        password: password.unwrap().to_string(),
    })
}

pub fn api_msg_gen_auth_login(auth: &AuthUser) -> String {
    let json_str = json!({
        "user": auth.user,
        "password": auth.password,
    });

    json_str.to_string()
}

pub fn api_msg_parse_count(data: &str) -> Result<i64, Box<dyn Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    let count = v["count"].as_i64();
    if count.is_none() {
        return Err("count not found".into());
    }

    Ok(count.unwrap())
}

pub fn api_msg_gen_count(count: i64) -> String {
    let json_str = json!({
        "count": count,
    });

    json_str.to_string()
}

pub fn api_msg_parse_domain(data: &str) -> Result<DomainData, Box<dyn Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    let id = v["id"].as_u64();
    if id.is_none() {
        return Err("id not found".into());
    }
    let timestamp = v["timestamp"].as_u64();
    if timestamp.is_none() {
        return Err("timestamp not found".into());
    }
    let domain = v["domain"].as_str();
    if domain.is_none() {
        return Err("domain not found".into());
    }
    let domain_type = v["domain-type"].as_u64();
    if domain_type.is_none() {
        return Err("domain-type not found".into());
    }
    let client = v["client"].as_str();
    if client.is_none() {
        return Err("client not found".into());
    }
    let domain_group = v["domain-group"].as_str();
    if domain_group.is_none() {
        return Err("domain-group not found".into());
    }
    let reply_code = v["reply-code"].as_u64();
    if reply_code.is_none() {
        return Err("reply-code not found".into());
    }

    Ok(DomainData {
        id: id.unwrap(),
        timestamp: timestamp.unwrap(),
        domain: domain.unwrap().to_string(),
        domain_type: domain_type.unwrap() as u32,
        client: client.unwrap().to_string(),
        domain_group: domain_group.unwrap().to_string(),
        reply_code: reply_code.unwrap() as u16,
    })
}

pub fn api_msg_gen_domain(domain: &DomainData) -> String {
    let json_str = json!({
        "id": domain.id,
        "timestamp": domain.timestamp,
        "domain": domain.domain,
        "domain-type": domain.domain_type,
        "client": domain.client,
        "domain-group": domain.domain_group,
        "reply-code": domain.reply_code,
    });

    json_str.to_string()
}

pub fn api_msg_parse_domain_list(data: &str) -> Result<Vec<DomainData>, Box<dyn Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    let list_count = v["list-count"].as_u64();
    if list_count.is_none() {
        return Err("list-count not found".into());
    }
    let list_count = list_count.unwrap();
    let mut domain_list = Vec::new();
    for i in 0..list_count {
        let domain = &v["domian-list"][i as usize];
        let id = domain["id"].as_u64();
        if id.is_none() {
            return Err("id not found".into());
        }
        let timestamp = domain["timestamp"].as_u64();
        if timestamp.is_none() {
            return Err("timestamp not found".into());
        }
        let domain_str = domain["domain"].as_str();
        if domain_str.is_none() {
            return Err("domain not found".into());
        }
        let domain_type = domain["domain-type"].as_u64();
        if domain_type.is_none() {
            return Err("domain-type not found".into());
        }
        let client = domain["client"].as_str();
        if client.is_none() {
            return Err("client not found".into());
        }
        let domain_group = domain["domain-group"].as_str();
        if domain_group.is_none() {
            return Err("domain-group not found".into());
        }
        let reply_code = domain["reply-code"].as_u64();
        if reply_code.is_none() {
            return Err("reply-code not found".into());
        }

        domain_list.push(DomainData {
            id: id.unwrap(),
            timestamp: timestamp.unwrap(),
            domain: domain_str.unwrap().to_string(),
            domain_type: domain_type.unwrap() as u32,
            client: client.unwrap().to_string(),
            domain_group: domain_group.unwrap().to_string(),
            reply_code: reply_code.unwrap() as u16,
        });
    }

    Ok(domain_list)
}

pub fn api_msg_gen_domain_list(domain_list: Vec<DomainData>, total_page: u32) -> String {
    let json_str = json!({
        "list-count": domain_list.len(),
        "total-page": total_page,
        "domian-list":
            domain_list
                .iter()
                .map(|x| {
                    let s = json!({
                        "id": x.id,
                        "timestamp": x.timestamp,
                        "domain": x.domain,
                        "domain-type": x.domain_type,
                        "client": x.client,
                        "domain-group": x.domain_group,
                        "reply-code": x.reply_code,
                    });
                    s
                })
                .collect::<Vec<serde_json::Value>>()

    });

    json_str.to_string()
}

pub fn api_msg_gen_client_list(client_list: Vec<ClientData>) -> String {
    let json_str = json!({
        "list-count": client_list.len(),
        "client-list":
            client_list
                .iter()
                .map(|x| {
                    let s = json!({
                        "id": x.id,
                        "client-ip": x.client_ip,
                    });
                    s
                })
                .collect::<Vec<serde_json::Value>>()

    });

    json_str.to_string()
}

pub fn api_msg_auth_token(token: &str, expired: &str) -> String {
    let json_str = json!({
        "token": token,
        "expires-in": expired,
    });

    json_str.to_string()
}

pub fn api_msg_parse_auth_token(data: &str) -> Result<TokenResponse, Box<dyn Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    let token = v["token"].as_str();
    if token.is_none() {
        return Err("token not found".into());
    }
    let expired = v["expires-in"].as_str();
    if expired.is_none() {
        return Err("expires-in not found".into());
    }

    Ok(TokenResponse {
        token: token.unwrap().to_string(),
        expires_in: expired.unwrap().to_string(),
    })
}

pub fn api_msg_gen_cache_number(cache_number: i32) -> String {
    let json_str = json!({
        "cache-number": cache_number,
    });

    json_str.to_string()
}

pub fn api_msg_parse_cache_number(data: &str) -> Result<i32, Box<dyn Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    let cache_number = v["cache-number"].as_i64();
    if cache_number.is_none() {
        return Err("cache-number not found".into());
    }

    Ok(cache_number.unwrap() as i32)
}

pub fn api_msg_error(msg: &str) -> String {
    let json_str = json!({
        "error": msg,
    });

    json_str.to_string()
}

pub fn api_msg_parse_error(data: &str) -> Result<String, Box<dyn Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    let error = v["error"].as_str();
    if error.is_none() {
        return Err("error not found".into());
    }

    Ok(error.unwrap().to_string())
}

pub fn api_msg_parse_loglevel(data: &str) -> Result<LogLevel, Box<dyn Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    let loglevel = v["log-level"].as_str();
    if loglevel.is_none() {
        return Err("loglevel not found".into());
    }

    let loglevel = loglevel.unwrap();
    match loglevel {
        "debug" => Ok(LogLevel::DEBUG),
        "info" => Ok(LogLevel::INFO),
        "notice" => Ok(LogLevel::NOTICE),
        "warn" => Ok(LogLevel::WARN),
        "error" => Ok(LogLevel::ERROR),
        "fatal" => Ok(LogLevel::FATAL),
        _ => Err("loglevel not found".into()),
    }
}

pub fn api_msg_gen_loglevel(loglevel: LogLevel) -> String {
    let loglevel = match loglevel {
        LogLevel::DEBUG => "debug",
        LogLevel::INFO => "info",
        LogLevel::NOTICE => "notice",
        LogLevel::WARN => "warn",
        LogLevel::ERROR => "error",
        LogLevel::FATAL => "fatal",
    };
    let json_str = json!({
        "log-level": loglevel,
    });

    json_str.to_string()
}

pub fn api_msg_gen_version(smartdns_version: &str, ui_version: &str) -> String {
    let json_str = json!({
        "smartdns": smartdns_version,
        "smartdns-ui": ui_version,
    });

    json_str.to_string()
}

pub fn api_msg_parse_version(data: &str) -> Result<(String, String), Box<dyn Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    let smartdns = v["smartdns"].as_str();
    if smartdns.is_none() {
        return Err("smartdns not found".into());
    }
    let ui = v["smartdns-ui"].as_str();
    if ui.is_none() {
        return Err("ui not found".into());
    }

    Ok((smartdns.unwrap().to_string(), ui.unwrap().to_string()))
}