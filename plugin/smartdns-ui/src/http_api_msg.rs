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

use crate::data_server::*;
use crate::data_upstream_server::UpstreamServerInfo;
use crate::db::*;
use crate::smartdns::LogLevel;
use crate::whois::WhoIsInfo;
use serde_json::json;
use std::collections::HashMap;
use std::error::Error;

#[derive(Debug)]
pub struct AuthUser {
    pub username: String,
    pub password: String,
}

#[derive(Debug)]
pub struct TokenResponse {
    pub token: String,
    pub expires_in: String,
}

pub fn api_msg_parse_auth(data: &str) -> Result<AuthUser, Box<dyn Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    let username = v["username"].as_str();
    if username.is_none() {
        return Err("username not found".into());
    }
    let password = v["password"].as_str();
    if password.is_none() {
        return Err("password not found".into());
    }

    Ok(AuthUser {
        username: username.unwrap().to_string(),
        password: password.unwrap().to_string(),
    })
}

pub fn api_msg_parse_auth_password_change(data: &str) -> Result<(String, String), Box<dyn Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    let old_password = v["old_password"].as_str();
    if old_password.is_none() {
        return Err("old_password not found".into());
    }
    let password = v["password"].as_str();
    if password.is_none() {
        return Err("password not found".into());
    }

    Ok((
        old_password.unwrap().to_string(),
        password.unwrap().to_string(),
    ))
}

pub fn api_msg_gen_auth_password_change(old_password: &str, password: &str) -> String {
    let json_str = json!({
        "old_password": old_password,
        "password": password,
    });

    json_str.to_string()
}

pub fn api_msg_gen_auth_login(auth: &AuthUser) -> String {
    let json_str = json!({
        "username": auth.username,
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

pub fn api_msg_parse_json_object_domain_value(
    data: &serde_json::Value,
) -> Result<DomainData, Box<dyn Error>> {
    let id = data["id"].as_u64();
    if id.is_none() {
        return Err("id not found".into());
    }

    let timestamp = data["timestamp"].as_u64();
    if timestamp.is_none() {
        return Err("timestamp not found".into());
    }

    let domain = data["domain"].as_str();
    if domain.is_none() {
        return Err("domain not found".into());
    }

    let domain_type = data["domain_type"].as_u64();
    if domain_type.is_none() {
        return Err("domain_type not found".into());
    }

    let client = data["client"].as_str();
    if client.is_none() {
        return Err("client not found".into());
    }

    let domain_group = data["domain_group"].as_str();
    if domain_group.is_none() {
        return Err("domain_group not found".into());
    }

    let reply_code = data["reply_code"].as_u64();
    if reply_code.is_none() {
        return Err("reply_code not found".into());
    }

    let query_time = data["query_time"].as_i64();
    if query_time.is_none() {
        return Err("query_time not found".into());
    }

    let ping_time = data["ping_time"].as_f64();
    if ping_time.is_none() {
        return Err("ping_time not found".into());
    }

    let is_blocked = data["is_blocked"].as_bool();
    if is_blocked.is_none() {
        return Err("is_blocked not found".into());
    }

    let is_cached = data["is_cached"].as_bool();
    if is_cached.is_none() {
        return Err("is_cached not found".into());
    }

    Ok(DomainData {
        id: id.unwrap(),
        timestamp: timestamp.unwrap(),
        domain: domain.unwrap().to_string(),
        domain_type: domain_type.unwrap() as u32,
        client: client.unwrap().to_string(),
        domain_group: domain_group.unwrap().to_string(),
        reply_code: reply_code.unwrap() as u16,
        query_time: query_time.unwrap() as i32,
        ping_time: ping_time.unwrap(),
        is_blocked: is_blocked.unwrap(),
        is_cached: is_cached.unwrap(),
    })
}

pub fn api_msg_parse_domain(data: &str) -> Result<DomainData, Box<dyn Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    api_msg_parse_json_object_domain_value(&v)
}

pub fn api_msg_gen_json_object_domain(domain: &DomainData) -> serde_json::Value {
    json!({
        "id": domain.id,
        "timestamp": domain.timestamp,
        "domain": domain.domain,
        "domain_type": domain.domain_type,
        "client": domain.client,
        "domain_group": domain.domain_group,
        "reply_code": domain.reply_code,
        "query_time": domain.query_time,
        "ping_time": domain.ping_time,
        "is_blocked": domain.is_blocked,
        "is_cached": domain.is_cached,
    })
}

pub fn api_msg_gen_domain(domain: &DomainData) -> String {
    let json_str = api_msg_gen_json_object_domain(domain);
    json_str.to_string()
}

pub fn api_msg_parse_domain_list(data: &str) -> Result<Vec<DomainData>, Box<dyn Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    let list_count = v["list_count"].as_u64();
    if list_count.is_none() {
        return Err("list_count not found".into());
    }
    let list_count = list_count.unwrap();
    let mut domain_list = Vec::new();
    for i in 0..list_count {
        let domain_object = &v["domain_list"][i as usize];
        let domain_data = api_msg_parse_json_object_domain_value(domain_object)?;
        domain_list.push(domain_data);
    }

    Ok(domain_list)
}

pub fn api_msg_gen_domain_list(
    domain_list_result: &QueryDomainListResult,
    total_page: u64,
    total_count: u64,
) -> String {
    let json_str = json!({
        "list_count": domain_list_result.domain_list.len(),
        "total_page": total_page,
        "total_count": total_count,
        "step_by_cursor": domain_list_result.step_by_cursor,
        "domain_list":
        domain_list_result.domain_list
                .iter()
                .map(|x| {
                    api_msg_gen_json_object_domain(x)
                })
                .collect::<Vec<serde_json::Value>>()

    });

    json_str.to_string()
}

pub fn api_msg_parse_client_list(data: &str) -> Result<Vec<ClientData>, Box<dyn Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    let list_count = v["list_count"].as_u64();
    if list_count.is_none() {
        return Err("list_count not found".into());
    }
    let list_count = list_count.unwrap();
    let mut client_list = Vec::new();
    for i in 0..list_count {
        let client_object = &v["client-list"][i as usize];
        let id = client_object["id"].as_u64();
        if id.is_none() {
            return Err("id not found".into());
        }

        let client_ip = client_object["client_ip"].as_str();
        if client_ip.is_none() {
            return Err("client_ip not found".into());
        }

        let mac = client_object["mac"].as_str();
        if mac.is_none() {
            return Err("mac not found".into());
        }

        let hostname = client_object["hostname"].as_str();
        if hostname.is_none() {
            return Err("hostname not found".into());
        }

        let last_query_time = client_object["last_query_time"].as_u64();
        if last_query_time.is_none() {
            return Err("last_query_time not found".into());
        }

        client_list.push(ClientData {
            id: id.unwrap() as u32,
            client_ip: client_ip.unwrap().to_string(),
            mac: mac.unwrap().to_string(),
            hostname: hostname.unwrap().to_string(),
            last_query_time: last_query_time.unwrap(),
        });
    }

    Ok(client_list)
}

pub fn api_msg_gen_client_list(client_list: &Vec<ClientData>) -> String {
    let json_str = json!({
        "list_count": client_list.len(),
        "client-list":
            client_list
                .iter()
                .map(|x| {
                    let s = json!({
                        "id": x.id,
                        "client_ip": x.client_ip,
                        "mac": x.mac,
                        "hostname": x.hostname,
                        "last_query_time": x.last_query_time,
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
        "token_type": "Bearer",
        "expires_in": expired,
    });

    json_str.to_string()
}

pub fn api_msg_parse_auth_token(data: &str) -> Result<TokenResponse, Box<dyn Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    let token = v["token"].as_str();
    if token.is_none() {
        return Err("token not found".into());
    }
    let expired = v["expires_in"].as_str();
    if expired.is_none() {
        return Err("expires_in not found".into());
    }

    Ok(TokenResponse {
        token: token.unwrap().to_string(),
        expires_in: expired.unwrap().to_string(),
    })
}

pub fn api_msg_gen_cache_number(cache_number: i32) -> String {
    let json_str = json!({
        "cache_number": cache_number,
    });

    json_str.to_string()
}

pub fn api_msg_parse_cache_number(data: &str) -> Result<i32, Box<dyn Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    let cache_number = v["cache_number"].as_i64();
    if cache_number.is_none() {
        return Err("cache_number not found".into());
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
    let loglevel = v["log_level"].as_str();
    if loglevel.is_none() {
        return Err("loglevel not found".into());
    }

    let ret = loglevel.unwrap().try_into();
    if ret.is_err() {
        return Err("log level is invalid".into());
    }

    Ok(ret.unwrap())
}

pub fn api_msg_gen_loglevel(loglevel: LogLevel) -> String {
    let loglevel_str = loglevel.to_string();
    let json_str = json!({
        "log_level": loglevel_str,
    });

    json_str.to_string()
}

pub fn api_msg_gen_version(smartdns_version: &str, ui_version: &str) -> String {
    let json_str = json!({
        "smartdns": smartdns_version,
        "smartdns_ui": ui_version,
    });

    json_str.to_string()
}

pub fn api_msg_gen_upstream_server_list(upstream_server_list: &Vec<UpstreamServerInfo>) -> String {
    let json_str = json!({
        "upstream_server_list":
            upstream_server_list
                .iter()
                .map(|x| {
                    let s = json!({
                        "host": x.host,
                        "ip": x.ip,
                        "port": x.port,
                        "server_type": x.server_type.to_string(),
                        "total_query_count": x.total_query_count,
                        "total_query_success": x.total_query_success,
                        "total_query_recv_count": x.total_query_recv_count,
                        "query_success_rate": x.query_success_rate,
                        "avg_time": x.avg_time,
                        "status": x.status,
                    });
                    s
                })
                .collect::<Vec<serde_json::Value>>()
    });

    json_str.to_string()
}

pub fn api_msg_parse_upstream_server_list(
    data: &str,
) -> Result<Vec<UpstreamServerInfo>, Box<dyn Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    let mut upstream_server_list = Vec::new();
    let server_list = v["upstream_server_list"].as_array();
    if server_list.is_none() {
        return Err("list_count not found".into());
    }

    for item in server_list.unwrap() {
        let host = item["host"].as_str();
        if host.is_none() {
            return Err("host not found".into());
        }

        let ip = item["ip"].as_str();
        if ip.is_none() {
            return Err("ip not found".into());
        }

        let port = item["port"].as_u64();
        if port.is_none() {
            return Err("port not found".into());
        }

        let server_type = item["server_type"].as_str();
        if server_type.is_none() {
            return Err("server_type not found".into());
        }

        let total_query_count = item["total_query_count"].as_u64();
        if total_query_count.is_none() {
            return Err("total_query_count not found".into());
        }

        let total_query_success = item["total_query_success"].as_u64();
        if total_query_success.is_none() {
            return Err("total_query_success not found".into());
        }

        let total_query_recv_count = item["total_query_recv_count"].as_u64();
        if total_query_recv_count.is_none() {
            return Err("total_query_recv_count not found".into());
        }

        let query_success_rate = item["query_success_rate"].as_f64();
        if query_success_rate.is_none() {
            return Err("query_success_rate not found".into());
        }

        let avg_time = item["avg_time"].as_f64();
        if avg_time.is_none() {
            return Err("avg_time not found".into());
        }

        let status = item["status"].as_str();
        if status.is_none() {
            return Err("status not found".into());
        }

        upstream_server_list.push(UpstreamServerInfo {
            host: host.unwrap().to_string(),
            ip: ip.unwrap().to_string(),
            port: port.unwrap() as u16,
            server_type: server_type.unwrap().parse()?,
            total_query_count: total_query_count.unwrap() as u64,
            total_query_success: total_query_success.unwrap() as u64,
            total_query_recv_count: total_query_recv_count.unwrap() as u64,
            query_success_rate: query_success_rate.unwrap(),
            avg_time: avg_time.unwrap(),
            status: status.unwrap().to_string(),
        });
    }

    Ok(upstream_server_list)
}

pub fn api_msg_parse_version(data: &str) -> Result<(String, String), Box<dyn Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    let smartdns = v["smartdns"].as_str();
    if smartdns.is_none() {
        return Err("smartdns not found".into());
    }
    let ui = v["smartdns_ui"].as_str();
    if ui.is_none() {
        return Err("ui not found".into());
    }

    Ok((smartdns.unwrap().to_string(), ui.unwrap().to_string()))
}

pub fn api_msg_gen_key_value(data: &HashMap<String, String>) -> String {
    let mut json_map = serde_json::Map::new();

    for (key, value) in data {
        json_map.insert(key.clone(), serde_json::Value::String(value.clone()));
    }

    serde_json::Value::Object(json_map).to_string()
}

pub fn api_msg_parse_key_value(data: &str) -> Result<HashMap<String, String>, Box<dyn Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    let mut conf_map = HashMap::new();

    if let serde_json::Value::Object(map) = v {
        for (key, value) in map {
            if let serde_json::Value::String(value_str) = value {
                conf_map.insert(key, value_str);
            }
        }
    }

    Ok(conf_map)
}

pub fn api_msg_gen_top_client_list(client_list: &Vec<ClientQueryCount>) -> String {
    let json_str = json!({
        "client_top_list":
            client_list
                .iter()
                .map(|x| {
                    let s = json!({
                        "client_ip": x.client_ip,
                        "query_count": x.count,
                    });
                    s
                })
                .collect::<Vec<serde_json::Value>>()
    });

    json_str.to_string()
}

pub fn api_msg_parse_top_client_list(data: &str) -> Result<Vec<ClientQueryCount>, Box<dyn Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    let mut client_list = Vec::new();
    let top_list = v["client_top_list"].as_array();
    if top_list.is_none() {
        return Err("list_count not found".into());
    }

    for item in top_list.unwrap() {
        let client_ip = item["client_ip"].as_str();
        if client_ip.is_none() {
            return Err("client_ip not found".into());
        }

        let query_count = item["query_count"].as_u64();
        if query_count.is_none() {
            return Err("query_count not found".into());
        }

        client_list.push(ClientQueryCount {
            client_ip: client_ip.unwrap().to_string(),
            count: query_count.unwrap() as u32,
        });
    }

    Ok(client_list)
}

pub fn api_msg_gen_top_domain_list(domain_list: &Vec<DomainQueryCount>) -> String {
    let json_str = json!({
        "domain_top_list":
            domain_list
                .iter()
                .map(|x| {
                    let s = json!({
                        "domain": x.domain,
                        "query_count": x.count,
                    });
                    s
                })
                .collect::<Vec<serde_json::Value>>()
    });

    json_str.to_string()
}

pub fn api_msg_parse_top_domain_list(data: &str) -> Result<Vec<DomainQueryCount>, Box<dyn Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    let mut domain_list = Vec::new();
    let top_list = v["domain_top_list"].as_array();
    if top_list.is_none() {
        return Err("list_count not found".into());
    }

    for item in top_list.unwrap() {
        let domain = item["domain"].as_str();
        if domain.is_none() {
            return Err("domain not found".into());
        }

        let query_count = item["query_count"].as_u64();
        if query_count.is_none() {
            return Err("query_count not found".into());
        }

        domain_list.push(DomainQueryCount {
            domain: domain.unwrap().to_string(),
            count: query_count.unwrap() as u32,
        });
    }

    Ok(domain_list)
}

pub fn api_msg_gen_metrics_data(data: &MetricsData) -> String {
    let json_str = json!({
        "total_query_count": data.total_query_count,
        "block_query_count": data.block_query_count,
        "avg_query_time": data.avg_query_time,
        "cache_hit_rate": data.cache_hit_rate,
        "cache_number": data.cache_number,
        "cache_memory_size": data.cache_memory_size,
        "qps": data.qps,
        "memory_usage": data.memory_usage,
        "is_metrics_suspended": data.is_metrics_suspended,
    });

    json_str.to_string()
}

pub fn api_msg_parse_metrics_data(data: &str) -> Result<MetricsData, Box<dyn Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    let total_query_count = v["total_query_count"].as_u64();
    if total_query_count.is_none() {
        return Err("total_query_count not found".into());
    }

    let block_query_count = v["block_query_count"].as_u64();
    if block_query_count.is_none() {
        return Err("block_query_count not found".into());
    }

    let avg_query_time = v["avg_query_time"].as_f64();
    if avg_query_time.is_none() {
        return Err("avg_query_time not found".into());
    }

    let cache_hit_rate = v["cache_hit_rate"].as_f64();
    if cache_hit_rate.is_none() {
        return Err("cache_hit_rate not found".into());
    }

    let cache_number = v["cache_number"].as_u64();
    if cache_number.is_none() {
        return Err("cache_number not found".into());
    }

    let cache_memory_size = v["cache_memory_size"].as_u64();
    if cache_memory_size.is_none() {
        return Err("cache_memory_size not found".into());
    }

    let qps = v["qps"].as_u64();
    if qps.is_none() {
        return Err("qps not found".into());
    }

    let memory_usage = v["memory_usage"].as_u64();
    if memory_usage.is_none() {
        return Err("memory_usage not found".into());
    }

    let is_metrics_suspended = v["is_metrics_suspended"].as_bool();

    Ok(MetricsData {
        total_query_count: total_query_count.unwrap() as u64,
        block_query_count: block_query_count.unwrap() as u64,
        avg_query_time: avg_query_time.unwrap(),
        cache_hit_rate: cache_hit_rate.unwrap(),
        cache_number: cache_number.unwrap() as u64,
        cache_memory_size: cache_memory_size.unwrap() as u64,
        qps: qps.unwrap() as u32,
        memory_usage: memory_usage.unwrap() as u64,
        is_metrics_suspended: is_metrics_suspended.unwrap_or(false),
    })
}

pub fn api_msg_gen_stats_overview(data: &OverviewData) -> String {
    let json_str = json!({
        "server_name": data.server_name,
        "database_size": data.db_size,
        "startup_timestamp": data.startup_timestamp,
        "free_disk_space": data.free_disk_space,
        "is_process_suspended": data.is_process_suspended,
    });

    json_str.to_string()
}

pub fn api_msg_parse_stats_overview(data: &str) -> Result<OverviewData, Box<dyn Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;

    let server_name = v["server_name"].as_str();
    if server_name.is_none() {
        return Err("server_name not found".into());
    }

    let db_size = v["database_size"].as_u64();
    if db_size.is_none() {
        return Err("database_size not found".into());
    }

    let startup_timestamp = v["startup_timestamp"].as_u64();
    if startup_timestamp.is_none() {
        return Err("startup_timestamp not found".into());
    }

    let free_disk_space = v["free_disk_space"].as_u64();
    if free_disk_space.is_none() {
        return Err("free_disk_space not found".into());
    }

    let is_process_suspended = v["is_process_suspended"].as_bool();
    if is_process_suspended.is_none() {
        return Err("is_process_suspended not found".into());
    }

    Ok(OverviewData {
        server_name: server_name.unwrap().to_string(),
        db_size: db_size.unwrap() as u64,
        startup_timestamp: startup_timestamp.unwrap() as u64,
        free_disk_space: free_disk_space.unwrap() as u64,
        is_process_suspended: is_process_suspended.unwrap(),

    })
}

pub fn api_msg_gen_hourly_query_count(hourly_count: &HourlyQueryCount) -> String {
    let json_str = json!({
        "query_timestamp": hourly_count.query_timestamp,
        "hourly_query_count":
        hourly_count.hourly_query_count
                .iter()
                .map(|x| {
                    let s = json!({
                        "hour": x.hour,
                        "query_count": x.query_count,
                    });
                    s
                })
                .collect::<Vec<serde_json::Value>>()
    });
    json_str.to_string()
}

pub fn api_msg_parse_hourly_query_count(
    data: &str,
) -> Result<HourlyQueryCount, Box<dyn Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    let query_timestamp = v["query_timestamp"].as_u64();
    if query_timestamp.is_none() {
        return Err("query_timestamp not found".into());
    }

    let mut hourly_query_count = Vec::new();
    let hourly_list = v["hourly_query_count"].as_array();
    if hourly_list.is_none() {
        return Err("hourly_query_count not found".into());
    }

    for item in hourly_list.unwrap() {
        let hour = item["hour"].as_str();
        if hour.is_none() {
            return Err("hour not found".into());
        }

        let query_count = item["query_count"].as_u64();
        if query_count.is_none() {
            return Err("query_count not found".into());
        }

        hourly_query_count.push(HourlyQueryCountItem {
            hour: hour.unwrap().to_string(),
            query_count: query_count.unwrap() as u32,
        });
    }

    Ok(HourlyQueryCount {
        query_timestamp: query_timestamp.unwrap(),
        hourly_query_count: hourly_query_count,
    })
}

pub fn api_msg_gen_request_qps(qps: u32) -> String {
    let json_str = json!({
        "qps": qps,
    });

    json_str.to_string()
}

pub fn api_msg_gen_daily_query_count(daily_count: &DailyQueryCount) -> String {
    let json_str = json!({
        "query_timestamp": daily_count.query_timestamp,
        "daily_query_count":
        daily_count.daily_query_count
                .iter()
                .map(|x| {
                    let s = json!({
                        "day": x.day,
                        "query_count": x.query_count,
                    });
                    s
                })
                .collect::<Vec<serde_json::Value>>()
    });
    json_str.to_string()
}

pub fn api_msg_parse_daily_query_count(data: &str) -> Result<DailyQueryCount, Box<dyn Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    let mut daily_query_count = Vec::new();
    let query_timestamp = v["query_timestamp"].as_u64();
    if query_timestamp.is_none() {
        return Err("query_timestamp not found".into());
    }

    let daily_list = v["daily_query_count"].as_array();
    if daily_list.is_none() {
        return Err("daily_query_count not found".into());
    }

    for item in daily_list.unwrap() {
        let day = item["day"].as_str();
        if day.is_none() {
            return Err("day not found".into());
        }

        let query_count = item["query_count"].as_u64();
        if query_count.is_none() {
            return Err("query_count not found".into());
        }

        daily_query_count.push(DailyQueryCountItem {
            day: day.unwrap().to_string(),
            query_count: query_count.unwrap() as u32,
        });
    }

    Ok(DailyQueryCount {
        query_timestamp: query_timestamp.unwrap(),
        daily_query_count: daily_query_count,
    })
}

pub fn api_msg_gen_whois_info(data: &WhoIsInfo) -> String {
    let json_str = json!({
        "domain": data.domain,
        "registrar": data.registrar,
        "organization": data.organization,
        "address": data.address,
        "city": data.city,
        "country": data.country,
    });

    json_str.to_string()
}

pub fn api_msg_parse_whois_info(data: &str) -> Result<WhoIsInfo, Box<dyn Error>> {
    let v: serde_json::Value = serde_json::from_str(data)?;
    let domain = v["domain"].as_str();
    if domain.is_none() {
        return Err("domain not found".into());
    }

    let registrar = v["registrar"].as_str();
    if registrar.is_none() {
        return Err("registrar not found".into());
    }

    let organization = v["organization"].as_str();
    if organization.is_none() {
        return Err("organization not found".into());
    }

    let address = v["address"].as_str();
    if address.is_none() {
        return Err("address not found".into());
    }

    let city = v["city"].as_str();
    if city.is_none() {
        return Err("city not found".into());
    }

    let country = v["country"].as_str();
    if country.is_none() {
        return Err("country not found".into());
    }

    let refer = v["refer"].as_str();
    let refer = if refer.is_none() {
        String::new()
    } else {
        refer.unwrap().to_string()
    };

    Ok(WhoIsInfo {
        refer: refer,
        domain: domain.unwrap().to_string(),
        registrar: registrar.unwrap().to_string(),
        organization: organization.unwrap().to_string(),
        address: address.unwrap().to_string(),
        city: city.unwrap().to_string(),
        country: country.unwrap().to_string(),
    })
}
