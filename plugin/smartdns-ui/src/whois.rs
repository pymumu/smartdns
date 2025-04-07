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

use std::collections::HashMap;
use std::error::Error;
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::dns_log;
use crate::smartdns::LogLevel;

#[derive(Debug, Clone)]
pub struct WhoIsInfo {
    pub domain: String,
    pub organization: String,
    pub address: String,
    pub city: String,
    pub country: String,
    pub registrar: String,
    pub refer: String,
}

pub struct WhoIs {
    root_server: String,
    server_lists: Mutex<HashMap<String, String>>,
}

impl WhoIs {
    pub fn new() -> Self {
        WhoIs {
            root_server: "whois.iana.org".to_string(),
            server_lists: Mutex::new(HashMap::new()),
        }
    }

    pub fn parser_whois(&self, whois: &str, whois_domain: &mut String) -> WhoIsInfo {
        let mut info = WhoIsInfo {
            domain: String::new(),
            registrar: String::new(),
            organization: String::new(),
            address: String::new(),
            city: String::new(),
            country: String::new(),
            refer: String::new(),
        };

        for line in whois.lines() {
            let line = line.trim();
            if let Some(value) = line.strip_prefix("Organization:") {
                info.organization = value.trim().to_string();
            } else if let Some(value) = line.strip_prefix("Registrar:") {
                info.registrar = value.trim().to_string();
            } else if let Some(value) = line.strip_prefix("Registrant:") {
                info.organization = value.trim().to_string();
            } else if let Some(value) = line.strip_prefix("Registrant Name:") {
                info.organization = value.trim().to_string();
            } else if let Some(value) = line.strip_prefix("Registrant Organization:") {
                info.organization = value.trim().to_string();
            } else if let Some(value) = line.strip_prefix("Registrant Street:") {
                info.address = value.trim().to_string();
            } else if let Some(value) = line.strip_prefix("Registrant City:") {
                info.city = value.trim().to_string();
            } else if let Some(value) = line.strip_prefix("Registrant Country:") {
                info.country = value.trim().to_string();
            } else if let Some(value) = line.strip_prefix("Registrant Country Code:") {
                info.country = value.trim().to_string();
            } else if let Some(value) = line.strip_prefix("Registrar WHOIS Server:") {
                info.refer = value.trim().to_string();
            } else if let Some(value) = line.strip_prefix("refer:") {
                info.refer = value.trim().to_string();
            } else if let Some(value) = line.strip_prefix("whois:") {
                info.refer = value.trim().to_string();
            } else if let Some(value) = line.strip_prefix("domain:") {
                *whois_domain = value.trim().to_string();
            }
        }
        info
    }

    pub async fn query_from_server(domain: &str, server: &str) -> Result<String, Box<dyn Error>> {
        let stream = TcpStream::connect(server);
        let stream_timeout =
            tokio::time::timeout(tokio::time::Duration::from_secs(20), stream).await;
        if let Err(_) = stream_timeout {
            return Err("Connect whois server timeout.".into());
        }

        let mut stream = stream_timeout.unwrap()?;
        let query = format!("{}\r\n", domain);
        stream.write_all(query.as_bytes()).await?;
        let mut output = String::new();
        let read_timeout = tokio::time::timeout(
            tokio::time::Duration::from_secs(10),
            stream.read_to_string(&mut output),
        )
        .await;

        if let Err(_) = read_timeout {
            return Err("Read whois server timeout.".into());
        }
        stream.shutdown().await?;
        Ok(output)
    }

    pub fn add_server(&self, domain: &str, server: &str) {
        let mut server_lists = self.server_lists.lock().unwrap();
        server_lists.insert(domain.to_string().to_lowercase(), server.to_string());
    }

    pub fn get_server(&self, domain: &str) -> Option<String> {
        let server_lists = self.server_lists.lock().unwrap();
        if let Some(server) = server_lists.get(domain) {
            return Some(server.clone());
        }
        None
    }

    pub fn get_server_by_domain(&self, domain: &str) -> String {
        let mut domain_tmp = domain.to_string().to_lowercase();
        loop {
            let server = self.get_server(domain_tmp.as_str());
            if let Some(s) = server {
                return s;
            }

            if let Some(index) = domain_tmp.find('.') {
                domain_tmp = domain_tmp[index + 1..].to_string();
            } else {
                return self.root_server.clone();
            }
        }
    }

    pub async fn query(&self, domain: &str) -> Result<WhoIsInfo, Box<dyn Error>> {
        let parts: Vec<&str> = domain.split('.').collect();
        let mut domainlist = Vec::new();
        if parts.len() < 2 {
            domainlist.push(domain.to_string());
        } else if parts.len() < 3 {
            let v = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
            domainlist.push(v);
        } else {
            let v = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
            domainlist.push(v);
            let v = format!(
                "{}.{}.{}",
                parts[parts.len() - 3],
                parts[parts.len() - 2],
                parts[parts.len() - 1]
            );
            domainlist.push(v);
        };

        let mut last_whoisinfo = WhoIsInfo {
            domain: domain.to_string(),
            organization: String::new(),
            address: String::new(),
            city: String::new(),
            country: String::new(),
            registrar: String::new(),
            refer: String::new(),
        };

        for main_domain in domainlist {
            let mut base_domain = main_domain.as_str();
            if let Some(v) = main_domain.find(".") {
                if v > 0 {
                    base_domain = main_domain.split_at(v + 1).1;
                }
            }

            let mut server = self.get_server_by_domain(base_domain);
            loop {
                let mut whois_domain = String::new();

                if server.is_empty() {
                    break;
                }
                let connect_host = format!("{}:43", server);
                dns_log!(
                    LogLevel::DEBUG,
                    "Query whois server: {}, domain:{}",
                    connect_host,
                    main_domain
                );
                let whois = WhoIs::query_from_server(main_domain.as_str(), &connect_host).await;
                if let Err(e) = whois {
                    if last_whoisinfo.registrar.len() > 0 {
                        return Ok(last_whoisinfo);
                    }
                    return Err(e);
                }

                let whois = whois.unwrap();
                let mut info = self.parser_whois(&whois, &mut whois_domain);

                info.domain = domain.to_string();
                if info.organization.len() > 0 {
                    return Ok(info);
                }

                if info.registrar.len() > 0 {
                    last_whoisinfo = info.clone();
                }
                if server == info.refer {
                    break;
                }

                server = info.refer;
                if whois_domain.len() > 0 {
                    self.add_server(whois_domain.as_str(), server.as_str());
                }
            }
        }

        if last_whoisinfo.registrar.len() > 0 {
            return Ok(last_whoisinfo);
        }

        Err("Cannot find whois.".into())
    }
}
