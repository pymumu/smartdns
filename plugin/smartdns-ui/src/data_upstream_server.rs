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

use crate::{smartdns, DnsServerType};

#[derive(Debug, Clone)]
pub struct UpstreamServerInfo {
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub server_type: DnsServerType,
    pub total_query_count: u64,
    pub total_query_success: u64,
    pub total_query_recv_count: u64,
    pub query_success_rate: f64,
    pub avg_time: f64,
    pub status: String,
}

impl UpstreamServerInfo {
    pub fn get_all() -> Result<Vec<UpstreamServerInfo>, Box<dyn std::error::Error>> {
        let mut servers = Vec::new();

        smartdns::DnsUpstreamServer::get_server_list()?
            .iter()
            .for_each(|server| {
                let stats = server.get_server_stats();
                let status = if stats.get_query_total() == 0 {
                    "Unknown"
                } else if server.is_server_alive() {
                    "Normal"
                } else {
                    "Abnormal"
                };

                servers.push(UpstreamServerInfo {
                    host: server.get_host(),
                    ip: server.get_ip(),
                    port: server.get_port(),
                    server_type: server.get_type(),
                    total_query_count: stats.get_query_total(),
                    total_query_recv_count: stats.get_query_recv(),
                    total_query_success: stats.get_query_success(),
                    query_success_rate: stats.get_success_rate(),
                    avg_time: stats.get_query_avg_time(),
                    status: status.to_string(),
                });
            });
        Ok(servers)
    }
}
