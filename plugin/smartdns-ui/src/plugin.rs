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
use crate::dns_log;
use crate::http_server::*;
use crate::smartdns::*;

use getopts::Options;
use std::error::Error;
use std::sync::Arc;

pub struct SmartdnsPlugin {
    http_server_ctl: HttpServerControl,
    http_conf: HttpServerConfig,

    data_server_ctl: Arc<DataServerControl>,
    data_conf: DataServerConfig,
}

impl SmartdnsPlugin {
    pub fn new() -> Self {
        SmartdnsPlugin {
            http_server_ctl: HttpServerControl::new(),
            http_conf: HttpServerConfig::new(),

            data_server_ctl: Arc::new(DataServerControl::new()),
            data_conf: DataServerConfig::new(),
        }
    }

    pub fn get_http_server(&self) -> Arc<HttpServer> {
        self.http_server_ctl.get_http_server()
    }

    pub fn get_data_server(&self) -> Arc<DataServer> {
        self.data_server_ctl.get_data_server()
    }

    fn parser_args(&mut self, args: &Vec<String>) -> Result<(), Box<dyn Error>> {
        let mut opts = Options::new();
        opts.optopt("i", "ip", "http ip", "IP");
        opts.optopt("r", "www-root", "http www root", "PATH");
        opts.optopt("", "data-dir", "http data dir", "PATH");
        opts.optopt("", "token-expire", "http token expire time", "TIME");

        if args.len() <= 0 {
            return Ok(());
        }

        let matches = match opts.parse(&args[1..]) {
            Ok(m) => m,
            Err(f) => {
                return Err(Box::new(f));
            }
        };

        let www_root = Plugin::dns_conf_plugin_config("smartdns-ui.www-root");
        if let Some(www_root) = www_root {
            self.http_conf.http_root = www_root;
        }

        let ip = Plugin::dns_conf_plugin_config("smartdns-ui.ip");
        if let Some(ip) = ip {
            self.http_conf.http_ip = ip;
        }

        if let Some(ip) = matches.opt_str("i") {
            self.http_conf.http_ip = ip;
        }

        if let Some(root) = matches.opt_str("r") {
            self.http_conf.http_root = root;
        }
        dns_log!(LogLevel::INFO, "www root: {}", self.http_conf.http_root);

        if let Some(token_expire) = matches.opt_str("token-expire") {
            let v = token_expire.parse::<u32>();
            if let Err(e) = v {
                dns_log!(
                    LogLevel::ERROR,
                    "parse token expire time error: {}",
                    e.to_string()
                );
                return Err(Box::new(e));
            }
            self.http_conf.token_expired_time = v.unwrap();
        }

        if let Some(data_dir) = matches.opt_str("data-dir") {
            self.data_conf.data_root = data_dir;
        }

        Ok(())
    }

    pub fn load_config(&mut self) -> Result<(), Box<dyn Error>> {
        let data_server = self.get_data_server();
        self.data_conf.load_config(data_server.clone())?;
        self.http_conf.load_config(data_server.clone())?;
        Ok(())
    }

    pub fn start(&mut self, args: &Vec<String>) -> Result<(), Box<dyn Error>> {
        self.parser_args(args)?;
        self.data_server_ctl.init_db(&self.data_conf)?;
        self.load_config()?;
        self.data_server_ctl.start_data_server()?;
        self.http_server_ctl
            .start_http_server(&self.http_conf, self.data_server_ctl.get_data_server())?;

        Ok(())
    }

    pub fn stop(&mut self) {
        self.http_server_ctl.stop_http_server();
        self.data_server_ctl.stop_data_server();
    }

    pub fn query_complete(&self, request: &mut DnsRequest) {
        let ret = self.data_server_ctl.send_request(request);
        if let Err(e) = ret {
            dns_log!(LogLevel::ERROR, "send data to data server error: {}", e);
            return;
        }
    }
}

impl Drop for SmartdnsPlugin {
    fn drop(&mut self) {
        self.stop();
    }
}

impl SmartdnsOperations for SmartdnsPlugin {
    fn server_query_complete(&self, request: &mut DnsRequest) {
        return self.query_complete(request);
    }

    fn server_init(&mut self, args: &Vec<String>) -> Result<(), Box<dyn Error>> {
        return self.start(args);
    }

    fn server_exit(&mut self) {
        self.stop();
    }
}
