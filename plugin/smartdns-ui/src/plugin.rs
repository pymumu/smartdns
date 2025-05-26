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

use crate::data_server::*;
use crate::dns_log;
use crate::http_server::*;
use crate::smartdns::*;

use getopts::Options;
use std::error::Error;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::runtime::Builder;
use tokio::runtime::Runtime;

pub struct SmartdnsPlugin {
    http_server_ctl: Arc<HttpServerControl>,
    http_conf: Mutex<HttpServerConfig>,

    data_server_ctl: Arc<DataServerControl>,
    data_conf: Mutex<DataServerConfig>,

    runtime: Arc<Runtime>,
}

impl SmartdnsPlugin {
    pub fn new() -> Arc<Self> {
        let rt = Builder::new_multi_thread()
            .enable_all()
            .thread_name("smartdns-ui")
            .thread_keep_alive(tokio::time::Duration::from_secs(30))
            .build()
            .unwrap();
        let plugin = Arc::new(SmartdnsPlugin {
            http_server_ctl: Arc::new(HttpServerControl::new()),
            http_conf: Mutex::new(HttpServerConfig::new()),

            data_server_ctl: Arc::new(DataServerControl::new()),
            data_conf: Mutex::new(DataServerConfig::new()),
            runtime: Arc::new(rt),
        });

        plugin.http_server_ctl.set_plugin(plugin.clone());
        plugin.data_server_ctl.set_plugin(plugin.clone());

        plugin
    }

    pub fn get_runtime(&self) -> Arc<Runtime> {
        self.runtime.clone()
    }

    pub fn get_http_server(&self) -> Arc<HttpServer> {
        self.http_server_ctl.get_http_server()
    }

    pub fn get_data_server(&self) -> Arc<DataServer> {
        self.data_server_ctl.get_data_server()
    }

    fn parser_args(&self, args: &Vec<String>) -> Result<(), Box<dyn Error>> {
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

        let mut http_conf = self.http_conf.lock().unwrap();
        let mut data_conf = self.data_conf.lock().unwrap();

        let www_root = Plugin::dns_conf_plugin_config("smartdns-ui.www-root");
        if let Some(www_root) = www_root {
            http_conf.http_root = smartdns_conf_get_conf_fullpath(&www_root);
        }

        let ip = Plugin::dns_conf_plugin_config("smartdns-ui.ip");
        if let Some(ip) = ip {
            http_conf.http_ip = ip;
        }

        if let Some(ip) = matches.opt_str("i") {
            http_conf.http_ip = ip;
        }

        if let Some(root) = matches.opt_str("r") {
            http_conf.http_root = root;
        }
        dns_log!(LogLevel::INFO, "www root: {}", http_conf.http_root);

        let mut token_expire = Plugin::dns_conf_plugin_config("smartdns-ui.token-expire");
        if token_expire.is_none() {
            token_expire = matches.opt_str("token-expire");
        }
        if let Some(token_expire) = token_expire {
            let v = token_expire.parse::<u32>();
            if let Err(e) = v {
                dns_log!(
                    LogLevel::ERROR,
                    "parse token expire time error: {}",
                    e.to_string()
                );
                return Err(Box::new(e));
            }
            http_conf.token_expired_time = v.unwrap();
        }

        if let Some(data_dir) = matches.opt_str("data-dir") {
            data_conf.data_root = data_dir;
        }

        Ok(())
    }

    pub fn load_config(&self) -> Result<(), Box<dyn Error>> {
        let data_server = self.get_data_server();
        self.data_conf
            .lock()
            .unwrap()
            .load_config(data_server.clone())?;
        self.http_conf
            .lock()
            .unwrap()
            .load_config(data_server.clone())?;
        Ok(())
    }

    pub fn start(&self, args: &Vec<String>) -> Result<(), Box<dyn Error>> {
        self.parser_args(args)?;
        self.data_server_ctl
            .init_db(&self.data_conf.lock().unwrap())?;
        self.load_config()?;
        self.data_server_ctl.start_data_server()?;
        let http_conf = self.http_conf.lock().unwrap().clone();
        self.http_server_ctl.start_http_server(&http_conf)?;

        Ok(())
    }

    pub fn stop(&self) {
        self.http_server_ctl.stop_http_server();
        self.data_server_ctl.stop_data_server();
    }

    pub fn query_complete(&self, request: Box<dyn DnsRequest>) -> Result<(), Box<dyn Error>> {
        let ret = self.data_server_ctl.send_request(request);
        if let Err(e) = ret {
            dns_log!(LogLevel::ERROR, "send request error: {}", e.to_string());
            return Err(e);
        }

        Ok(())
    }

    pub fn server_log(&self, level: LogLevel, msg: &str, msg_len: i32) {
        self.data_server_ctl.server_log(level, msg, msg_len);
    }
}

impl Drop for SmartdnsPlugin {
    fn drop(&mut self) {
        self.stop();
    }
}

pub struct SmartdnsPluginImpl {
    plugin: Arc<SmartdnsPlugin>,
}

impl SmartdnsPluginImpl {
    pub fn new() -> Self {
        SmartdnsPluginImpl {
            plugin: SmartdnsPlugin::new(),
        }
    }
}

impl Drop for SmartdnsPluginImpl {
    fn drop(&mut self) {
        self.plugin.stop();
    }
}

impl SmartdnsOperations for SmartdnsPluginImpl {
    fn server_query_complete(&self, request: Box<dyn DnsRequest>) {
        let _ = self.plugin.query_complete(request);
    }

    fn server_log(&self, level: LogLevel, msg: &str, msg_len: i32) {
        self.plugin.server_log(level, msg, msg_len);
    }

    fn server_init(&mut self, args: &Vec<String>) -> Result<(), Box<dyn Error>> {
        self.plugin.start(args)
    }

    fn server_exit(&mut self) {
        self.plugin.stop();
    }
}
