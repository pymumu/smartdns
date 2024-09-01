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

use crate::data_stats::*;
use crate::data_upstream_server::UpstreamServerInfo;
use crate::db::*;
use crate::dns_log;
use crate::plugin::SmartdnsPlugin;
use crate::server_log::ServerLog;
use crate::server_log::ServerLogMsg;
use crate::smartdns;
use crate::smartdns::*;
use crate::utils;
use crate::utils::ResultCache;
use crate::whois;
use crate::whois::WhoIsInfo;

use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{interval_at, Duration, Instant};

pub const DEFAULT_MAX_LOG_AGE: u64 = 30 * 24 * 60 * 60;
pub const DEFAULT_MAX_LOG_AGE_MS: u64 = DEFAULT_MAX_LOG_AGE * 1000;
pub const MAX_LOG_AGE_VALUE_MIN: u64 = 3600;
pub const MAX_LOG_AGE_VALUE_MAX: u64 = 365 * 24 * 60 * 60 * 10;

pub struct OverviewData {
    pub total_query_count: u64,
    pub block_query_count: u64,
    pub avg_query_time: f64,
    pub cache_hit_rate: f64,
    pub cache_number: u64,
}

#[derive(Clone)]
pub struct DataServerConfig {
    pub data_root: String,
    pub max_log_age_ms: u64,
}

impl DataServerConfig {
    pub fn new() -> Self {
        DataServerConfig {
            data_root: Plugin::dns_conf_data_dir() + "/smartdns.db",
            max_log_age_ms: DEFAULT_MAX_LOG_AGE_MS,
        }
    }

    pub fn load_config(&mut self, data_server: Arc<DataServer>) -> Result<(), Box<dyn Error>> {
        self.max_log_age_ms = utils::parse_value(
            data_server.get_server_config("smartdns-ui.max-query-log-age"),
            MAX_LOG_AGE_VALUE_MIN,
            MAX_LOG_AGE_VALUE_MAX,
            DEFAULT_MAX_LOG_AGE,
        ) * 1000;

        let log_level = data_server.get_server_config("log-level");
        if let Some(log_level) = log_level {
            let log_level = log_level.try_into();
            match log_level {
                Ok(log_level) => {
                    dns_log_set_level(log_level);
                }
                Err(_) => {
                    dns_log!(LogLevel::WARN, "log level is invalid");
                }
            }
        }

        Ok(())
    }
}

pub struct DataServerControl {
    data_server: Arc<DataServer>,
    server_thread: Mutex<Option<JoinHandle<()>>>,
    is_init: Mutex<bool>,
    is_run: Mutex<bool>,
    plugin: Mutex<Option<Arc<SmartdnsPlugin>>>,
}

impl DataServerControl {
    pub fn new() -> Self {
        DataServerControl {
            data_server: Arc::new(DataServer::new()),
            server_thread: Mutex::new(None),
            is_init: Mutex::new(false),
            is_run: Mutex::new(false),
            plugin: Mutex::new(None),
        }
    }

    pub fn get_data_server(&self) -> Arc<DataServer> {
        Arc::clone(&self.data_server)
    }

    pub fn set_plugin(&self, plugin: Arc<SmartdnsPlugin>) {
        *self.plugin.lock().unwrap() = Some(plugin);
    }

    pub fn get_plugin(&self) -> Arc<SmartdnsPlugin> {
        let plugin = self.plugin.lock().unwrap();
        Arc::clone(&plugin.as_ref().unwrap())
    }

    pub fn init_db(&self, conf: &DataServerConfig) -> Result<(), Box<dyn Error>> {
        let inner_clone = Arc::clone(&self.data_server);
        let ret = inner_clone.init_server(conf);
        if let Err(e) = ret {
            return Err(e);
        }

        *self.is_init.lock().unwrap() = true;
        Ok(())
    }

    pub fn start_data_server(&self) -> Result<(), Box<dyn Error>> {
        let inner_clone = Arc::clone(&self.data_server);

        if *self.is_init.lock().unwrap() == false {
            return Err("data server not init".into());
        }

        self.data_server.set_plugin(self.get_plugin());
        let rt = self.get_plugin().get_runtime();

        let server_thread = rt.spawn(async move {
            let ret = DataServer::data_server_loop(inner_clone).await;
            if let Err(e) = ret {
                dns_log!(LogLevel::ERROR, "data server error: {}", e);
                Plugin::smartdns_exit(1);
            }

            dns_log!(LogLevel::INFO, "data server exit.");
        });

        *self.is_run.lock().unwrap() = true;
        *self.server_thread.lock().unwrap() = Some(server_thread);
        Ok(())
    }

    pub fn stop_data_server(&self) {
        if *self.is_run.lock().unwrap() == false {
            return;
        }

        self.data_server.stop_data_server();
        let _server_thread = self.server_thread.lock().unwrap().take();
        if let Some(server_thread) = _server_thread {
            let rt = self.get_plugin().get_runtime();
            tokio::task::block_in_place(|| {
                if let Err(e) = rt.block_on(server_thread) {
                    dns_log!(LogLevel::ERROR, "http server stop error: {}", e);
                }
            });
        }
        *self.is_run.lock().unwrap() = false;
    }

    pub fn send_request(&self, request: &mut DnsRequest) -> Result<(), Box<dyn Error>> {
        if let Some(tx) = self.data_server.data_tx.as_ref() {
            tx.try_send(request.clone())?;
        }
        Ok(())
    }

    pub fn server_log(&self, level: LogLevel, msg: &str, msg_len: i32) {
        self.data_server.server_log(level, msg, msg_len);
    }
}

impl Drop for DataServerControl {
    fn drop(&mut self) {
        self.stop_data_server();
    }
}

macro_rules! query_default_with_cache {
    ($cache:expr, $db:expr, $func:ident, $count:expr, $default_count:expr, $result_type:ty) => {{
        if $count.is_none() {
            let db_clone = $db.clone();
            let load_func = move || -> Option<$result_type> {
                let ret = db_clone.$func($default_count);
                if let Ok(ret) = ret {
                    return Some(ret);
                }
                dns_log!(LogLevel::ERROR, "load cache error");
                None
            };
            let ret = $cache.get(load_func);
            if let Some(ret) = ret {
                if ! (*ret).is_empty() {
                    return Ok(ret);
                }
            }

            let ret = $db.$func($default_count);
            if let Ok(ret) = ret {
                $cache.set(ret.clone());
                return Ok(ret);
            }

            return ret;
        }

        $db.$func($count.unwrap_or($default_count))
    }};
}

pub struct DataResultCache {
    hourly_query_count: Arc<ResultCache<Vec<HourlyQueryCount>>>,
    top_client_top_list: Arc<ResultCache<Vec<ClientQueryCount>>>,
    top_domain_top_list: Arc<ResultCache<Vec<DomainQueryCount>>>,
}

pub struct DataServer {
    conf: RwLock<DataServerConfig>,
    notify_tx: Option<mpsc::Sender<()>>,
    notify_rx: Mutex<Option<mpsc::Receiver<()>>>,
    data_tx: Option<mpsc::Sender<DnsRequest>>,
    data_rx: Mutex<Option<mpsc::Receiver<DnsRequest>>>,
    db: Arc<DB>,
    stat: Arc<DataStats>,
    server_log: ServerLog,
    plugin: Mutex<Option<Arc<SmartdnsPlugin>>>,
    result_cache: Arc<DataResultCache>,
    whois: whois::WhoIs,
}

impl DataServer {
    pub fn new() -> Self {
        let mut plugin = DataServer {
            conf: RwLock::new(DataServerConfig::new()),
            notify_tx: None,
            notify_rx: Mutex::new(None),
            data_tx: None,
            data_rx: Mutex::new(None),
            db: Arc::new(DB::new()),
            stat: DataStats::new(),
            server_log: ServerLog::new(),
            plugin: Mutex::new(None),
            result_cache: Arc::new(DataResultCache {
                hourly_query_count: ResultCache::new(Duration::from_secs(60 * 10)),
                top_client_top_list: ResultCache::new(Duration::from_secs(60 * 10)),
                top_domain_top_list: ResultCache::new(Duration::from_secs(60 * 10)),
            }),
            whois: whois::WhoIs::new(),
        };

        let (tx, rx) = mpsc::channel(100);
        plugin.notify_tx = Some(tx);
        plugin.notify_rx = Mutex::new(Some(rx));

        let (tx, rx) = mpsc::channel(4096);
        plugin.data_tx = Some(tx);
        plugin.data_rx = Mutex::new(Some(rx));

        plugin
    }

    fn init_server(&self, conf: &DataServerConfig) -> Result<(), Box<dyn Error>> {
        let mut conf_clone = self.conf.write().unwrap();
        *conf_clone = conf.clone();
        dns_log!(LogLevel::INFO, "open db: {}", conf_clone.data_root);
        let ret = self.db.open(&conf_clone.data_root);
        if let Err(e) = ret {
            return Err(e);
        }

        let ret = self.stat.clone().init();
        if let Err(e) = ret {
            return Err(e);
        }

        Ok(())
    }

    pub fn set_plugin(&self, plugin: Arc<SmartdnsPlugin>) {
        *self.plugin.lock().unwrap() = Some(plugin);
    }

    pub fn get_plugin(&self) -> Arc<SmartdnsPlugin> {
        let plugin = self.plugin.lock().unwrap();
        Arc::clone(&plugin.as_ref().unwrap())
    }

    pub fn get_config(&self, key: &str) -> Option<String> {
        let ret = self.db.get_config(key);
        if let Ok(value) = ret {
            return value;
        }

        None
    }

    pub fn get_server_config(&self, key: &str) -> Option<String> {
        let ret = self.get_config(key);
        if let Some(value) = ret {
            return Some(value);
        }

        let ret = Plugin::dns_conf_plugin_config(key);
        if let Some(value) = ret {
            return Some(value);
        }

        None
    }

    pub async fn whois(&self, domain: &str) -> Result<WhoIsInfo, Box<dyn Error>> {
        self.whois.query(domain).await
    }

    pub fn get_config_list(&self) -> Result<HashMap<String, String>, Box<dyn Error>> {
        self.db.get_config_list()
    }

    pub fn set_config(&self, key: &str, value: &str) -> Result<(), Box<dyn Error>> {
        self.db.set_config(key, value)
    }

    pub fn get_upstream_server_list(&self) -> Result<Vec<UpstreamServerInfo>, Box<dyn Error>> {
        let servers = UpstreamServerInfo::get_all()?;
        Ok(servers)
    }

    pub fn get_domain_list(
        &self,
        param: &DomainListGetParam,
    ) -> Result<QueryDomainListResult, Box<dyn Error>> {
        self.db.get_domain_list(Some(param))
    }

    pub fn get_domain_list_count(&self) -> u32 {
        self.db.get_domain_list_count(None)
    }

    pub fn delete_domain_by_id(&self, id: u64) -> Result<u64, Box<dyn Error>> {
        self.db.delete_domain_by_id(id)
    }

    pub fn delete_domain_before_timestamp(&self, timestamp: u64) -> Result<u64, Box<dyn Error>> {
        self.db.delete_domain_before_timestamp(timestamp)
    }

    pub fn get_client_list(&self) -> Result<Vec<ClientData>, Box<dyn Error>> {
        self.db.get_client_list()
    }

    pub fn get_top_client_top_list(
        &self,
        count: Option<u32>,
    ) -> Result<Vec<ClientQueryCount>, Box<dyn Error>> {
        query_default_with_cache!(
            self.result_cache.top_client_top_list,
            self.db,
            get_client_top_list,
            count,
            10,
            Vec<ClientQueryCount>
        )
    }

    pub fn get_top_domain_top_list(
        &self,
        count: Option<u32>,
    ) -> Result<Vec<DomainQueryCount>, Box<dyn Error>> {
        query_default_with_cache!(
            self.result_cache.top_domain_top_list,
            self.db,
            get_domain_top_list,
            count,
            10,
            Vec<DomainQueryCount>
        )
    }

    pub fn get_hourly_query_count(
        &self,
        past_hours: Option<u32>,
    ) -> Result<Vec<HourlyQueryCount>, Box<dyn Error>> {
        query_default_with_cache!(
            self.result_cache.hourly_query_count,
            self.db,
            get_hourly_query_count,
            past_hours,
            24,
            Vec<HourlyQueryCount>
        )
    }

    pub fn get_overview(&self) -> Result<OverviewData, Box<dyn Error>> {
        let overview = OverviewData {
            total_query_count: smartdns::Stats::get_request_total(),
            block_query_count: smartdns::Stats::get_request_blocked(),
            avg_query_time: smartdns::Stats::get_avg_process_time(),
            cache_hit_rate: smartdns::Stats::get_cache_hit_rate(),
            cache_number: smartdns::Plugin::dns_cache_total_num() as u64,
        };

        Ok(overview)
    }

    pub fn insert_domain_by_list(&self, data: &Vec<DomainData>) -> Result<(), Box<dyn Error>> {
        let mut client_ip = Vec::new();
        for item in data {
            client_ip.push(item.client.clone());
        }
        self.db.insert_client(&client_ip)?;
        self.db.insert_domain(data)
    }

    pub fn insert_domain(&self, data: &DomainData) -> Result<(), Box<dyn Error>> {
        let client_ip = vec![data.client.clone()];
        self.db.insert_client(&client_ip)?;
        let list = vec![data.clone()];
        self.db.insert_domain(&list)
    }

    async fn data_server_handle_dns_request(this: Arc<DataServer>, req_list: &Vec<DnsRequest>) {
        let mut data_list = Vec::new();
        for req in req_list {
            if req.is_prefetch_request() {
                continue;
            }

            if req.is_dualstack_request() {
                continue;
            }

            let domain_data = DomainData {
                id: 0,
                domain: req.get_domain(),
                domain_type: req.get_qtype(),
                client: req.get_remote_addr(),
                domain_group: req.get_group_name(),
                reply_code: req.get_rcode(),
                timestamp: req.get_query_timestamp(),
                query_time: req.get_query_time(),
                ping_time: req.get_ping_time(),
                is_blocked: req.get_is_blocked(),
                is_cached: req.get_is_cached(),
            };
            dns_log!(
                LogLevel::DEBUG,
                "insert domain:{}, type:{}",
                domain_data.domain,
                domain_data.domain_type
            );

            data_list.push(domain_data);
        }

        dns_log!(
            LogLevel::DEBUG,
            "insert domain list count:{}",
            data_list.len()
        );
        let ret = this.insert_domain_by_list(&data_list);
        if let Err(e) = ret {
            dns_log!(LogLevel::ERROR, "insert domain error: {}", e);
        }
    }

    async fn hourly_work(this: Arc<DataServer>) {
        dns_log!(LogLevel::ERROR, "start hourly work");
        let now = get_utc_time_ms();

        let ret = this
            .delete_domain_before_timestamp(now - this.conf.read().unwrap().max_log_age_ms as u64);
        if let Err(e) = ret {
            dns_log!(
                LogLevel::WARN,
                "delete domain before timestamp error: {}",
                e
            );
        }
    }

    pub async fn get_log_stream(&self) -> mpsc::Receiver<ServerLogMsg> {
        return self.server_log.get_log_stream().await;
    }

    pub fn server_log(&self, level: LogLevel, msg: &str, msg_len: i32) {
        self.server_log.dispatch_log(level, msg, msg_len);
    }

    async fn data_server_loop(this: Arc<DataServer>) -> Result<(), Box<dyn Error>> {
        let mut rx: mpsc::Receiver<()>;
        let mut data_rx: mpsc::Receiver<DnsRequest>;

        {
            let mut _rx = this.notify_rx.lock().unwrap();
            rx = _rx.take().unwrap();
            let mut _rx = this.data_rx.lock().unwrap();
            data_rx = _rx.take().unwrap();
        }

        this.stat.clone().start_worker()?;

        let start: Instant = Instant::now() + Duration::from_secs(utils::seconds_until_next_hour());
        let mut hour_timer = interval_at(start, Duration::from_secs(60 * 60));
        let mut req_list: Vec<DnsRequest> = Vec::new();
        let mut batch_timer: Option<tokio::time::Interval> = None;

        dns_log!(LogLevel::INFO, "data server start.");

        loop {
            tokio::select! {
                _ = rx.recv() => {
                    break;
                }
                _ = hour_timer.tick() => {
                    DataServer::hourly_work(this.clone()).await;
                }
                _ = async {
                    if let Some(ref mut timer) = batch_timer {
                        timer.tick().await;
                    }
                }, if batch_timer.is_some() => {
                    DataServer::data_server_handle_dns_request(this.clone(), &req_list).await;
                    req_list.clear();
                    batch_timer = None;
                }
                res = data_rx.recv() => {
                    match res {
                        Some(req) => {
                            req_list.push(req);
                            if req_list.len() == 1 {
                                batch_timer = Some(tokio::time::interval_at(
                                    Instant::now() + Duration::from_millis(500),
                                    Duration::from_secs(1),
                                ));
                            }

                            if req_list.len() < 1000 {
                                continue;
                            }

                            DataServer::data_server_handle_dns_request(this.clone(), &req_list).await;
                            req_list.clear();
                            batch_timer = None;
                        }
                        None => {
                            continue;
                        }
                    }
                }
            }
        }

        this.stat.clone().stop_worker();

        Ok(())
    }

    fn stop_data_server(&self) {
        if let Some(tx) = self.notify_tx.as_ref().cloned() {
            let rt = self.get_plugin().get_runtime();
            tokio::task::block_in_place(|| {
                let _ = rt.block_on(async {
                    let _ = tx.send(()).await;
                });
            });
        }
    }
}
