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
use crate::whois;
use crate::whois::WhoIsInfo;

use std::collections::HashMap;
use std::error::Error;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tokio::time::Instant;

pub const DEFAULT_MAX_LOG_AGE: u64 = 30 * 24 * 60 * 60;
pub const DEFAULT_MAX_LOG_AGE_MS: u64 = DEFAULT_MAX_LOG_AGE * 1000;
pub const MAX_LOG_AGE_VALUE_MIN: u64 = 3600;
pub const MAX_LOG_AGE_VALUE_MAX: u64 = 365 * 24 * 60 * 60 * 10;
pub const MIN_FREE_DISK_SPACE: u64 = 1024 * 1024 * 8;

#[derive(Clone)]
pub struct OverviewData {
    pub server_name: String,
    pub db_size: u64,
    pub startup_timestamp: u64,
    pub free_disk_space: u64,
    pub is_process_suspended: bool,
}

#[derive(Clone)]
pub struct MetricsData {
    pub total_query_count: u64,
    pub block_query_count: u64,
    pub avg_query_time: f64,
    pub cache_hit_rate: f64,
    pub cache_number: u64,
    pub cache_memory_size: u64,
    pub qps: u32,
    pub memory_usage: u64,
    pub is_metrics_suspended: bool,
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

    pub fn send_request(&self, request: Box<dyn DnsRequest>) -> Result<(), Box<dyn Error>> {
        if request.is_prefetch_request() {
            return Ok(());
        }

        self.data_server.get_stat().add_qps_count(1);

        if self.data_server.is_handle_request_disabled() {
            return Ok(());
        }

        if let Some(tx) = self.data_server.data_tx.as_ref() {
            let ret = tx.try_send(request);
            if let Err(e) = ret {
                self.data_server.get_stat().add_request_drop(1);
                return Err(e.to_string().into());
            }
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

pub struct DataServer {
    conf: Arc<RwLock<DataServerConfig>>,
    notify_tx: Option<mpsc::Sender<()>>,
    notify_rx: Mutex<Option<mpsc::Receiver<()>>>,
    data_tx: Option<mpsc::Sender<Box<dyn DnsRequest>>>,
    data_rx: Mutex<Option<mpsc::Receiver<Box<dyn DnsRequest>>>>,
    db: Arc<DB>,
    disable_handle_request: AtomicBool,
    stat: Arc<DataStats>,
    server_log: ServerLog,
    plugin: Mutex<Option<Arc<SmartdnsPlugin>>>,
    whois: whois::WhoIs,
    startup_timestamp: u64,
    recv_in_batch: Mutex<bool>,
}

impl DataServer {
    pub fn new() -> Self {
        let db = Arc::new(DB::new());
        let conf = Arc::new(RwLock::new(DataServerConfig::new()));
        let mut plugin = DataServer {
            conf: conf.clone(),
            notify_tx: None,
            notify_rx: Mutex::new(None),
            data_tx: None,
            data_rx: Mutex::new(None),
            db: db.clone(),
            stat: DataStats::new(db, conf.clone()),
            server_log: ServerLog::new(),
            plugin: Mutex::new(None),
            whois: whois::WhoIs::new(),
            startup_timestamp: get_utc_time_ms(),
            disable_handle_request: AtomicBool::new(false),
            recv_in_batch: Mutex::new(true),
        };

        let (tx, rx) = mpsc::channel(100);
        plugin.notify_tx = Some(tx);
        plugin.notify_rx = Mutex::new(Some(rx));

        let (tx, rx) = mpsc::channel(1024 * 32);
        plugin.data_tx = Some(tx);
        plugin.data_rx = Mutex::new(Some(rx));

        plugin
    }

    pub fn get_recv_in_batch(&self) -> bool {
        *self.recv_in_batch.lock().unwrap()
    }

    pub fn set_recv_in_batch(&self, recv_in_batch: bool) {
        *self.recv_in_batch.lock().unwrap() = recv_in_batch;
    }

    fn init_server(&self, conf: &DataServerConfig) -> Result<(), Box<dyn Error>> {
        let mut conf_clone = self.conf.write().unwrap();
        *conf_clone = conf.clone();

        smartdns::smartdns_enable_update_neighbour(true);

        dns_log!(LogLevel::INFO, "open db: {}", conf_clone.data_root);
        let ret = self.db.open(&conf_clone.data_root);
        if let Err(e) = ret {
            return Err(e);
        }

        let ret = self.stat.init();
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

    pub fn get_data_server_config(&self) -> DataServerConfig {
        let conf = self.conf.read().unwrap();
        conf.clone()
    }

    pub fn get_config(&self, key: &str) -> Option<String> {
        let ret = self.db.get_config(key);
        if let Ok(value) = ret {
            return value;
        }

        None
    }

    pub fn get_server_config_from_file(&self, key: &str) -> Option<String> {
        let ret = Plugin::dns_conf_plugin_config(key);
        if let Some(value) = ret {
            return Some(value);
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

    pub fn get_domain_list_count(&self) -> u64 {
        self.db.get_domain_list_count(None)
    }

    pub fn delete_domain_by_id(&self, id: u64) -> Result<u64, Box<dyn Error>> {
        self.db.delete_domain_by_id(id)
    }

    pub fn delete_domain_before_timestamp(&self, timestamp: u64) -> Result<u64, Box<dyn Error>> {
        self.db.delete_domain_before_timestamp(timestamp)
    }

    pub fn delete_client_by_id(&self, id: u64) -> Result<u64, Box<dyn Error>> {
        self.db.delete_client_by_id(id)
    }

    pub fn get_client_list(&self) -> Result<Vec<ClientData>, Box<dyn Error>> {
        self.db.get_client_list()
    }

    pub fn get_top_client_top_list(
        &self,
        count: Option<u32>,
    ) -> Result<Vec<ClientQueryCount>, Box<dyn Error>> {
        self.db.get_client_top_list(count.unwrap_or(10))
    }

    pub fn get_top_domain_top_list(
        &self,
        count: Option<u32>,
    ) -> Result<Vec<DomainQueryCount>, Box<dyn Error>> {
        self.db.get_domain_top_list(count.unwrap_or(10))
    }

    pub fn get_hourly_query_count(
        &self,
        past_hours: Option<u32>,
    ) -> Result<HourlyQueryCount, Box<dyn Error>> {
        self.db.get_hourly_query_count(past_hours.unwrap_or(24))
    }

    pub fn get_daily_query_count(
        &self,
        past_days: Option<u32>,
    ) -> Result<DailyQueryCount, Box<dyn Error>> {
        self.db.get_daily_query_count(past_days.unwrap_or(30))
    }

    pub fn get_stat(&self) -> Arc<DataStats> {
        self.stat.clone()
    }

    pub fn get_metrics(&self) -> Result<MetricsData, Box<dyn Error + Send>> {
        let metrics = MetricsData {
            total_query_count: self.stat.get_total_request(),
            block_query_count: self.stat.get_total_blocked_request(),
            avg_query_time: smartdns::Stats::get_avg_process_time(),
            cache_hit_rate: smartdns::Stats::get_cache_hit_rate(),
            cache_number: smartdns::Plugin::dns_cache_total_num() as u64,
            cache_memory_size: smartdns::Stats::get_cache_memory_size(),
            qps: self.stat.get_qps(),
            memory_usage: self.stat.get_memory_usage(),
            is_metrics_suspended: self.is_handle_request_disabled(),
        };

        Ok(metrics)
    }

    pub fn is_handle_request_disabled(&self) -> bool {
        self.disable_handle_request
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn get_free_disk_space(&self) -> u64 {
        utils::get_free_disk_space(&self.get_data_server_config().data_root)
    }

    pub fn get_overview(&self) -> Result<OverviewData, Box<dyn Error + Send>> {
        let overview = OverviewData {
            server_name: smartdns::smartdns_get_server_name(),
            db_size: self.db.get_db_size(),
            startup_timestamp: self.startup_timestamp,
            free_disk_space: self.get_free_disk_space(),
            is_process_suspended: self.is_handle_request_disabled(),
        };

        Ok(overview)
    }

    pub fn insert_client_by_list(&self, data: &Vec<ClientData>) -> Result<(), Box<dyn Error>> {
        self.db.insert_client(data)
    }

    pub fn insert_domain_by_list(&self, data: &Vec<DomainData>) -> Result<(), Box<dyn Error>> {
        self.db.insert_domain(data)
    }

    pub fn insert_domain(&self, data: &DomainData) -> Result<(), Box<dyn Error>> {
        let list = vec![data.clone()];
        self.stat.add_total_request(1);
        if data.is_blocked {
            self.stat.add_total_blocked_request(1);
        }

        self.db.insert_domain(&list)
    }

    async fn data_server_handle_dns_request(
        this: Arc<DataServer>,
        req_list: &Vec<Box<dyn DnsRequest>>,
    ) {
        let mut domain_data_list = Vec::new();
        let mut client_data_list = Vec::new();
        let mut blocked_num = 0;
        let timestamp_now = get_utc_time_ms();

        for req in req_list {
            if req.is_prefetch_request() {
                continue;
            }

            if req.is_dualstack_request() {
                continue;
            }

            if req.get_is_blocked() {
                blocked_num += 1;
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

            domain_data_list.push(domain_data);

            let mac_str = req
                .get_remote_mac()
                .iter()
                .map(|byte| format!("{:02x}", byte))
                .collect::<Vec<String>>()
                .join(":");

            let client_data = ClientData {
                id: 0,
                client_ip: req.get_remote_addr(),
                hostname: "".to_string(),
                mac: mac_str,
                last_query_timestamp: timestamp_now,
            };

            client_data_list.push(client_data);
        }

        this.stat.add_total_request(domain_data_list.len() as u64);
        this.stat.add_total_blocked_request(blocked_num as u64);

        dns_log!(
            LogLevel::DEBUG,
            "insert domain list count:{}",
            domain_data_list.len()
        );

        let ret = DataServer::call_blocking(this.clone(), move || {
            let _ = match this.insert_domain_by_list(&domain_data_list) {
                Ok(v) => v,
                Err(e) => return Err(e.to_string()),
            };

            let ret = match this.insert_client_by_list(&client_data_list) {
                Ok(v) => v,
                Err(e) => return Err(e.to_string()),
            };

            Ok(ret)
        })
        .await;

        if let Err(e) = ret {
            dns_log!(LogLevel::ERROR, "insert domain error: {}", e);
            return;
        }

        let ret = ret.unwrap();

        if let Err(e) = ret {
            dns_log!(LogLevel::ERROR, "insert domain error: {}", e);
        }
    }

    pub async fn get_log_stream(&self) -> mpsc::Receiver<ServerLogMsg> {
        return self.server_log.get_log_stream().await;
    }

    pub fn server_log(&self, level: LogLevel, msg: &str, msg_len: i32) {
        self.server_log.dispatch_log(level, msg, msg_len);
    }

    fn server_check(&self) {
        let free_disk_space = self.get_free_disk_space();
        if free_disk_space < MIN_FREE_DISK_SPACE {
            if self
                .disable_handle_request
                .fetch_or(true, std::sync::atomic::Ordering::Relaxed)
            {
                return;
            }

            dns_log!(
                LogLevel::WARN,
                "free disk space is low, stop handle request. {}",
                self.disable_handle_request
                    .load(std::sync::atomic::Ordering::Relaxed)
            );
        } else {
            if !self
                .disable_handle_request
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                return;
            }

            self.disable_handle_request
                .store(false, std::sync::atomic::Ordering::Relaxed);
            dns_log!(
                LogLevel::INFO,
                "free disk space is enough, start handle request."
            );
        }
    }

    async fn data_server_loop(this: Arc<DataServer>) -> Result<(), Box<dyn Error>> {
        let mut rx: mpsc::Receiver<()>;
        let mut data_rx: mpsc::Receiver<Box<dyn DnsRequest>>;
        let batch_mode  = *this.recv_in_batch.lock().unwrap();

        {
            let mut _rx = this.notify_rx.lock().unwrap();
            rx = _rx.take().unwrap();
            let mut _rx = this.data_rx.lock().unwrap();
            data_rx = _rx.take().unwrap();
        }

        this.stat.clone().start_worker()?;

        let mut req_list: Vec<Box<dyn DnsRequest>> = Vec::new();
        let mut batch_timer: Option<tokio::time::Interval> = None;
        let mut check_timer = tokio::time::interval(Duration::from_secs(60));
        let is_check_timer_running = Arc::new(AtomicBool::new(false));

        dns_log!(LogLevel::INFO, "data server start.");

        loop {
            tokio::select! {
                _ = rx.recv() => {
                    break;
                }
                _ = check_timer.tick() => {
                    if is_check_timer_running.fetch_xor(true, std::sync::atomic::Ordering::Relaxed) {
                        continue;
                    }

                    let is_check_timer_running_clone = is_check_timer_running.clone();
                    let this_clone = this.clone();
                    let ret = DataServer::call_blocking(this.clone(), move || {
                        this_clone.server_check();
                        is_check_timer_running_clone.store(false, std::sync::atomic::Ordering::Relaxed);
                    }).await;

                    if let Err(e) = ret {
                        dns_log!(LogLevel::WARN, "data server check error: {}", e);
                    }
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

                            if batch_mode {
                                if req_list.len() == 1 {
                                    batch_timer = Some(tokio::time::interval_at(
                                        Instant::now() + Duration::from_millis(500),
                                        Duration::from_secs(1),
                                    ));
                                }

                                if req_list.len() <= 65535 {
                                    continue;
                                }
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

    async fn call_blocking<F, R>(
        this: Arc<DataServer>,
        func: F,
    ) -> Result<R, Box<dyn std::error::Error + Send>>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let rt = this.get_plugin().get_runtime();

        let ret = rt.spawn_blocking(move || -> R {
            return func();
        });

        let ret = ret.await;
        if ret.is_err() {
            return Err(Box::new(ret.err().unwrap()));
        }

        let ret = ret.unwrap();

        return Ok(ret);
    }
}
