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
use crate::db::*;
use crate::dns_log;
use crate::smartdns;
use crate::smartdns::*;
use crate::utils;

use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use tokio::sync::mpsc;
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
}

#[derive(Clone)]
pub struct DataServerConfig {
    pub data_root: String,
    pub max_log_age_ms: u64,
}

impl DataServerConfig {
    pub fn new() -> Self {
        DataServerConfig {
            data_root: Plugin::dns_conf_data_dir() + "/ui.db",
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
    server_thread: Mutex<Option<thread::JoinHandle<()>>>,
    is_init: Mutex<bool>,
    is_run: Mutex<bool>,
}

impl DataServerControl {
    pub fn new() -> Self {
        DataServerControl {
            data_server: Arc::new(DataServer::new()),
            server_thread: Mutex::new(None),
            is_init: Mutex::new(false),
            is_run: Mutex::new(false),
        }
    }

    pub fn get_data_server(&self) -> Arc<DataServer> {
        Arc::clone(&self.data_server)
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

        let server_thread = thread::spawn(move || {
            let ret = DataServer::data_server_loop(inner_clone);
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
            server_thread.join().unwrap();
        }
        *self.is_run.lock().unwrap() = false;
    }

    pub fn send_request(&self, request: &mut DnsRequest) -> Result<(), Box<dyn Error>> {
        if let Some(tx) = self.data_server.data_tx.as_ref() {
            tx.try_send(request.clone())?;
        }
        Ok(())
    }
}

impl Drop for DataServerControl {
    fn drop(&mut self) {
        self.stop_data_server();
    }
}

pub struct DataServer {
    conf: RwLock<DataServerConfig>,
    notify_tx: Option<mpsc::Sender<()>>,
    notify_rx: Mutex<Option<mpsc::Receiver<()>>>,
    data_tx: Option<mpsc::Sender<DnsRequest>>,
    data_rx: Mutex<Option<mpsc::Receiver<DnsRequest>>>,
    db: DB,
    stat: Arc<DataStats>,
}

impl DataServer {
    pub fn new() -> Self {
        let mut plugin = DataServer {
            conf: RwLock::new(DataServerConfig::new()),
            notify_tx: None,
            notify_rx: Mutex::new(None),
            data_tx: None,
            data_rx: Mutex::new(None),
            db: DB::new(),
            stat: DataStats::new(),
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

    pub fn get_config_list(&self) -> Result<HashMap<String, String>, Box<dyn Error>> {
        self.db.get_config_list()
    }

    pub fn set_config(&self, key: &str, value: &str) -> Result<(), Box<dyn Error>> {
        self.db.set_config(key, value)
    }

    pub fn get_domain_list(
        &self,
        param: &DomainListGetParam,
    ) -> Result<Vec<DomainData>, Box<dyn Error>> {
        self.db.get_domain_list(param)
    }

    pub fn get_domain_list_count(&self) -> u32 {
        self.db.get_domain_list_count()
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
        count: u32,
    ) -> Result<Vec<ClientQueryCount>, Box<dyn Error>> {
        self.db.get_client_top_list(count)
    }

    pub fn get_top_domain_top_list(
        &self,
        count: u32,
    ) -> Result<Vec<DomainQueryCount>, Box<dyn Error>> {
        self.db.get_domain_top_list(count)
    }

    pub fn get_hourly_query_count(&self, pastt_hours: u32) -> Result<Vec<HourlyQueryCount>, Box<dyn Error>> {
        self.db.get_hourly_query_count(pastt_hours)
    }

    pub fn get_overview(&self) -> Result<OverviewData, Box<dyn Error>> {
        let overview = OverviewData {
            total_query_count: smartdns::Stats::get_request_total(),
            block_query_count: smartdns::Stats::get_request_blocked(),
            avg_query_time: smartdns::Stats::get_avg_process_time(),
            cache_hit_rate: smartdns::Stats::get_cache_hit_rate(),
        };

        Ok(overview)
    }

    pub fn insert_domain(&self, data: &DomainData) -> Result<(), Box<dyn Error>> {
        let client_ip = &data.client;
        self.db.insert_client(client_ip.as_str())?;
        self.db.insert_domain(data)
    }

    async fn data_server_handle(this: Arc<DataServer>, req: DnsRequest) {
        if req.is_prefetch_request() {
            return;
        }

        if req.is_dualstack_request() {
            return;
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

        let ret = this.insert_domain(&domain_data);
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

    #[tokio::main]
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

        let start: Instant =
            Instant::now() + Duration::from_secs(utils::seconds_until_next_hour());
        let mut hour_timer = interval_at(start, Duration::from_secs(60 * 60));

        dns_log!(LogLevel::INFO, "data server start.");

        loop {
            tokio::select! {
                _ = rx.recv() => {
                    break;
                }
                _ = hour_timer.tick() => {
                    DataServer::hourly_work(this.clone()).await;
                }
                res = data_rx.recv() => {
                    match res {
                        Some(req) => {
                            DataServer::data_server_handle(this.clone(), req).await;
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
            let t = thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async move {
                    _ = tx.send(()).await;
                });
            });

            let _ = t.join();
        }
    }
}
