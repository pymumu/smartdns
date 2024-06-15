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
use crate::dns_log;
use crate::smartdns::*;

use std::error::Error;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use tokio::sync::mpsc;
use tokio::time::{interval_at, Duration, Instant};

#[derive(Clone)]
pub struct DataServerConfig {
    pub data_root: String,
    pub max_log_age_ms: u32,
}

impl DataServerConfig {
    pub fn new() -> Self {
        DataServerConfig {
            data_root: Plugin::dns_conf_data_dir() + "/ui.db",
            // max_log_age_ms: 7 * 24 * 60 * 60 * 1000,
            max_log_age_ms: 60 * 60 * 1000,
        }
    }
}

pub struct DataServerControl {
    data_server: Arc<DataServer>,
    server_thread: Mutex<Option<thread::JoinHandle<()>>>,
}

impl DataServerControl {
    pub fn new() -> Self {
        DataServerControl {
            data_server: Arc::new(DataServer::new()),
            server_thread: Mutex::new(None),
        }
    }

    pub fn get_data_server(&self) -> Arc<DataServer> {
        Arc::clone(&self.data_server)
    }

    pub fn start_data_server(&self, conf: &DataServerConfig) -> Result<(), Box<dyn Error>> {
        let inner_clone = Arc::clone(&self.data_server);

        let ret = inner_clone.init_server(conf);
        if let Err(e) = ret {
            return Err(e);
        }

        let server_thread = thread::spawn(move || {
            let ret = DataServer::data_server_loop(inner_clone);
            if let Err(e) = ret {
                dns_log!(LogLevel::ERROR, "data server error: {}", e);
                Plugin::smartdns_exit(1);
            }
        });

        *self.server_thread.lock().unwrap() = Some(server_thread);
        Ok(())
    }

    pub fn stop_data_server(&self) {
        self.data_server.stop_data_server();
        let _server_thread = self.server_thread.lock().unwrap().take();
        if let Some(server_thread) = _server_thread {
            server_thread.join().unwrap();
        }
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
            dns_log!(LogLevel::ERROR, "open db error: {}", e);
            return Err(e);
        }
        Ok(())
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

    pub fn insert_domain(&self, data: &DomainData) -> Result<(), Box<dyn Error>> {
        self.db.insert_domain(data)
    }

    async fn data_server_handle(this: Arc<DataServer>, req: DnsRequest) {
        let domain_data = DomainData {
            id: 0,
            domain: req.get_domain(),
            domain_type: req.get_qtype(),
            client: req.get_remote_addr(),
            domain_group: req.get_group_name(),
            reply_code: req.get_rcode(),
            timestamp: req.get_query_time(),
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
        dns_log!(LogLevel::INFO, "start hourly work");
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

        let start = Instant::now() + Duration::from_secs(60);
        let mut hour_timer = interval_at(start, Duration::from_secs(60 * 60));

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
