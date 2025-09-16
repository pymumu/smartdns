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

use std::{
    collections::HashMap,
    error::Error,
    sync::{atomic::AtomicU32, RwLock},
};

use crate::{data_server::DataServerConfig, db::*, dns_log, smartdns::*, utils};

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

#[cfg(target_has_atomic = "64")]
use std::sync::atomic::AtomicU64;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{interval_at, Instant};

#[cfg(target_has_atomic = "64")]
struct DataStatsItem {
    total_request: AtomicU64,
    total_blocked_request: AtomicU64,
    total_failed_request: AtomicU64,
    qps: AtomicU32,
    qps_count: AtomicU32,
    request_dropped: AtomicU64,
}

#[cfg(not(target_has_atomic = "64"))]
struct DataStatsItem {
    total_request: Arc<Mutex<u64>>,
    total_blocked_request: Arc<Mutex<u64>>,
    total_failed_request: Arc<Mutex<u64>>,
    qps: AtomicU32,
    qps_count: AtomicU32,
    request_dropped: Arc<Mutex<u64>>,
}

impl DataStatsItem {
    pub fn new() -> Self {
        #[cfg(target_has_atomic = "64")]
        let ret = DataStatsItem {
            total_request: 0.into(),
            total_blocked_request: 0.into(),
            total_failed_request: 0.into(),
            qps: 0.into(),
            qps_count: 0.into(),
            request_dropped: 0.into(),
        };
        #[cfg(not(target_has_atomic = "64"))]
        let ret = DataStatsItem {
            total_request: Arc::new(Mutex::new(0)),
            total_blocked_request: Arc::new(Mutex::new(0)),
            total_failed_request: Arc::new(Mutex::new(0)),
            qps: 0.into(),
            qps_count: 0.into(),
            request_dropped: Arc::new(Mutex::new(0)),
        };

        return ret;
    }

    pub fn get_qps(&self) -> u32 {
        return self.qps.load(Ordering::Relaxed);
    }

    pub fn add_qps_count(&self, count: u32) {
        self.qps_count.fetch_add(count, Ordering::Relaxed);
    }

    pub fn update_qps(&self) {
        let qps = self.qps_count.fetch_and(0, Ordering::Relaxed);
        self.qps.store(qps, Ordering::Relaxed);
    }

    pub fn add_request_drop(&self, count: u64) {
        #[cfg(target_has_atomic = "64")]
        {
            self.request_dropped.fetch_and(count, Ordering::Relaxed);
        }

        #[cfg(not(target_has_atomic = "64"))]
        {
            let mut dropped = self.request_dropped.lock().unwrap();
            *dropped += count;
        }
    }

    pub fn get_total_request(&self) -> u64 {
        #[cfg(target_has_atomic = "64")]
        {
            return self.total_request.load(Ordering::Relaxed);
        }

        #[cfg(not(target_has_atomic = "64"))]
        {
            let total = self.total_request.lock().unwrap();
            return *total;
        }
    }

    pub fn add_total_request(&self, total: u64) {
        #[cfg(target_has_atomic = "64")]
        {
            self.total_request.fetch_add(total, Ordering::Relaxed);
        }

        #[cfg(not(target_has_atomic = "64"))]
        {
            let mut total_request = self.total_request.lock().unwrap();
            *total_request += total;
        }
    }

    pub fn get_total_blocked_request(&self) -> u64 {
        #[cfg(target_has_atomic = "64")]
        {
            return self.total_blocked_request.load(Ordering::Relaxed);
        }

        #[cfg(not(target_has_atomic = "64"))]
        {
            let total = self.total_blocked_request.lock().unwrap();
            return *total;
        }
    }

    pub fn add_total_blocked_request(&self, total: u64) {
        #[cfg(target_has_atomic = "64")]
        {
            self.total_blocked_request
                .fetch_add(total, Ordering::Relaxed);
        }

        #[cfg(not(target_has_atomic = "64"))]
        {
            let mut total_blocked_request = self.total_blocked_request.lock().unwrap();
            *total_blocked_request += total;
        }
    }

    pub fn add_total_failed_request(&self, total: u64) {
        #[cfg(target_has_atomic = "64")]
        {
            self.total_failed_request
                .fetch_add(total, Ordering::Relaxed);
        }

        #[cfg(not(target_has_atomic = "64"))]
        {
            let mut total_failed_request = self.total_failed_request.lock().unwrap();
            *total_failed_request += total;
        }
    }

    pub fn get_total_failed_request(&self) -> u64 {
        #[cfg(target_has_atomic = "64")]
        {
            return self.total_failed_request.load(Ordering::Relaxed);
        }

        #[cfg(not(target_has_atomic = "64"))]
        {
            let total = self.total_failed_request.lock().unwrap();
            return *total;
        }
    }

    #[allow(dead_code)]
    pub fn get_current_hour_total(&self) -> u64 {
        return Stats::get_request_total();
    }
}

pub struct DataStats {
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    notify_tx: Option<mpsc::Sender<()>>,
    notify_rx: Mutex<Option<mpsc::Receiver<()>>>,
    is_run: AtomicBool,
    data: DataStatsItem,
    db: Arc<crate::db::DB>,
    conf: Arc<RwLock<DataServerConfig>>,
    is_hourly_work_running: AtomicBool,
}

impl DataStats {
    pub fn new(db: Arc<crate::db::DB>, conf: Arc<RwLock<DataServerConfig>>) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(100);

        Arc::new(DataStats {
            task: Mutex::new(None),
            notify_rx: Mutex::new(Some(rx)),
            notify_tx: Some(tx),
            is_run: AtomicBool::new(false),
            data: DataStatsItem::new(),
            db: db,
            conf: conf,
            is_hourly_work_running: AtomicBool::new(false),
        })
    }

    pub fn get_qps(&self) -> u32 {
        return self.data.get_qps();
    }

    pub fn add_qps_count(&self, count: u32) {
        self.data.add_qps_count(count);
    }

    pub fn update_qps(&self) {
        self.data.update_qps();
    }

    pub fn add_request_drop(&self, count: u64) {
        self.data.add_request_drop(count);
    }

    pub fn get_total_blocked_request(&self) -> u64 {
        return self.data.get_total_blocked_request();
    }

    pub fn add_total_blocked_request(&self, total: u64) {
        self.data.add_total_blocked_request(total);
    }

    pub fn get_total_failed_request(&self) -> u64 {
        return self.data.get_total_failed_request();
    }

    pub fn add_total_failed_request(&self, total: u64) {
        self.data.add_total_failed_request(total);
    }

    pub fn get_total_request(&self) -> u64 {
        return self.data.get_total_request();
    }

    pub fn get_current_hour_total(&self) -> u64 {
        return self.data.get_current_hour_total();
    }

    pub fn add_total_request(&self, total: u64) {
        self.data.add_total_request(total);
    }

    pub fn get_memory_usage(&self) -> u64 {
        let statm_path = "/proc/self/statm";
        let statm = std::fs::read_to_string(statm_path);
        if let Err(_) = statm {
            return 0;
        }

        let statm = statm.unwrap();
        let statm: Vec<&str> = statm.split_whitespace().collect();
        if statm.len() < 2 {
            return 0;
        }

        let pages = statm[1].parse::<u64>();
        if let Err(_) = pages {
            return 0;
        }

        let pages = pages.unwrap();
        let pagesizie = utils::get_page_size() as u64;
        return pages * pagesizie;
    }

    pub fn init(self: &Arc<Self>) -> Result<(), Box<dyn Error>> {
        dns_log!(LogLevel::DEBUG, "init data stats");
        self.load_status_data()?;
        Ok(())
    }

    pub fn load_status_data(self: &Arc<Self>) -> Result<(), Box<dyn Error>> {
        let status_data = match self.db.get_status_data_list() {
            Ok(data) => data,
            Err(_) => HashMap::new(),
        };

        // load total request count
        let mut total_count = 0 as u64;
        let status_data_total_count = status_data.get("total_request");
        if status_data_total_count.is_some() {
            let count = status_data_total_count.unwrap().parse::<u64>();
            if let Ok(count) = count {
                total_count = count;
            } else {
                total_count = 0;
            }
        }

        if total_count == 0 {
            let count = self.db.get_domain_list_count(None);
            total_count = count;
        }
        self.data.add_total_request(total_count);

        // load total blocked request
        let mut total_blocked_count = 0 as u64;
        let status_data_total_blocked_count = status_data.get("total_blocked_request");
        if status_data_total_blocked_count.is_some() {
            let count = status_data_total_blocked_count.unwrap().parse::<u64>();
            if let Ok(count) = count {
                total_blocked_count = count;
            } else {
                total_blocked_count = 0;
            }
        }

        if total_blocked_count == 0 {
            let mut parm = DomainListGetParam::new();
            parm.is_blocked = Some(true);
            
            let count = self.db.get_domain_list_count(Some(&parm));
            total_blocked_count = count;
        }
        self.data.add_total_blocked_request(total_blocked_count);

        // load total failed request
        let mut total_failed_count = 0 as u64;
        let status_data_total_failed_count = status_data.get("total_failed_request");
        if status_data_total_failed_count.is_some() {
            let count = status_data_total_failed_count.unwrap().parse::<u64>();
            if let Ok(count) = count {
                total_failed_count = count;
            } else {
                total_failed_count = 0;
            }
        }
        self.data.add_total_failed_request(total_failed_count);
        Ok(())
    }

    pub fn save_status_data(self: &Arc<Self>) -> Result<(), Box<dyn Error>> {
        self.db.set_status_data(
            "total_request",
            self.get_total_request().to_string().as_str(),
        )?;
        self.db.set_status_data(
            "total_blocked_request",
            self.get_total_blocked_request().to_string().as_str(),
        )?;
        self.db.set_status_data(
            "total_failed_request",
            self.get_total_failed_request().to_string().as_str(),
        )?;

        Ok(())
    }

    pub fn start_worker(self: &Arc<Self>) -> Result<(), Box<dyn Error>> {
        let this = self.clone();
        let task = tokio::spawn(async move {
            DataStats::worker_loop(&this).await;
        });

        *(self.task.lock().unwrap()) = Some(task);
        self.is_run.store(true, Ordering::Relaxed);
        Ok(())
    }

    pub fn refresh(self: &Arc<Self>) {
        let now = get_utc_time_ms();

        let ret = self
            .db
            .delete_domain_before_timestamp(now - self.conf.read().unwrap().max_log_age_ms as u64);
        if let Err(e) = ret {
            if e.to_string() == "Query returned no rows" {
                return;
            }

            dns_log!(
                LogLevel::WARN,
                "delete domain before timestamp error: {}",
                e
            );
        }

        let ret = self.db.refresh_client_top_list(now - 7 * 24 * 3600 * 1000);
        if let Err(e) = ret {
            dns_log!(LogLevel::WARN, "refresh client top list error: {}", e);
        }

        let ret = self.db.refresh_domain_top_list(now - 7 * 24 * 3600 * 1000);
        if let Err(e) = ret {
            dns_log!(LogLevel::WARN, "refresh domain top list error: {}", e);
        }
        let _ = self
            .db
            .delete_hourly_query_count_before_timestamp(30 * 24 * 3600 * 1000);
        let _ = self
            .db
            .delete_daily_query_count_before_timestamp(90 * 24 * 3600 * 1000);
    }

    async fn update_stats(self: &Arc<Self>) {
        if self
            .is_hourly_work_running
            .fetch_or(true, Ordering::Acquire)
        {
            return;
        }

        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            this.refresh();
            this.is_hourly_work_running.store(false, Ordering::Release);
        });
    }

    async fn worker_loop(this: &Arc<Self>) {
        let mut rx: mpsc::Receiver<()>;
        {
            let mut _rx = this.notify_rx.lock().unwrap();
            rx = _rx.take().unwrap();
        }

        this.clone().update_stats().await;
        let start: Instant = Instant::now() + Duration::from_secs(utils::seconds_until_next_hour());
        let mut hour_timer = interval_at(start, Duration::from_secs(60 * 60));
        let mut second_timer = interval_at(Instant::now(), Duration::from_secs(1));

        loop {
            tokio::select! {
                _ = rx.recv() => {
                    break;
                }

                _ = second_timer.tick() => {
                    this.update_qps();
                }

                _ = hour_timer.tick() => {
                    this.update_stats().await;
                }
            }
        }

        let ret = this.save_status_data();
        if let Err(e) = ret {
            dns_log!(LogLevel::WARN, "save status data error: {}", e);
        }
    }

    pub fn stop_worker(&self) {
        if self.is_run.load(Ordering::Relaxed) == false {
            return;
        }

        if let Some(tx) = self.notify_tx.as_ref().cloned() {
            let _ = tx.try_send(());
        }

        let mut task = self.task.lock().unwrap();
        if let Some(task) = task.take() {
            tokio::task::block_in_place(|| {
                let _ = tokio::runtime::Handle::current().block_on(task);
            });
        }

        self.is_run.store(false, Ordering::Relaxed);
    }
}

impl Drop for DataStats {
    fn drop(&mut self) {
        self.stop_worker();
    }
}
