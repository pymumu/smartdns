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

use std::error::Error;
use std::thread;

use crate::smartdns::*;

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{interval_at, Instant};

use crate::utils;

struct DataStatsItem {

}

impl DataStatsItem {
    pub fn new() -> Self {
        DataStatsItem { }
    }

    #[allow(dead_code)]
    pub fn get_current_hour_total(&self) -> u64 {
        return Stats::get_request_total();
    }

    #[allow(dead_code)]
    pub fn update_total(&mut self, _total: u64) {

    }
}

pub struct DataStats {
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    notify_tx: Option<mpsc::Sender<()>>,
    notify_rx: Mutex<Option<mpsc::Receiver<()>>>,
    is_run: AtomicBool,
    data: Mutex<DataStatsItem>,
}

impl DataStats {
    pub fn new() -> Arc<Self> {
        let (tx, rx) = mpsc::channel(100);

        Arc::new(DataStats {
            task: Mutex::new(None),
            notify_rx: Mutex::new(Some(rx)),
            notify_tx: Some(tx),
            is_run: AtomicBool::new(false),
            data: Mutex::new(DataStatsItem::new()),
        })
    }

    pub fn init(self: Arc<Self>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    pub fn start_worker(self: Arc<Self>) -> Result<(), Box<dyn Error>> {
        let this = self.clone();
        let task = tokio::spawn(async move {
            DataStats::worker_loop(this).await;
        });

        *(self.task.lock().unwrap()) = Some(task);
        self.is_run.store(true, Ordering::Relaxed);
        Ok(())
    }

    async fn update_stats(&self) {
        let mut data = self.data.lock().unwrap();
        let total = Stats::get_request_total();
        data.update_total(total);
    }

    async fn worker_loop(this: Arc<Self>) {
        let mut rx: mpsc::Receiver<()>;
        {
            let mut _rx = this.notify_rx.lock().unwrap();
            rx = _rx.take().unwrap();
        }

        let start: Instant = Instant::now() + Duration::from_secs(utils::seconds_until_next_hour());
        let mut hour_timer = interval_at(start, Duration::from_secs(60 * 60));

        loop {
            tokio::select! {
                _ = rx.recv() => {
                    break;
                }

                _ = hour_timer.tick() => {
                    this.update_stats().await;
                }
            }
        }
    }

    pub fn stop_worker(&self) {
        if self.is_run.load(Ordering::Relaxed) == false {
            return;
        }

        if let Some(tx) = self.notify_tx.as_ref().cloned() {
            let t = thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async move {
                    _ = tx.send(()).await;
                });
            });

            let _ = t.join();
        }

        self.is_run.store(false, Ordering::Relaxed);
    }
}

impl Drop for DataStats {
    fn drop(&mut self) {
        self.stop_worker();
    }
}
