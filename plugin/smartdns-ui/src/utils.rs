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

use std::{
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

pub fn parse_value<T>(value: Option<String>, min: T, max: T, default: T) -> T
where
    T: PartialOrd + std::str::FromStr,
{
    if value.is_none() {
        return default;
    }

    let value = value.unwrap().parse::<T>();
    if let Err(_) = value {
        return default;
    }

    let mut value = value.unwrap_or_else(|_| default);

    if value < min {
        value = min;
    }

    if value > max {
        value = max;
    }

    value
}

pub fn seconds_until_next_hour() -> u64 {
    let now = chrono::Local::now();
    let minutes = chrono::Timelike::minute(&now);
    let seconds = chrono::Timelike::second(&now);
    let remaining_seconds = 3600 - (minutes * 60 + seconds) as u64;
    remaining_seconds
}

pub struct ResultCache<T: Send> {
    ttl: Duration,
    store: Mutex<Option<T>>,
    instant: Mutex<Instant>,
    thread: Mutex<Option<thread::JoinHandle<()>>>,
}

impl<T: Send> Drop for ResultCache<T> {
    fn drop(&mut self) {
        let mut thread = self.thread.lock().unwrap();
        if let Some(thread) = thread.take() {
            thread.join().unwrap();
        }
    }
}

impl<T: Send + 'static> ResultCache<T>
where
    T: Clone,
{
    pub fn new(ttl: Duration) -> Arc<Self> {
        Arc::new(ResultCache {
            ttl: ttl,
            store: Mutex::new(None),
            instant: Mutex::new(Instant::now()),
            thread: Mutex::new(None),
        })
    }

    pub fn get<F>(self: &Arc<Self>, load_func: F) -> Option<T>
    where
        F: FnOnce() -> Option<T> + Send + 'static,
    {
        let now = Instant::now();

        let time_since_last_update = now.duration_since(*self.instant.lock().unwrap());
        if time_since_last_update > self.ttl {
            return None;
        }

        if self.ttl - time_since_last_update <= Duration::from_secs(self.ttl.as_secs() / 2 + self.ttl.as_secs() / 4) {
            let self_clone = self.clone();
            let mut thread = self.thread.lock().unwrap();
            if thread.is_none() {
                *thread = Some(thread::spawn(move || {
                    let ret = load_func();
                    if let Some(store) = ret {
                        self_clone.set(store);
                    }
                    self_clone.thread.lock().unwrap().take();
                }));
            }
        }

        let store = self.store.lock().unwrap();
        if store.is_none() {
            return None;
        }

        let store = store.as_ref().unwrap();
        Some(store.clone())
    }

    pub fn set(&self, store: T) {
        *self.instant.lock().unwrap() = Instant::now();
        let mut this_store = self.store.lock().unwrap();
        *this_store = Some(store);
    }
}
