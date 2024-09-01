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

use tokio::sync::{mpsc, RwLock};

use crate::LogLevel;

#[derive(Clone)]
pub struct ServerLogMsg {
    pub level: LogLevel,
    pub msg: String,
    pub len: i32,
}

pub struct ServerLog {
    streams: RwLock<Vec<mpsc::Sender<ServerLogMsg>>>,
}

impl ServerLog {
    pub fn new() -> Self {
        ServerLog {
            streams: RwLock::new(Vec::new()),
        }
    }

    pub async fn get_log_stream(&self) -> mpsc::Receiver<ServerLogMsg> {
        let (tx, rx) = mpsc::channel(4096);
        self.streams.write().await.push(tx);
        rx
    }

    pub fn dispatch_log(&self, level: LogLevel, msg: &str, len: i32) {
        let mut remove_list = Vec::new();

        {
            let streams = self.streams.blocking_read();
            if streams.len() == 0 {
                return;
            }

            let msg = ServerLogMsg {
                level,
                msg: msg.to_string(),
                len,
            };

            for (i, stream) in streams.iter().enumerate() {
                let ret = stream.try_send(msg.clone());
                if let Err(e) = ret {
                    match e {
                        mpsc::error::TrySendError::Full(_) => {}
                        mpsc::error::TrySendError::Closed(_) => {
                            remove_list.push(i);
                        }
                    }
                }
            }
        }

        if remove_list.len() > 0 {
            let mut streams = self.streams.blocking_write();
            for i in remove_list.iter().rev() {
                streams.remove(*i);
            }
        }
    }
}
