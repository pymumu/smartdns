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

use futures::sink::SinkExt;
use futures::stream::StreamExt;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{interval_at, Instant};
use tokio_fd::AsyncFd;

use crate::smartdns::*;
use hyper_tungstenite::{tungstenite, HyperWebsocket};
use nix::errno::Errno;
use nix::libc::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tungstenite::Message;

use crate::data_server::DataServer;
use crate::dns_log;
use crate::http_api_msg::api_msg_gen_metrics_data;
use crate::http_server::HttpServer;
use crate::smartdns::LogLevel;

type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

const LOG_CONTROL_MESSAGE_TYPE: u8 = 1;
const LOG_CONTROL_PAUSE: u8 = 1;
const LOG_CONTROL_RESUME: u8 = 2;
const LOG_CONTROL_LOGLEVEL: u8 = 3;

struct LogLevelGuard {
    old_log_level: LogLevel,
}

impl Drop for LogLevelGuard {
    fn drop(&mut self) {
        dns_log_set_level(self.old_log_level);
    }
}
impl LogLevelGuard {
    fn new() -> Self {
        let old_log_level = dns_log_get_level();
        LogLevelGuard { old_log_level }
    }
}

pub async fn serve_log_stream(
    http_server: Arc<HttpServer>,
    websocket: HyperWebsocket,
) -> Result<(), Error> {
    let mut websocket = websocket.await?;
    let mut is_pause = false;

    let data_server = http_server.get_data_server();
    let mut log_stream = data_server.get_log_stream().await;

    let _log_guard = LogLevelGuard::new();

    loop {
        tokio::select! {
            msg = log_stream.recv() => {
                if is_pause {
                    continue;
                }

                match msg {
                    Some(msg) => {
                        let mut binary_msg = Vec::with_capacity(2 + msg.msg.len());
                        binary_msg.push(0);
                        binary_msg.push(msg.level as u8);
                        binary_msg.extend_from_slice(msg.msg.as_bytes());
                        let msg = Message::Binary(binary_msg.into());
                        websocket.send(msg).await?;
                    }
                    None => {
                        websocket.send(Message::Close(None)).await?;
                        break;
                    }
                }
            }

            msg = websocket.next() => {
                let message = msg.ok_or("websocket closed")??;
                match message {
                    Message::Text(_msg) => {}
                    Message::Binary(msg) => {
                        if msg.len() == 0 {
                            continue;
                        }

                        let msg_type = msg[0];
                        match msg_type {
                            LOG_CONTROL_MESSAGE_TYPE => {
                                if msg.len() < 2 {
                                    continue;
                                }
                                let control_type = msg[1];
                                match control_type {
                                    LOG_CONTROL_PAUSE => {
                                        is_pause = true;
                                        continue;
                                    }
                                    LOG_CONTROL_RESUME => {
                                        is_pause = false;
                                        continue;
                                    }
                                    LOG_CONTROL_LOGLEVEL => {
                                        if msg.len() < 6 {
                                            continue;
                                        }

                                        let level_msg = &msg[2..2 + msg.len() - 2];
                                        let str_log_level = std::str::from_utf8(level_msg);
                                        if str_log_level.is_err() {
                                            continue;
                                        }

                                        let str_log_level = str_log_level.unwrap();
                                        if str_log_level.len() == 0 {
                                            continue;
                                        }

                                        let str_log_level = str_log_level.to_lowercase();
                                        let str_log_level = str_log_level.as_str();

                                        let log_level = str_log_level.try_into();
                                        if log_level.is_err() {
                                            continue;
                                        }

                                        let log_level = log_level.unwrap();
                                        dns_log_set_level(log_level);
                                    }
                                    _ => {
                                        continue;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    Message::Ping(_msg) => {}
                    Message::Pong(_msg) => {}
                    Message::Close(_msg) => {
                        websocket.send(Message::Close(None)).await?;
                        break;
                    }
                    Message::Frame(_msg) => {
                        unreachable!();
                    }
                }
            }
        }
    }

    Ok(())
}

pub async fn serve_audit_log_stream(
    http_server: Arc<HttpServer>,
    websocket: HyperWebsocket,
) -> Result<(), Error> {
    let mut websocket = websocket.await?;
    let mut is_pause = false;

    let data_server = http_server.get_data_server();
    let mut log_stream = data_server.get_audit_log_stream().await;

    loop {
        tokio::select! {
            msg = log_stream.recv() => {
                if is_pause {
                    continue;
                }

                match msg {
                    Some(msg) => {
                        let mut binary_msg = Vec::with_capacity(1 + msg.msg.len());
                        binary_msg.push(0);
                        binary_msg.extend_from_slice(msg.msg.as_bytes());
                        let msg = Message::Binary(binary_msg.into());
                        websocket.send(msg).await?;
                    }
                    None => {
                        websocket.send(Message::Close(None)).await?;
                        break;
                    }
                }
            }

            msg = websocket.next() => {
                let message = msg.ok_or("websocket closed")??;
                match message {
                    Message::Text(_msg) => {}
                    Message::Binary(msg) => {
                        if msg.len() == 0 {
                            continue;
                        }

                        let msg_type = msg[0];
                        match msg_type {
                            LOG_CONTROL_MESSAGE_TYPE => {
                                if msg.len() < 2 {
                                    continue;
                                }
                                let control_type = msg[1];
                                match control_type {
                                    LOG_CONTROL_PAUSE => {
                                        is_pause = true;
                                        continue;
                                    }
                                    LOG_CONTROL_RESUME => {
                                        is_pause = false;
                                        continue;
                                    }
                                    _ => {
                                        continue;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    Message::Ping(_msg) => {}
                    Message::Pong(_msg) => {}
                    Message::Close(_msg) => {
                        websocket.send(Message::Close(None)).await?;
                        break;
                    }
                    Message::Frame(_msg) => {
                        unreachable!();
                    }
                }
            }
        }
    }

    Ok(())
}

pub async fn serve_metrics(
    data_server: Arc<DataServer>,
    websocket: HyperWebsocket,
) -> Result<(), Error> {
    let mut websocket = websocket.await?;
    let mut second_timer = interval_at(Instant::now(), Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = second_timer.tick() => {
                let metrics = data_server.get_metrics();
                match metrics {
                    Ok(metrics) => {
                        let data_server = api_msg_gen_metrics_data(&metrics);
                        let msg = Message::Text(data_server.into());
                        websocket.send(msg).await?;
                    }
                    Err(e) => {
                        let msg = Message::Text(format!("{{\"error\": \"{}\"}}", e).into());
                        websocket.send(msg).await?;
                    }
                }
            }
            msg = websocket.next() => {
                let message = msg.ok_or("websocket closed")??;
                match message {
                    Message::Text(_msg) => {}
                    Message::Binary(_msg) => {}
                    Message::Ping(_msg) => {}
                    Message::Pong(_msg) => {}
                    Message::Close(_msg) => {
                        websocket.send(Message::Close(None)).await?;
                        break;
                    }
                    Message::Frame(_msg) => {
                        unreachable!();
                    }
                }
            }
        }
    }

    Ok(())
}

enum TermMessageType {
    Data,
    Err,
    Resize,
    Pause,
    Resume,
}

impl TryFrom<u8> for TermMessageType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(TermMessageType::Data),
            1 => Ok(TermMessageType::Err),
            2 => Ok(TermMessageType::Resize),
            3 => Ok(TermMessageType::Pause),
            4 => Ok(TermMessageType::Resume),
            _ => Err(()),
        }
    }
}

#[cfg(target_os = "linux")]
pub async fn serve_term(websocket: HyperWebsocket) -> Result<(), Error> {
    type WsType =
        hyper_tungstenite::WebSocketStream<hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>>;
    let mut websocket = websocket.await?;

    let (pid, asyncfd) = unsafe {
        let mut fd_master: std::os::fd::RawFd = 0;
        let mut ws = winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let pid = forkpty(
            &mut fd_master,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut ws,
        );
        if pid < 0 {
            dns_log!(LogLevel::ERROR, "forkpty failed, error: {}", Errno::last());
            return Err(format!("forkpty failed, error: {}", Errno::last()).into());
        }

        if pid == 0 {
            let _ = ioctl(0, TIOCSCTTY, 1);
            for i in 3..1024 {
                close(i);
            }
            use std::ffi::CString;
            std::env::set_var("TERM", "xterm-256color");

            let find_cmd = |cmd: &str| -> Result<String, Box<dyn std::error::Error>> {
                let env_path = std::env::var("PATH")?;
                let paths = env_path.split(':');

                for path in paths {
                    let cmd_path = format!("{}/{}", path, cmd);
                    if std::fs::metadata(&cmd_path).is_ok() {
                        return Ok(cmd_path);
                    }
                }

                Err(format!("command not found {}", cmd).into())
            };

            let su_path = find_cmd("su");
            let login_path = find_cmd("login");
            let mut err = ENOENT;

            if su_path.is_ok() && (login_path.is_err() || geteuid() != 0) {
                let uid = getuid();
                let pw = getpwuid(uid);

                if pw.is_null() {
                    println!("getpwuid failed");
                    _exit(1);
                }

                let arg0 = CString::new("su").unwrap();
                let arg1 = CString::new("-").unwrap();
                let arg2 = (*pw).pw_name;
                let login_message =
                    format!("Login as {}", std::ffi::CStr::from_ptr(arg2).to_str()?);
                println!("{}", login_message);

                let cmd_path = CString::new(su_path.unwrap()).unwrap();
                let args = [arg0.as_ptr(), arg1.as_ptr(), arg2, std::ptr::null()];
                let ret = execv(cmd_path.as_ptr(), args.as_ptr());
                if ret < 0 {
                    err = Errno::last_raw();
                }
                println!("Please install `su` and add current user to sudoers");
            } else if login_path.is_ok() {
                if geteuid() != 0 {
                    println!("Login must be run as root, please run smartdns as root");
                    _exit(1);
                }

                let arg0 = CString::new("login").unwrap();
                let cmd_path = CString::new(login_path.unwrap()).unwrap();
                let args = [arg0.as_ptr(), std::ptr::null()];
                let ret = execv(cmd_path.as_ptr(), args.as_ptr());
                if ret < 0 {
                    err = Errno::last_raw();
                }
                println!("Please install `login` and run as root");
            } else {
                println!("No su or login found, please install one of them");
            }

            println!("Failed to execute `su` or `login`, code: {}", err);
            _exit(1);
        }

        (pid, AsyncFd::try_from(fd_master))
    };

    if let Err(e) = asyncfd {
        if pid > 0 {
            unsafe {
                let _ = kill(pid, SIGKILL);
                let _ = waitpid(pid, std::ptr::null_mut(), 0);
            }
        }
        return Err(e.into());
    }

    let send_error_msg = |ws: &mut WsType, msg: &str| {
        let mut buf = [0u8; 4096];
        buf[0] = TermMessageType::Err as u8;
        buf[1..msg.len() + 1].copy_from_slice(msg.as_bytes());
        let msg = Message::Binary(buf[..msg.len() + 1].to_vec().into());
        let _ = ws.send(msg);

        let msg = Message::Close(None);
        let _ = ws.send(msg);
    };

    let mut asyncfd = asyncfd.unwrap();
    let mut is_pause = false;
    loop {
        let mut buf = [0u8; 4096];
        let (data_type, data_buf) = buf.split_at_mut(1);
        let data_len;
        tokio::select! {
            n = asyncfd.read(data_buf) => {
                match n {
                    Ok(n) => {
                        if n == 0 {
                            websocket.send(Message::Close(None)).await?;
                            dns_log!(LogLevel::DEBUG, "EOF");
                            break;
                        }

                        if is_pause {
                            continue;
                        }

                        data_len = n + 1;
                        data_type[0] = TermMessageType::Data as u8;
                        let msg = Message::Binary(buf[..data_len].to_vec().into());
                        websocket.send(msg).await?;
                    }
                    Err(e) => {
                        send_error_msg(&mut websocket, e.to_string().as_str());
                        dns_log!(LogLevel::DEBUG, "Error: {}", e.to_string().as_str());
                        break;
                    }
                }
            }
            msg = websocket.next() => {
                let message = msg.ok_or("websocket closed")??;
                match message {
                    Message::Text(msg) => {
                        asyncfd.write(msg.as_bytes()).await?;
                    }
                    Message::Binary(msg) => {
                        if msg.len() == 0 {
                            continue;
                        }

                        let msg_type = TermMessageType::try_from(msg[0]);
                        if msg_type.is_err() {
                            send_error_msg(&mut websocket, "invalid message type");
                            break;
                        }

                        let msg_type = msg_type.unwrap();
                        let msg = &msg[1..];

                        match msg_type {
                            TermMessageType::Resize => {
                                let ws = winsize {
                                    ws_col: u16::from_be_bytes(msg[0..2].try_into().unwrap()),
                                    ws_row: u16::from_be_bytes(msg[2..4].try_into().unwrap()),
                                    ws_xpixel: 0,
                                    ws_ypixel: 0,
                                };
                                unsafe {
                                    let _ = ioctl(asyncfd.as_raw_fd(), TIOCSWINSZ, &ws);
                                }
                            }
                            TermMessageType::Pause => {
                                is_pause = true;
                            }
                            TermMessageType::Resume => {
                                is_pause = false;
                            }
                            TermMessageType::Data => {
                                asyncfd.write(msg).await?;
                            }
                            _ => {
                                continue;
                            }
                        }
                    }
                    Message::Ping(_msg) => {}
                    Message::Pong(_msg) => {}
                    Message::Close(_msg) => {
                        dns_log!(LogLevel::DEBUG, "Peer term closed");
                        break;
                    }
                    Message::Frame(_msg) => {
                        unreachable!();
                    }
                }
            }

        }
    }

    unsafe {
        let fd = asyncfd.as_raw_fd();
        if fd > 0 {
            let _ = close(fd);
        }
        let _ = kill(pid, SIGKILL);
        let _ = waitpid(pid, std::ptr::null_mut(), 0);
    }

    Ok(())
}
