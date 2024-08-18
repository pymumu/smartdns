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

use futures::sink::SinkExt;
use futures::stream::StreamExt;
use std::os::fd::AsRawFd;
use tokio_fd::AsyncFd;

use hyper_tungstenite::{tungstenite, HyperWebsocket};
use nix::libc::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tungstenite::Message;

use crate::dns_log;
use crate::smartdns::LogLevel;

type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

pub async fn serve_log_stream(websocket: HyperWebsocket) -> Result<(), Error> {
    let mut websocket = websocket.await?;

    loop {
        tokio::select! {
            msg = websocket.next() => {
                let message = msg.ok_or("websocket closed")??;
                match message {
                    Message::Text(_msg) => {}
                    Message::Binary(_msg) => {}
                    Message::Ping(_msg) => {}
                    Message::Pong(_msg) => {}
                    Message::Close(_msg) => {
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
}

impl TryFrom<u8> for TermMessageType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(TermMessageType::Data),
            1 => Ok(TermMessageType::Err),
            2 => Ok(TermMessageType::Resize),
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
            return Err("forkpty failed".into());
        }

        if pid == 0 {
            let _ = ioctl(0, TIOCSCTTY, 1);
            for i in 3..1024 {
                close(i);
            }
            use std::ffi::CString;

            let find_cmd = |cmd: &str| -> Result<String, Box<dyn std::error::Error>> {
                let env_path = std::env::var("PATH")?;
                let paths = env_path.split(':');

                for path in paths {
                    let cmd_path = format!("{}/{}", path, cmd);
                    if std::fs::metadata(&cmd_path).is_ok() {
                        return Ok(cmd_path);
                    }
                }

                Err("command not found".into())
            };

            let su_path = find_cmd("su");
            let login_path = find_cmd("login");

            if su_path.is_ok() {
                let uid = getuid();
                let pw = getpwuid(uid);

                if pw.is_null() {
                    return Err("getpwuid failed".into());
                }

                let arg0 = CString::new("su").unwrap();
                let arg1 = CString::new("-").unwrap();
                let arg2 = (*pw).pw_name;
                let login_message =
                    format!("Login as {}", std::ffi::CStr::from_ptr(arg2).to_str()?);
                println!("{}", login_message);

                let cmd_path = CString::new(su_path.unwrap()).unwrap();
                let args = [arg0.as_ptr(), arg1.as_ptr(), arg2, std::ptr::null()];
                let _ = execv(cmd_path.as_ptr(), args.as_ptr());
            } else if login_path.is_ok() {
                let arg0 = CString::new("login").unwrap();
                let cmd_path = CString::new(login_path.unwrap()).unwrap();
                let args = [arg0.as_ptr()];
                let _ = execv(cmd_path.as_ptr(), args.as_ptr());
            }

            println!("Failed to execute `su` or `login`");
            exit(1);
        }

        (pid, AsyncFd::try_from(fd_master))
    };

    if let Err(e) = asyncfd {
        return Err(e.into());
    }

    let send_error_msg = |ws: &mut WsType, msg: &str| {
        let mut buf = [0u8; 4096];
        buf[0] = TermMessageType::Err as u8;
        buf[1..msg.len() + 1].copy_from_slice(msg.as_bytes());
        let msg = Message::Binary(buf[..msg.len() + 1].to_vec());
        let _ = ws.send(msg);

        let msg = Message::Close(None);
        let _ = ws.send(msg);
    };

    let mut asyncfd = asyncfd.unwrap();
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
                            dns_log!(LogLevel::ERROR, "EOF");
                            break;
                        }
                        data_len = n + 1;
                        data_type[0] = TermMessageType::Data as u8;
                        let msg = Message::Binary(buf[..data_len].to_vec());
                        websocket.send(msg).await?;
                    }
                    Err(e) => {
                        send_error_msg(&mut websocket, e.to_string().as_str());
                        dns_log!(LogLevel::ERROR, "Error: {}", e.to_string().as_str());
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
        let _ = kill(pid, SIGKILL);
        let _ = waitpid(pid, std::ptr::null_mut(), 0);
    }

    Ok(())
}
