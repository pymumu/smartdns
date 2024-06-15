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

use futures::stream::StreamExt;
use hyper_tungstenite::{tungstenite, HyperWebsocket};
use tungstenite::Message;

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
