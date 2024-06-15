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

use std::string::FromUtf8Error;

use crate::http_api_msg::*;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};

#[derive(Debug)]
pub struct HttpError {
    pub code: StatusCode,
    pub msg: String,
}

impl HttpError {
    pub fn new(code: StatusCode, msg: String) -> Self {
        HttpError {
            code: code,
            msg: msg.to_string(),
        }
    }

    pub fn to_response(&self) -> Response<Full<Bytes>> {
        let bytes = Bytes::from(api_msg_error(&self.msg));
        let mut response = Response::new(Full::new(bytes));
        response
            .headers_mut()
            .insert("Content-Type", "application/json".parse().unwrap());
        *response.status_mut() = self.code;
        response
    }
}

impl From<hyper::Error> for HttpError {
    fn from(err: hyper::Error) -> HttpError {
        HttpError {
            code: StatusCode::INTERNAL_SERVER_ERROR,
            msg: format!("Hyper error: {}", err),
        }
    }
}

impl From<FromUtf8Error> for HttpError {
    fn from(err: FromUtf8Error) -> HttpError {
        HttpError {
            code: StatusCode::BAD_REQUEST,
            msg: format!("FromUtf8Error: {}", err),
        }
    }
}

impl From<std::io::Error> for HttpError {
    fn from(err: std::io::Error) -> HttpError {
        HttpError {
            code: StatusCode::INTERNAL_SERVER_ERROR,
            msg: format!("IO error: {}", err),
        }
    }
}

impl From<Box<dyn std::error::Error>> for HttpError {
    fn from(err: Box<dyn std::error::Error>) -> HttpError {
        HttpError {
            code: StatusCode::INTERNAL_SERVER_ERROR,
            msg: format!("Error: {}", err),
        }
    }
}
