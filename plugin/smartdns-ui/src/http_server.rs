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

use crate::data_server::*;
use crate::dns_log;
use crate::http_api_msg::*;
use crate::http_jwt::*;
use crate::http_server_api::*;
use crate::smartdns;
use crate::smartdns::*;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body;
use hyper::server::conn::http1;
use hyper::StatusCode;
use hyper::{service::service_fn, Request, Response};
use hyper_util::rt::TokioIo;
use rustls_pemfile;
use std::convert::Infallible;
use std::error::Error;
use std::fs::Metadata;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::path::{Component, Path};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tokio::fs::read;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::{rustls, TlsAcceptor};

#[derive(Clone)]
pub struct HttpServerConfig {
    pub http_ip: String,
    pub http_root: String,
    pub user: String,
    pub password: String,
    pub token_expired_time: u32,
}

impl HttpServerConfig {
    pub fn new() -> Self {
        HttpServerConfig {
            http_ip: "http://0.0.0.0:8080".to_string(),
            http_root: "/usr/local/shared/smartdns/wwww".to_string(),
            user: "admin".to_string(),
            password: "password".to_string(),
            token_expired_time: 600,
        }
    }
}

pub struct HttpServerControl {
    http_server: Arc<HttpServer>,
    server_thread: Option<thread::JoinHandle<()>>,
}

#[allow(dead_code)]
impl HttpServerControl {
    pub fn new() -> Self {
        HttpServerControl {
            http_server: Arc::new(HttpServer::new()),
            server_thread: None,
        }
    }

    pub fn get_http_server(&self) -> Arc<HttpServer> {
        Arc::clone(&self.http_server)
    }

    pub fn start_http_server(
        &mut self,
        conf: &HttpServerConfig,
        data_server: Arc<DataServer>,
    ) -> Result<(), Box<dyn Error>> {
        dns_log!(LogLevel::INFO, "start smartdns-ui server.");

        let inner_clone = Arc::clone(&self.http_server);
        let ret = inner_clone.set_conf(conf);
        if let Err(e) = ret {
            return Err(e);
        }

        let ret = inner_clone.set_data_server(data_server);
        if let Err(e) = ret {
            return Err(e);
        }

        let (tx, rx) = std::sync::mpsc::channel::<i32>();

        let server_thread = thread::spawn(move || {
            let ret = HttpServer::http_server_loop(inner_clone, &tx);
            if let Err(e) = ret {
                _ = tx.send(0);
                dns_log!(LogLevel::ERROR, "http server error: {}", e);
                Plugin::smartdns_exit(1);
            }
            dns_log!(LogLevel::INFO, "http server exit.");
        });

        rx.recv().unwrap();

        self.server_thread = Some(server_thread);
        Ok(())
    }

    pub fn stop_http_server(&mut self) {
        if self.server_thread.is_none() {
            return;
        }

        dns_log!(LogLevel::INFO, "stop smartdns-ui server.");

        self.http_server.stop_http_server();

        if let Some(server_thread) = self.server_thread.take() {
            server_thread.join().unwrap();
        }

        self.server_thread = None;
    }
}

impl Drop for HttpServerControl {
    fn drop(&mut self) {
        self.stop_http_server();
    }
}

pub struct HttpServer {
    conf: Mutex<HttpServerConfig>,
    notify_tx: Option<mpsc::Sender<()>>,
    notify_rx: Mutex<Option<mpsc::Receiver<()>>>,
    data_server: Mutex<Arc<DataServer>>,
    api: API,
    local_addr: Mutex<Option<SocketAddr>>,
    mime_map: std::collections::HashMap<&'static str, &'static str>,
}

#[allow(dead_code)]
impl HttpServer {
    fn new() -> Self {
        let mut plugin = HttpServer {
            conf: Mutex::new(HttpServerConfig::new()),
            notify_tx: None,
            notify_rx: Mutex::new(None),
            data_server: Mutex::new(Arc::new(DataServer::new())),
            api: API::new(),
            local_addr: Mutex::new(None),
            mime_map: std::collections::HashMap::from([
                ("htm", "text/html"),
                ("html", "text/html"),
                ("js", "text/javascript"),
                ("css", "text/css"),
                ("json", "application/json"),
                ("png", "image/png"),
                ("gif", "image/gif"),
                ("jpeg", "image/jpeg"),
                ("svg", "image/svg+xml"),
                ("tar", "application/x-tar"),
                ("zip", "application/zip"),
                ("txt", "text/plain"),
                ("conf", "text/plain"),
                ("ico", "application/octet-stream"),
                ("xml", "text/xml"),
                ("mpeg", "video/mpeg"),
                ("mp3", "audio/mpeg"),
            ]),
        };

        let (tx, rx) = mpsc::channel(100);
        plugin.notify_tx = Some(tx);
        plugin.notify_rx = Mutex::new(Some(rx));

        plugin
    }

    pub fn get_conf(&self) -> HttpServerConfig {
        let conf = self.conf.lock().unwrap();
        conf.clone()
    }

    pub fn get_local_addr(&self) -> Option<SocketAddr> {
        let local_addr = self.local_addr.lock().unwrap();
        local_addr.clone()
    }

    fn set_conf(&self, conf: &HttpServerConfig) -> Result<(), Box<dyn Error>> {
        let mut conf_clone = self.conf.lock().unwrap();
        *conf_clone = conf.clone();
        dns_log!(LogLevel::INFO, "http server URI: {}", conf_clone.http_ip);
        dns_log!(
            LogLevel::INFO,
            "http server www root: {}",
            conf_clone.http_root
        );
        Ok(())
    }

    fn set_data_server(&self, data_server: Arc<DataServer>) -> Result<(), Box<dyn Error>> {
        let mut _data_server = self.data_server.lock().unwrap();
        *_data_server = data_server.clone();
        Ok(())
    }

    pub fn get_data_server(&self) -> Arc<DataServer> {
        let data_server = self.data_server.lock().unwrap();
        Arc::clone(&*data_server)
    }

    pub fn auth_token_is_valid(&self, req: &Request<body::Incoming>) -> bool {
        let token = req.headers().get("Authorization");
        if token.is_none() {
            return false;
        }

        let token = token.unwrap().to_str().unwrap();
        let conf = self.conf.lock().unwrap();
        let jwt = Jwt::new(&conf.user, &conf.password, "", conf.token_expired_time);

        if !jwt.is_token_valid(token) {
            return false;
        }
        true
    }

    async fn server_handle_http_api_request(
        this: Arc<HttpServer>,
        req: Request<body::Incoming>,
        _path: PathBuf,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let error_response = |code: StatusCode, msg: &str| {
            let bytes = Bytes::from(api_msg_error(msg));
            let mut response = Response::new(Full::new(bytes));
            response
                .headers_mut()
                .insert("Content-Type", "application/json".parse().unwrap());
            response
                .headers_mut()
                .insert("Cache-Control", "no-cache".parse().unwrap());
            *response.status_mut() = code;
            Ok(response)
        };

        dns_log!(LogLevel::DEBUG, "api request: {:?}", req.uri());
        match this.api.get_router(req.method(), req.uri().path()) {
            Some((router, param)) => {
                if router.auth && !this.auth_token_is_valid(&req) {
                    return error_response(StatusCode::UNAUTHORIZED, "Please login.");
                }

                if router.method != req.method() {
                    return error_response(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
                }

                let resp = (router.handler)(this.clone(), param, req).await;
                match resp {
                    Ok(resp) => {
                        let mut resp = resp;
                        if resp.headers().get("Content-Type").is_none() {
                            resp.headers_mut()
                                .insert("Content-Type", "application/json".parse().unwrap());
                        }

                        if resp.headers().get("Cache-Control").is_none() {
                            resp.headers_mut()
                                .insert("Cache-Control", "no-cache".parse().unwrap());
                        }
                        Ok(resp)
                    }
                    Err(e) => Ok(e.to_response()),
                }
            }
            None => error_response(StatusCode::NOT_FOUND, "API not found."),
        }
    }

    pub fn get_mime_type(&self, file: &str) -> String {
        let ext = file.split('.').last().unwrap();
        if let Some(mime) = self.mime_map.get(ext) {
            return mime.to_string();
        }

        "application/octet-stream".to_string()
    }

    async fn server_handle_http_request(
        this: Arc<HttpServer>,
        req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let path = PathBuf::from(req.uri().path());
        let www_root = {
            let conf = this.conf.lock().unwrap();
            PathBuf::from(conf.http_root.clone())
        };

        let mut path = normalize_path(path.as_path());
        if path.starts_with("/") {
            path = path.strip_prefix("/").unwrap().to_path_buf();
        }

        if path.starts_with("api/") {
            let ret = HttpServer::server_handle_http_api_request(this, req, path.clone()).await;
            if let Err(e) = ret {
                dns_log!(LogLevel::ERROR, "api request error: {:?}", e);
                let mut response = Response::new(Full::new(Bytes::from("Internal Server Error")));
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                return ret;
            }

            return ret;
        }

        dns_log!(LogLevel::DEBUG, "page request: {:?}", req.uri());
        let mut filepath = www_root.join(path);
        let mut path = req.uri().path().to_string();

        if !filepath.exists() {
            filepath = www_root.join("index.html");
            path = format!("{}/index.html", path);
        }

        if filepath.is_dir() {
            filepath = filepath.join("index.html");
            path = format!("{}/index.html", path);
        }

        let mut file_meta: Option<Metadata> = None;
        let fn_get_etag = |meta: &Metadata| -> String {
            let modify_time = meta.modified();
            if let Err(_) = modify_time {
                return "".to_string();
            }
            format!(
                "{:x}-{:?}",
                meta.len(),
                modify_time
                    .unwrap()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            )
        };

        if filepath.exists() {
            let meta = filepath.metadata();
            if let Ok(meta) = meta {
                file_meta = Some(meta);
            }
        }

        let if_none_match = req.headers().get("If-None-Match");
        if if_none_match.is_some() && file_meta.is_some() {
            let etag = fn_get_etag(&file_meta.as_ref().unwrap());
            if etag == if_none_match.unwrap().to_str().unwrap() {
                let mut response = Response::new(Full::new(Bytes::from("")));
                *response.status_mut() = StatusCode::NOT_MODIFIED;
                return Ok(response);
            }
        }

        match read(filepath).await {
            Ok(contents) => {
                let bytes = Bytes::from(contents);
                let bytes_len = bytes.len();
                let mut response = Response::new(Full::new(bytes));
                let header = response.headers_mut();
                header.insert("Content-Length", bytes_len.to_string().parse().unwrap());
                header.insert("Content-Type", this.get_mime_type(&path).parse().unwrap());

                if file_meta.as_ref().is_some() {
                    let etag = fn_get_etag(&file_meta.as_ref().unwrap());
                    header.insert("ETag", etag.parse().unwrap());
                }
                *response.status_mut() = StatusCode::OK;
                Ok(response)
            }
            Err(_) => {
                let bytes = Bytes::from("Not Found");
                let mut response = Response::new(Full::new(bytes));
                *response.status_mut() = StatusCode::NOT_FOUND;
                Ok(response)
            }
        }
    }

    async fn http_server_handle_conn(this: Arc<HttpServer>, stream: TcpStream) {
        let io = TokioIo::new(stream);

        let handle_func = move |req| HttpServer::server_handle_http_request(this.clone(), req);

        tokio::task::spawn(async move {
            let conn = http1::Builder::new()
                .serve_connection(io, service_fn(handle_func))
                .with_upgrades()
                .await;
            if let Err(err) = conn {
                dns_log!(LogLevel::DEBUG, "Error serving connection: {:?}", err);
                return;
            }
        });
    }

    async fn https_server_handle_conn(
        this: Arc<HttpServer>,
        stream: tokio_rustls::server::TlsStream<TcpStream>,
    ) {
        let io = TokioIo::new(stream);

        let handle_func = move |req| HttpServer::server_handle_http_request(this.clone(), req);

        tokio::task::spawn(async move {
            let conn = http1::Builder::new()
                .serve_connection(io, service_fn(handle_func))
                .with_upgrades()
                .await;
            if let Err(err) = conn {
                dns_log!(LogLevel::DEBUG, "Error serving connection: {:?}", err);
                return;
            }
        });
    }

    async fn handle_tls_accept(this: Arc<HttpServer>, acceptor: TlsAcceptor, stream: TcpStream) {
        tokio::task::spawn(async move {
            let acceptor_future = acceptor.accept(stream);
            let stream_ssl_tmout =
                tokio::time::timeout(tokio::time::Duration::from_secs(60), acceptor_future).await;
            if let Err(e) = stream_ssl_tmout {
                dns_log!(LogLevel::DEBUG, "tls accept timeout. {}", e);
                return;
            }

            let stream_ret = stream_ssl_tmout.unwrap();
            if let Err(e) = stream_ret {
                dns_log!(LogLevel::DEBUG, "tls accept error: {}", e);
                return;
            }

            let stream_ssl = stream_ret.unwrap();
            HttpServer::https_server_handle_conn(this, stream_ssl).await;
        });
    }

    #[tokio::main]
    async fn http_server_loop(
        this: Arc<HttpServer>,
        kickoff_tx: &std::sync::mpsc::Sender<i32>,
    ) -> Result<(), Box<dyn Error>> {
        let addr: String;
        let mut rx: mpsc::Receiver<()>;

        {
            let conf = this.conf.lock().unwrap();
            addr = format!("{}", conf.http_ip);
            let mut _rx = this.notify_rx.lock().unwrap();
            rx = _rx.take().unwrap();
        }

        let url = addr.parse::<url::Url>()?;
        let mut acceptor = None;
        if url.scheme() == "https" {
            let cert_info = smartdns::Plugin::smartdns_get_cert()?;

            dns_log!(
                LogLevel::DEBUG,
                "cert: {}, key: {}",
                cert_info.cert,
                cert_info.key
            );
            let cert_chain: Result<Vec<rustls::pki_types::CertificateDer<'_>>, _> =
                rustls_pemfile::certs(&mut BufReader::new(std::fs::File::open(cert_info.cert)?))
                    .collect();
            let cert_chain = cert_chain.unwrap_or_else(|_| Vec::new());
            let key_der = rustls_pemfile::private_key(&mut BufReader::new(std::fs::File::open(
                cert_info.key,
            )?))?
            .unwrap();

            let config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(cert_chain, key_der)?;
            acceptor = Some(TlsAcceptor::from(Arc::new(config)));
        }
        let host = url.host_str().unwrap_or("0.0.0.0");
        let port = url.port().unwrap_or(80);
        let sock_addr = format!("{}:{}", host, port).parse::<SocketAddr>()?;

        let listner = TcpListener::bind(sock_addr).await?;
        let addr = listner.local_addr()?;

        *this.local_addr.lock().unwrap() = Some(addr);
        dns_log!(LogLevel::INFO, "http server listen at {}", url);

        _ = kickoff_tx.send(0);
        loop {
            tokio::select! {
                _ = rx.recv() => {
                    break;
                }
                res = listner.accept() => {
                    match res {
                        Ok((stream, _)) => {
                            let sock_ref = socket2::SockRef::from(&stream);

                            let mut ka = socket2::TcpKeepalive::new();
                            ka = ka.with_time(Duration::from_secs(30));
                            ka = ka.with_interval(Duration::from_secs(10));
                            sock_ref.set_tcp_keepalive(&ka)?;
                            sock_ref.set_nonblocking(true)?;
                            if acceptor.is_some() {
                                let acceptor = acceptor.clone().unwrap().clone();
                                let this_clone = this.clone();
                                HttpServer::handle_tls_accept(this_clone, acceptor, stream).await;
                            } else {
                                HttpServer::http_server_handle_conn(this.clone(), stream).await;
                            }
                        }
                        Err(e) => {
                            dns_log!(LogLevel::ERROR, "accept error: {}", e);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn stop_http_server(&self) {
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

pub fn normalize_path(path: &Path) -> PathBuf {
    let mut components = path.components().peekable();
    let mut ret = if let Some(c @ Component::Prefix(..)) = components.peek().cloned() {
        components.next();
        PathBuf::from(c.as_os_str())
    } else {
        PathBuf::new()
    };

    for component in components {
        match component {
            Component::Prefix(..) => unreachable!(),
            Component::RootDir => {
                ret.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                ret.pop();
            }
            Component::Normal(c) => {
                ret.push(c);
            }
        }
    }
    ret
}
