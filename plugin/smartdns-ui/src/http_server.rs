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

extern crate cfg_if;

use crate::data_server::*;
use crate::dns_log;
use crate::http_api_msg::*;
use crate::http_jwt::*;
use crate::http_server_api::*;
use crate::plugin::SmartdnsPlugin;
use crate::smartdns::*;
use crate::utils;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body;
use hyper::header::HeaderValue;
use hyper::StatusCode;
use hyper::{service::service_fn, Request, Response};
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto;
use std::convert::Infallible;
use std::error::Error;
use std::fs::Metadata;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::path::{Component, Path};
use std::sync::MutexGuard;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;
use tokio::fs::read;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
cfg_if::cfg_if! {
    if #[cfg(feature = "https")] {
        use rustls_pemfile;
        use std::io::BufReader;
        use tokio_rustls::{rustls, TlsAcceptor};
    }
}

const HTTP_SERVER_DEFAULT_PASSWORD: &str = "password";
const HTTP_SERVER_DEFAULT_USERNAME: &str = "admin";
const HTTP_SERVER_DEFAULT_WWW_ROOT: &str = "/usr/share/smartdns/wwwroot";
const HTTP_SERVER_DEFAULT_IP: &str = "http://0.0.0.0:6080";

#[derive(Clone)]
pub struct HttpServerConfig {
    pub http_ip: String,
    pub http_root: String,
    pub username: String,
    pub password: String,
    pub token_expired_time: u32,
    pub enable_cors: bool,
    pub enable_terminal: bool,
}

impl HttpServerConfig {
    pub fn new() -> Self {
        HttpServerConfig {
            http_ip: HTTP_SERVER_DEFAULT_IP.to_string(),
            http_root: HTTP_SERVER_DEFAULT_WWW_ROOT.to_string(),
            username: HTTP_SERVER_DEFAULT_USERNAME.to_string(),
            password: utils::hash_password(HTTP_SERVER_DEFAULT_PASSWORD, Some(1000)).unwrap(),
            token_expired_time: 600,
            enable_cors: false,
            enable_terminal: false,
        }
    }

    pub fn settings_map(&self) -> std::collections::HashMap<String, String> {
        let mut map = std::collections::HashMap::new();
        map.insert("http_ip".to_string(), self.http_ip.clone());
        map.insert("username".to_string(), self.username.clone());
        map.insert(
            "token_expired_time".to_string(),
            self.token_expired_time.to_string(),
        );
        map.insert("enable_cors".to_string(), self.enable_cors.to_string());
        map.insert(
            "enable_terminal".to_string(),
            self.enable_terminal.to_string(),
        );
        map
    }

    pub fn load_config(&mut self, data_server: Arc<DataServer>) -> Result<(), Box<dyn Error>> {
        if let Some(password) = data_server.get_config("smartdns-ui.password") {
            self.password = password;
        } else {
            if let Some(password_from_file) =
                data_server.get_server_config_from_file("smartdns-ui.password")
            {
                self.password =
                    utils::hash_password(password_from_file.as_str(), Some(10000)).unwrap();
            }
        }

        if let Some(username) = data_server.get_server_config("smartdns-ui.username") {
            self.username = username;
        }

        if let Some(enable_cors) = data_server.get_server_config("smartdns-ui.enable-cors") {
            if enable_cors.eq_ignore_ascii_case("yes") || enable_cors.eq_ignore_ascii_case("true") {
                self.enable_cors = true;
            } else {
                self.enable_cors = false;
            }
        }

        if let Some(enable_terminal) = data_server.get_server_config("smartdns-ui.enable-terminal")
        {
            if enable_terminal.eq_ignore_ascii_case("yes")
                || enable_terminal.eq_ignore_ascii_case("true")
            {
                self.enable_terminal = true;
            } else {
                self.enable_terminal = false;
            }
        }

        Ok(())
    }
}

pub struct HttpServerControl {
    http_server: Arc<HttpServer>,
    server_thread: Mutex<Option<JoinHandle<()>>>,
    plugin: Mutex<Option<Arc<SmartdnsPlugin>>>,
}

#[allow(dead_code)]
impl HttpServerControl {
    pub fn new() -> Self {
        HttpServerControl {
            http_server: Arc::new(HttpServer::new()),
            server_thread: Mutex::new(None),
            plugin: Mutex::new(None),
        }
    }

    pub fn set_plugin(&self, plugin: Arc<SmartdnsPlugin>) {
        *self.plugin.lock().unwrap() = Some(plugin);
    }

    pub fn get_plugin(&self) -> Arc<SmartdnsPlugin> {
        let plugin = self.plugin.lock().unwrap();
        Arc::clone(&plugin.as_ref().unwrap())
    }

    pub fn get_http_server(&self) -> Arc<HttpServer> {
        Arc::clone(&self.http_server)
    }

    pub fn start_http_server(&self, conf: &HttpServerConfig) -> Result<(), Box<dyn Error>> {
        dns_log!(LogLevel::INFO, "start smartdns-ui server.");

        let inner_clone = Arc::clone(&self.http_server);
        let ret = inner_clone.set_conf(conf);
        if let Err(e) = ret {
            return Err(e);
        }

        inner_clone.set_plugin(self.get_plugin());

        let (tx, rx) = std::sync::mpsc::channel::<i32>();
        let rt = self.get_plugin().get_runtime();

        let server_thread = rt.spawn(async move {
            let ret = HttpServer::http_server_loop(inner_clone, &tx).await;
            if let Err(e) = ret {
                _ = tx.send(0);
                dns_log!(LogLevel::ERROR, "http server error: {}", e);
                Plugin::smartdns_exit(1);
            }
            dns_log!(LogLevel::INFO, "http server exit.");
        });

        rx.recv().unwrap();

        *self.server_thread.lock().unwrap() = Some(server_thread);

        Ok(())
    }

    pub fn stop_http_server(&self) {
        let mut server_thread = self.server_thread.lock().unwrap();
        if server_thread.is_none() {
            return;
        }

        dns_log!(LogLevel::INFO, "stop smartdns-ui server.");

        self.http_server.stop_http_server();

        if let Some(server_thread) = server_thread.take() {
            let rt = self.get_plugin().get_runtime();
            tokio::task::block_in_place(|| {
                if let Err(e) = rt.block_on(server_thread) {
                    dns_log!(LogLevel::ERROR, "http server stop error: {}", e);
                }
            });
        }

        *server_thread = None;
    }
}

impl Drop for HttpServerControl {
    fn drop(&mut self) {
        self.stop_http_server();
    }
}

#[derive(Clone)]
pub struct TokioExecutor;

impl<F> hyper::rt::Executor<F> for TokioExecutor
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        tokio::task::spawn(fut);
    }
}

pub struct HttpServer {
    conf: Mutex<HttpServerConfig>,
    notify_tx: Option<mpsc::Sender<()>>,
    notify_rx: Mutex<Option<mpsc::Receiver<()>>>,
    api: API,
    local_addr: Mutex<Option<SocketAddr>>,
    mime_map: std::collections::HashMap<&'static str, &'static str>,
    login_attempts: Mutex<(i32, Instant)>,
    plugin: Mutex<Option<Arc<SmartdnsPlugin>>>,
}

#[allow(dead_code)]
impl HttpServer {
    fn new() -> Self {
        let mut plugin = HttpServer {
            conf: Mutex::new(HttpServerConfig::new()),
            notify_tx: None,
            notify_rx: Mutex::new(None),
            api: API::new(),
            local_addr: Mutex::new(None),
            login_attempts: Mutex::new((0, Instant::now())),
            plugin: Mutex::new(None),
            mime_map: std::collections::HashMap::from([
                /* text */
                ("htm", "text/html"),
                ("html", "text/html"),
                ("js", "text/javascript"),
                ("css", "text/css"),
                ("txt", "text/plain"),
                ("conf", "text/plain"),
                ("xml", "text/xml"),
                ("csv", "text/csv"),
                ("md", "text/markdown"),
                /* image */
                ("png", "image/png"),
                ("gif", "image/gif"),
                ("jpeg", "image/jpeg"),
                ("svg", "image/svg+xml"),
                ("ico", "image/x-icon"),
                ("bmp", "image/bmp"),
                ("avif", "image/avif"),
                /* video */
                ("mpeg", "video/mpeg"),
                ("mp4", "video/mp4"),
                ("webm", "video/webm"),
                /* audio */
                ("mp3", "audio/mpeg"),
                ("ogg", "audio/ogg"),
                ("wav", "audio/wav"),
                /* font */
                ("woff", "font/woff"),
                ("woff2", "font/woff2"),
                ("ttf", "font/ttf"),
                ("otf", "font/otf"),
                /* application */
                ("wasm", "application/wasm"),
                ("pdf", "application/pdf"),
                ("json", "application/json"),
                ("tar", "application/x-tar"),
                ("zip", "application/zip"),
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

    pub fn get_conf_mut(&self) -> MutexGuard<HttpServerConfig> {
        self.conf.lock().unwrap()
    }

    pub fn login_attempts_reset(&self) {
        let mut attempts = self.login_attempts.lock().unwrap();
        attempts.0 = 0;
        attempts.1 = Instant::now();
    }

    pub fn login_attempts_check(&self) -> bool {
        let mut attempts = self.login_attempts.lock().unwrap();

        if attempts.0 == 0 {
            attempts.1 = Instant::now();
        }

        attempts.0 += 1;

        if attempts.0 > 5 {
            let now = Instant::now();
            let duration = now.duration_since(attempts.1);
            if duration.as_secs() < 60 {
                if duration.as_secs() < 30 {
                    attempts.1 = Instant::now();
                }
                return false;
            }

            attempts.0 = 0;
            attempts.1 = now;
        }

        true
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

    fn set_plugin(&self, plugin: Arc<SmartdnsPlugin>) {
        let mut _plugin = self.plugin.lock().unwrap();
        *_plugin = Some(plugin)
    }

    fn get_plugin(&self) -> Arc<SmartdnsPlugin> {
        let plugin = self.plugin.lock().unwrap();
        Arc::clone(&plugin.as_ref().unwrap())
    }

    pub fn get_data_server(&self) -> Arc<DataServer> {
        self.get_plugin().get_data_server()
    }

    pub fn get_token_from_header(
        req: &Request<body::Incoming>,
    ) -> Result<Option<String>, Box<dyn Error>> {
        let token: String;
        let header_auth = req.headers().get("Authorization");
        if header_auth.is_none() {
            let cookie = req.headers().get("Cookie");
            if cookie.is_none() {
                return Ok(None);
            }

            let cookie = cookie.unwrap().to_str();
            if let Err(_) = cookie {
                return Ok(None);
            }

            let cookies = cookie.unwrap().split(';').collect::<Vec<&str>>();
            let token_cookie = cookies.iter().find(|c| c.trim().starts_with("token="));
            if token_cookie.is_none() {
                return Ok(None);
            }

            let token_cookie = token_cookie.unwrap().trim().strip_prefix("token=");
            if token_cookie.is_none() {
                return Ok(None);
            }

            let data = urlencoding::decode(token_cookie.unwrap());
            if let Err(_) = data {
                return Ok(None);
            }

            let data = data.unwrap();
            token = data.to_string();
        } else {
            let auth = header_auth.unwrap().to_str();
            if let Err(_) = auth {
                return Ok(None);
            }

            token = auth.unwrap().to_string();
        }

        let token_type = "Bearer";
        if !token.starts_with(token_type) {
            return Err("Invalid authorization type".into());
        }

        let token = token.strip_prefix(token_type).unwrap().trim();

        Ok(Some(token.to_string()))
    }

    pub fn auth_token_is_valid(
        &self,
        req: &Request<body::Incoming>,
    ) -> Result<bool, Box<dyn Error>> {
        let token = HttpServer::get_token_from_header(req)?;

        if token.is_none() {
            return Ok(false);
        }

        let token = token.unwrap();
        let conf = self.conf.lock().unwrap();
        let jwt = Jwt::new(&conf.username, &conf.password, "", conf.token_expired_time);
        if !jwt.is_token_valid(token.as_str()) {
            return Ok(false);
        }
        Ok(true)
    }

    fn server_add_cors_header(
        &self,
        origin: &Option<hyper::header::HeaderValue>,
        response: &mut Response<Full<Bytes>>,
    ) {
        if self.get_conf().enable_cors {
            if let Some(origin) = origin {
                response
                    .headers_mut()
                    .insert("Access-Control-Allow-Origin", origin.clone());
            } else {
                response
                    .headers_mut()
                    .insert("Access-Control-Allow-Origin", "*".parse().unwrap());
            }

            response.headers_mut().insert(
                "Access-Control-Allow-Methods",
                "GET, POST, PUT, DELETE, OPTIONS, PATCH".parse().unwrap(),
            );

            response.headers_mut().insert(
                "Access-Control-Allow-Headers",
                "Content-Type, Authorization, Set-Cookie".parse().unwrap(),
            );

            response
                .headers_mut()
                .insert("Access-Control-Allow-Credentials", "true".parse().unwrap());

            response
                .headers_mut()
                .insert("Access-Control-Max-Age", "600".parse().unwrap());
        }
    }

    async fn server_handle_http_api_request(
        this: Arc<HttpServer>,
        req: Request<body::Incoming>,
        _path: PathBuf,
    ) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error>> {
        let mut origin: Option<HeaderValue> = None;

        if let Some(o) = req.headers().get("Origin") {
            origin = Some(o.clone());
        }

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

            this.server_add_cors_header(&origin, &mut response);
            Ok(response)
        };

        dns_log!(LogLevel::DEBUG, "api request: {:?}", req.uri());

        if req.method() == hyper::Method::OPTIONS {
            let mut response = Response::new(Full::new(Bytes::from("")));
            response
                .headers_mut()
                .insert("Content-Type", "application/json".parse().unwrap());
            response
                .headers_mut()
                .insert("Cache-Control", "no-cache".parse().unwrap());
            this.server_add_cors_header(&origin, &mut response);
            return Ok(response);
        }

        match this.api.get_router(req.method(), req.uri().path()) {
            Some((router, param)) => {
                if router.auth {
                    let is_token_valid = this.auth_token_is_valid(&req);
                    if let Err(e) = is_token_valid {
                        return error_response(StatusCode::BAD_REQUEST, e.to_string().as_str());
                    }

                    if !is_token_valid.unwrap() {
                        return error_response(StatusCode::UNAUTHORIZED, "Please login.");
                    }
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

                        this.server_add_cors_header(&origin, &mut resp);

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
        let mut is_404 = false;
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
                return Ok(response);
            }

            let ret = ret.unwrap();
            return Ok(ret);
        }

        dns_log!(LogLevel::DEBUG, "page request: {:?}", req.uri());
        let mut filepath = www_root.join(path);
        let uri_path = req.uri().path().to_string();
        let mut path = uri_path.clone();

        if !filepath.exists() || filepath.is_dir() {
            let suffix = filepath.extension();
            if suffix.is_none() && !uri_path.ends_with("/") {
                let check_filepath = filepath.with_extension("html");
                if check_filepath.exists() {
                    filepath = check_filepath;
                    path = format!("{}.html", uri_path);
                }
            }

            if filepath.is_dir() {
                filepath = filepath.join("index.html");
                path = format!("{}/index.html", uri_path);
            }

            if !filepath.exists() {
                filepath = www_root.join("404.html");
                path = "/404.html".to_string();
                if !filepath.exists() {
                    filepath = www_root.join("index.html");
                    path = format!("/index.html");
                } else {
                    is_404 = true;
                }
            }
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
                header.insert("Connection", "keep-alive".parse().unwrap());
                header.insert("Keep-Alive", "timeout=60, max=1000".parse().unwrap());

                if file_meta.as_ref().is_some() {
                    let etag = fn_get_etag(&file_meta.as_ref().unwrap());
                    header.insert("ETag", etag.parse().unwrap());
                }

                if is_404 {
                    *response.status_mut() = StatusCode::NOT_FOUND;
                } else {
                    *response.status_mut() = StatusCode::OK;
                }

                Ok(response)
            }
            Err(_) => {
                let bytes = Bytes::from("Page Not Found");
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
            let conn = auto::Builder::new(TokioExecutor)
                .serve_connection_with_upgrades(io, service_fn(handle_func))
                .await;
            if let Err(err) = conn {
                dns_log!(LogLevel::DEBUG, "Error serving connection: {:?}", err);
                return;
            }
        });
    }

    #[cfg(feature = "https")]
    async fn https_server_handle_conn(
        this: Arc<HttpServer>,
        stream: tokio_rustls::server::TlsStream<TcpStream>,
    ) {
        let io = TokioIo::new(stream);

        let handle_func = move |req| HttpServer::server_handle_http_request(this.clone(), req);

        tokio::task::spawn(async move {
            let conn = auto::Builder::new(TokioExecutor)
                .serve_connection_with_upgrades(io, service_fn(handle_func))
                .await;
            if let Err(err) = conn {
                dns_log!(LogLevel::DEBUG, "Error serving connection: {:?}", err);
                return;
            }
        });
    }

    #[cfg(feature = "https")]
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

        cfg_if::cfg_if! {
            if #[cfg(feature = "https")]
            {
                let mut acceptor = None;
                if url.scheme() == "https" {
                    #[cfg(feature = "https")]
                    let cert_info = Plugin::smartdns_get_cert()?;

                    dns_log!(
                        LogLevel::DEBUG,
                        "cert: {}, key: {}",
                        cert_info.cert,
                        cert_info.key
                    );
                    let cert_chain: Result<Vec<rustls::pki_types::CertificateDer<'_>>, _> =
                        rustls_pemfile::certs(&mut BufReader::new(std::fs::File::open(
                            cert_info.cert,
                        )?))
                        .collect();
                    let cert_chain = cert_chain.unwrap_or_else(|_| Vec::new());
                    let key_der = rustls_pemfile::private_key(&mut BufReader::new(
                        std::fs::File::open(cert_info.key)?,
                    ))?
                    .unwrap();

                    let mut config = rustls::ServerConfig::builder()
                        .with_no_client_auth()
                        .with_single_cert(cert_chain, key_der)?;

                    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
                    acceptor = Some(TlsAcceptor::from(Arc::new(config)));
                }
            } else {
                if url.scheme() == "https" {
                    return Err("https is not supported.".into());
                }
            }
        }

        let host = url.host_str().unwrap_or("127.0.0.1");
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
                            ka = ka.with_time(Duration::from_secs(60));
                            ka = ka.with_interval(Duration::from_secs(30));
                            sock_ref.set_tcp_keepalive(&ka)?;
                            sock_ref.set_nonblocking(true)?;
                            sock_ref.tcp_nodelay()?;

                            if let Err(_) = sock_ref.set_recv_buffer_size(262144) {
                                dns_log!(LogLevel::DEBUG, "Failed to set recv buffer size");
                            }

                            if let Err(_) = sock_ref.set_send_buffer_size(262144) {
                                dns_log!(LogLevel::DEBUG, "Failed to set send buffer size");
                            }
                            cfg_if::cfg_if! {
                                if #[cfg(feature = "https")]
                                {
                                    if acceptor.is_some() {
                                        let acceptor = acceptor.clone().unwrap().clone();
                                        let this_clone = this.clone();
                                        HttpServer::handle_tls_accept(this_clone, acceptor, stream).await;
                                    } else {
                                        HttpServer::http_server_handle_conn(this.clone(), stream).await;
                                    }
                                } else  {
                                    HttpServer::http_server_handle_conn(this.clone(), stream).await;
                                }
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
            let rt = self.get_plugin().get_runtime();
            tokio::task::block_in_place(|| {
                let _ = rt.block_on(async {
                    let _ = tx.send(()).await;
                });
            });
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
