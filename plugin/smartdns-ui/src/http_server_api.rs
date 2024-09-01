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

use crate::db::*;
use crate::dns_log;
use crate::http_api_msg::*;
use crate::http_error::*;
use crate::http_jwt::*;
use crate::http_server::*;
use crate::http_server_stream;
use crate::smartdns;
use crate::smartdns::*;
use crate::Plugin;

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::{body, Method, Request, Response, StatusCode};
use matchit::Router;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use url::form_urlencoded;

const PASSWORD_CONFIG_KEY: &str = "smartdns-ui.password";
const REST_API_PATH: &str = "/api";

type APIRouteFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
type APIRouterFun = fn(
    this: Arc<HttpServer>,
    param: APIRouteParam,
    req: Request<body::Incoming>,
) -> APIRouteFuture<'static, Result<Response<Full<Bytes>>, HttpError>>;
type APIRouteParam = HashMap<String, String>;

pub struct APIRouter {
    pub method: Method,
    pub auth: bool,
    pub handler: APIRouterFun,
}

pub struct API {
    router: Router<std::collections::HashMap<Method, APIRouter>>,
}

macro_rules! APIRoute {
    ( $fn:path) => {
        |r, p, h| Box::pin($fn(r, p, h))
    };
}

#[allow(dead_code)]
impl API {
    #[rustfmt::skip]
    pub fn new() -> Self {
        let mut api = API {
            router: Router::new(),
        };

        api.register(Method::PUT, "/api/service/restart",  true, APIRoute!(API::api_service_restart));
        api.register(Method::PUT, "/api/cache/flush",  true, APIRoute!(API::api_cache_flush));
        api.register(Method::GET, "/api/cache/count",  true, APIRoute!(API::api_cache_count));
        api.register(Method::POST, "/api/auth/login",  false, APIRoute!(API::api_auth_login));
        api.register(Method::POST, "/api/auth/logout",  false, APIRoute!(API::api_auth_logout));
        api.register(Method::GET, "/api/auth/check",  true, APIRoute!(API::api_auth_check));
        api.register(Method::PUT, "/api/auth/password",  false, APIRoute!(API::api_auth_change_password));
        api.register(Method::POST, "/api/auth/refresh",  true, APIRoute!(API::api_auth_refresh));
        api.register(Method::GET, "/api/domain",  true, APIRoute!(API::api_domain_get_list));
        api.register(Method::DELETE, "/api/domain",  true, APIRoute!(API::api_domain_delete_list));
        api.register(Method::GET, "/api/domain/count",  true, APIRoute!(API::api_domain_get_list_count));
        api.register(Method::GET, "/api/domain/{id}",  true, APIRoute!(API::api_domain_get_by_id));
        api.register(Method::DELETE, "/api/domain/{id}",  true, APIRoute!(API::api_domain_delete_by_id));
        api.register(Method::GET, "/api/client", true, APIRoute!(API::api_client_get_list));
        api.register(Method::GET, "/api/log/stream", true, APIRoute!(API::api_log_stream));
        api.register(Method::PUT, "/api/log/level", true, APIRoute!(API::api_log_set_level));
        api.register(Method::GET, "/api/log/level", true, APIRoute!(API::api_log_get_level));
        api.register(Method::GET, "/api/server/version", false, APIRoute!(API::api_server_version));
        api.register(Method::GET, "/api/upstream-server", true, APIRoute!(API::api_upstream_server_get_list));
        api.register(Method::GET, "/api/config/settings", true, APIRoute!(API::api_config_get_settings));
        api.register(Method::PUT, "/api/config/settings", true, APIRoute!(API::api_config_set_settings));
        api.register(Method::GET, "/api/stats/top/client", true, APIRoute!(API::api_stats_get_top_client));
        api.register(Method::GET, "/api/stats/top/domain", true, APIRoute!(API::api_stats_get_top_domain));
        api.register(Method::GET, "/api/stats/overview", true, APIRoute!(API::api_stats_get_overview));
        api.register(Method::GET, "/api/stats/hourly-query-count", true, APIRoute!(API::api_stats_get_hourly_query_count));
        api.register(Method::GET, "/api/whois", true, APIRoute!(API::api_whois));
        api.register(Method::GET, "/api/tool/term", true, APIRoute!(API::api_tool_term));
        api
    }

    pub fn register(&mut self, method: Method, path: &str, auth: bool, handler: APIRouterFun) {
        let route_data = APIRouter {
            method: method.clone(),
            auth: auth,
            handler: handler,
        };

        let mut m = self.router.at_mut(path);
        if m.is_err() {
            let map_new = std::collections::HashMap::new();
            _ = self.router.insert(path, map_new);
            m = self.router.at_mut(path);
            if m.is_err() {
                return;
            }
        }

        let m = m.unwrap();
        let mutmethod_map = m.value;
        mutmethod_map.insert(method, route_data);
    }

    pub fn get_router(&self, method: &Method, path: &str) -> Option<(&APIRouter, APIRouteParam)> {
        let m = self.router.at(path);
        if m.is_err() {
            return None;
        }

        let m = m.unwrap();
        let method_map = m.value;
        let route_data = method_map.get(method);
        if route_data.is_none() {
            return None;
        }

        let route_data = route_data.unwrap();
        let mut param = APIRouteParam::new();

        m.params.iter().for_each(|(k, v)| {
            let v = v.to_string();
            param.insert(k.to_string(), v);
        });
        Some((route_data, param))
    }

    fn get_params(req: &Request<body::Incoming>) -> HashMap<String, String> {
        let b = req.uri().query().unwrap_or("").to_string();
        form_urlencoded::parse(b.as_ref())
            .into_owned()
            .collect::<HashMap<String, String>>()
    }

    fn params_parser_value<T: std::str::FromStr>(v: Option<&String>) -> Option<T> {
        if v.is_none() {
            return None;
        }
        let v = v.unwrap();

        match T::from_str(&v) {
            Ok(value) => Some(value),
            Err(_) => None,
        }
    }

    fn params_get_value<T: std::str::FromStr>(
        params: &HashMap<String, String>,
        key: &str,
    ) -> Option<T> {
        let v = params.get(key);
        if v.is_none() {
            return None;
        }

        let v = v.unwrap();
        API::params_parser_value(Some(v))
    }

    fn params_get_value_default<T: std::str::FromStr>(
        params: &HashMap<String, String>,
        key: &str,
        default: T,
    ) -> Result<T, HttpError> {
        let v = params.get(key);
        if v.is_none() {
            return Ok(default);
        }
        let v = v.unwrap();
        match v.parse::<T>() {
            Ok(v) => return Ok(v),
            Err(_) => {
                return Err(HttpError::new(
                    StatusCode::BAD_REQUEST,
                    format!("Invalid parameter: {}", key),
                ));
            }
        }
    }

    pub fn response_error(code: StatusCode, msg: &str) -> Result<Response<Full<Bytes>>, HttpError> {
        let bytes = Bytes::from(api_msg_error(msg));
        let mut response = Response::new(Full::new(bytes));
        response
            .headers_mut()
            .insert("Content-Type", "application/json".parse().unwrap());
        *response.status_mut() = code;
        Ok(response)
    }

    pub fn response_build(
        code: StatusCode,
        body: String,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        let mut response = Response::new(Full::new(Bytes::from(body)));
        response
            .headers_mut()
            .insert("Content-Type", "application/json".parse().unwrap());
        *response.status_mut() = code;
        Ok(response)
    }

    async fn api_auth_refresh(
        this: Arc<HttpServer>,
        _param: APIRouteParam,
        req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        let token = HttpServer::get_token_from_header(&req)?;
        let unauth_response =
            || API::response_error(StatusCode::UNAUTHORIZED, "Incorrect username or password.");

        if token.is_none() {
            return unauth_response();
        }

        let token = token.unwrap();
        let conf = this.get_conf();
        let jtw = Jwt::new(
            &conf.username.as_str(),
            conf.password.as_str(),
            "",
            conf.token_expired_time,
        );

        let calim = jtw.decode_token(token.as_str());
        if calim.is_err() {
            return unauth_response();
        }

        let token_new = jtw.refresh_token(token.as_str());
        if token_new.is_err() {
            return unauth_response();
        }

        let token_new = token_new.unwrap();
        let mut resp = API::response_build(
            StatusCode::OK,
            api_msg_auth_token(&token_new.token, &token_new.expire),
        );

        let cookie_token = format!("Bearer {}", token_new.token);
        let token_urlencode = urlencoding::encode(cookie_token.as_str());
        let cookie = format!(
            "token={}; HttpOnly; Max-Age={}; Path={}",
            token_urlencode, token_new.expire, REST_API_PATH
        );

        resp.as_mut()
            .unwrap()
            .headers_mut()
            .insert(hyper::header::SET_COOKIE, cookie.parse().unwrap());

        resp
    }

    /// Login
    /// API: POST /api/auth/login
    ///     body:
    /// {
    ///   "username": "admin"
    ///   "password": "password"
    /// }
    async fn api_auth_login(
        this: Arc<HttpServer>,
        _param: APIRouteParam,
        req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        let whole_body = String::from_utf8(req.into_body().collect().await?.to_bytes().into())?;
        let userinfo = api_msg_parse_auth(whole_body.as_str());
        if let Err(e) = userinfo {
            return API::response_error(StatusCode::BAD_REQUEST, e.to_string().as_str());
        }

        let conf = this.get_conf();
        let userinfo = userinfo.unwrap();

        if !this.login_attempts_check() {
            return API::response_error(
                StatusCode::FORBIDDEN,
                "Too many login attempts, please try again later.",
            );
        }

        if userinfo.username != conf.username || userinfo.password != conf.password {
            return API::response_error(
                StatusCode::UNAUTHORIZED,
                "Incorrect username or password.",
            );
        }

        this.login_attempts_reset();

        let jtw = Jwt::new(
            userinfo.username.as_str(),
            conf.password.as_str(),
            "",
            conf.token_expired_time,
        );
        let token = jtw.encode_token();
        let mut resp = API::response_build(
            StatusCode::OK,
            api_msg_auth_token(&token.token, &token.expire),
        );

        let cookie_token = format!("Bearer {}", token.token);
        let token_urlencode = urlencoding::encode(cookie_token.as_str());
        let cookie = format!(
            "token={}; HttpOnly; Max-Age={}; Path={}",
            token_urlencode, token.expire, REST_API_PATH
        );

        resp.as_mut()
            .unwrap()
            .headers_mut()
            .insert(hyper::header::SET_COOKIE, cookie.parse().unwrap());

        resp
    }

    async fn api_auth_logout(
        _this: Arc<HttpServer>,
        _param: APIRouteParam,
        _req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        let mut response = Response::new(Full::new(Bytes::from("")));

        let cookie = format!("token=none; HttpOnly; Max-Age=1; Path={}", REST_API_PATH);

        response
            .headers_mut()
            .insert(hyper::header::SET_COOKIE, cookie.parse().unwrap());
        *response.status_mut() = StatusCode::NO_CONTENT;
        Ok(response)
    }

    async fn api_auth_check(
        _this: Arc<HttpServer>,
        _param: APIRouteParam,
        _req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        API::response_build(StatusCode::OK, "".to_string())
    }

    async fn api_auth_change_password(
        this: Arc<HttpServer>,
        _param: APIRouteParam,
        req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        let unauth_response =
            || API::response_error(StatusCode::UNAUTHORIZED, "Incorrect username or password.");
        let token = HttpServer::get_token_from_header(&req)?;
        let whole_body = String::from_utf8(req.into_body().collect().await?.to_bytes().into())?;
        if token.is_none() {
            return unauth_response();
        }

        let password_info = api_msg_parse_auth_password_change(whole_body.as_str());
        if let Err(e) = password_info {
            return API::response_error(StatusCode::BAD_REQUEST, e.to_string().as_str());
        }

        let password_info = password_info.unwrap();
        if password_info.0 == password_info.1 {
            return API::response_error(
                StatusCode::BAD_REQUEST,
                "The new password is the same as the old password.",
            );
        }

        let token = token.unwrap();
        let mut conf = this.get_conf_mut();
        let jtw = Jwt::new(
            &conf.username.as_str(),
            password_info.0.as_str(),
            "",
            conf.token_expired_time,
        );

        if !this.login_attempts_check() {
            return API::response_error(
                StatusCode::FORBIDDEN,
                "Too many login attempts, please try again later.",
            );
        }

        let calim = jtw.decode_token(token.as_str());
        if calim.is_err() {
            return API::response_error(StatusCode::FORBIDDEN, "Incorrect password.");
        }

        let data_server = this.get_data_server();
        conf.password = password_info.1.clone();
        let ret = data_server.set_config(PASSWORD_CONFIG_KEY, password_info.1.as_str());
        if let Err(e) = ret {
            return API::response_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string().as_str());
        }

        this.login_attempts_reset();
        API::response_build(StatusCode::NO_CONTENT, "".to_string())
    }

    /// Restart the service <br>
    /// API: PUT /api/service/restart
    ///
    async fn api_service_restart(
        _this: Arc<HttpServer>,
        _param: APIRouteParam,
        _req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        let mut response = Response::new(Full::new(Bytes::from("")));
        response
            .headers_mut()
            .insert("Content-Type", "application/json".parse().unwrap());
        *response.status_mut() = StatusCode::NO_CONTENT;
        Plugin::smartdns_restart();
        Ok(response)
    }

    /// Get the number of cache <br>
    /// API: GET /api/cache/count
    ///
    async fn api_cache_count(
        _this: Arc<HttpServer>,
        _param: APIRouteParam,
        _req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        API::response_build(
            StatusCode::OK,
            api_msg_gen_cache_number(Plugin::dns_cache_total_num()),
        )
    }

    /// Flush the cache <br>
    /// API: PUT /api/cache/flush
    ///
    async fn api_cache_flush(
        _this: Arc<HttpServer>,
        _param: APIRouteParam,
        _req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        Plugin::dns_cache_flush();
        API::response_build(
            StatusCode::OK,
            api_msg_gen_cache_number(Plugin::dns_cache_total_num()),
        )
    }

    /// Get the number of domain list <br>
    /// API: GET /api/domain/count
    ///
    async fn api_domain_get_list_count(
        this: Arc<HttpServer>,
        _param: APIRouteParam,
        _req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        let data_server = this.get_data_server();
        let count = data_server.get_domain_list_count();
        let body = api_msg_gen_count(count as i64);

        API::response_build(StatusCode::OK, body)
    }

    /// Get the domain by id <br>
    /// API: GET /api/domain/{id}
    async fn api_domain_get_by_id(
        this: Arc<HttpServer>,
        param: APIRouteParam,
        _req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        let id = API::params_parser_value(param.get("id"));
        if id.is_none() {
            return API::response_error(StatusCode::BAD_REQUEST, "Invalid parameter.");
        }

        let id = id.unwrap();
        let mut get_param = DomainListGetParam::new();
        get_param.id = Some(id);

        let data_server = this.get_data_server();
        let domain_list = data_server.get_domain_list(&get_param)?;
        if domain_list.domain_list.len() == 0 {
            return API::response_error(StatusCode::NOT_FOUND, "Not found");
        }
        let body = api_msg_gen_domain(&domain_list.domain_list[0]);

        API::response_build(StatusCode::OK, body)
    }

    /// Delete the domain by id <br>
    /// API: DELETE /api/domain/{id}
    ///
    async fn api_domain_delete_by_id(
        this: Arc<HttpServer>,
        param: APIRouteParam,
        _req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        let id = API::params_parser_value(param.get("id"));
        if id.is_none() {
            return API::response_error(StatusCode::BAD_REQUEST, "Invalid parameter.");
        }

        let id = id.unwrap();
        let data_server = this.get_data_server();
        let ret = data_server.delete_domain_by_id(id);
        if let Err(e) = ret {
            return API::response_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string().as_str());
        }

        if ret.unwrap() == 0 {
            return API::response_error(StatusCode::NOT_FOUND, "Not found");
        }

        API::response_build(StatusCode::NO_CONTENT, "".to_string())
    }

    /// Get the domain list <br>
    /// API: GET /api/domain <br>
    ///   parameter: <br>
    ///     page_num: u32: Page number <br>
    ///     page_size: u32: Page size <br>
    ///     domain: String: Domain <br>
    ///     domain_type: String: Domain type <br>
    ///     domain_group: String: Domain group <br>
    ///     client: String: Client <br>
    ///     reply_code: String: Reply code <br>
    ///
    ///
    async fn api_domain_get_list(
        this: Arc<HttpServer>,
        _param: APIRouteParam,
        req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        let params = API::get_params(&req);

        let page_num = API::params_get_value_default(&params, "page_num", 1 as u32)?;
        let page_size = API::params_get_value_default(&params, "page_size", 10 as u32)?;
        if page_num == 0 || page_size == 0 {
            return API::response_error(
                StatusCode::BAD_REQUEST,
                "Invalid parameter: page_num or page_size",
            );
        }

        let id = API::params_get_value(&params, "id");
        let domain = API::params_get_value(&params, "domain");
        let domain_filter_mode = API::params_get_value(&params, "domain_filter_mode");
        let domain_type = API::params_get_value(&params, "domain_type");
        let domain_group = API::params_get_value(&params, "domain_group");
        let client = API::params_get_value(&params, "client");
        let reply_code = API::params_get_value(&params, "reply_code");
        let order = API::params_get_value(&params, "order");
        let timestamp_after = API::params_get_value(&params, "timestamp_after");
        let timestamp_before = API::params_get_value(&params, "timestamp_before");

        let mut param = DomainListGetParam::new();
        param.id = id;
        param.page_num = page_num;
        param.page_size = page_size;
        param.domain = domain;
        param.domain_filter_mode = domain_filter_mode;
        param.domain_type = domain_type;
        param.domain_group = domain_group;
        param.client = client;
        param.reply_code = reply_code;
        param.order = order;
        param.timestamp_after = timestamp_after;
        param.timestamp_before = timestamp_before;

        let data_server = this.get_data_server();
        let ret = API::call_blocking(this, move || {
            let ret = data_server.get_domain_list(&param);
            if let Err(e) = ret {
                return Err(e.to_string());
            }

            let ret = ret.unwrap();

            return Ok(ret);
        })
        .await;

        if let Err(e) = ret {
            return API::response_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string().as_str());
        }

        let ret = ret.unwrap();
        if let Err(e) = ret {
            return API::response_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string().as_str());
        }

        let domain_list = ret.unwrap();
        let list_count = domain_list.total_count;
        let mut total_page = list_count / page_size;
        if list_count % page_size != 0 {
            total_page += 1;
        }

        let total_count = domain_list.total_count;
        let body = api_msg_gen_domain_list(&domain_list.domain_list, total_page, total_count);

        API::response_build(StatusCode::OK, body)
    }

    /// Delete the domain list before timestamp <br>
    /// API: DELETE /api/domain <br>
    ///   parameter: <br>
    ///     timestamp: u64: Unix timestamp <br>
    ///
    async fn api_domain_delete_list(
        this: Arc<HttpServer>,
        _param: APIRouteParam,
        req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        let params = API::get_params(&req);
        let timestamp_before = API::params_get_value(&params, "timestamp_before");
        if timestamp_before.is_none() {
            return API::response_error(StatusCode::BAD_REQUEST, "Invalid parameter.");
        }

        let timestamp_before = timestamp_before.unwrap();
        let data_server = this.get_data_server();
        let ret = data_server.delete_domain_before_timestamp(timestamp_before);
        if let Err(e) = ret {
            return API::response_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string().as_str());
        }

        if *ret.as_ref().unwrap() == 0 {
            return API::response_error(StatusCode::NOT_FOUND, "Not found");
        }

        let body = api_msg_gen_count(ret.unwrap() as i64);
        API::response_build(StatusCode::OK, body)
    }

    async fn api_client_get_list(
        this: Arc<HttpServer>,
        _param: APIRouteParam,
        _req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        let data_server = this.get_data_server();
        let client_list: Vec<ClientData> = data_server.get_client_list()?;
        let body = api_msg_gen_client_list(&client_list);

        API::response_build(StatusCode::OK, body)
    }

    async fn api_log_stream(
        this: Arc<HttpServer>,
        _param: APIRouteParam,
        mut req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        if hyper_tungstenite::is_upgrade_request(&req) {
            let (response, websocket) = hyper_tungstenite::upgrade(&mut req, None)
                .map_err(|e| HttpError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            tokio::spawn(async move {
                if let Err(e) = http_server_stream::serve_log_stream(this, websocket).await {
                    dns_log!(LogLevel::DEBUG, "Error in websocket connection: {e}");
                }
            });

            Ok(response)
        } else {
            return API::response_error(StatusCode::BAD_REQUEST, "Need websocket upgrade.");
        }
    }

    async fn api_log_set_level(
        this: Arc<HttpServer>,
        _param: APIRouteParam,
        _req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        let whole_body = String::from_utf8(_req.into_body().collect().await?.to_bytes().into())?;
        let level = api_msg_parse_loglevel(whole_body.as_str());
        if let Err(e) = level {
            return API::response_error(StatusCode::BAD_REQUEST, e.to_string().as_str());
        }

        let level = level.unwrap();
        dns_log_set_level(level);
        let data_server = this.get_data_server();
        _ = data_server.set_config("log-level", level.to_string().as_str());
        API::response_build(StatusCode::NO_CONTENT, "".to_string())
    }

    async fn api_log_get_level(
        _this: Arc<HttpServer>,
        _param: APIRouteParam,
        _req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        let level = dns_log_get_level();
        let msg = api_msg_gen_loglevel(level);
        API::response_build(StatusCode::OK, msg)
    }

    async fn api_server_version(
        _this: Arc<HttpServer>,
        _param: APIRouteParam,
        _req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        let server_version = &smartdns::smartdns_version();
        let ui_version = &smartdns::smartdns_ui_version();
        let msg = api_msg_gen_version(server_version, ui_version);
        API::response_build(StatusCode::OK, msg)
    }

    async fn api_upstream_server_get_list(
        this: Arc<HttpServer>,
        _param: APIRouteParam,
        _req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        let data_server = this.get_data_server();
        let upstream_server_list = data_server.get_upstream_server_list()?;
        let body = api_msg_gen_upstream_server_list(&upstream_server_list);

        API::response_build(StatusCode::OK, body)
    }

    async fn api_config_get_settings(
        this: Arc<HttpServer>,
        _param: APIRouteParam,
        _req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        let data_server = this.get_data_server();
        let settings = data_server.get_config_list();
        if settings.is_err() {
            return API::response_error(StatusCode::NOT_FOUND, "Not found");
        }

        let mut settings = settings.unwrap();
        let pass = settings.get(PASSWORD_CONFIG_KEY);
        if pass.is_some() {
            let pass = "********".to_string();
            settings.insert(PASSWORD_CONFIG_KEY.to_string(), pass);
        }
        let msg = api_msg_gen_key_value(&settings);
        API::response_build(StatusCode::OK, msg)
    }

    async fn api_config_set_settings(
        this: Arc<HttpServer>,
        _param: APIRouteParam,
        req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        let data_server = this.get_data_server();
        let whole_body = String::from_utf8(req.into_body().collect().await?.to_bytes().into())?;
        let settings = api_msg_parse_key_value(whole_body.as_str());
        if let Err(e) = settings {
            return API::response_error(StatusCode::BAD_REQUEST, e.to_string().as_str());
        }

        let settings = settings.unwrap();
        for (key, value) in settings {
            if key == PASSWORD_CONFIG_KEY {
                continue;
            }
            let ret = data_server.set_config(key.as_str(), value.as_str());
            if let Err(e) = ret {
                return API::response_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    e.to_string().as_str(),
                );
            }
        }

        API::response_build(StatusCode::NO_CONTENT, "".to_string())
    }

    async fn api_stats_get_top_client(
        this: Arc<HttpServer>,
        _param: APIRouteParam,
        _req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        let data_server = this.get_data_server();
        let params = API::get_params(&_req);
        let count = API::params_get_value(&params, "count");

        let ret = API::call_blocking(this, move || {
            let ret = data_server.get_top_client_top_list(count);
            if let Err(e) = ret {
                return Err(e.to_string());
            }

            let ret = ret.unwrap();

            return Ok(ret);
        })
        .await;

        if let Err(e) = ret {
            return API::response_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string().as_str());
        }

        let ret = ret.unwrap();
        if let Err(e) = ret {
            return API::response_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string().as_str());
        }

        let body = api_msg_gen_top_client_list(&ret.unwrap());

        API::response_build(StatusCode::OK, body)
    }

    async fn api_stats_get_top_domain(
        this: Arc<HttpServer>,
        _param: APIRouteParam,
        _req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        let data_server = this.get_data_server();
        let params = API::get_params(&_req);
        let count = API::params_get_value(&params, "count");

        let ret = API::call_blocking(this, move || {
            let ret = data_server.get_top_domain_top_list(count);
            if let Err(e) = ret {
                return Err(e.to_string());
            }

            let ret = ret.unwrap();

            return Ok(ret);
        })
        .await;

        if let Err(e) = ret {
            return API::response_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string().as_str());
        }

        let ret = ret.unwrap();
        if let Err(e) = ret {
            return API::response_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string().as_str());
        }

        let body = api_msg_gen_top_domain_list(&ret.unwrap());
        API::response_build(StatusCode::OK, body)
    }

    async fn api_stats_get_overview(
        this: Arc<HttpServer>,
        _param: APIRouteParam,
        _req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        let data_server = this.get_data_server();
        let overview = data_server.get_overview()?;
        let body = api_msg_gen_stats_overview(&overview);
        API::response_build(StatusCode::OK, body)
    }

    async fn api_stats_get_hourly_query_count(
        this: Arc<HttpServer>,
        _param: APIRouteParam,
        _req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        let params = API::get_params(&_req);
        let past_hours = API::params_get_value(&params, "past_hours");
        let data_server = this.get_data_server();
        let ret = API::call_blocking(this, move || {
            let ret = data_server.get_hourly_query_count(past_hours);
            if let Err(e) = ret {
                return Err(e.to_string());
            }

            let ret = ret.unwrap();

            return Ok(ret);
        })
        .await;

        if let Err(e) = ret {
            return API::response_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string().as_str());
        }

        let ret = ret.unwrap();
        if let Err(e) = ret {
            return API::response_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string().as_str());
        }

        let body = api_msg_gen_hourly_query_count(&ret.unwrap());
        API::response_build(StatusCode::OK, body)
    }

    async fn api_whois(
        this: Arc<HttpServer>,
        _param: APIRouteParam,
        _req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        let params = API::get_params(&_req);
        let domain = API::params_get_value(&params, "domain");
        if domain.is_none() {
            return API::response_error(StatusCode::BAD_REQUEST, "Invalid parameter.");
        }

        let domain:String = domain.unwrap();
        let data_server = this.get_data_server();
        let ret = data_server.whois(domain.as_str()).await;

        if let Err(e) = ret {
            return API::response_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string().as_str());
        }

        let body = api_msg_gen_whois_info(&ret.unwrap());
        API::response_build(StatusCode::OK, body)
    }

    async fn api_tool_term(
        _this: Arc<HttpServer>,
        _param: APIRouteParam,
        mut req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        if hyper_tungstenite::is_upgrade_request(&req) {
            let (response, websocket) = hyper_tungstenite::upgrade(&mut req, None)
                .map_err(|e| HttpError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            tokio::spawn(async move {
                if let Err(e) = http_server_stream::serve_term(websocket).await {
                    dns_log!(LogLevel::DEBUG, "Error in websocket connection: {e}");
                }
            });

            Ok(response)
        } else {
            return API::response_error(StatusCode::BAD_REQUEST, "Need websocket upgrade.");
        }
    }

    async fn call_blocking<F, R>(
        this: Arc<HttpServer>,
        func: F,
    ) -> Result<R, Box<dyn std::error::Error + Send>>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let rt = this.get_data_server().get_plugin().get_runtime();

        let ret = rt.spawn_blocking(move || -> R {
            return func();
        });

        let ret = ret.await;
        if ret.is_err() {
            return Err(Box::new(ret.err().unwrap()));
        }

        let ret = ret.unwrap();
        
        return Ok(ret);
    }
}
