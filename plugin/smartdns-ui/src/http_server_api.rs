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
use crate::http_api_msg::*;
use crate::http_error::*;
use crate::http_jwt::*;
use crate::http_server::*;
use crate::http_server_log_stream;
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
        let token = req.headers().get("Authorization");
        if token.is_none() {
            return API::response_error(
                StatusCode::UNAUTHORIZED,
                "Incorrect username or password.",
            );
        }

        let conf = this.get_conf();

        let jtw = Jwt::new(
            &conf.user.as_str(),
            conf.password.as_str(),
            "",
            conf.token_expired_time,
        );

        let token = token.unwrap().to_str().unwrap();
        let token_new = jtw.refresh_token(token);
        if token_new.is_err() {
            return API::response_error(
                StatusCode::UNAUTHORIZED,
                "Incorrect username or password.",
            );
        }
        let token_new = token_new.unwrap();
        API::response_build(
            StatusCode::OK,
            api_msg_auth_token(&token_new.token, &token_new.expire),
        )
    }

    /// Login
    /// API: POST /api/auth/login
    ///     body:
    /// {
    ///   "user": "admin"
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

        if userinfo.user != conf.user || userinfo.password != conf.password {
            return API::response_error(
                StatusCode::UNAUTHORIZED,
                "Incorrect username or password.",
            );
        }

        let jtw = Jwt::new(
            userinfo.user.as_str(),
            conf.password.as_str(),
            "",
            conf.token_expired_time,
        );
        let token = jtw.encode_token();
        API::response_build(
            StatusCode::OK,
            api_msg_auth_token(&token.token, &token.expire),
        )
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
        let domain_list: Vec<DomainData> = data_server.get_domain_list(&get_param)?;
        if domain_list.len() == 0 {
            return API::response_error(StatusCode::NOT_FOUND, "Not found");
        }
        let body = api_msg_gen_domain(&domain_list[0]);

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

        let domain = API::params_get_value(&params, "domain");
        let domain_type = API::params_get_value(&params, "domain_type");
        let domain_group = API::params_get_value(&params, "domain_group");
        let client = API::params_get_value(&params, "client");
        let reply_code = API::params_get_value(&params, "reply_code");
        let order = API::params_get_value(&params, "order");
        let timestamp_after = API::params_get_value(&params, "timestamp_after");
        let timestamp_before = API::params_get_value(&params, "timestamp_before");

        let mut param = DomainListGetParam::new();
        param.page_num = page_num;
        param.page_size = page_size;
        param.domain = domain;
        param.domain_type = domain_type;
        param.domain_group = domain_group;
        param.client = client;
        param.reply_code = reply_code;
        param.order = order;
        param.timestamp_after = timestamp_after;
        param.timestamp_before = timestamp_before;

        let data_server = this.get_data_server();
        let domain_list: Vec<DomainData> = data_server.get_domain_list(&param)?;
        let list_count = data_server.get_domain_list_count();
        let mut total_page = list_count / page_size;
        if list_count % page_size != 0 {
            total_page += 1;
        }
        let body = api_msg_gen_domain_list(domain_list, total_page);

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
        let body = api_msg_gen_client_list(client_list);

        API::response_build(StatusCode::OK, body)
    }

    async fn api_log_stream(
        _this: Arc<HttpServer>,
        _param: APIRouteParam,
        mut req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        if hyper_tungstenite::is_upgrade_request(&req) {
            let (response, websocket) = hyper_tungstenite::upgrade(&mut req, None)
                .map_err(|e| HttpError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            tokio::spawn(async move {
                if let Err(e) = http_server_log_stream::serve_log_stream(websocket).await {
                    eprintln!("Error in websocket connection: {e}");
                }
            });

            Ok(response)
        } else {
            return API::response_error(StatusCode::BAD_REQUEST, "Need websocket upgrade.");
        }
    }

    async fn api_log_set_level(
        _this: Arc<HttpServer>,
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

    async  fn api_server_version(
        _this: Arc<HttpServer>,
        _param: APIRouteParam,
        _req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, HttpError> {
        let server_version = &smartdns::smartdns_version();
        let ui_version = &smartdns::smartdns_ui_version();
        let msg = api_msg_gen_version(server_version, ui_version);
        API::response_build(StatusCode::OK, msg)
    }
}
