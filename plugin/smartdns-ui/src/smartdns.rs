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

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(improper_ctypes)]
pub mod smartdns_c {
    include!(concat!(env!("OUT_DIR"), "/smartdns_bindings.rs"));
}

use std::error::Error;
use std::ffi::CString;
use std::fmt;
use std::os::raw::*;

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq)]
#[allow(dead_code)]
pub enum LogLevel {
    DEBUG = 0,
    INFO = 1,
    NOTICE = 2,
    WARN = 3,
    ERROR = 4,
    FATAL = 5,
}

impl From<LogLevel> for u32 {
    fn from(level: LogLevel) -> u32 {
        level as u32
    }
}

impl ToString for LogLevel {
    fn to_string(&self) -> String {
        match self {
            LogLevel::DEBUG => "debug".to_string(),
            LogLevel::INFO => "info".to_string(),
            LogLevel::NOTICE => "notice".to_string(),
            LogLevel::WARN => "warn".to_string(),
            LogLevel::ERROR => "error".to_string(),
            LogLevel::FATAL => "fatal".to_string(),
        }
    }
}

impl TryFrom<u32> for LogLevel {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(LogLevel::DEBUG),
            1 => Ok(LogLevel::INFO),
            2 => Ok(LogLevel::NOTICE),
            3 => Ok(LogLevel::WARN),
            4 => Ok(LogLevel::ERROR),
            5 => Ok(LogLevel::FATAL),
            _ => Err(()),
        }
    }
}

impl TryFrom<&str> for LogLevel {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "debug" => Ok(LogLevel::DEBUG),
            "info" => Ok(LogLevel::INFO),
            "notice" => Ok(LogLevel::NOTICE),
            "warn" => Ok(LogLevel::WARN),
            "error" => Ok(LogLevel::ERROR),
            "fatal" => Ok(LogLevel::FATAL),
            _ => Err(()),
        }
    }
}

impl TryFrom<String> for LogLevel {
    type Error = ();
    fn try_from(value: String) -> Result<Self, Self::Error> {
        LogLevel::try_from(value.as_str())
    }
}

#[derive(Debug, Clone)]
pub enum DnsServerType {
    SERVER_UDP,
    SERVER_TCP,
    SERVER_TLS,
    SERVER_HTTPS,
    SERVER_MDNS,
    SERVER_UNKNOWN,
}

impl From<u32> for DnsServerType {
    fn from(t: u32) -> DnsServerType {
        match t {
            0 => DnsServerType::SERVER_UDP,
            1 => DnsServerType::SERVER_TCP,
            2 => DnsServerType::SERVER_TLS,
            3 => DnsServerType::SERVER_HTTPS,
            4 => DnsServerType::SERVER_MDNS,
            _ => DnsServerType::SERVER_UNKNOWN,
        }
    }
}

impl std::str::FromStr for DnsServerType {
    type Err = String;

    fn from_str(t: &str) -> Result<DnsServerType, String> {
        match t {
            "udp" => Ok(DnsServerType::SERVER_UDP),
            "tcp" => Ok(DnsServerType::SERVER_TCP),
            "tls" => Ok(DnsServerType::SERVER_TLS),
            "https" => Ok(DnsServerType::SERVER_HTTPS),
            "mdns" => Ok(DnsServerType::SERVER_MDNS),
            _ => Err("unknown".to_string()),
        }
    }
}

impl ToString for DnsServerType {
    fn to_string(&self) -> String {
        match self {
            DnsServerType::SERVER_UDP => "udp".to_string(),
            DnsServerType::SERVER_TCP => "tcp".to_string(),
            DnsServerType::SERVER_TLS => "tls".to_string(),
            DnsServerType::SERVER_HTTPS => "https".to_string(),
            DnsServerType::SERVER_MDNS => "mdns".to_string(),
            DnsServerType::SERVER_UNKNOWN => "unknown".to_string(),
        }
    }
}

#[macro_export]
macro_rules! dns_log {
    ($level:expr, $($arg:tt)*) => {
        if $crate::smartdns::dns_can_log($level) {
            $crate::smartdns::dns_log_out($level, file!(), line!(), &format!($($arg)*));
        }
    };
}
pub fn dns_can_log(level: LogLevel) -> bool {
    unsafe { smartdns_c::smartdns_plugin_can_log(level as u32) != 0 }
}

pub fn dns_log_set_level(level: LogLevel) {
    unsafe {
        smartdns_c::smartdns_plugin_log_setlevel(level as u32);
    }
}

pub fn dns_log_get_level() -> LogLevel {
    unsafe {
        let leve = smartdns_c::smartdns_plugin_log_getlevel();
        LogLevel::try_from(leve as u32).unwrap()
    }
}

pub fn dns_log_out(level: LogLevel, file: &str, line: u32, message: &str) {
    let filename_only = std::path::Path::new(file)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap();
    let file_cstring = CString::new(filename_only).expect("Failed to convert to CString");
    let message_cstring = CString::new(message).expect("Failed to convert to CString");

    unsafe {
        smartdns_c::smartdns_plugin_log(
            level as u32,
            file_cstring.as_ptr(),
            line as i32,
            std::ptr::null(),
            message_cstring.as_ptr(),
        );
    }
}

pub fn smartdns_version() -> String {
    unsafe {
        let version = smartdns_c::smartdns_version();
        std::ffi::CStr::from_ptr(version)
            .to_string_lossy()
            .into_owned()
    }
}

pub fn smartdns_ui_version() -> String {
    let mut ver = env!("CARGO_PKG_VERSION").to_string();

    if env!("GIT_VERSION").is_empty() {
        return ver;
    }

    ver.push_str(" (");
    ver.push_str(env!("GIT_VERSION"));
    ver.push_str(")");

    ver
}

pub fn smartdns_get_server_name() -> String {
    unsafe {
        let mut buffer = [0u8; 4096];
        smartdns_c::dns_server_get_server_name(
            buffer.as_mut_ptr() as *mut c_char,
            buffer.len() as i32,
        );
        let srv_name = std::ffi::CStr::from_ptr(buffer.as_ptr() as *const c_char)
            .to_string_lossy()
            .into_owned();

        srv_name
    }
}

pub fn smartdns_server_run(file: &str) -> Result<(), Box<dyn Error>> {
    let file = CString::new(file).expect("Failed to convert to CString");
    let ret: i32;
    unsafe {
        ret = smartdns_c::smartdns_server_run(file.as_ptr());
    };

    if ret != 0 {
        return Err("smartdns server run error".into());
    }

    Ok(())
}

pub fn smartdns_enable_update_neighbour(enable: bool) {
    unsafe {
        if enable {
            smartdns_c::dns_server_enable_update_neighbor_cache(1);
        } else {
            smartdns_c::dns_server_enable_update_neighbor_cache(0);
        }
    }
}

pub fn smartdns_server_stop() {
    unsafe {
        smartdns_c::smartdns_server_stop();
    }
}

pub fn get_utc_time_ms() -> u64 {
    unsafe { smartdns_c::get_utc_time_ms() }
}

static SMARTDNS_OPS: smartdns_c::smartdns_operations = smartdns_c::smartdns_operations {
    server_recv: None,
    server_query_complete: Some(dns_request_complete),
    server_log: Some(dns_server_log),
};

#[no_mangle]
extern "C" fn dns_request_complete(request: *mut smartdns_c::dns_request) {
    unsafe {
        let plugin_addr = std::ptr::addr_of_mut!(PLUGIN);
        let ops = (*plugin_addr).ops.as_ref();
        if let None = ops {
            return;
        }

        let ops = ops.unwrap();
        let req = DnsRequest_C::new(request);
        ops.server_query_complete(Box::new(req));
    }
}

#[no_mangle]
extern "C" fn dns_server_log(
    level: smartdns_c::smartdns_log_level,
    msg: *const c_char,
    msg_len: i32,
) {
    unsafe {
        let plugin_addr = std::ptr::addr_of_mut!(PLUGIN);
        let ops = (*plugin_addr).ops.as_ref();
        if let None = ops {
            return;
        }

        let raw_msg = std::slice::from_raw_parts(msg as *const u8, msg_len as usize + 1);
        let msg = std::ffi::CStr::from_bytes_with_nul_unchecked(raw_msg)
            .to_string_lossy()
            .into_owned();
        let level = LogLevel::try_from(level as u32).unwrap();

        let ops = ops.unwrap();
        ops.server_log(level, msg.as_str(), msg_len as i32);
    }
}

#[no_mangle]
extern "C" fn dns_plugin_init(plugin: *mut smartdns_c::dns_plugin) -> i32 {
    unsafe {
        let plugin_addr = std::ptr::addr_of_mut!(PLUGIN);
        (*plugin_addr).parser_args(plugin).unwrap();
        smartdns_c::smartdns_operations_register(&SMARTDNS_OPS);
        let ret = (*plugin_addr)
            .ops
            .as_mut()
            .unwrap()
            .server_init((*plugin_addr).get_args());
        if let Err(e) = ret {
            dns_log!(LogLevel::ERROR, "server init error: {}", e);
            return -1;
        }
    }

    return 0;
}

#[no_mangle]
extern "C" fn dns_plugin_exit(_plugin: *mut smartdns_c::dns_plugin) -> i32 {
    unsafe {
        let plugin_addr = std::ptr::addr_of_mut!(PLUGIN);
        smartdns_c::smartdns_operations_unregister(&SMARTDNS_OPS);
        (*plugin_addr).ops.as_mut().unwrap().server_exit();
    }
    return 0;
}

pub trait DnsRequest: Send + Sync {
    fn get_group_name(&self) -> String;
    fn get_domain(&self) -> String;
    fn get_qtype(&self) -> u32;
    fn get_qclass(&self) -> i32;
    fn get_id(&self) -> u16;
    fn get_rcode(&self) -> u16;
    fn get_query_time(&self) -> i32;
    fn get_query_timestamp(&self) -> u64;
    fn get_ping_time(&self) -> f64;
    fn get_is_blocked(&self) -> bool;
    fn get_is_cached(&self) -> bool;
    fn get_remote_mac(&self) -> [u8; 6];
    fn get_remote_addr(&self) -> String;
    fn get_local_addr(&self) -> String;
    fn is_prefetch_request(&self) -> bool;
    fn is_dualstack_request(&self) -> bool;
}

pub struct DnsRequest_C {
    request: *mut smartdns_c::dns_request,
}

#[allow(dead_code)]
impl DnsRequest_C {
    fn new(request: *mut smartdns_c::dns_request) -> DnsRequest_C {
        unsafe {
            smartdns_c::dns_server_request_get(request);
        }

        DnsRequest_C { request }
    }

    fn put_ref(&mut self) {
        unsafe {
            smartdns_c::dns_server_request_put(self.request);
            self.request = std::ptr::null_mut();
        }
    }
}

#[allow(dead_code)]
impl DnsRequest for DnsRequest_C {
    fn get_group_name(&self) -> String {
        unsafe {
            let group_name = smartdns_c::dns_server_request_get_group_name(self.request);
            std::ffi::CStr::from_ptr(group_name)
                .to_string_lossy()
                .into_owned()
        }
    }

    fn get_domain(&self) -> String {
        unsafe {
            let domain = smartdns_c::dns_server_request_get_domain(self.request);
            std::ffi::CStr::from_ptr(domain)
                .to_string_lossy()
                .into_owned()
        }
    }

    fn get_qtype(&self) -> u32 {
        unsafe { smartdns_c::dns_server_request_get_qtype(self.request) as u32 }
    }

    fn get_qclass(&self) -> i32 {
        unsafe { smartdns_c::dns_server_request_get_qclass(self.request) }
    }

    fn get_id(&self) -> u16 {
        unsafe { smartdns_c::dns_server_request_get_id(self.request) as u16 }
    }

    fn get_rcode(&self) -> u16 {
        unsafe { smartdns_c::dns_server_request_get_rcode(self.request) as u16 }
    }

    fn get_query_time(&self) -> i32 {
        unsafe { smartdns_c::dns_server_request_get_query_time(self.request) }
    }

    fn get_query_timestamp(&self) -> u64 {
        unsafe { smartdns_c::dns_server_request_get_query_timestamp(self.request) }
    }

    fn get_ping_time(&self) -> f64 {
        let v = unsafe { smartdns_c::dns_server_request_get_ping_time(self.request) };
        let mut ping_time = v as f64;
        ping_time = (ping_time * 10.0).round() / 10.0;
        ping_time
    }

    fn get_is_blocked(&self) -> bool {
        unsafe { smartdns_c::dns_server_request_is_blocked(self.request) != 0 }
    }

    fn get_is_cached(&self) -> bool {
        unsafe { smartdns_c::dns_server_request_is_cached(self.request) != 0 }
    }

    fn get_remote_mac(&self) -> [u8; 6] {
        unsafe {
            let _mac_ptr = smartdns_c::dns_server_request_get_remote_mac(self.request);
            if _mac_ptr.is_null() {
                return [0u8; 6];
            }

            let mac = std::slice::from_raw_parts(_mac_ptr, 6);
            return mac.try_into().unwrap();
        }
    }

    fn get_remote_addr(&self) -> String {
        unsafe {
            let addr = smartdns_c::dns_server_request_get_remote_addr(self.request);
            if addr.is_null() {
                return "API".to_string();
            }
            let mut buf = [0u8; 1024];
            let retstr = smartdns_c::get_host_by_addr(
                buf.as_mut_ptr() as *mut c_char,
                buf.len() as i32,
                addr as *const smartdns_c::sockaddr,
            );
            if retstr.is_null() {
                return String::new();
            }

            let addr = std::ffi::CStr::from_ptr(retstr)
                .to_string_lossy()
                .into_owned();
            addr
        }
    }

    fn get_local_addr(&self) -> String {
        unsafe {
            let addr = smartdns_c::dns_server_request_get_local_addr(self.request);
            let mut buf = [0u8; 1024];
            let retstr = smartdns_c::get_host_by_addr(
                buf.as_mut_ptr() as *mut c_char,
                buf.len() as i32,
                addr as *const smartdns_c::sockaddr,
            );
            if retstr.is_null() {
                return String::new();
            }

            let addr = std::ffi::CStr::from_ptr(retstr)
                .to_string_lossy()
                .into_owned();
            addr
        }
    }

    fn is_prefetch_request(&self) -> bool {
        unsafe { smartdns_c::dns_server_request_is_prefetch(self.request) != 0 }
    }

    fn is_dualstack_request(&self) -> bool {
        unsafe { smartdns_c::dns_server_request_is_dualstack(self.request) != 0 }
    }
}

impl Drop for DnsRequest_C {
    fn drop(&mut self) {
        self.put_ref();
    }
}

impl Clone for DnsRequest_C {
    fn clone(&self) -> Self {
        unsafe {
            smartdns_c::dns_server_request_get(self.request);
        }

        DnsRequest_C {
            request: self.request,
        }
    }
}

unsafe impl Send for DnsRequest_C {}
unsafe impl Sync for DnsRequest_C {}

pub struct DnsServerStats {
    stats: *mut smartdns_c::dns_server_stats,
    server_info: *mut smartdns_c::dns_server_info,
}

impl DnsServerStats {
    fn new(
        stats: *mut smartdns_c::dns_server_stats,
        server_info: *mut smartdns_c::dns_server_info,
    ) -> Self {
        unsafe { smartdns_c::dns_client_server_info_get(server_info) };
        DnsServerStats { stats, server_info }
    }

    pub fn get_query_total(&self) -> u64 {
        unsafe { smartdns_c::dns_stats_server_stats_total_get(self.stats) }
    }

    pub fn get_query_success(&self) -> u64 {
        unsafe { smartdns_c::dns_stats_server_stats_success_get(self.stats) }
    }

    pub fn get_query_recv(&self) -> u64 {
        unsafe { smartdns_c::dns_stats_server_stats_recv_get(self.stats) }
    }

    pub fn get_success_rate(&self) -> f64 {
        let total = self.get_query_total();
        let success = self.get_query_success();
        let mut success_rate: f64 = 0.0;
        if total == 0 {
            return success_rate;
        }

        success_rate = success as f64 / total as f64 * 100.0;
        success_rate = (success_rate * 10.0).round() / 10.0;
        success_rate
    }

    pub fn get_query_avg_time(&self) -> f64 {
        let v = unsafe { smartdns_c::dns_stats_server_stats_avg_time_get(self.stats) };
        let mut avg_time = v as f64;
        avg_time = (avg_time * 10.0).round() / 10.0;
        avg_time
    }
}

impl Drop for DnsServerStats {
    fn drop(&mut self) {
        unsafe {
            if !self.server_info.is_null() {
                smartdns_c::dns_client_server_info_release(self.server_info);
            }
        }
    }
}

pub struct DnsUpstreamServer {
    server_info: *mut smartdns_c::dns_server_info,
}

impl DnsUpstreamServer {
    fn new(server_info: *mut smartdns_c::dns_server_info) -> Self {
        unsafe {
            smartdns_c::dns_client_server_info_get(server_info);
        }

        DnsUpstreamServer { server_info }
    }

    pub fn get_server_num() -> i32 {
        unsafe { smartdns_c::dns_server_num() }
    }

    pub fn dns_server_alive_num() -> i32 {
        unsafe { smartdns_c::dns_server_alive_num() }
    }

    pub fn get_server_stats(&self) -> DnsServerStats {
        let stats = unsafe { smartdns_c::dns_client_get_server_stats(self.server_info) };
        DnsServerStats::new(stats, self.server_info)
    }

    pub fn is_server_alive(&self) -> bool {
        unsafe { smartdns_c::dns_client_server_is_alive(self.server_info) != 0 }
    }

    pub fn get_server_list() -> Result<Vec<DnsUpstreamServer>, String> {
        let mut servers = Vec::new();
        let server_num = DnsUpstreamServer::get_server_num();

        unsafe {
            let mut server_info: Vec<*mut smartdns_c::dns_server_info> =
                Vec::with_capacity(server_num as usize);
            let ret =
                smartdns_c::dns_client_get_server_info_lists(server_info.as_mut_ptr(), server_num);
            if ret < 0 {
                return Err(("get server info failed.").to_string());
            }

            if ret > server_num {
                return Err(("get server info failed.").to_string());
            }
            server_info.set_len(ret as usize);

            for i in 0..ret {
                let server_info = server_info[i as usize];
                servers.push(DnsUpstreamServer::new(server_info));
                smartdns_c::dns_client_server_info_release(server_info);
            }
        }

        Ok(servers)
    }

    pub fn get_ip(&self) -> String {
        unsafe {
            let ip = smartdns_c::dns_client_get_server_ip(self.server_info);
            std::ffi::CStr::from_ptr(ip).to_string_lossy().into_owned()
        }
    }

    pub fn get_host(&self) -> String {
        unsafe {
            let host = smartdns_c::dns_client_get_server_host(self.server_info);
            std::ffi::CStr::from_ptr(host)
                .to_string_lossy()
                .into_owned()
        }
    }

    pub fn get_port(&self) -> u16 {
        unsafe { smartdns_c::dns_client_get_server_port(self.server_info) as u16 }
    }

    pub fn get_type(&self) -> DnsServerType {
        unsafe {
            let t = smartdns_c::dns_client_get_server_type(self.server_info)
                as smartdns_c::dns_server_type_t;
            DnsServerType::from(t)
        }
    }

    pub fn get_groups(&self) -> Vec<String> {
        let groups = Vec::new();
        groups
    }
}

impl Drop for DnsUpstreamServer {
    fn drop(&mut self) {
        unsafe {
            smartdns_c::dns_client_server_info_release(self.server_info);
        }
    }
}

impl Clone for DnsUpstreamServer {
    fn clone(&self) -> Self {
        unsafe {
            smartdns_c::dns_client_server_info_get(self.server_info);
        }

        DnsUpstreamServer {
            server_info: self.server_info,
        }
    }
}

unsafe impl Send for DnsUpstreamServer {}

pub trait SmartdnsOperations {
    fn server_query_complete(&self, request: Box<dyn DnsRequest>);
    fn server_log(&self, level: LogLevel, msg: &str, msg_len: i32);
    fn server_init(&mut self, args: &Vec<String>) -> Result<(), Box<dyn Error>>;
    fn server_exit(&mut self);
}

pub static mut PLUGIN: Plugin = Plugin {
    args: Vec::new(),
    ops: None,
};

pub struct Plugin {
    args: Vec<String>,
    ops: Option<Box<dyn SmartdnsOperations>>,
}

pub struct SmartdnsCert {
    pub key: String,
    pub cert: String,
    pub password: String,
}

#[allow(dead_code)]
impl Plugin {
    pub fn get_args(&self) -> &Vec<String> {
        &self.args
    }

    pub fn set_operation(&mut self, ops: Box<dyn SmartdnsOperations>) {
        self.ops = Some(ops);
    }

    pub fn clear_operation(&mut self) {
        self.ops = None;
    }

    pub fn smartdns_exit(status: i32) {
        unsafe {
            smartdns_c::smartdns_exit(status);
        }
    }

    pub fn smartdns_restart() {
        unsafe {
            smartdns_c::smartdns_restart();
        }
    }

    pub fn smartdns_get_cert() -> Result<SmartdnsCert, String> {
        unsafe {
            let mut key = [0u8; 4096];
            let mut cert = [0u8; 4096];
            let ret = smartdns_c::smartdns_get_cert(
                key.as_mut_ptr() as *mut c_char,
                cert.as_mut_ptr() as *mut c_char,
            );
            if ret != 0 {
                return Err("get cert error".to_string());
            }

            let key = std::ffi::CStr::from_ptr(key.as_ptr() as *const c_char)
                .to_string_lossy()
                .into_owned();
            let cert = std::ffi::CStr::from_ptr(cert.as_ptr() as *const c_char)
                .to_string_lossy()
                .into_owned();
            Ok(SmartdnsCert {
                key,
                cert,
                password: "".to_string(),
            })
        }
    }

    pub fn dns_cache_flush() {
        unsafe {
            smartdns_c::dns_cache_flush();
        }
    }

    pub fn dns_cache_total_num() -> i32 {
        unsafe { smartdns_c::dns_cache_total_num() }
    }

    #[allow(dead_code)]
    pub fn dns_conf_cache_dir() -> String {
        unsafe {
            let cache_dir = smartdns_c::dns_conf_get_cache_dir();
            std::ffi::CStr::from_ptr(cache_dir)
                .to_string_lossy()
                .into_owned()
        }
    }

    #[allow(dead_code)]
    pub fn dns_conf_data_dir() -> String {
        unsafe {
            let data_dir = smartdns_c::dns_conf_get_data_dir();
            std::ffi::CStr::from_ptr(data_dir)
                .to_string_lossy()
                .into_owned()
        }
    }

    #[allow(dead_code)]
    pub fn dns_conf_plugin_config(key: &str) -> Option<String> {
        let key = CString::new(key).expect("Failed to convert to CString");
        unsafe {
            let value = smartdns_c::smartdns_plugin_get_config(key.as_ptr());
            if value.is_null() {
                return None;
            }

            Some(
                std::ffi::CStr::from_ptr(value)
                    .to_string_lossy()
                    .into_owned(),
            )
        }
    }

    #[allow(dead_code)]
    pub fn dns_conf_plugin_config_default(key: &str, default_val: &String) -> String {
        let v = Plugin::dns_conf_plugin_config(key);
        if let Some(v) = v {
            return v;
        }

        default_val.clone()
    }

    #[allow(dead_code)]
    pub fn dns_conf_plugin_clear_all_config() {
        unsafe {
            smartdns_c::smartdns_plugin_clear_all_config();
        }
    }

    fn parser_args(&mut self, plugin: *mut smartdns_c::dns_plugin) -> Result<(), String> {
        let argc = unsafe { smartdns_c::dns_plugin_get_argc(plugin) };
        let args: Vec<String> = unsafe {
            let argv = smartdns_c::dns_plugin_get_argv(plugin);
            let mut args = Vec::new();
            for i in 0..argc {
                let arg = std::ffi::CStr::from_ptr(*argv.offset(i as isize))
                    .to_string_lossy()
                    .into_owned();
                args.push(arg);
            }
            args
        };

        self.args = args;
        Ok(())
    }
}

pub struct Stats {}

impl Stats {
    pub fn get_avg_process_time() -> f64 {
        unsafe {
            let v = smartdns_c::dns_stats_avg_time_get();
            let mut process_time = v as f64;
            process_time = (process_time * 10.0).round() / 10.0;
            process_time
        }
    }

    pub fn get_request_total() -> u64 {
        unsafe { smartdns_c::dns_stats_request_total_get() }
    }

    pub fn get_request_success() -> u64 {
        unsafe { smartdns_c::dns_stats_request_success_get() }
    }

    pub fn get_request_from_client() -> u64 {
        unsafe { smartdns_c::dns_stats_request_from_client_get() }
    }

    pub fn get_request_blocked() -> u64 {
        unsafe { smartdns_c::dns_stats_request_blocked_get() }
    }

    pub fn get_cache_hit() -> u64 {
        unsafe { smartdns_c::dns_stats_cache_hit_get() }
    }

    pub fn get_cache_memsize() -> u64 {
        unsafe { smartdns_c::dns_cache_total_memsize() as u64 }
    }

    pub fn get_cache_hit_rate() -> f64 {
        unsafe {
            let v = smartdns_c::dns_stats_cache_hit_rate_get() as f64;
            let mut cache_hit_rate = v as f64;
            cache_hit_rate = (cache_hit_rate * 10.0).round() / 10.0;
            cache_hit_rate
        }
    }

    pub fn get_cache_memory_size() -> u64 {
        unsafe { smartdns_c::dns_cache_total_memsize() as u64 }
    }
}

impl fmt::Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Stats")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_log() {
        dns_log!(LogLevel::DEBUG, "test log");
    }
}
