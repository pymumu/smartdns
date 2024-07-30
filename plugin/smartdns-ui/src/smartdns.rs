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
mod smartdns_c {
    use libc::gid_t;
    use libc::in6_addr;
    use libc::in_addr;
    use libc::sockaddr;
    use libc::sockaddr_storage;
    use libc::socklen_t;
    use libc::time_t;
    use libc::timeval;
    use libc::tm;
    use libc::uid_t;
    use u32 as u_int;
    include!(concat!(env!("OUT_DIR"), "/smartdns_bindings.rs"));

}

extern crate libc;
use std::error::Error;
use std::ffi::CString;

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
    env!("CARGO_PKG_VERSION").to_string()
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
};

#[no_mangle]
extern "C" fn dns_request_complete(request: *mut smartdns_c::dns_request) {
    unsafe {
        let ops = PLUGIN.ops.as_ref();
        if let None = ops {
            return;
        }

        let ops = ops.unwrap();
        let mut req = DnsRequest::new(request);
        ops.server_query_complete(&mut req);
    }
}

#[no_mangle]
extern "C" fn dns_plugin_init(plugin: *mut smartdns_c::dns_plugin) -> i32 {
    unsafe {
        PLUGIN.parser_args(plugin).unwrap();
        smartdns_c::smartdns_operations_register(&SMARTDNS_OPS);
        let ret = PLUGIN.ops.as_mut().unwrap().server_init(PLUGIN.get_args());
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
        smartdns_c::smartdns_operations_unregister(&SMARTDNS_OPS);
        PLUGIN.ops.as_mut().unwrap().server_exit();
    }
    return 0;
}

pub struct DnsRequest {
    request: *mut smartdns_c::dns_request,
}

#[allow(dead_code)]
impl DnsRequest {
    fn new(request: *mut smartdns_c::dns_request) -> DnsRequest {
        unsafe {
            smartdns_c::dns_server_request_get(request);
        }

        DnsRequest { request }
    }

    fn put_ref(&mut self) {
        unsafe {
            smartdns_c::dns_server_request_put(self.request);
            self.request = std::ptr::null_mut();
        }
    }

    pub fn get_group_name(&self) -> String {
        unsafe {
            let group_name = smartdns_c::dns_server_request_get_group_name(self.request);
            std::ffi::CStr::from_ptr(group_name)
                .to_string_lossy()
                .into_owned()
        }
    }

    pub fn get_domain(&self) -> String {
        unsafe {
            let domain = smartdns_c::dns_server_request_get_domain(self.request);
            std::ffi::CStr::from_ptr(domain)
                .to_string_lossy()
                .into_owned()
        }
    }

    pub fn get_qtype(&self) -> u32 {
        unsafe { smartdns_c::dns_server_request_get_qtype(self.request) as u32 }
    }

    pub fn get_qclass(&self) -> i32 {
        unsafe { smartdns_c::dns_server_request_get_qclass(self.request) }
    }

    pub fn get_id(&self) -> u16 {
        unsafe { smartdns_c::dns_server_request_get_id(self.request) as u16 }
    }

    pub fn get_rcode(&self) -> u16 {
        unsafe { smartdns_c::dns_server_request_get_rcode(self.request) as u16 }
    }

    pub fn get_query_time(&self) -> u64 {
        unsafe { smartdns_c::dns_server_request_get_query_time(self.request) }
    }

    pub fn get_remote_addr(&self) -> String {
        unsafe {
            let addr = smartdns_c::dns_server_request_get_remote_addr(self.request);
            let mut buf = [0u8; 1024];
            let retstr = smartdns_c::get_host_by_addr(
                buf.as_mut_ptr(),
                buf.len() as i32,
                addr as *const libc::sockaddr,
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

    pub fn get_local_addr(&self) -> String {
        unsafe {
            let addr = smartdns_c::dns_server_request_get_local_addr(self.request);
            let mut buf = [0u8; 1024];
            let retstr = smartdns_c::get_host_by_addr(
                buf.as_mut_ptr(),
                buf.len() as i32,
                addr as *const libc::sockaddr,
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
}

impl Drop for DnsRequest {
    fn drop(&mut self) {
        self.put_ref();
    }
}

impl Clone for DnsRequest {
    fn clone(&self) -> Self {
        unsafe {
            smartdns_c::dns_server_request_get(self.request);
        }

        DnsRequest {
            request: self.request,
        }
    }
}

unsafe impl Send for DnsRequest {}

pub trait SmartdnsOperations {
    fn server_query_complete(&self, request: &mut DnsRequest);
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
                key.as_mut_ptr() as *mut libc::c_char,
                cert.as_mut_ptr() as *mut libc::c_char,
            );
            if ret != 0 {
                return Err("get cert error".to_string());
            }

            let key = std::ffi::CStr::from_ptr(key.as_ptr() as *const libc::c_char)
                .to_string_lossy()
                .into_owned();
            let cert = std::ffi::CStr::from_ptr(cert.as_ptr() as *const libc::c_char)
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
    pub fn dns_conf_plugin_config(key: &str, default: &str) -> String {
        let key = CString::new(key).expect("Failed to convert to CString");
        unsafe {
            let value = smartdns_c::smartdns_plugin_get_config(key.as_ptr());
            if value.is_null() {
                return default.to_string();
            }

            std::ffi::CStr::from_ptr(value)
                .to_string_lossy()
                .into_owned()
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_log() {
        dns_log!(LogLevel::DEBUG, "test log");
    }
}
