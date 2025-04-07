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

use smartdns_ui::data_server::DataServer;
use smartdns_ui::db::*;
use smartdns_ui::dns_log;
use smartdns_ui::plugin::*;
use smartdns_ui::smartdns::*;
use std::io::Write;
use std::sync::Arc;
use tempfile::TempDir;

static INSTANCE_LOCK: std::sync::RwLock<()> = std::sync::RwLock::new(());

pub struct InstanceLockGuard<'a> {
    _read_guard: Option<std::sync::RwLockReadGuard<'a, ()>>,
    _write_guard: Option<std::sync::RwLockWriteGuard<'a, ()>>,
}

impl<'a> InstanceLockGuard<'a> {
    pub fn new_read_guard() -> Self {
        Self {
            _read_guard: Some(INSTANCE_LOCK.read().unwrap()),
            _write_guard: None,
        }
    }

    pub fn new_write_guard() -> Self {
        Self {
            _read_guard: None,
            _write_guard: Some(INSTANCE_LOCK.write().unwrap()),
        }
    }
}

pub struct TestDnsRequest {
    pub domain: String,
    pub group_name: String,
    pub qtype: u32,
    pub qclass: i32,
    pub id: u16,
    pub rcode: u16,
    pub query_time: i32,
    pub query_timestamp: u64,
    pub ping_time: f64,
    pub is_blocked: bool,
    pub is_cached: bool,
    pub remote_mac: [u8; 6],
    pub remote_addr: String,
    pub local_addr: String,
    pub prefetch_request: bool,
    pub dualstack_request: bool,
    pub drop_callback: Option<Box<dyn Fn() + Send + Sync>>,
}

#[allow(dead_code)]
impl TestDnsRequest {
    pub fn new() -> Self {
        TestDnsRequest {
            domain: "".to_string(),
            group_name: "default".to_string(),
            qtype: 1,
            qclass: 1,
            id: 0,
            rcode: 2,
            query_time: 0,
            query_timestamp: get_utc_time_ms(),
            ping_time: -0.1 as f64,
            is_blocked: false,
            is_cached: false,
            remote_mac: [0; 6],
            remote_addr: "127.0.0.1".to_string(),
            local_addr: "127.0.0.1".to_string(),
            prefetch_request: false,
            dualstack_request: false,
            drop_callback: None,
        }
    }
}

#[allow(dead_code)]
impl DnsRequest for TestDnsRequest {
    fn get_group_name(&self) -> String {
        self.group_name.clone()
    }

    fn get_domain(&self) -> String {
        self.domain.clone()
    }

    fn get_qtype(&self) -> u32 {
        self.qtype
    }

    fn get_qclass(&self) -> i32 {
        self.qclass
    }

    fn get_id(&self) -> u16 {
        self.id
    }

    fn get_rcode(&self) -> u16 {
        self.rcode
    }

    fn get_query_time(&self) -> i32 {
        self.query_time
    }

    fn get_query_timestamp(&self) -> u64 {
        self.query_timestamp
    }

    fn get_ping_time(&self) -> f64 {
        self.ping_time
    }

    fn get_is_blocked(&self) -> bool {
        self.is_blocked
    }

    fn get_is_cached(&self) -> bool {
        self.is_cached
    }

    fn get_remote_mac(&self) -> [u8; 6] {
        self.remote_mac
    }

    fn get_remote_addr(&self) -> String {
        self.remote_addr.clone()
    }

    fn get_local_addr(&self) -> String {
        self.local_addr.clone()
    }

    fn is_prefetch_request(&self) -> bool {
        self.prefetch_request
    }

    fn is_dualstack_request(&self) -> bool {
        self.dualstack_request
    }
}

impl Drop for TestDnsRequest {
    fn drop(&mut self) {
        if let Some(f) = &self.drop_callback {
            f();
        }
    }
}

unsafe impl Send for TestDnsRequest {}
unsafe impl Sync for TestDnsRequest {}

#[allow(dead_code)]
struct TestSmartDnsConfigItem {
    pub key: String,
    pub value: String,
}

pub struct TestSmartDnsServer {
    confs: Vec<TestSmartDnsConfigItem>,
    is_started: bool,
    workdir: String,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl TestSmartDnsServer {
    pub fn new() -> Self {
        let mut server = TestSmartDnsServer {
            confs: Vec::new(),
            is_started: false,
            workdir: "/tmp/smartdns-test.conf".to_string(),
            thread: None,
        };

        server.add_conf("bind", ":66603");
        server.add_conf("log-level", "debug");
        server.add_conf("log-num", "0");
        server.add_conf("cache-persist", "no");

        server
    }

    pub fn set_workdir(&mut self, workdir: &str) {
        self.workdir = workdir.to_string();
    }

    pub fn add_conf(&mut self, key: &str, value: &str) {
        self.confs.push(TestSmartDnsConfigItem {
            key: key.to_string(),
            value: value.to_string(),
        });
    }

    fn gen_conf_file(&self) -> std::io::Result<String> {
        let file = self.workdir.clone() + "/smartdns.conf";
        let mut f = std::fs::File::create(&file)?;
        for conf in self.confs.iter() {
            f.write_all(format!("{} {}\n", conf.key, conf.value).as_bytes())?;
        }
        Ok(file)
    }

    pub fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let conf_file = self.gen_conf_file()?;
        let t = std::thread::spawn(move || {
            dns_log!(LogLevel::ERROR, "smartdns server run start...");
            smartdns_ui::smartdns::smartdns_server_run(&conf_file).unwrap();
            dns_log!(LogLevel::ERROR, "smartdns server run exit...");
        });
        self.thread = Some(t);
        self.is_started = true;
        dns_log!(LogLevel::ERROR, "smartdns_server_run");
        Ok(())
    }

    pub fn stop(&mut self) {
        if !self.is_started {
            return;
        }
        self.is_started = false;
        smartdns_ui::smartdns::smartdns_server_stop();
        if self.thread.is_none() {
            return;
        }
        let _ = self.thread.take().unwrap().join();
    }
}

impl Drop for TestSmartDnsServer {
    fn drop(&mut self) {
        self.stop();
    }
}

pub struct TestServer {
    dns_server: TestSmartDnsServer,
    dns_server_enable: bool,
    plugin: Arc<SmartdnsPlugin>,
    args: Vec<String>,
    workdir: String,
    temp_dir: TempDir,
    www_root: String,
    is_started: bool,
    ip: String,
    is_https: bool,
    log_level: LogLevel,
    old_log_level: LogLevel,
    one_instance: bool,
    instance_lock_guard: Option<InstanceLockGuard<'static>>,
}

impl TestServer {
    pub fn new() -> Self {
        let mut server = TestServer {
            dns_server: TestSmartDnsServer::new(),
            dns_server_enable: false,
            plugin: SmartdnsPlugin::new(),
            args: Vec::new(),
            workdir: String::new(),
            temp_dir: TempDir::with_prefix("smartdns-ui-").unwrap(),
            www_root: String::new(),
            is_started: false,
            ip: "http://127.0.0.1:0".to_string(),
            is_https: false,
            log_level: LogLevel::INFO,
            old_log_level: LogLevel::INFO,
            one_instance: false,
            instance_lock_guard: None,
        };

        server.workdir = server.temp_dir.path().to_str().unwrap().to_string();
        server.dns_server.set_workdir(&server.workdir);
        server.get_data_server().set_recv_in_batch(false);
        server
    }

    fn setup_default_args(&mut self) {
        self.args.insert(0, "--ip".to_string());
        self.args.insert(1, self.ip.clone());

        self.args.insert(0, "--data-dir".to_string());
        self.args.insert(1, self.workdir.clone() + "/data.db");

        self.args.insert(0, "--www-root".to_string());
        self.www_root = self.workdir.clone() + "/www";
        self.args.insert(1, self.www_root.clone());

        self.args.insert(0, "smartdns-ui".to_string());
        dns_log!(LogLevel::INFO, "workdir: {}", self.workdir);
    }

    #[allow(dead_code)]
    pub fn get_url(&self, path: &str) -> String {
        self.ip.clone() + path
    }

    pub fn get_host(&self) -> String {
        self.ip.clone()
    }

    #[allow(dead_code)]
    pub fn get_www_root(&self) -> &String {
        &self.www_root
    }

    fn create_workdir(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.workdir)?;
        std::fs::create_dir_all(&self.www_root)?;
        Ok(())
    }

    fn remove_workdir(&self) -> std::io::Result<()> {
        let r = std::fs::remove_dir_all(&self.workdir);
        return r;
    }

    #[allow(dead_code)]
    pub fn add_mock_server_conf(&mut self, key: &str, value: &str) {
        self.dns_server.add_conf(key, value);
    }

    #[allow(dead_code)]
    pub fn enable_mock_server(&mut self) {
        self.dns_server_enable = true;
        self.set_one_instance(true);
    }

    #[allow(dead_code)]
    pub fn add_args(&mut self, args: Vec<String>) {
        for arg in args.iter() {
            self.args.push(arg.clone());
        }
    }

    #[allow(dead_code)]
    pub fn send_test_dnsrequest(
        &mut self,
        mut request: TestDnsRequest,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let batch_mode = self.get_data_server().get_recv_in_batch();
        let (tx, rx) = std::sync::mpsc::channel();
        let request_drop_callback = move || {
            tx.send(()).unwrap();
        };

        if batch_mode == false {
            request.drop_callback = Some(Box::new(request_drop_callback));
        }

        let ret = self.plugin.query_complete(Box::new(request));
        if let Err(e) = ret {
            dns_log!(LogLevel::ERROR, "send_test_dnsrequest error: {:?}", e);
            return Err(e);
        }

        if batch_mode == false {
            rx.recv().unwrap();
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn new_mock_domain_record(&self) -> DomainData {
        DomainData {
            id: 0,
            timestamp: smartdns_ui::smartdns::get_utc_time_ms(),
            domain: "example.com".to_string(),
            domain_type: 1,
            client: "127.0.0.1".to_string(),
            domain_group: "default".to_string(),
            reply_code: 0,
            query_time: 0,
            ping_time: -0.1 as f64,
            is_blocked: false,
            is_cached: false,
        }
    }

    #[allow(dead_code)]
    pub fn get_data_server(&self) -> Arc<DataServer> {
        self.plugin.get_data_server()
    }

    #[allow(dead_code)]
    pub fn add_domain_record(
        &mut self,
        record: &DomainData,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.plugin.get_data_server().insert_domain(record)
    }

    pub fn set_log_level(&mut self, level: LogLevel) {
        self.log_level = level;
    }

    fn init_server(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.create_workdir()?;

        self.old_log_level = smartdns_ui::smartdns::dns_log_get_level();
        smartdns_ui::smartdns::dns_log_set_level(self.log_level);

        Ok(())
    }

    #[allow(dead_code)]
    pub fn set_https(&mut self, enable: bool) {
        self.is_https = enable;
        if enable {
            self.ip = "https://127.0.0.1:0".to_string();
        } else {
            self.ip = "http://127.0.0.1:0".to_string();
        }
    }

    pub fn set_one_instance(&mut self, one_instance: bool) {
        self.one_instance = one_instance;
    }

    pub fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.one_instance {
            self.instance_lock_guard = Some(InstanceLockGuard::new_write_guard());
            if self.dns_server_enable {
                let ret = self.dns_server.start();
                if let Err(e) = ret {
                    dns_log!(LogLevel::ERROR, "start dns server failed: {:?}", e);
                    return Err(e);
                }
            }
        } else {
            self.instance_lock_guard = Some(InstanceLockGuard::new_read_guard());
        }

        self.setup_default_args();

        dns_log!(LogLevel::INFO, "TestServer start");
        let ret = self.init_server();
        if let Err(e) = ret {
            dns_log!(LogLevel::ERROR, "init server failed: {:?}", e);
            return Err(e);
        }

        let result = self.plugin.start(&self.args);
        if let Err(e) = result {
            dns_log!(LogLevel::ERROR, "start error: {:?}", e);
            return Err(e);
        }

        let addr = self.plugin.get_http_server().get_local_addr();
        if addr.is_none() {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "get local addr failed",
            )));
        }

        let addr = addr.unwrap();
        if self.is_https {
            self.ip = format!("https://{}:{}", addr.ip(), addr.port());
        } else {
            self.ip = format!("http://{}:{}", addr.ip(), addr.port());
        }
        self.is_started = true;
        Ok(())
    }

    pub fn stop(&mut self) {
        if !self.is_started {
            return;
        }
        dns_log!(LogLevel::INFO, "TestServer stop");
        self.plugin.stop();
        self.is_started = false;
        self.one_instance = false;
        smartdns_ui::smartdns::dns_log_set_level(self.old_log_level);
        self.dns_server.stop();
        self.instance_lock_guard = None;
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop();
        let _ = self.remove_workdir();
    }
}
