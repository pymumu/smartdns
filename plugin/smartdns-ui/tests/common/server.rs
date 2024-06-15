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

use smartdns_ui::db::*;
use smartdns_ui::dns_log;
use smartdns_ui::plugin::*;
use smartdns_ui::smartdns::*;
use std::io::Write;
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
    plugin: SmartdnsPlugin,
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

    pub fn get_url(&self, path: &str) -> String {
        self.ip.clone() + path
    }

    pub fn get_host(&self) -> String {
        self.ip.clone()
    }

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

    pub fn add_mock_server_conf(&mut self, key: &str, value: &str) {
        self.dns_server.add_conf(key, value);
    }

    pub fn enable_mock_server(&mut self) {
        self.dns_server_enable = true;
        self.set_one_instance(true);
    }

    pub fn add_args(&mut self, args: Vec<String>) {
        for arg in args.iter() {
            self.args.push(arg.clone());
        }
    }

    pub fn new_mock_domain_record(&self) -> DomainData {
        DomainData {
            id: 0,
            timestamp: smartdns_ui::smartdns::get_utc_time_ms(),
            domain: "example.com".to_string(),
            domain_type: 1,
            client: "127.0.0.1".to_string(),
            domain_group: "default".to_string(),
            reply_code: 0,
        }
    }

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
