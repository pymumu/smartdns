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

use crate::dns_log;
use crate::smartdns;
use crate::smartdns::*;
use crate::utils;
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::sync::Mutex;
use std::vec;

use chrono::Local;
use rusqlite::Transaction;
use rusqlite::{Connection, OpenFlags, Result};

pub struct DB {
    conn: Mutex<Option<Connection>>,
    version: i32,
    query_plan: bool,
}

#[derive(Debug, Clone)]
pub struct ClientData {
    pub id: u32,
    pub hostname: String,
    pub client_ip: String,
    pub mac: String,
    pub last_query_timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct ClientQueryCount {
    pub client_ip: String,
    pub count: u32,
    pub timestamp_start: u64,
    pub timestamp_end: u64,
}

#[derive(Debug, Clone)]
pub struct DomainQueryCount {
    pub domain: String,
    pub count: u32,
    pub timestamp_start: u64,
    pub timestamp_end: u64,
}

#[derive(Debug, Clone)]
pub struct HourlyQueryCountItem {
    pub hour: String,
    pub query_count: u32,
}

#[derive(Debug, Clone)]
pub struct HourlyQueryCount {
    pub query_timestamp: u64,
    pub hourly_query_count: Vec<HourlyQueryCountItem>,
}

#[derive(Debug, Clone)]
pub struct DailyQueryCountItem {
    pub day: String,
    pub query_count: u32,
}

#[derive(Debug, Clone)]
pub struct DailyQueryCount {
    pub query_timestamp: u64,
    pub daily_query_count: Vec<DailyQueryCountItem>,
}

#[derive(Debug, Clone)]
pub struct DomainData {
    pub id: u64,
    pub timestamp: u64,
    pub domain: String,
    pub domain_type: u32,
    pub client: String,
    pub domain_group: String,
    pub reply_code: u16,
    pub query_time: i32,
    pub ping_time: f64,
    pub is_blocked: bool,
    pub is_cached: bool,
}

#[derive(Debug, Clone)]
pub struct QueryDomainListResult {
    pub domain_list: Vec<DomainData>,
    pub total_count: u64,
    pub step_by_cursor: bool,
}

#[derive(Debug, Clone)]
pub struct DomainListGetParamCursor {
    pub id: Option<u64>,
    pub total_count: u64,
    pub direction: String,
}

#[derive(Debug, Clone)]
pub struct QueryClientListResult {
    pub client_list: Vec<ClientData>,
    pub total_count: u64,
    pub step_by_cursor: bool,
}

#[derive(Debug, Clone)]
pub struct ClientListGetParamCursor {
    pub id: Option<u64>,
    pub total_count: u64,
    pub direction: String,
}

#[derive(Debug, Clone)]
pub struct ClientListGetParam {
    pub id: Option<u64>,
    pub order: Option<String>,
    pub page_num: u64,
    pub page_size: u64,
    pub client_ip: Option<String>,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub timestamp_before: Option<u64>,
    pub timestamp_after: Option<u64>,
    pub cursor: Option<ClientListGetParamCursor>,
}

impl ClientListGetParam {
    pub fn new() -> Self {
        ClientListGetParam {
            id: None,
            page_num: 1,
            order: None,
            page_size: 10,
            client_ip: None,
            mac: None,
            hostname: None,
            timestamp_before: None,
            timestamp_after: None,
            cursor: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DomainListGetParam {
    pub id: Option<u64>,
    pub order: Option<String>,
    pub page_num: u64,
    pub page_size: u64,
    pub domain: Option<String>,
    pub domain_filter_mode: Option<String>,
    pub domain_type: Option<u32>,
    pub client: Option<String>,
    pub domain_group: Option<String>,
    pub reply_code: Option<u16>,
    pub timestamp_before: Option<u64>,
    pub timestamp_after: Option<u64>,
    pub is_blocked: Option<bool>,
    pub is_cached: Option<bool>,
    pub cursor: Option<DomainListGetParamCursor>,
}

impl DomainListGetParam {
    pub fn new() -> Self {
        DomainListGetParam {
            id: None,
            page_num: 1,
            order: None,
            page_size: 10,
            domain: None,
            domain_filter_mode: None,
            domain_type: None,
            client: None,
            domain_group: None,
            reply_code: None,
            timestamp_before: None,
            timestamp_after: None,
            is_blocked: None,
            is_cached: None,
            cursor: None,
        }
    }
}

impl DB {
    pub fn new() -> Self {
        DB {
            conn: Mutex::new(None),
            version: 10000, /* x: major version, xx: minor version, xx: patch version */
            query_plan: std::env::var("SMARTDNS_DEBUG_SQL").is_ok(),
        }
    }

    fn create_table(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS domain (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp BIGINT NOT NULL,
                domain TEXT NOT NULL,
                domain_type INTEGER NOT NULL,
                client TEXT NOT NULL,
                domain_group TEXT NOT NULL,
                reply_code INTEGER NOT NULL,
                query_time INTEGER NOT NULL,
                ping_time REAL NOT NULL,
                is_blocked INTEGER DEFAULT 0,
                is_cached INTEGER DEFAULT 0
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_domain_timestamp ON domain (timestamp)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_domain_client ON domain (client)",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS domain_hourly_count (
                timestamp BIGINT PRIMARY KEY,
                count INTEGER DEFAULT 0
            );",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS domain_daily_count (
                timestamp BIGINT PRIMARY KEY,
                count INTEGER DEFAULT 0
            );",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS top_domain_list (
                domain TEXT PRIMARY KEY,
                count INTEGER DEFAULT 0,
                timestamp_start BIGINT DEFAULT 0,
                timestamp_end BIGINT DEFAULT 0
            );",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS top_client_list (
                client TEXT PRIMARY KEY,
                count INTEGER DEFAULT 0,
                timestamp_start BIGINT DEFAULT 0,
                timestamp_end BIGINT DEFAULT 0
            );",
            [],
        )?;

        conn.execute(
            "
        CREATE TABLE IF NOT EXISTS client (
            id INTEGER PRIMARY KEY,
            client_ip TEXT NOT NULL,
            mac TEXT NOT NULL,
            hostname TEXT NOT NULL,
            last_query_timestamp BIGINT NOT NULL,
            UNIQUE(client_ip, mac)
        )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_client_last_query_timestamp ON client (last_query_timestamp)",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS status_data (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "INSERT INTO schema_version (version) VALUES (?)",
            [self.version],
        )?;

        Ok(())
    }

    fn migrate_db(&self, _conn: &Connection) -> Result<(), Box<dyn Error>> {
        return Err(
            "Currently Not Support Migrate Database, Please Backup DB File, And Restart Server."
                .into(),
        );
    }

    fn init_db(&self, conn: &Connection) -> Result<(), Box<dyn Error>> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY
            )",
            [],
        )?;

        let current_version: i32 = conn
            .query_row(
                "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap_or(self.version);

        if current_version >= self.version {
            self.create_table(conn)?;
        } else {
            self.migrate_db(conn)?;
        }

        Ok(())
    }

    pub fn open(&self, path: &str) -> Result<(), Box<dyn Error>> {
        let ruconn: std::result::Result<Connection, rusqlite::Error> =
            Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE);
        let mut conn = self.conn.lock().unwrap();
        if let Err(_) = ruconn {
            let ruconn = Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            )?;

            let ret = self.init_db(&ruconn);
            if let Err(e) = ret {
                _ = ruconn.close();
                fs::remove_file(path)?;
                return Err(e);
            }

            *conn = Some(ruconn);
        } else {
            *conn = Some(ruconn.unwrap());
        }

        conn.as_ref()
            .unwrap()
            .execute("PRAGMA synchronous = OFF", [])?;
        conn.as_ref()
            .unwrap()
            .execute("PRAGMA page_size  = 4096", [])?;
        conn.as_ref()
            .unwrap()
            .execute("PRAGMA cache_size = 10000", [])?;
        conn.as_ref()
            .unwrap()
            .execute("PRAGMA temp_store = MEMORY", [])?;
        conn.as_ref()
            .unwrap()
            .query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()))?;
        Ok(())
    }

    pub fn set_config(&self, key: &str, value: &str) -> Result<(), Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();
        let mut stmt =
            conn.prepare("INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)")?;
        let ret = stmt.execute(&[&key, &value]);

        if let Err(e) = ret {
            return Err(Box::new(e));
        }

        Ok(())
    }

    pub fn get_config_list(&self) -> Result<HashMap<String, String>, Box<dyn Error>> {
        let mut ret = HashMap::new();
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();
        let mut stmt = conn.prepare("SELECT key, value FROM config").unwrap();

        let rows = stmt.query_map([], |row| {
            let key: String = row.get(0)?;
            let value: String = row.get(1)?;
            Ok((key, value))
        });

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    ret.insert(row.0, row.1);
                }
            }
        }

        Ok(ret)
    }

    pub fn set_status_data(&self, key: &str, value: &str) -> Result<(), Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();
        let mut stmt =
            conn.prepare("INSERT OR REPLACE INTO status_data (key, value) VALUES (?1, ?2)")?;
        let ret = stmt.execute(&[&key, &value]);

        if let Err(e) = ret {
            return Err(Box::new(e));
        }

        Ok(())
    }

    pub fn get_status_data_list(&self) -> Result<HashMap<String, String>, Box<dyn Error>> {
        let mut ret = HashMap::new();
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();
        let stmt = conn.prepare("SELECT key, value FROM status_data");
        if let Err(e) = stmt {
            return Err(Box::new(e));
        }
        let mut stmt = stmt.unwrap();

        let rows = stmt.query_map([], |row| {
            let key: String = row.get(0)?;
            let value: String = row.get(1)?;
            Ok((key, value))
        });

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    ret.insert(row.0, row.1);
                }
            }
        }

        Ok(ret)
    }

    pub fn debug_query_plan(&self, conn: &Connection, sql: String, sql_param: &Vec<String>) {
        if !self.query_plan {
            return;
        }

        let sqlplan = "EXPLAIN QUERY PLAN ".to_string() + &sql;
        let stmt = conn.prepare(sqlplan.as_str());
        if let Err(e) = stmt {
            dns_log!(LogLevel::DEBUG, "query plan sql error: {}", e);
            return;
        }

        let mut stmt = stmt.unwrap();
        let plan_rows = stmt.query_map(rusqlite::params_from_iter(sql_param.clone()), |row| {
            Ok(row.get::<_, String>(3)?)
        });

        if let Err(e) = plan_rows {
            dns_log!(LogLevel::DEBUG, "query plan error: {}", e);
            return;
        }

        let plan_rows = plan_rows.unwrap();
        dns_log!(LogLevel::NOTICE, "sql: {}", sql);
        for plan in plan_rows {
            if let Ok(plan) = plan {
                dns_log!(LogLevel::NOTICE, "plan: {}", plan);
            }
        }
    }

    pub fn get_config(&self, key: &str) -> Result<Option<String>, Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();
        let mut stmt = conn
            .prepare("SELECT value FROM config WHERE key = ?")
            .unwrap();
        let rows = stmt.query_map(&[&key], |row| Ok(row.get(0)?));

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    return Ok(Some(row));
                }
            }
        }

        Ok(None)
    }

    pub fn update_domain_hourly_count(
        &self,
        tx: &Transaction<'_>,
        hourly_count: &HashMap<u64, u32>,
    ) -> Result<(), Box<dyn Error>> {
        let mut stmt = tx.prepare(
            "INSERT INTO domain_hourly_count (timestamp, count)
                 VALUES (
                    ?1,
                    ?2
                )
                ON CONFLICT(timestamp) DO UPDATE SET count = count + ?2;",
        )?;

        for (k, v) in hourly_count {
            stmt.execute(rusqlite::params![k, v])?;
        }
        stmt.finalize()?;
        Ok(())
    }

    pub fn update_domain_daily_count(
        &self,
        tx: &Transaction<'_>,
        daily_count: &HashMap<u64, u32>,
    ) -> Result<(), Box<dyn Error>> {
        let mut stmt = tx.prepare(
            "INSERT INTO domain_daily_count (timestamp, count)
                 VALUES (
                    ?1,
                    ?2
                )
                ON CONFLICT(timestamp) DO UPDATE SET count = count + ?2;",
        )?;

        for (k, v) in daily_count {
            stmt.execute(rusqlite::params![k, v])?;
        }
        stmt.finalize()?;
        Ok(())
    }

    pub fn insert_domain(&self, data: &Vec<DomainData>) -> Result<(), Box<dyn Error>> {
        let local_offset = Local::now().offset().local_minus_utc();
        let mut conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let mut hourly_count = HashMap::new();
        let mut daily_count = HashMap::new();
        let conn = conn.as_mut().unwrap();

        let tx = conn.transaction()?;

        let mut stmt = tx.prepare(
            "INSERT INTO domain \
            (timestamp, domain, domain_type, client, domain_group, reply_code, query_time, ping_time, is_blocked, is_cached) \
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)")?;

        for d in data {
            let ret = stmt.execute(rusqlite::params![
                &d.timestamp.to_string(),
                &d.domain,
                &d.domain_type.to_string(),
                &d.client,
                &d.domain_group,
                &d.reply_code,
                &d.query_time,
                &d.ping_time,
                &(d.is_blocked as i32),
                &(d.is_cached as i32)
            ]);

            if let Err(e) = ret {
                stmt.finalize()?;
                tx.rollback()?;
                return Err(Box::new(e));
            }

            let localtimestamp = d.timestamp + local_offset as u64 * 1000;

            let hour_timestamp =
                localtimestamp - localtimestamp % 3600000 - local_offset as u64 * 1000;
            let day_timestamp =
                localtimestamp - localtimestamp % 86400000 - local_offset as u64 * 1000;

            hourly_count
                .entry(hour_timestamp)
                .and_modify(|v| *v += 1)
                .or_insert(1);
            daily_count
                .entry(day_timestamp)
                .and_modify(|v| *v += 1)
                .or_insert(1);
        }

        stmt.finalize()?;

        self.update_domain_hourly_count(&tx, &hourly_count)?;
        self.update_domain_daily_count(&tx, &daily_count)?;

        tx.commit()?;

        Ok(())
    }

    pub fn get_db_file_path(&self) -> Option<String> {
        let conn = self.conn.lock().unwrap();
        if conn.is_none() {
            return None;
        }

        let conn = conn.as_ref().unwrap();
        conn.path().map(|v| v.to_string())
    }

    pub fn get_readonly_conn(&self) -> Option<Connection> {
        let conn = self.conn.lock().unwrap();
        if conn.is_none() {
            return None;
        }

        let conn = conn.as_ref().unwrap();

        let read_conn = Connection::open_with_flags(
            conn.path().unwrap(),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        );

        if let Err(_) = read_conn {
            return None;
        }

        Some(read_conn.unwrap())
    }

    /// # Returns
    ///
    /// A tuple containing:
    /// - `String`: The SQL WHERE clause.
    /// - `String`: The SQL ORDER BY clause.
    /// - `Vec<String>`: The parameters for the SQL query.
    pub fn get_domain_sql_where(
        param: Option<&DomainListGetParam>,
    ) -> Result<(String, String, Vec<String>), Box<dyn Error>> {
        let mut is_desc_order = true;
        let mut is_cursor_prev = false;
        let param = match param {
            Some(v) => v,
            None => return Ok((String::new(), String::new(), Vec::new())),
        };
        let mut order_timestamp_first = true;
        let mut cusor_with_timestamp = false;

        let mut sql_where = Vec::new();
        let mut sql_param: Vec<String> = Vec::new();
        let mut sql_order = String::new();

        if let Some(v) = &param.id {
            sql_where.push("id = ?".to_string());
            sql_param.push(v.to_string());
            order_timestamp_first = false;
        }

        if let Some(v) = &param.order {
            if v.eq_ignore_ascii_case("asc") {
                is_cursor_prev = true;
            } else if v.eq_ignore_ascii_case("desc") {
                is_cursor_prev = false;
            } else {
                return Err("order param error".into());
            }
        }

        if let Some(v) = &param.cursor {
            if v.direction.eq_ignore_ascii_case("prev") {
                is_desc_order = !is_desc_order;
            } else if v.direction.eq_ignore_ascii_case("next") {
                is_desc_order = is_desc_order;
            } else {
                return Err("cursor direction param error".into());
            }
        }

        if let Some(v) = &param.domain {
            if let Some(m) = &param.domain_filter_mode {
                match m.as_str() {
                    "endwith" => {
                        sql_where.push("domain LIKE ?".to_string());
                        sql_param.push(format!("{}%", v));
                    }
                    "startwith" => {
                        sql_where.push("domain LIKE ?".to_string());
                        sql_param.push(format!("%{}", v));
                    }
                    "contains" => {
                        sql_where.push("domain LIKE ?".to_string());
                        sql_param.push(format!("%{}%", v));
                    }
                    "equals" => {
                        sql_where.push("domain = ?".to_string());
                        sql_param.push(v.to_string());
                    }
                    _ => return Err("domain_filter_mode param error".into()),
                }
            } else {
                sql_where.push("domain = ?".to_string());
                sql_param.push(v.to_string());
                order_timestamp_first = false;
            }
        }

        if let Some(v) = &param.domain_type {
            sql_where.push("domain_type = ?".to_string());
            sql_param.push(v.to_string());
            order_timestamp_first = false;
        }

        if let Some(v) = &param.client {
            sql_where.push("client = ?".to_string());
            sql_param.push(v.clone());
            order_timestamp_first = false;
        }

        if let Some(v) = &param.domain_group {
            sql_where.push("domain_group = ?".to_string());
            sql_param.push(v.clone());
            order_timestamp_first = false;
        }

        if let Some(v) = &param.reply_code {
            sql_where.push("reply_code = ?".to_string());
            sql_param.push(v.to_string());
            order_timestamp_first = false;
        }

        if let Some(v) = &param.timestamp_before {
            let mut use_cursor = false;
            if param.cursor.is_some() && (is_desc_order || is_cursor_prev) {
                let v = param.cursor.as_ref().unwrap().id;
                if let Some(v) = v {
                    sql_where.push("id < ?".to_string());
                    sql_param.push(v.to_string());
                    use_cursor = true;
                    order_timestamp_first = false;
                    cusor_with_timestamp = true;
                }
            }

            if use_cursor == false {
                sql_where.push("timestamp <= ?".to_string());
                sql_param.push(v.to_string());
            }
        }

        if let Some(v) = &param.timestamp_after {
            let mut use_cursor = false;
            if param.cursor.is_some() && (!is_desc_order || is_cursor_prev) {
                let v = param.cursor.as_ref().unwrap().id;
                if let Some(v) = v {
                    sql_where.push("id > ?".to_string());
                    sql_param.push(v.to_string());
                    use_cursor = true;
                    order_timestamp_first = false;
                    cusor_with_timestamp = true;
                }
            }

            if use_cursor == false {
                sql_where.push("timestamp >= ?".to_string());
                sql_param.push(v.to_string());
            }
        }

        if !cusor_with_timestamp {
            if let Some(v) = &param.cursor {
                if is_cursor_prev {
                    if let Some(id) = &v.id {
                        if is_desc_order {
                            sql_where.push("id > ?".to_string());
                        } else {
                            sql_where.push("id < ?".to_string());
                        }

                        sql_param.push(id.to_string());
                        order_timestamp_first = false;
                    }
                } else {
                    if let Some(id) = &v.id {
                        if is_desc_order {
                            sql_where.push("id < ?".to_string());
                        } else {
                            sql_where.push("id > ?".to_string());
                        }

                        sql_param.push(id.to_string());
                        order_timestamp_first = false;
                    }
                }
            }
        }

        if let Some(v) = &param.is_blocked {
            if *v {
                sql_where.push("is_blocked = 1".to_string());
            } else {
                sql_where.push("is_blocked = 0".to_string());
            }
            order_timestamp_first = false;
        }

        if let Some(v) = &param.is_cached {
            if *v {
                sql_where.push("is_cached = 1".to_string());
            } else {
                sql_where.push("is_cached = 0".to_string());
            }
            order_timestamp_first = false;
        }

        if is_cursor_prev {
            is_desc_order = !is_desc_order;
        }

        if is_desc_order {
            if order_timestamp_first {
                sql_order.push_str(" ORDER BY timestamp DESC, id DESC");
            } else {
                sql_order.push_str(" ORDER BY id DESC, timestamp DESC");
            }
        } else {
            if order_timestamp_first {
                sql_order.push_str(" ORDER BY timestamp ASC, id ASC");
            } else {
                sql_order.push_str(" ORDER BY id ASC, timestamp ASC");
            }
        }

        let sql_where = if sql_where.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", sql_where.join(" AND "))
        };

        Ok((sql_where, sql_order, sql_param))
    }

    pub fn get_domain_list_count(&self, param: Option<&DomainListGetParam>) -> u64 {
        let conn = self.get_readonly_conn();
        if conn.as_ref().is_none() {
            return 0;
        }

        let conn = conn.as_ref().unwrap();
        let mut sql = String::new();
        let mut sql_param = Vec::new();
        sql.push_str("SELECT COUNT(*) FROM domain");
        if let Ok((sql_where, sql_order, mut ret_sql_param)) = Self::get_domain_sql_where(param) {
            sql.push_str(sql_where.as_str());
            sql.push_str(sql_order.as_str());
            sql_param.append(&mut ret_sql_param);
        }

        let mut stmt = conn.prepare(sql.as_str()).unwrap();
        let rows = stmt.query_map(rusqlite::params_from_iter(sql_param), |row| Ok(row.get(0)?));

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    return row;
                }
            }
        }

        0
    }

    pub fn delete_domain_by_id(&self, id: u64) -> Result<u64, Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();

        let ret = conn.execute("DELETE FROM domain WHERE id = ?", &[&id]);

        if let Err(e) = ret {
            return Err(Box::new(e));
        }

        Ok(ret.unwrap() as u64)
    }

    pub fn delete_domain_before_timestamp(&self, timestamp: u64) -> Result<u64, Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();

        let ret = conn.execute("DELETE FROM domain WHERE timestamp <= ?", &[&timestamp]);

        if let Err(e) = ret {
            return Err(Box::new(e));
        }

        Ok(ret.unwrap() as u64)
    }

    pub fn refresh_client_top_list(&self, timestamp: u64) -> Result<(), Box<dyn Error>> {
        let mut client_count_list = Vec::new();
        let conn = match self.get_readonly_conn() {
            Some(v) => v,
            None => return Err("db is not open".into()),
        };

        let timestamp_now = smartdns::get_utc_time_ms();
        let sql = "SELECT client, COUNT(*) FROM domain WHERE timestamp >= ? GROUP BY client ORDER BY COUNT(*) DESC LIMIT 20";
        self.debug_query_plan(&conn, sql.to_string(), &vec![timestamp.to_string()]);
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map([timestamp.to_string()], |row| {
            Ok(ClientQueryCount {
                client_ip: row.get(0)?,
                count: row.get(1)?,
                timestamp_start: timestamp,
                timestamp_end: timestamp_now,
            })
        });

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    client_count_list.push(row);
                }
            }
        }

        let mut conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_mut().unwrap();

        let tx = conn.transaction()?;
        let mut stmt = tx.prepare("DELETE FROM top_client_list")?;
        stmt.execute([])?;
        stmt.finalize()?;
        let mut stmt =
            tx.prepare("INSERT INTO top_client_list (client, count, timestamp_start, timestamp_end) VALUES ( ?1, ?2, $3, $4)")?;
        for client in &client_count_list {
            stmt.execute(rusqlite::params![
                client.client_ip,
                client.count,
                client.timestamp_start,
                client.timestamp_end
            ])?;
            dns_log!(
                LogLevel::DEBUG,
                "client: {}, count: {}, timestamp_start: {}, timestamp_end: {}",
                client.client_ip,
                client.count,
                client.timestamp_start,
                client.timestamp_end
            );
        }
        stmt.finalize()?;
        tx.commit()?;

        Ok(())
    }

    pub fn get_client_top_list(&self, count: u32) -> Result<Vec<ClientQueryCount>, Box<dyn Error>> {
        let mut ret = Vec::new();
        let conn = self.get_readonly_conn();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();
        let mut stmt =
            conn.prepare("SELECT client, count, timestamp_start, timestamp_end FROM top_client_list ORDER BY count DESC LIMIT ?")?;
        let rows = stmt.query_map([count.to_string()], |row| {
            Ok(ClientQueryCount {
                client_ip: row.get(0)?,
                count: row.get(1)?,
                timestamp_start: row.get(2)?,
                timestamp_end: row.get(3)?,
            })
        });

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    ret.push(row);
                }
            }
        }

        Ok(ret)
    }

    pub fn delete_daily_query_count_before_timestamp(
        &self,
        timestamp: u64,
    ) -> Result<u64, Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();

        let ret = conn.execute(
            "DELETE FROM domain_daily_count WHERE timestamp <= ?",
            &[&timestamp],
        );

        if let Err(e) = ret {
            return Err(Box::new(e));
        }

        Ok(ret.unwrap() as u64)
    }

    pub fn get_daily_query_count(&self, past_days: u32) -> Result<DailyQueryCount, Box<dyn Error>> {
        let mut ret = Vec::new();
        let conn = self.get_readonly_conn();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();
        let seconds = 86400 * past_days - utils::seconds_until_next_hour() as u32;
        let mut stmt = conn.prepare(
            "SELECT \
                    strftime('%Y-%m-%d', datetime(timestamp / 1000, 'unixepoch', 'localtime')) AS date, timestamp, count \
                 FROM \
                    domain_daily_count \
                 WHERE \
                    timestamp >= strftime('%s', 'now') * 1000 - ? * 1000 \
                 ORDER BY \
                    timestamp DESC;\
                 ",
        )?;

        let rows = stmt.query_map([seconds.to_string()], |row| {
            Ok(DailyQueryCountItem {
                day: row.get(0)?,
                query_count: row.get(2)?,
            })
        });

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    ret.push(row);
                }
            }
        }

        Ok(DailyQueryCount {
            query_timestamp: smartdns::get_utc_time_ms(),
            daily_query_count: ret,
        })
    }

    pub fn delete_hourly_query_count_before_timestamp(
        &self,
        timestamp: u64,
    ) -> Result<u64, Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();

        let ret = conn.execute(
            "DELETE FROM domain_hourly_count WHERE timestamp <= ?",
            &[&timestamp],
        );

        if let Err(e) = ret {
            return Err(Box::new(e));
        }

        Ok(ret.unwrap() as u64)
    }

    pub fn get_hourly_query_count(
        &self,
        past_hours: u32,
    ) -> Result<HourlyQueryCount, Box<dyn Error>> {
        let mut ret = Vec::new();
        let conn = self.get_readonly_conn();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let query_start = std::time::Instant::now();
        let conn = conn.as_ref().unwrap();
        let seconds = 3600 * past_hours - utils::seconds_until_next_hour() as u32;

        let sql = "SELECT \
                    strftime('%Y-%m-%d %H:00:00', datetime(timestamp / 1000, 'unixepoch', 'localtime')) AS hour, timestamp, count \
                 FROM \
                    domain_hourly_count \
                 WHERE \
                    timestamp >= strftime('%s', 'now') * 1000 - ? * 1000 \
                 ORDER BY \
                    timestamp DESC;\
                 ";
        self.debug_query_plan(conn, sql.to_string(), &vec![seconds.to_string()]);
        let mut stmt = conn.prepare(sql)?;

        let rows = stmt.query_map([seconds.to_string()], |row| {
            Ok(HourlyQueryCountItem {
                hour: row.get(0)?,
                query_count: row.get(2)?,
            })
        });

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    ret.push(row);
                }
            }
        }

        dns_log!(
            LogLevel::DEBUG,
            "hourly_query_count time: {}ms",
            query_start.elapsed().as_millis()
        );

        Ok(HourlyQueryCount {
            query_timestamp: smartdns::get_utc_time_ms(),
            hourly_query_count: ret,
        })
    }

    pub fn refresh_domain_top_list(&self, timestamp: u64) -> Result<(), Box<dyn Error>> {
        let mut domain_count_list = Vec::new();
        let conn = match self.get_readonly_conn() {
            Some(v) => v,
            None => return Err("db is not open".into()),
        };

        let timestamp_now = smartdns::get_utc_time_ms();
        let sql = "SELECT domain, COUNT(*) FROM domain WHERE timestamp >= ? GROUP BY domain ORDER BY COUNT(*) DESC LIMIT 20";
        self.debug_query_plan(&conn, sql.to_string(), &vec![timestamp.to_string()]);
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map([timestamp.to_string()], |row| {
            Ok(DomainQueryCount {
                domain: row.get(0)?,
                count: row.get(1)?,
                timestamp_start: timestamp,
                timestamp_end: timestamp_now,
            })
        });

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    domain_count_list.push(row);
                }
            }
        }

        let mut conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_mut().unwrap();
        let tx = conn.transaction()?;
        let mut stmt = tx.prepare("DELETE FROM top_domain_list")?;
        stmt.execute([])?;
        stmt.finalize()?;
        let mut stmt =
            tx.prepare("INSERT INTO top_domain_list (domain, count, timestamp_start, timestamp_end) VALUES ( ?1, ?2, ?3, ?4)")?;
        for domain in &domain_count_list {
            stmt.execute(rusqlite::params![
                domain.domain,
                domain.count,
                domain.timestamp_start,
                domain.timestamp_end
            ])?;
        }
        stmt.finalize()?;
        tx.commit()?;

        Ok(())
    }

    pub fn get_domain_top_list(&self, count: u32) -> Result<Vec<DomainQueryCount>, Box<dyn Error>> {
        let mut ret = Vec::new();
        let conn = self.get_readonly_conn();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();

        let mut stmt = conn.prepare("SELECT domain, count, timestamp_start, timestamp_end FROM top_domain_list DESC LIMIT ?")?;
        let rows = stmt.query_map([count.to_string()], |row| {
            Ok(DomainQueryCount {
                domain: row.get(0)?,
                count: row.get(1)?,
                timestamp_start: row.get(2)?,
                timestamp_end: row.get(3)?,
            })
        });

        if let Err(e) = rows {
            return Err(Box::new(e));
        }

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    ret.push(row);
                }
            }
        }

        Ok(ret)
    }

    pub fn get_domain_list(
        &self,
        param: Option<&DomainListGetParam>,
    ) -> Result<QueryDomainListResult, Box<dyn Error>> {
        let query_start = std::time::Instant::now();
        let mut cursor_reverse = false;

        let mut ret = QueryDomainListResult {
            domain_list: vec![],
            total_count: 0,
            step_by_cursor: false,
        };

        let conn = self.get_readonly_conn();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();

        let (sql_where, sql_order, mut sql_param) = Self::get_domain_sql_where(param)?;

        let mut sql = String::new();
        sql.push_str("SELECT id, timestamp, domain, domain_type, client, domain_group, reply_code, query_time, ping_time, is_blocked, is_cached FROM domain");

        sql.push_str(sql_where.as_str());
        sql.push_str(sql_order.as_str());

        if let Some(p) = param {
            let mut with_offset = true;
            if let Some(cursor) = &p.cursor {
                if cursor.id.is_some() {
                    sql.push_str(" LIMIT ?");
                    sql_param.push(p.page_size.to_string());
                    with_offset = false;
                }

                if cursor.direction.eq_ignore_ascii_case("prev") {
                    cursor_reverse = true;
                }
            }

            if with_offset {
                sql.push_str(" LIMIT ? OFFSET ?");
                sql_param.push(p.page_size.to_string());
                sql_param.push(((p.page_num - 1) * p.page_size).to_string());
            }
        }

        self.debug_query_plan(conn, sql.clone(), &sql_param);
        let stmt = conn.prepare(&sql);

        if let Err(e) = stmt {
            dns_log!(LogLevel::ERROR, "get_domain_list error: {}", e);
            return Err("get_domain_list error".into());
        }

        let mut stmt = stmt?;

        let rows = stmt.query_map(rusqlite::params_from_iter(sql_param), |row| {
            Ok(DomainData {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                domain: row.get(2)?,
                domain_type: row.get(3)?,
                client: row.get(4)?,
                domain_group: row.get(5)?,
                reply_code: row.get(6)?,
                query_time: row.get(7)?,
                ping_time: row.get(8)?,
                is_blocked: row.get(9)?,
                is_cached: row.get(10)?,
            })
        });

        if let Err(e) = rows {
            return Err(Box::new(e));
        }

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    ret.domain_list.push(row);
                }
            }
        }

        if cursor_reverse {
            ret.domain_list.reverse();
        }

        if let Some(p) = param {
            if let Some(v) = &p.cursor {
                ret.total_count = v.total_count;
                ret.step_by_cursor = true;
            } else {
                let total_count = self.get_domain_list_count(param);
                ret.total_count = total_count;
            }
        }

        dns_log!(
            LogLevel::DEBUG,
            "domain_list time: {}ms",
            query_start.elapsed().as_millis()
        );
        Ok(ret)
    }

    pub fn insert_client(&self, client_data: &Vec<ClientData>) -> Result<(), Box<dyn Error>> {
        let mut conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_mut().unwrap();
        let tx = conn.transaction()?;
        let mut stmt = tx.prepare("INSERT INTO client (id, client_ip, mac, hostname, last_query_timestamp) VALUES (
            (SELECT MAX(rowid) FROM client) + 1,
            ?1, ?2, ?3, ?4)
            ON CONFLICT(client_ip, mac) DO UPDATE SET last_query_timestamp = excluded.last_query_timestamp;
            ")?;
        for d in client_data {
            let ret = stmt.execute(rusqlite::params![
                d.client_ip,
                d.mac,
                d.hostname,
                d.last_query_timestamp
            ]);

            if let Err(e) = ret {
                stmt.finalize()?;
                tx.rollback()?;
                return Err(Box::new(e));
            }
        }
        stmt.finalize()?;
        tx.commit()?;

        Ok(())
    }

    pub fn get_client_list_count(&self, param: Option<&ClientListGetParam>) -> u64 {
        let conn = self.get_readonly_conn();
        if conn.as_ref().is_none() {
            return 0;
        }

        let conn = conn.as_ref().unwrap();
        let mut sql = String::new();
        let mut sql_param = Vec::new();
        sql.push_str("SELECT COUNT(*) FROM client");
        if let Ok((sql_where, sql_order, mut ret_sql_param)) = Self::get_client_sql_where(param) {
            sql.push_str(sql_where.as_str());
            sql.push_str(sql_order.as_str());
            sql_param.append(&mut ret_sql_param);
        }

        let mut stmt = conn.prepare(sql.as_str()).unwrap();
        let rows = stmt.query_map(rusqlite::params_from_iter(sql_param), |row| Ok(row.get(0)?));

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    return row;
                }
            }
        }

        0
    }

    fn get_client_sql_where(
        param: Option<&ClientListGetParam>,
    ) -> Result<(String, String, Vec<String>), Box<dyn Error>> {
        let mut is_desc_order = true;
        let mut is_cursor_prev = false;
        let param = match param {
            Some(v) => v,
            None => return Ok((String::new(), String::new(), Vec::new())),
        };
        let mut order_timestamp_first = false;
        let mut cusor_with_timestamp = false;

        let mut sql_where = Vec::new();
        let mut sql_param: Vec<String> = Vec::new();
        let mut sql_order = String::new();

        if let Some(v) = &param.id {
            sql_where.push("id = ?".to_string());
            sql_param.push(v.to_string());
            order_timestamp_first = false;
        }

        if let Some(v) = &param.order {
            if v.eq_ignore_ascii_case("asc") {
                is_cursor_prev = true;
            } else if v.eq_ignore_ascii_case("desc") {
                is_cursor_prev = false;
            } else {
                return Err("order param error".into());
            }
        }

        if let Some(v) = &param.cursor {
            if v.direction.eq_ignore_ascii_case("prev") {
                is_desc_order = !is_desc_order;
            } else if v.direction.eq_ignore_ascii_case("next") {
                is_desc_order = is_desc_order;
            } else {
                return Err("cursor direction param error".into());
            }
        }

        if let Some(v) = &param.client_ip {
            sql_where.push("client_ip = ?".to_string());
            sql_param.push(v.to_string());
        }

        if let Some(v) = &param.mac {
            sql_where.push("mac = ?".to_string());
            sql_param.push(v.to_string());
        }

        if let Some(v) = &param.hostname {
            sql_where.push("hostname = ?".to_string());
            sql_param.push(v.to_string());
        }

        if let Some(v) = &param.timestamp_before {
            let mut use_cursor = false;
            if param.cursor.is_some() && (is_desc_order || is_cursor_prev) {
                let v = param.cursor.as_ref().unwrap().id;
                if let Some(v) = v {
                    sql_where.push("id < ?".to_string());
                    sql_param.push(v.to_string());
                    use_cursor = true;
                    order_timestamp_first = false;
                    cusor_with_timestamp = true;
                }
            }

            if use_cursor == false {
                sql_where.push("last_query_timestamp <= ?".to_string());
                sql_param.push(v.to_string());
            }
        }

        if let Some(v) = &param.timestamp_after {
            let mut use_cursor = false;
            if param.cursor.is_some() && (!is_desc_order || is_cursor_prev) {
                let v = param.cursor.as_ref().unwrap().id;
                if let Some(v) = v {
                    sql_where.push("id > ?".to_string());
                    sql_param.push(v.to_string());
                    use_cursor = true;
                    order_timestamp_first = false;
                    cusor_with_timestamp = true;
                }
            }

            if use_cursor == false {
                sql_where.push("last_query_timestamp >= ?".to_string());
                sql_param.push(v.to_string());
            }
        }

        if !cusor_with_timestamp {
            if let Some(v) = &param.cursor {
                if is_cursor_prev {
                    if let Some(id) = &v.id {
                        if is_desc_order {
                            sql_where.push("id > ?".to_string());
                        } else {
                            sql_where.push("id < ?".to_string());
                        }

                        sql_param.push(id.to_string());
                        order_timestamp_first = false;
                    }
                } else {
                    if let Some(id) = &v.id {
                        if is_desc_order {
                            sql_where.push("id < ?".to_string());
                        } else {
                            sql_where.push("id > ?".to_string());
                        }

                        sql_param.push(id.to_string());
                        order_timestamp_first = false;
                    }
                }
            }
        }

        if is_desc_order {
            if order_timestamp_first {
                sql_order.push_str(" ORDER BY last_query_timestamp DESC, id DESC");
            } else {
                sql_order.push_str(" ORDER BY id DESC, last_query_timestamp DESC");
            }
        } else {
            if order_timestamp_first {
                sql_order.push_str(" ORDER BY last_query_timestamp ASC, id ASC");
            } else {
                sql_order.push_str(" ORDER BY id ASC, last_query_timestamp ASC");
            }
        }

        let sql_where = if sql_where.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", sql_where.join(" AND "))
        };

        Ok((sql_where, sql_order, sql_param))
    }

    pub fn get_client_list(
        &self,
        param: Option<&ClientListGetParam>,
    ) -> Result<QueryClientListResult, Box<dyn Error>> {
        let query_start = std::time::Instant::now();
        let mut cursor_reverse = false;

        let mut ret = QueryClientListResult {
            client_list: vec![],
            total_count: 0,
            step_by_cursor: false,
        };

        let conn = self.get_readonly_conn();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();

        let (sql_where, sql_order, mut sql_param) = Self::get_client_sql_where(param)?;

        let mut sql = String::new();
        sql.push_str("SELECT id, client_ip, mac, hostname, last_query_timestamp FROM client");

        sql.push_str(sql_where.as_str());
        sql.push_str(sql_order.as_str());

        if let Some(p) = param {
            let mut with_offset = true;
            if let Some(cursor) = &p.cursor {
                if cursor.id.is_some() {
                    sql.push_str(" LIMIT ?");
                    sql_param.push(p.page_size.to_string());
                    with_offset = false;
                }

                if cursor.direction.eq_ignore_ascii_case("prev") {
                    cursor_reverse = true;
                }
            }

            if with_offset {
                sql.push_str(" LIMIT ? OFFSET ?");
                sql_param.push(p.page_size.to_string());
                sql_param.push(((p.page_num - 1) * p.page_size).to_string());
            }
        }

        self.debug_query_plan(conn, sql.clone(), &sql_param);
        let stmt = conn.prepare(&sql);
        if let Err(e) = stmt {
            dns_log!(LogLevel::ERROR, "get_client_list error: {}", e);
            return Err("get_client_list error".into());
        }
        let mut stmt = stmt?;

        let rows = stmt.query_map(rusqlite::params_from_iter(sql_param), |row| {
            Ok(ClientData {
                id: row.get(0)?,
                client_ip: row.get(1)?,
                mac: row.get(2)?,
                hostname: row.get(3)?,
                last_query_timestamp: row.get(4)?,
            })
        });

        if let Err(e) = rows {
            return Err(Box::new(e));
        }

        if let Ok(rows) = rows {
            for row in rows {
                if let Ok(row) = row {
                    ret.client_list.push(row);
                }
            }
        }

        if cursor_reverse {
            ret.client_list.reverse();
        }

        if let Some(p) = param {
            if let Some(v) = &p.cursor {
                ret.total_count = v.total_count;
                ret.step_by_cursor = true;
            } else {
                let total_count = self.get_client_list_count(param);
                ret.total_count = total_count;
            }
        }

        dns_log!(
            LogLevel::DEBUG,
            "domain_list time: {}ms",
            query_start.elapsed().as_millis()
        );
        Ok(ret)
    }

    pub fn delete_client_by_id(&self, id: u64) -> Result<u64, Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();

        let ret = conn.execute("DELETE FROM client WHERE id = ?", &[&id]);

        if let Err(e) = ret {
            return Err(Box::new(e));
        }

        Ok(ret.unwrap() as u64)
    }

    pub fn get_db_size(&self) -> u64 {
        let db_file = self.get_db_file_path();
        let mut total_size = 0;
        if db_file.is_none() {
            return 0;
        }

        let db_file = db_file.unwrap();
        let wal_file = db_file.clone() + "-wal";

        let metadata = fs::metadata(db_file);
        if let Err(_) = metadata {
            return 0;
        }
        total_size += metadata.unwrap().len();

        let wal_metadata = fs::metadata(wal_file);
        if let Ok(wal_metadata) = wal_metadata {
            let wal_size = wal_metadata.len();
            total_size += wal_size;
        }

        total_size
    }

    pub fn close(&self) {
        let mut conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return;
        }

        if let Some(t) = conn.take() {
            let _ = t.close();
        }
    }
}

impl Drop for DB {
    fn drop(&mut self) {
        self.close();
    }
}
