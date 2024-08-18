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

use crate::dns_log;
use crate::smartdns::*;
use crate::utils;
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::sync::Mutex;

use rusqlite::{Connection, OpenFlags, Result};

pub struct DB {
    conn: Mutex<Option<Connection>>,
    version: i32,
}

#[derive(Debug, Clone)]
pub struct ClientData {
    pub id: u32,
    pub client_ip: String,
}

#[derive(Debug, Clone)]
pub struct ClientQueryCount {
    pub client_ip: String,
    pub count: u32,
}

#[derive(Debug, Clone)]
pub struct DomainQueryCount {
    pub domain: String,
    pub count: u32,
}

#[derive(Debug, Clone)]
pub struct HourlyQueryCount {
    pub hour: String,
    pub query_count: u32,
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
pub struct DomainListGetParam {
    pub id: Option<u64>,
    pub order: Option<String>,
    pub page_num: u32,
    pub page_size: u32,
    pub domain: Option<String>,
    pub domain_type: Option<u32>,
    pub client: Option<String>,
    pub domain_group: Option<String>,
    pub reply_code: Option<u16>,
    pub timestamp_before: Option<u64>,
    pub timestamp_after: Option<u64>,
    pub is_blocked: Option<bool>,
    pub is_cached: Option<bool>,
}

impl DomainListGetParam {
    pub fn new() -> Self {
        DomainListGetParam {
            id: None,
            page_num: 1,
            order: None,
            page_size: 10,
            domain: None,
            domain_type: None,
            client: None,
            domain_group: None,
            reply_code: None,
            timestamp_before: None,
            timestamp_after: None,
            is_blocked: None,
            is_cached: None,
        }
    }
}

impl DB {
    pub fn new() -> Self {
        DB {
            conn: Mutex::new(None),
            version: 10000, /* x: major version, xx: minor version, xx: patch version */
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
            "
        CREATE TABLE IF NOT EXISTS client (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_ip TEXT NOT NULL UNIQUE
        )",
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
            .query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()))?;
        Ok(())
    }

    pub fn set_config(&self, key: &str, value: &str) -> Result<(), Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Ok(());
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
            return Ok(ret);
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

    pub fn get_config(&self, key: &str) -> Result<Option<String>, Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Ok(None);
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

    pub fn insert_domain(&self, data: &DomainData) -> Result<(), Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Ok(());
        }

        let conn = conn.as_ref().unwrap();
        let mut stmt = conn.prepare(
            "INSERT INTO domain \
            (timestamp, domain, domain_type, client, domain_group, reply_code, query_time, ping_time, is_blocked, is_cached) \
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)")?;
        let ret = stmt.execute(rusqlite::params![
            &data.timestamp.to_string(),
            &data.domain,
            &data.domain_type.to_string(),
            &data.client,
            &data.domain_group,
            &data.reply_code,
            &data.query_time,
            &data.ping_time,
            &(data.is_blocked as i32),
            &(data.is_cached as i32)
        ]);

        if let Err(e) = ret {
            return Err(Box::new(e));
        }

        Ok(())
    }

    pub fn get_domain_list_count(&self) -> u32 {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return 0;
        }

        let conn = conn.as_ref().unwrap();

        let mut stmt = conn.prepare("SELECT COUNT(*) FROM domain").unwrap();
        let rows = stmt.query_map([], |row| Ok(row.get(0)?));

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
            return Ok(0);
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
            return Ok(0);
        }

        let conn = conn.as_ref().unwrap();

        let ret = conn.execute("DELETE FROM domain WHERE timestamp <= ?", &[&timestamp]);

        if let Err(e) = ret {
            return Err(Box::new(e));
        }

        Ok(ret.unwrap() as u64)
    }

    pub fn get_client_top_list(&self, count: u32) -> Result<Vec<ClientQueryCount>, Box<dyn Error>> {
        let mut ret = Vec::new();
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Ok(ret);
        }

        let conn = conn.as_ref().unwrap();
        let mut stmt = conn.prepare(
            "SELECT client, COUNT(*) FROM domain GROUP BY client ORDER BY COUNT(*) DESC LIMIT ?",
        )?;
        let rows = stmt.query_map([count.to_string()], |row| {
            Ok(ClientQueryCount {
                client_ip: row.get(0)?,
                count: row.get(1)?,
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

    pub fn get_hourly_query_count(
        &self,
        past_hours: u32,
    ) -> Result<Vec<HourlyQueryCount>, Box<dyn Error>> {
        let mut ret = Vec::new();
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Ok(ret);
        }

        let seconds = 3600 * past_hours - utils::seconds_until_next_hour() as u32;

        let conn = conn.as_ref().unwrap();
        let mut stmt = conn.prepare(
            "SELECT \
                    strftime('%Y-%m-%d %H:00:00', datetime(timestamp / 1000, 'unixepoch', 'localtime')) AS hour, \
                    COUNT(*) AS query_count \
                 FROM \
                    domain \
                 WHERE \
                    timestamp >= strftime('%s', 'now', 'utc') * 1000 - ? * 1000 \
                 GROUP BY \
                    hour \
                 ORDER BY \
                    hour DESC;\
                 ",
        )?;

        let rows = stmt.query_map([seconds.to_string()], |row| {
            Ok(HourlyQueryCount {
                hour: row.get(0)?,
                query_count: row.get(1)?,
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

    pub fn get_domain_top_list(&self, count: u32) -> Result<Vec<DomainQueryCount>, Box<dyn Error>> {
        let mut ret = Vec::new();
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Ok(ret);
        }

        let conn = conn.as_ref().unwrap();
        let mut stmt = conn.prepare(
            "SELECT domain, COUNT(*) FROM domain GROUP BY domain ORDER BY COUNT(*) DESC LIMIT ?",
        )?;
        let rows = stmt.query_map([count.to_string()], |row| {
            Ok(DomainQueryCount {
                domain: row.get(0)?,
                count: row.get(1)?,
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
        param: &DomainListGetParam,
    ) -> Result<Vec<DomainData>, Box<dyn Error>> {
        let mut ret = Vec::new();
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Ok(ret);
        }

        let mut sql_where = String::new();
        let mut sql_order = String::new();
        let mut sql_param: Vec<String> = Vec::new();

        if let Some(v) = &param.id {
            if !sql_where.is_empty() {
                sql_where.push_str(" AND ");
            }
            sql_where.push_str("id = ?");
            sql_param.push(v.to_string());
        }

        if let Some(v) = &param.domain {
            if !sql_where.is_empty() {
                sql_where.push_str(" AND ");
            }
            sql_where.push_str("domain = ?");
            sql_param.push(v.to_string());
        }

        if let Some(v) = &param.domain_type {
            if !sql_where.is_empty() {
                sql_where.push_str(" AND ");
            }
            sql_where.push_str("domain_type = ?");
            sql_param.push(v.to_string());
        }

        if let Some(v) = &param.client {
            if !sql_where.is_empty() {
                sql_where.push_str(" AND ");
            }
            sql_where.push_str("client = ?");
            sql_param.push(v.clone());
        }

        if let Some(v) = &param.domain_group {
            if !sql_where.is_empty() {
                sql_where.push_str(" AND ");
            }
            sql_where.push_str("domain_group = ?");
            sql_param.push(v.clone());
        }

        if let Some(v) = &param.reply_code {
            if !sql_where.is_empty() {
                sql_where.push_str(" AND ");
            }
            sql_where.push_str("reply_code = ?");
            sql_param.push(v.to_string());
        }

        if let Some(v) = &param.timestamp_before {
            if !sql_where.is_empty() {
                sql_where.push_str(" AND ");
            }
            sql_where.push_str("timestamp <= ?");
            sql_param.push(v.to_string());
        }

        if let Some(v) = &param.timestamp_after {
            if !sql_where.is_empty() {
                sql_where.push_str(" AND ");
            }
            sql_where.push_str("timestamp >= ?");
            sql_param.push(v.to_string());
        }

        if let Some(v) = &param.is_blocked {
            if !sql_where.is_empty() {
                sql_where.push_str(" AND ");
            }

            if *v {
                sql_where.push_str("is_blocked = 1");
            } else {
                sql_where.push_str("is_blocked = 0");
            }
        }

        if let Some(v) = &param.is_cached {
            if !sql_where.is_empty() {
                sql_where.push_str(" AND ");
            }

            if *v {
                sql_where.push_str("is_cached = 1");
            } else {
                sql_where.push_str("is_cached = 0");
            }
        }

        if let Some(v) = &param.order {
            if v.eq_ignore_ascii_case("asc") {
                sql_order.push_str(" ORDER BY id ASC");
            } else if v.eq_ignore_ascii_case("desc") {
                sql_order.push_str(" ORDER BY id DESC");
            } else {
                return Err("order param error".into());
            }
        } else {
            sql_order.push_str(" ORDER BY id DESC");
        }

        let mut sql = String::new();
        sql.push_str("SELECT id, timestamp, domain, domain_type, client, domain_group, reply_code, query_time, ping_time, is_blocked, is_cached FROM domain");

        if !sql_where.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(sql_where.as_str());
        }

        sql.push_str(sql_order.as_str());
        sql.push_str(" LIMIT ? OFFSET ?");

        sql_param.push(param.page_size.to_string());
        sql_param.push(((param.page_num - 1) * param.page_size).to_string());

        let conn = conn.as_ref().unwrap();
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
                    ret.push(row);
                }
            }
        }

        Ok(ret)
    }

    pub fn insert_client(&self, client_ip: &str) -> Result<(), Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Ok(());
        }

        let conn = conn.as_ref().unwrap();
        let mut stmt = conn.prepare("INSERT OR IGNORE INTO client (client_ip) VALUES (?1)")?;
        let ret = stmt.execute(rusqlite::params![client_ip]);

        if let Err(e) = ret {
            return Err(Box::new(e));
        }

        Ok(())
    }

    pub fn get_client_list(&self) -> Result<Vec<ClientData>, Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Err("db is not open".into());
        }

        let conn = conn.as_ref().unwrap();
        let mut ret = Vec::new();
        let mut stmt = conn.prepare("SELECT id, client_ip FROM client").unwrap();
        let rows = stmt.query_map([], |row| {
            Ok(ClientData {
                id: row.get(0)?,
                client_ip: row.get(1)?,
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
