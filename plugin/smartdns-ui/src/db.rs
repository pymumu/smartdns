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
use std::error::Error;
use std::fs;
use std::sync::Mutex;

use rusqlite::{Connection, OpenFlags, Result};

pub struct DB {
    conn: Mutex<Option<Connection>>,
}

pub struct ClientData {
    pub id: u32,
    pub client_ip: String,
}

pub struct ConfigData {
    pub key: String,
    pub value: String,
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
}

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
        }
    }
}

impl DB {
    pub fn new() -> Self {
        DB {
            conn: Mutex::new(None),
        }
    }

    fn init_db(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS domain (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp BIGINT NOT NULL,
                domain TEXT NOT NULL,
                domain_type INTEGER NOT NULL,
                client TEXT NOT NULL,
                domain_group TEXT NOT NULL,
                reply_code INTEGER NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "
        CREATE TABLE IF NOT EXISTS client (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_ip TEXT NOT NULL
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
                return Err(Box::new(e));
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

    pub fn insert_config(&self, conf: &ConfigData) -> Result<(), Box<dyn Error>> {
        let conn = self.conn.lock().unwrap();
        if conn.as_ref().is_none() {
            return Ok(());
        }

        let conn = conn.as_ref().unwrap();
        let mut stmt = conn
            .prepare("INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)")
            .unwrap();
        let ret = stmt.execute(&[&conf.key, &conf.value]);

        if let Err(e) = ret {
            return Err(Box::new(e));
        }

        Ok(())
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
        let mut stmt = conn.prepare("INSERT INTO domain (timestamp, domain, domain_type, client, domain_group, reply_code) VALUES (?1, ?2, ?3, ?4, ?5, ?6)").unwrap();
        let ret = stmt.execute(&[
            &data.timestamp.to_string(),
            &data.domain,
            &data.domain_type.to_string(),
            &data.client,
            &data.domain_group,
            &data.reply_code.to_string(),
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
        sql.push_str("SELECT id, timestamp, domain, domain_type, client, domain_group, reply_code FROM domain");

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

        let mut stmt = stmt.unwrap();

        let rows = stmt.query_map(rusqlite::params_from_iter(sql_param), |row| {
            Ok(DomainData {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                domain: row.get(2)?,
                domain_type: row.get(3)?,
                client: row.get(4)?,
                domain_group: row.get(5)?,
                reply_code: row.get(6)?,
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
