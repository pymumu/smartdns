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

pub mod data_server;
pub mod db;
pub mod http_api_msg;
pub mod http_error;
pub mod http_jwt;
pub mod http_server;
pub mod http_server_api;
pub mod http_server_stream;
pub mod plugin;
pub mod data_stats;
pub mod utils;
pub mod smartdns;

use ctor::ctor;
use ctor::dtor;
#[cfg(not(test))]
use plugin::*;
use smartdns::*;

#[cfg(not(test))]
fn lib_init_ops() {
    let ops: Box<dyn SmartdnsOperations> = Box::new(SmartdnsPlugin::new());
    unsafe {
        PLUGIN.set_operation(ops);
    }
}

#[cfg(not(test))]
fn lib_deinit_ops() {
    unsafe {
        PLUGIN.clear_operation();
    }
}

#[cfg(test)]
fn lib_init_smartdns_lib() {
    smartdns::dns_log_set_level(LogLevel::DEBUG);
}

#[ctor]
fn lib_init() {
    #[cfg(not(test))]
    lib_init_ops();

    #[cfg(test)]
    lib_init_smartdns_lib();
}

#[dtor]
fn lib_deinit() {
    #[cfg(not(test))]
    lib_deinit_ops();
}
