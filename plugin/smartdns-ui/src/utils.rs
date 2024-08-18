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

pub fn parse_value<T>(value: Option<String>, min: T, max: T, default: T) -> T
where
    T: PartialOrd + std::str::FromStr,
{
    if value.is_none() {
        return default;
    }

    let value = value.unwrap().parse::<T>();
    if let Err(_) = value {
        return default;
    }

    let mut value = value.unwrap_or_else(|_| default);

    if value < min {
        value = min;
    }

    if value > max {
        value = max;
    }

    value
}


pub fn seconds_until_next_hour() -> u64 {
    let now = chrono::Local::now();
    let minutes = chrono::Timelike::minute(&now);
    let seconds = chrono::Timelike::second(&now);
    let remaining_seconds = 3600 - (minutes * 60 + seconds) as u64;
    remaining_seconds
}
