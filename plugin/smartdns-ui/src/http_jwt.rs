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

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub user: String,
    pub ip: String,
    pub exp: u64,
}

pub struct Jwt {
    user: String,
    secret: String,
    ip: String,
    expired_in: u32,
}

pub struct TokenInfo {
    pub token: String,
    pub expire: String,
}

impl Jwt {
    pub fn new(user: &str, secret: &str, ip: &str, expired_in: u32) -> Self {
        Jwt {
            user: user.to_string(),
            secret: secret.to_string(),
            ip: ip.to_string(),
            expired_in: expired_in,
        }
    }

    pub fn refresh_token(&self, token: &str) -> Result<TokenInfo, String> {
        if !self.is_token_valid(token) {
            return Err("token is invalid".to_string());
        }
        
        Ok(self.encode_token())
    }

    pub fn encode_token(&self) -> TokenInfo {
        let calims = JwtClaims {
            user: self.user.clone(),
            ip: self.ip.clone(),
            exp: jsonwebtoken::get_current_timestamp() + self.expired_in as u64,
        };
        let token = encode(
            &Header::default(),
            &calims,
            &EncodingKey::from_secret(self.secret.as_ref()),
        );

        let exp = self.expired_in.to_string();
        TokenInfo {
            token: token.unwrap(),
            expire: exp,
        }
    }

    pub fn is_token_valid(&self, token: &str) -> bool {
        let calim = self.decode_token(token);
        if self.decode_token(token).is_err() {
            return false;
        }

        let calim = calim.unwrap();

        if calim.user != self.user || calim.ip != self.ip {
            return false;
        }

        true
    }

    pub fn decode_token(&self, token: &str) -> Result<JwtClaims, String> {
        let calims = decode::<JwtClaims>(
            &token,
            &DecodingKey::from_secret(self.secret.as_ref()),
            &Validation::default(),
        );
        match calims {
            Ok(c) => Ok(c.claims),
            Err(e) => Err(e.to_string()),
        }
    }
}
