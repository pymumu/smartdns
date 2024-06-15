
# Copyright (C) 2018-2023 Ruilin Peng (Nick) <pymumu@gmail.com>.
#
# smartdns is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# smartdns is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

BIN=smartdns-ui
SMARTDNS_SRC_DIR=../../src

ifdef DEBUG
CARGO_BUILD_TYPE=
CARGO_BUILD_PATH=target/debug
SMARTDNS_BUILD_TYPE=DEBUG=1
else
CARGO_BUILD_TYPE=--release
CARGO_BUILD_PATH=target/release
SMARTDNS_BUILD_TYPE=
endif

.PHONY: all clean $(BIN)

all: $(BIN)

test-prepare:
	$(MAKE) -C $(SMARTDNS_SRC_DIR) libsmartdns-test.a

smartdns:
	$(MAKE) -C $(SMARTDNS_SRC_DIR) $(SMARTDNS_BUILD_TYPE)

$(BIN): smartdns
	MAKEFLAGS= cargo build $(CARGO_BUILD_TYPE) --features "build-release"
	cp $(CARGO_BUILD_PATH)/libsmartdns_ui.so target/ 

test: test-prepare
	MAKEFLAGS= cargo test

clean:
	cargo clean
	$(MAKE) -C $(SMARTDNS_SRC_DIR) clean
	rm -rf target/libsmartdns_ui.so
