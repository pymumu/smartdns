
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
PREFIX := /usr
SBINDIR := $(PREFIX)/sbin
SLIBDIR := $(PREFIX)/lib
DESTDIR :=
SMARTDNS_SRC_DIR=../../src

ifeq ($(origin CC), environment)
  ARCH_TARGET:=$(shell $(CC) -dumpmachine | sed 's/-[^-]*-linux-/-linux-/')
  ARCH=$(shell echo $(ARCH_TARGET) | cut -d - -f 1)
  ABI=$(shell echo $(ARCH_TARGET) | cut -d - -f 3)
  ifneq ($(ABI),)
    RUST_ARCH_TARGET:=$(shell rustc --print target-list | grep $(ARCH) | grep linux | grep $(ABI) | head -n 1)
  endif

  ifneq ($(RUST_ARCH_TARGET),)
    ARCH_TARGET_PATH=$(RUST_ARCH_TARGET)/
    override CARGO_RUSTFLAGS=-C linker=$(CC)
    CARGO_BUILD_ARGS +=--target=$(RUST_ARCH_TARGET)
  endif
endif

IS_MUSL=$(shell $(CC) -v 2>&1 | grep -i musl >/dev/null 2>&1 && echo 1 || echo 0)
ifeq ($(IS_MUSL), 1)
override CARGO_RUSTFLAGS +=-C target-feature=-crt-static
endif

ifdef DEBUG
  CARGO_BUILD_PATH=target/$(ARCH_TARGET_PATH)debug
  SMARTDNS_BUILD_TYPE=DEBUG=1
else
  ifdef OPTIMIZE_SIZE
    CARGO_BUILD_ARGS += --profile release-optmize-size
	CARGO_BUILD_PATH=target/$(ARCH_TARGET_PATH)release-optmize-size
  else
    CARGO_BUILD_ARGS +=--release
  	CARGO_BUILD_PATH=target/$(ARCH_TARGET_PATH)release
  endif

  SMARTDNS_BUILD_TYPE=
endif

.PHONY: all clean install $(BIN)

all: $(BIN)

test-prepare:
	$(MAKE) -C $(SMARTDNS_SRC_DIR) libsmartdns-test.a

$(BIN):
	MAKEFLAGS= RUSTFLAGS="$(CARGO_RUSTFLAGS) $(RUSTFLAGS)" cargo build $(CARGO_BUILD_ARGS) --features "build-release"
	cp $(CARGO_BUILD_PATH)/libsmartdns_ui.so target/ 

install: $(BIN)
	install -v -m 0644 -D -t $(DESTDIR)$(SLIBDIR)/smartdns target/libsmartdns_ui.so

test: test-prepare
	MAKEFLAGS= cargo test

clean:
	cargo clean
	$(MAKE) -C $(SMARTDNS_SRC_DIR) clean
	rm -rf target/libsmartdns_ui.so
