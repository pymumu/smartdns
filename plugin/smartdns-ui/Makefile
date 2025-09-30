
# Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
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
CARGO_BUILD_ENV :=
SMARTDNS_SRC_DIR=../../src
 
ifeq ($(origin CC), environment)
  ifeq ($(CARGO_BUILD_TARGET),)
    ifeq ($(CARGO_BUILD_ARGS),)
      # find default target by compiler
      ARCH_TARGET:=$(shell $(CC) -dumpmachine)
      override CARGO_BUILD_TARGET:=$(shell rustc --print target-list | grep $(ARCH_TARGET) | head -n 1)

      ifeq ($(CARGO_BUILD_TARGET),)
        # not found, try to find target by compiler
        ARCH_TARGET:=$(shell $(CC) -dumpmachine | sed 's/-[^-]*-linux-/-linux-/')
        ARCH=$(shell echo $(ARCH_TARGET) | cut -d - -f 1)
        ABI=$(shell echo $(ARCH_TARGET) | cut -d - -f 3)
        ifneq ($(ABI),)
          # force set target to $(ARCH)-unknown-linux-$(ABI)
          override CARGO_BUILD_TARGET:=$(shell rustc --print target-list | grep $(ARCH) | grep linux | grep $(ABI) | grep unknown | head -n 1)
        endif
      endif

      ifneq ($(CARGO_BUILD_TARGET),)
        ARCH_TARGET_PATH=$(CARGO_BUILD_TARGET)/
        override CARGO_RUSTFLAGS=-C linker=$(CC)
         CARGO_BUILD_ARGS +=--target=$(CARGO_BUILD_TARGET)
      endif
    endif
  endif

  IS_NATIVE_BUILD=$(shell [ "$(CC)" = "cc" ] || [ "$(CC)" = "gcc" ] && echo 1 || echo 0)
  ifeq ($(IS_NATIVE_BUILD), 0)
    # find sysroot
    SYSROOT:=$(shell $(CC) -print-sysroot)
    ifeq ($(SYSROOT),)
      # if sysroot is not set, try find sysroot from compiler default include path
      SYSROOT:=$(shell $(CC) -xc /dev/null -E -Wp,-v 2>&1 | sed -n 's,^ ,,p' | head -n 1)
      ifneq ($(SYSROOT),)
        # find sysroot, add sysroot to BINDGEN_EXTRA_CLANG_ARGS
        SYSROOT:=$(SYSROOT)/..
        override CARGO_BUILD_ENV += BINDGEN_EXTRA_CLANG_ARGS="--sysroot=$(SYSROOT)"
        CARGO_BUILD_ARGS +=--target=$(CARGO_BUILD_TARGET)
      endif
    endif
  endif
endif

ifneq ($(CARGO_BUILD_TARGET),)
  ARCH_TARGET_PATH=$(CARGO_BUILD_TARGET)/
endif

# check and install bindgen
IS_BINDGEN_INSTALL=$(shell which bindgen 2>/dev/null)
ifeq ($(IS_BINDGEN_INSTALL),)
  $(shell cargo install --force --locked bindgen-cli)
endif

ifneq ($(CARGO_BUILD_TARGET),)
  CARGO_BUILD_TARGET_INSTALL=$(shell rustup target list | grep $(CARGO_BUILD_TARGET) | grep installed)
  ifeq ($(CARGO_BUILD_TARGET_INSTALL),)
    # install target
    $(shell rustup target add $(CARGO_BUILD_TARGET))
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
	CXXFLAGS= CFLAGS= MAKEFLAGS= RUSTFLAGS="$(CARGO_RUSTFLAGS) $(RUSTFLAGS)" $(CARGO_BUILD_ENV) cargo build $(CARGO_BUILD_ARGS) --features "build-release"
	cp $(CARGO_BUILD_PATH)/libsmartdns_ui.so target/smartdns_ui.so

install: $(BIN)
	install -v -m 0644 -D -t $(DESTDIR)$(SLIBDIR)/smartdns target/smartdns_ui.so

test: test-prepare
	MAKEFLAGS= cargo test

clean:
	cargo clean
	$(MAKE) -C $(SMARTDNS_SRC_DIR) clean
	rm -rf target/smartdns_ui.so
