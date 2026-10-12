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

BIN=smartdns
SMARTDNS_LIB=libsmartdns.a
SMARTDNS_TEST_LIB=libsmartdns-test.a
# libs without main.o
OBJS=$(filter-out main.o, $(patsubst %.c,%.o,$(wildcard *.c)) $(patsubst %.c,%.o,$(wildcard */*.c)))
# libs without lib/%.o
LINT_OBJS=$(filter-out lib/%.o, $(OBJS))
TEST_OBJS=$(patsubst %.o,%_test.o,$(OBJS))
MAIN_OBJ = main.o

ifeq ($(filter -j,$(MAKEFLAGS)),)
MAKEFLAGS += -j$(shell nproc)
endif

# cflags
ifndef CFLAGS
 ifdef DEBUG
  CFLAGS = -g -DDEBUG
 else
  CFLAGS = -O2
 endif
 CFLAGS +=-Wall -Wstrict-prototypes -fno-omit-frame-pointer -Wstrict-aliasing -funwind-tables -Wmissing-prototypes -Wshadow -Wextra -Wno-unused-parameter
endif

# Pin the language standard. GCC defaults moved from gnu11 (6.x) to gnu17 (11.x)
# and then to gnu23 (15.x); C23 turns typeof/bool/true/false into keywords and
# drops old style parameter lists, so leaving it implicit makes the build
# compiler dependent.
override CFLAGS += -std=gnu11

HASH := \#
# -Wimplicit-fallthrough only exists from GCC 7 onwards. Probe with the
# enabling (-Wxxx) form, not the -Wno-xxx form: GCC accepts an unknown -Wno-xxx
# silently and returns 0, whereas an unknown -Wxxx makes the compile fail, so
# only the enabling form actually detects an old compiler.
HAS_FALLTHROUGH_WARN := $(shell printf 'int main(void) { return 0; }' | $(CC) -Wimplicit-fallthrough -x c - -o /dev/null >/dev/null 2>&1 && echo -n 1 || echo -n 0)
ifeq ($(HAS_FALLTHROUGH_WARN), 1)
override CFLAGS += -Wno-implicit-fallthrough
endif

# Feature probes must use a conforming main(): `void main()` is undefined and
# a stricter/newer compiler can reject it, silently turning the feature off.
HAS_UNWIND := $(shell printf '$(HASH)include <unwind.h>\nint main(void) { _Unwind_Backtrace(0, 0); return 0; }' | $(CC) -x c - -o /dev/null >/dev/null 2>&1 && echo -n 1 || echo -n 0)
ifeq ($(HAS_UNWIND), 1)
override CFLAGS += -DHAVE_UNWIND_BACKTRACE
endif

WITH_ZLIB ?= auto
HAS_ZLIB := $(shell printf '$(HASH)include <zlib.h>\nint main(void) { return zlibVersion()[0] == 0; }' | $(CC) -x c - -lz -o /dev/null >/dev/null 2>&1 && echo -n 1 || echo -n 0)
ifeq ($(WITH_ZLIB), yes)
override WITH_ZLIB := 1
endif
ifeq ($(WITH_ZLIB), auto)
 ifeq ($(HAS_ZLIB), 1)
  override CFLAGS += -DWITH_ZLIB
  override LDFLAGS += -lz
 endif
else ifeq ($(WITH_ZLIB), 1)
override CFLAGS += -DWITH_ZLIB
override LDFLAGS += -lz
endif

override CFLAGS +=-Iinclude
override CFLAGS += -DBASE_FILE_NAME='"$(notdir $<)"'
override CFLAGS += $(EXTRA_CFLAGS)

ifdef VER
 override CFLAGS += -DSMARTDNS_VERION='"$(VER)"'
endif

HAS_GIT := $(shell command -v git 2> /dev/null)
ifndef NO_GIT_VER
 ifdef HAS_GIT
  IS_GIT_REPO := $(shell git rev-parse --is-inside-work-tree 2>/dev/null)
  ifdef IS_GIT_REPO
   override COMMIT_VERION = $(shell git describe --tags --always --dirty)
  endif
 endif
endif

ifdef COMMIT_VERION
 override CFLAGS += -DCOMMIT_VERION='"$(shell git describe --tags --always --dirty)"'
endif

CXXFLAGS=-O2 -g -Wall -std=c++11 
override CXXFLAGS +=-Iinclude

ifeq ($(STATIC), yes)
STATIC = 1
endif

ifdef STATIC
 override CFLAGS += -DBUILD_STATIC
 override LDFLAGS += -lssl -lcrypto -Wl,--whole-archive -lpthread -Wl,--no-whole-archive -ldl -lm -static -rdynamic
else
 override LDFLAGS += -lssl -lcrypto -lpthread -ldl -lm -rdynamic
endif

USE_ATOMIC := $(shell printf '$(HASH)include <stdint.h>\nint main(void) { uint64_t value=0;__atomic_add_fetch(&value, 1, __ATOMIC_SEQ_CST);__atomic_load_n(&value,__ATOMIC_SEQ_CST); return 0; }' | $(CC) -x c - -o /dev/null >/dev/null 2>&1 && echo -n 1 || echo -n 0)
ifeq ($(USE_ATOMIC), 0)
 override CFLAGS += -DUSE_ATOMIC
 override LDFLAGS += -latomic 
endif

override LDFLAGS += $(EXTRA_LDFLAGS)

.PHONY: all clean

all: $(BIN)

%_test.o: %.c
	$(CC) -DTEST $(CFLAGS) -c $< -o $@

$(BIN) : $(MAIN_OBJ) $(SMARTDNS_LIB)
	$(CC) $^ -o $@ $(LDFLAGS)

$(SMARTDNS_TEST_LIB): $(TEST_OBJS)
	$(AR) rcs $@ $^

$(SMARTDNS_LIB): $(OBJS)
	$(AR) rcs $@ $^

clang-tidy-parallel:
	@echo "Running clang-tidy with $(shell nproc) parallel jobs..."
	@printf '%s\n' $(LINT_OBJS:.o=.c) | xargs -P $(shell nproc) -I {} clang-tidy {} -- $(CFLAGS)

clang-tidy:
	clang-tidy -p=. $(LINT_OBJS:.o=.c) -- $(CFLAGS)

clean:
	$(RM) $(OBJS) $(BIN) $(SMARTDNS_LIB) $(MAIN_OBJ) $(SMARTDNS_TEST_LIB) $(TEST_OBJS)

# lint specific files
# make lint-files FILES="dns.c proxy.c"
lint-files:
	@echo "Specify FILES variable to lint specific files, e.g., make lint-files FILES='src/dns.c src/proxy.c'"
	clang-tidy -p=. $(FILES) -- $(CFLAGS)
