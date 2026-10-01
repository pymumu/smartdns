
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

SMARTDNS_SRC_DIR=../src

BIN=test.bin
SMARTDNS_TEST_LIB=$(SMARTDNS_SRC_DIR)/libsmartdns-test.a

CXXFLAGS += -g
CXXFLAGS += -DTEST
CXXFLAGS += -I./ -I../src -I../src/include
CXXFLAGS += -fno-omit-frame-pointer -Wstrict-aliasing -funwind-tables

TEST_SOURCES := $(wildcard *.cc) $(wildcard */*.cc) $(wildcard */*/*.cc)
TEST_OBJECTS := $(patsubst %.cc, %.o, $(TEST_SOURCES))
OBJS += $(TEST_OBJECTS)

SMARTDNS_SRC_FILES := $(wildcard $(SMARTDNS_SRC_DIR)/*.c) $(wildcard $(SMARTDNS_SRC_DIR)/*.h) $(wildcard $(SMARTDNS_SRC_DIR)/lib/*.c)

ifeq ($(filter -j,$(MAKEFLAGS)),)
MAKEFLAGS += -j$(shell nproc)
endif

HASH := \#
WITH_ZLIB ?= auto
HAS_ZLIB := $(shell printf '$(HASH)include <zlib.h>\nint main(void) { return zlibVersion()[0] == 0; }' | $(CC) -x c - -lz -o /dev/null >/dev/null 2>&1 && echo -n 1 || echo -n 0)
ifeq ($(WITH_ZLIB), yes)
override WITH_ZLIB := 1
endif
ifeq ($(WITH_ZLIB), auto)
 ifeq ($(HAS_ZLIB), 1)
  ZLIB_CXXFLAGS += -DWITH_ZLIB
  ZLIB_LDFLAGS += -lz
 endif
else ifeq ($(WITH_ZLIB), 1)
ZLIB_CXXFLAGS += -DWITH_ZLIB
ZLIB_LDFLAGS += -lz
endif

CXXFLAGS += $(ZLIB_CXXFLAGS)
LDFLAGS += -lssl -lcrypto -lpthread -ldl -lgtest -lstdc++ -lm -rdynamic
LDFLAGS += $(ZLIB_LDFLAGS)
LDFLAGS += $(EXTRA_LDFLAGS)

.PHONY: all clean test $(SMARTDNS_TEST_LIB)

all: $(BIN)

$(BIN) : $(OBJS) $(SMARTDNS_TEST_LIB)
	$(CC) $^  -o $@ $(LDFLAGS)

test: $(BIN)
	./$(BIN)

$(SMARTDNS_TEST_LIB): 
	$(MAKE) DEBUG=1 WITH_ZLIB=$(WITH_ZLIB) -C $(SMARTDNS_SRC_DIR) libsmartdns-test.a

clean:
	$(RM) $(OBJS) $(BIN)
	$(MAKE) -C $(SMARTDNS_SRC_DIR) clean
