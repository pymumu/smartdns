
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

TEST_SOURCES := $(wildcard *.cc) $(wildcard */*.cc) $(wildcard */*/*.cc)
TEST_OBJECTS := $(patsubst %.cc, %.o, $(TEST_SOURCES))
OBJS += $(TEST_OBJECTS)

SMARTDNS_SRC_FILES := $(wildcard $(SMARTDNS_SRC_DIR)/*.c) $(wildcard $(SMARTDNS_SRC_DIR)/*.h) $(wildcard $(SMARTDNS_SRC_DIR)/lib/*.c)


LDFLAGS += -lssl -lcrypto -lpthread -ldl -lgtest -lstdc++ -lm
LDFLAGS += $(EXTRA_LDFLAGS)

.PHONY: all clean test $(SMARTDNS_TEST_LIB)

all: $(BIN)

$(BIN) : $(OBJS) $(SMARTDNS_TEST_LIB)
	$(CC) $^  -o $@ $(LDFLAGS)

test: $(BIN)
	./$(BIN)

$(SMARTDNS_TEST_LIB): 
	$(MAKE) -C $(SMARTDNS_SRC_DIR) libsmartdns-test.a

clean:
	$(RM) $(OBJS) $(BIN)
	$(MAKE) -C $(SMARTDNS_SRC_DIR) clean
