
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

BIN=test.bin
CFLAGS += -I../src -I../src/include
CFLAGS += -DTEST
CFLAGS += -g -Wall -Wstrict-prototypes -fno-omit-frame-pointer -Wstrict-aliasing -funwind-tables -Wmissing-prototypes -Wshadow -Wextra -Wno-unused-parameter -Wno-implicit-fallthrough

CXXFLAGS += -g
CXXFLAGS += -DTEST
CXXFLAGS += -I./ -I../src -I../src/include

SMARTDNS_OBJS = lib/rbtree.o lib/art.o lib/bitops.o lib/radix.o lib/conf.o lib/nftset.o lib/timer_wheel.o lib/idna.o
SMARTDNS_OBJS += smartdns.o fast_ping.o dns_client.o dns_server.o dns.o util.o tlog.o dns_conf.o dns_cache.o http_parse.o proxy.o timer.o
OBJS = $(addprefix ../src/, $(SMARTDNS_OBJS))

TEST_SOURCES := $(wildcard *.cc) $(wildcard */*.cc) $(wildcard */*/*.cc)
TEST_OBJECTS := $(patsubst %.cc, %.o, $(TEST_SOURCES))
OBJS += $(TEST_OBJECTS)

LDFLAGS += -lssl -lcrypto -lpthread -ldl -lgtest -lstdc++ -lm

.PHONY: all clean test

all: $(BIN)

$(BIN) : $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

test: $(BIN)
	./$(BIN)

clean:
	$(RM) $(OBJS) $(BIN)
