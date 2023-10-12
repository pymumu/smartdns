
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

BIN=smartdns 
OBJS_LIB=lib/rbtree.o lib/art.o lib/bitops.o lib/radix.o lib/timer_wheel.o
OBJS_MAIN=smartdns.o fast_ping.o dns_client.o dns_server.o dns.o util.o tlog.o dns_conf.o dns_cache.o http_parse.o proxy.o timer.o lib/conf.o lib/nftset.o regexp.o
OBJS=$(OBJS_MAIN) $(OBJS_LIB)

# cflags
ifndef CFLAGS
 ifdef DEBUG
  CFLAGS = -g -DDEBUG
 else
  CFLAGS = -O2
 endif
CFLAGS +=-Wall -Wstrict-prototypes -fno-omit-frame-pointer -Wstrict-aliasing -funwind-tables -Wmissing-prototypes -Wshadow -Wextra -Wno-unused-parameter -Wno-implicit-fallthrough
endif
override CFLAGS +=-Iinclude
override CFLAGS += -DBASE_FILE_NAME='"$(notdir $<)"'
override CFLAGS += $(EXTRA_CFLAGS)
ifdef VER
override CFLAGS += -DSMARTDNS_VERION='"$(VER)"'
endif

CXXFLAGS=-O2 -g -Wall -std=c++11
override CXXFLAGS +=-Iinclude

# ldflags
ifeq ($(STATIC), yes)
 override LDFLAGS += -lssl -lcrypto -Wl,--whole-archive -lpthread -Wl,--no-whole-archive -ldl -static
else
 override LDFLAGS += -lssl -lcrypto -lpthread -ldl -lcre2
endif

.PHONY: all clean

all: $(BIN)

$(BIN) : $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

clang-tidy:
	clang-tidy -p=. $(OBJS_MAIN:.o=.c) -- $(CFLAGS)

clean:
	$(RM) $(OBJS) $(BIN)
