
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

BIN=smartdns_demo.so 
OBJS_MAIN=$(patsubst %.c,%.o,$(wildcard *.c))
OBJS=$(OBJS_MAIN)

# cflags
ifndef CFLAGS
 ifdef DEBUG
  CFLAGS = -g -DDEBUG
 else
  CFLAGS = -O2
 endif
 CFLAGS +=-fPIC -Wall -Wstrict-prototypes -fno-omit-frame-pointer -Wstrict-aliasing -funwind-tables -Wmissing-prototypes -Wshadow -Wextra -Wno-unused-parameter
endif

# Keep in sync with src/Makefile: pin the language standard and only pass
# -Wno-implicit-fallthrough when the compiler actually knows it (GCC 7+).
override CFLAGS += -std=gnu11
HASH := \#
HAS_FALLTHROUGH_WARN := $(shell printf 'int main(void) { return 0; }' | $(CC) -Wimplicit-fallthrough -x c - -o /dev/null >/dev/null 2>&1 && echo -n 1 || echo -n 0)
ifeq ($(HAS_FALLTHROUGH_WARN), 1)
override CFLAGS += -Wno-implicit-fallthrough
endif

override CFLAGS +=-Iinclude -I../../src/include -I../../src
override CFLAGS += -DBASE_FILE_NAME='"$(notdir $<)"'
override CFLAGS += $(EXTRA_CFLAGS)

override LDFLAGS += -lpthread -shared

.PHONY: all clean

all: $(BIN)

$(BIN) : $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

clean:
	$(RM) $(OBJS) $(BIN)
