
# Copyright (C) 2018-2024 Ruilin Peng (Nick) <pymumu@gmail.com>.
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
OBJS_LIB=$(patsubst %.c,%.o,$(wildcard lib/*.c))
OBJS_MAIN=$(patsubst %.c,%.o,$(wildcard *.c))
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

HASH := \#
HAS_UNWIND := $(shell echo '$(HASH)include <unwind.h>\nvoid main() { _Unwind_Backtrace(0, 0);}' | $(CC) -x c - -o /dev/null >/dev/null 2>&1 && echo 1 || echo 0)
ifeq ($(HAS_UNWIND), 1)
override CFLAGS += -DHAVE_UNWIND_BACKTRACE
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
 override CFLAGS += -DBUILD_STATIC
 override LDFLAGS += -lssl -lcrypto -Wl,--whole-archive -lpthread -Wl,--no-whole-archive -ldl -lm -static -rdynamic
else
 override LDFLAGS += -lssl -lcrypto -lpthread -ldl -lm -rdynamic
endif

.PHONY: all clean

all: $(BIN)

$(BIN) : $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

clang-tidy:
	clang-tidy -p=. $(OBJS_MAIN:.o=.c) -- $(CFLAGS)

clean:
	$(RM) $(OBJS) $(BIN)
