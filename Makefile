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

PKG_CONFIG := pkg-config
DESTDIR :=
PREFIX := /usr
SBINDIR := $(PREFIX)/sbin
SLIBDIR := $(PREFIX)/lib
SYSCONFDIR := /etc
RUNSTATEDIR := /run
SYSTEMDSYSTEMUNITDIR := $(shell ${PKG_CONFIG} --variable=systemdsystemunitdir systemd)
SMARTDNS_SYSTEMD = systemd/smartdns.service

ifneq ($(strip $(DESTDIR)),)
$(shell mkdir -p $(DESTDIR) -m 0755)
override DESTDIR := $(realpath $(DESTDIR))
endif

PLUGINS := 
WITH_UI ?= 0

ifeq ($(WITH_UI), 1)
PLUGINS += plugin/smartdns-ui
endif

define PLUGINS_TARGETS
    $(foreach plugin,$(PLUGINS),$(MAKE) $(MFLAGS) DESTDIR=$(DESTDIR) -C $(plugin) $(1);)
endef

.PHONY: all clean install help SMARTDNS_BIN 
all: SMARTDNS_BIN 

SMARTDNS_BIN: $(SMARTDNS_SYSTEMD)
	$(MAKE) $(MFLAGS) -C src all
	$(call PLUGINS_TARGETS, all)

$(SMARTDNS_SYSTEMD): systemd/smartdns.service.in
	cp $< $@
	sed -i 's|@SBINDIR@|$(SBINDIR)|' $@
	sed -i 's|@SYSCONFDIR@|$(SYSCONFDIR)|' $@
	sed -i 's|@RUNSTATEDIR@|$(RUNSTATEDIR)|' $@

help:
	@echo "Options:"
	@echo "  WITH_UI=1: Build with smartdns-ui plugin"

clean:
	$(MAKE) $(MFLAGS) -C src clean  
	$(RM) $(SMARTDNS_SYSTEMD)
	$(call PLUGINS_TARGETS, clean)

install: SMARTDNS_BIN 
	install -v -m 0640 -D -t $(DESTDIR)$(SYSCONFDIR)/default etc/default/smartdns
	install -v -m 0755 -D -t $(DESTDIR)$(SYSCONFDIR)/init.d etc/init.d/smartdns
	install -v -m 0640 -D -t $(DESTDIR)$(SYSCONFDIR)/smartdns etc/smartdns/smartdns.conf
	install -v -m 0755 -D -t $(DESTDIR)$(SBINDIR) src/smartdns
	install -v -m 0644 -D -t $(DESTDIR)$(SYSTEMDSYSTEMUNITDIR) systemd/smartdns.service
	$(call PLUGINS_TARGETS, install)

