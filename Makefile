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

DESTDIR :=
SMARTDNS_SITE = site
SMARTDNS_SITE_EN = en/site

.PHONY: all clean
all: $(SMARTDNS_SITE)

$(SMARTDNS_SITE): $(SMARTDNS_SITE_EN)
	mkdocs build
	mv $(SMARTDNS_SITE_EN) site/en

$(SMARTDNS_SITE_EN):
	cd en && mkdocs build

clean:
	$(RM) -fr $(SMARTDNS_SITE)
	$(RM) -fr $(SMARTDNS_SITE_EN)

serve:
	mkdocs serve

serve-en:
	cd en && mkdocs serve

install-deps:
	pip3 install -r requirements.txt
