#
# Copyright (C) 2018-2020 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

include $(TOPDIR)/rules.mk

PKG_NAME:=smarttdns
PKG_VERSION:=2018.7.1.1607
PKG_RELEASE:=$(PKG_SOURCE_VERSION)

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/smartdns
	SECTION:=net
	CATEGORY:=Network
	TITLE:=smartdns
	URL:=https://github.com/pymumu/smartdns
	MAINTAINER:=Nick Peng <pymumu@gmail.com>
	DEPENDS:=
endef

define Package/smartdns/description
	smartdns server, find fastest ip.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp -r ../* $(PKG_BUILD_DIR)
endef

define Package/smartdns/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/smartdns $(1)/usr/sbin
endef

$(eval $(call BuildPackage, smartdns))
