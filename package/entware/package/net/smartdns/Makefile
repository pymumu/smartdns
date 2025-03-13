#
# Copyright (c) 2018-2020 Nick Peng (pymumu@gmail.com)
# This is free software, licensed under the GNU General Public License v3.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=smartdns
PKG_VERSION:=3.2023.41.9
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/weiping/smartdns.git
PKG_SOURCE_VERSION:=73f8a643bab39c2d3f36fad83f90e7d37576010b
PKG_MIRROR_HASH:=73f8a643bab39c2d3f36fad83f90e7d37576010b

PKG_MAINTAINER:=Nick Peng <pymumu@gmail.com>
PKG_LICENSE:=GPL-3.0-or-later
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

MAKE_VARS += VER=$(PKG_VERSION) 
MAKE_PATH:=src

define Package/smartdns
  SECTION:=net
  CATEGORY:=Network
  TITLE:=smartdns server
  DEPENDS:=+libpthread +libopenssl +cre2
  URL:=https://www.github.com/pymumu/smartdns/
endef

define Package/smartdns/description
SmartDNS is a local DNS server which accepts DNS query requests from local network clients,
gets DNS query results from multiple upstream DNS servers concurrently, and returns the fastest IP to clients.
Unlike dnsmasq's all-servers, smartdns returns the fastest IP. 
endef

define Package/smartdns/conffiles
/opt/etc/smartdns/smartdns.conf
endef

define Package/smartdns/install
	$(INSTALL_DIR) $(1)/opt/sbin $(1)/opt/etc/init.d $(1)/opt/etc/smartdns
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/smartdns $(1)/opt/sbin/smartdns
	$(INSTALL_BIN) ./files/S38smartdns $(1)/opt/etc/init.d
#	$(INSTALL_BIN) $(PKG_BUILD_DIR)/package/openwrt/files/etc/init.d/smartdns $(1)/etc/init.d/smartdns
#	$(INSTALL_CONF) $(PKG_BUILD_DIR)/package/openwrt/address.conf $(1)/etc/smartdns/address.conf
#	$(INSTALL_CONF) $(PKG_BUILD_DIR)/package/openwrt/blacklist-ip.conf $(1)/etc/smartdns/blacklist-ip.conf
#	$(INSTALL_CONF) $(PKG_BUILD_DIR)/package/openwrt/custom.conf $(1)/etc/smartdns/custom.conf
#	$(INSTALL_CONF) $(PKG_BUILD_DIR)/package/openwrt/files/etc/config/smartdns $(1)/etc/config/smartdns
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/etc/smartdns/smartdns.conf $(1)/opt/etc/smartdns
endef

$(eval $(call BuildPackage,smartdns))
