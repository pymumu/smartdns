#
# Copyright (c) 2018-2024 Nick Peng (pymumu@gmail.com)
# This is free software, licensed under the GNU General Public License v3.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=smartdns
PKG_VERSION:=1.2025.46.2
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://www.github.com/pymumu/smartdns.git
PKG_MIRROR_HASH:=skip
PKG_SOURCE_VERSION:=2303cffe0e5c2c42e9e9eb4c9a527099f3b16960

PKG_MAINTAINER:=Nick Peng <pymumu@gmail.com>
PKG_LICENSE:=GPL-3.0-or-later
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_PARALLEL:=1
PKG_BUILD_DEPENDS:=rust/host node/host

include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk
include $(INCLUDE_DIR)/package.mk

MAKE_VARS += VER=$(PKG_VERSION) 
MAKE_PATH:=src

define Package/smartdns
  SECTION:=net
  CATEGORY:=Network
  TITLE:=smartdns server
  DEPENDS:=+libpthread +libopenssl
  URL:=https://www.github.com/pymumu/smartdns/
endef

define Package/smartdns/description
SmartDNS is a local DNS server which accepts DNS query requests from local network clients,
gets DNS query results from multiple upstream DNS servers concurrently, and returns the fastest IP to clients.
Unlike dnsmasq's all-servers, smartdns returns the fastest IP, and encrypt DNS queries with DoT or DoH. 
endef

define Package/smartdns/conffiles
/etc/config/smartdns
/etc/smartdns/address.conf
/etc/smartdns/blacklist-ip.conf
/etc/smartdns/custom.conf
/etc/smartdns/domain-block.list
/etc/smartdns/domain-forwarding.list
endef

define Package/smartdns-ui
  SECTION:=net
  CATEGORY:=Network
  TITLE:=smartdns server webui
  DEPENDS:=+smartdns
  URL:=https://www.github.com/pymumu/smartdns/
endef

define Build/Compile/smartdns-ui
	CARGO_BUILD_ARGS="$(if $(strip $(RUST_PKG_FEATURES)),--features "$(strip $(RUST_PKG_FEATURES))") --profile $(CARGO_PKG_PROFILE)"
	+$(CARGO_PKG_VARS) CARGO_BUILD_ARGS="$(CARGO_BUILD_ARGS)" CC=$(TARGET_CC)\
	make -C $(PKG_BUILD_DIR)/plugin/smartdns-ui
	git clone https://github.com/pymumu/smartdns-webui.git --dept=1 $(PKG_BUILD_DIR)/webui
	(cd $(PKG_BUILD_DIR)/webui && npm install && npm run build)
endef

define Package/smartdns-ui/install
	$(INSTALL_DIR) $(1)/usr/lib $(1)/usr/share/smartdns/wwwroot $(1)/etc/smartdns/data
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/plugin/smartdns-ui/target/$(ARCH)-unknown-linux-musl/release/libsmartdns_ui.so $(1)/usr/lib/libsmartdns_ui.so
	cp -ra $(PKG_BUILD_DIR)/webui/out/* $(1)/usr/share/smartdns/wwwroot
endef

define Build/Compile
	$(call Build/Compile/Default,smartdns)
ifneq ($(CONFIG_PACKAGE_smartdns-ui),)
	$(call Build/Compile/smartdns-ui)
endif
endef

define Package/smartdns/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/config $(1)/etc/init.d 
	$(INSTALL_DIR) $(1)/etc/smartdns $(1)/etc/smartdns/domain-set $(1)/etc/smartdns/conf.d/
	$(INSTALL_DIR) $(1)/etc/smartdns/ip-set $(1)/etc/smartdns/download
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/smartdns $(1)/usr/sbin/smartdns
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/package/openwrt/files/etc/init.d/smartdns $(1)/etc/init.d/smartdns
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/package/openwrt/address.conf $(1)/etc/smartdns/address.conf
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/package/openwrt/blacklist-ip.conf $(1)/etc/smartdns/blacklist-ip.conf
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/package/openwrt/custom.conf $(1)/etc/smartdns/custom.conf
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/package/openwrt/domain-block.list $(1)/etc/smartdns/domain-block.list
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/package/openwrt/domain-forwarding.list $(1)/etc/smartdns/domain-forwarding.list
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/package/openwrt/files/etc/config/smartdns $(1)/etc/config/smartdns
endef

$(eval $(call BuildPackage,smartdns))
$(eval $(call BuildPackage,smartdns-ui))