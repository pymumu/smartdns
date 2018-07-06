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
