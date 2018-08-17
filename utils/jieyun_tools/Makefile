#
# Copyright (C) 2014 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=jieyun_tools
PKG_VERSION:=0.0.1
PKG_RELEASE=$(PKG_SOURCE_VERSION)


PKG_MAINTAINER:=zhanyige <zhanyige@veryci.com>

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk

define Package/jieyun_tools
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=jieyun router dev tools
  DEPENDS:=+libc +libpthread +libcurl
endef

TARGET_CFLAGS += -I. -I$(STAGING_DIR)/usr/include
TARGET_CFLAGS_NEW := $(TARGET_CFLAGS) -I$(PKG_BUILD_DIR)/public_fun
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -Wall \
		-o $(PKG_BUILD_DIR)/jy_black_list/jy_black_list $(PKG_BUILD_DIR)/jy_black_list/jy_black_list.c
	$(TARGET_CC) $(TARGET_CFLAGS) -Wall \
		-o $(PKG_BUILD_DIR)/ngx_update/ngx_update $(PKG_BUILD_DIR)/ngx_update/*.c
	$(TARGET_CC) $(TARGET_CFLAGS) -Wall \
		 -o $(PKG_BUILD_DIR)/get_js/get_js $(PKG_BUILD_DIR)/get_js/*.c -lcurl
	$(TARGET_CC) $(TARGET_CFLAGS_NEW) -Wall \
		 -o $(PKG_BUILD_DIR)/idmapping/idmapping $(PKG_BUILD_DIR)/idmapping/*.c $(PKG_BUILD_DIR)/public_fun/*.c -lcurl -lpthread
endef

define Package/jieyun_tools/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d $(1)/etc/config $(1)/sbin $(1)/etc/nginx
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/jy_black_list/jy_black_list $(1)/usr/bin/
	$(INSTALL_BIN) ./files/jy_black_list.cfg $(1)/etc/config/jy_black_list.cfg
	$(INSTALL_BIN) ./files/sync_sysver.init $(1)/etc/init.d/sync_sysver
	$(INSTALL_BIN) ./files/ngx_conf_ver $(1)/etc/nginx
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ngx_update/ngx_update $(1)/usr/bin/
	$(INSTALL_BIN) ./files/ngx_update.init  $(1)/etc/init.d/ngx_update
	$(INSTALL_BIN) ./files/report_conf_file  $(1)/etc/config/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/get_js/get_js $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/idmapping/idmapping $(1)/usr/bin/

endef

$(eval $(call BuildPackage,jieyun_tools))
