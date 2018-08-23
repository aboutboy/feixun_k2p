#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <curl/curl.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>


#include "list.h"
#include "cJSON.h"
#include "log_tools.h"
#include "file_ops.h"
#include "pub_head.h"

#define MAX_URL_VAL	(50)
#define UDP_PORT	(6789)
#define SERV_IP		"127.0.0.1"
#define POST_ADDR	"http://ssp.fytpay.cn/delsey/data?slot=1001"
#define POST_IOS_ADDR	"http://ssp.fytpay.cn/delsey/api?slot=1001"
#define POST_DAYLIVE_ADDR	"http://c.so9.cc/dayliveupload/"
#define GET_IOS_ADDR		"http://ssp.fytpay.cn/delsey/getkey?slot=1001"

#ifdef FXK2P
#define GET_FILTER_HOST_ADDR_FMT	"http://c.so9.cc/router/c/?t=fxk2p&f=F&g=%s&v=2&dv=1.1&rv=1.0"
#define GET_DAYLIVE_HTTP_NR_ADDR_FC_FMT	"http://c.so9.cc/router/c/?t=fxk2p&g=%s&v=3&h=%d"
#else
#define GET_FILTER_HOST_ADDR_FMT	"http://c.so9.cc/router/c/?t=fxk2&f=F&g=%s&v=2&dv=1.1&rv=1.0"
#define GET_DAYLIVE_HTTP_NR_ADDR_FC_FMT	"http://c.so9.cc/router/c/?t=fxk2&g=%s&v=3&h=%d"
#endif

#define POST_DAYLIVE_HTTP_NR_ADDR_FX_FMT	"http://soho.cloud.phicomm.com/router/report/active?mac=%s"
#define POST_FIELDS	"slot=8000"
#define MONITOR_NETIF	"br-lan"
#define IOS_REALTIME_HOST	"iosapps.itunes.apple.com"
#define IOS_TIMEOUT	(60*60)
#define CMD_GET_WANIFNAME	"uci get network.wan.ifname"
#define MAC_FMT  "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_FMT_NO_COLON "%02x%02x%02x%02x%02x%02x"
typedef unsigned char u8;
#define MAC_ARG(x) ((u8*)(x))[0],((u8*)(x))[1],((u8*)(x))[2],((u8*)(x))[3],((u8*)(x))[4],((u8*)(x))[5]
#define ONE_DAY_SECONDS (24*60*60)
typedef struct {
	struct list_head list;
	int sendflag; // 1:idmapping 2:realtime ios 0:statistic everyday
	uint32_t  binip;
	char dotip[16];
	char url[512];
	char ua[256];
	char mac[32];
}ua_url_t;

typedef struct {
	int type; 	// 1:GET, 2:POST
        int sendflag; 	// 1:idmapping 2:realtime ios 0: statistic everyday
	char *uri;
	char *host;
	char *user_agent;
	uint32_t binip;
	char mac[32];
} uri_host_ua_t;

typedef struct {
	struct list_head head;
	int curr;
	int max;
	// mutex
}list_ctl_head_t;

typedef struct {
	struct list_head list;
	time_t time;
	char dat[32];
}ios_uri_data_t;

typedef struct {
	struct list_head list;
	time_t time;
	char hostname[64];
}filter_hostname_t;

enum sendflag {
	DAY_STATIS,
	IDMAPPING,
};

