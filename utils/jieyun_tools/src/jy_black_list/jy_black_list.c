#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "pub_head.h"

#define JY_BLACK_LIST_CFG_FILE	"/etc/config/jy_black_list.cfg"
#define JY_LINE_MAX_LEN			(128)
#define JY_GET_LAN_IP		"uci get network.lan.ipaddr"
#define JY_IPSET_CREAT_CMD	"ipset create blacklist hash:net maxelem 1000000"
#define JY_IPSET_ADD_IP_FMT	"ipset add blacklist %s"
#define JY_IPSET_DEL_IP_FMT	"ipset del blacklist %s"
#define JY_IPT_ADD_BLACK_LIST_CMD	"/usr/sbin/iptables -t nat -I PREROUTING -m set --match-set blacklist dst -p tcp -j ACCEPT"
#define JY_IPT_DEL_BLACK_LIST_CMD	"/usr/sbin/iptables -t nat -D PREROUTING -m set --match-set blacklist dst -p tcp -j ACCEPT"
#define JY_GW_INTERFACE			"br-lan"
#define JY_DEBUG
#ifdef JY_DEBUG
#define	jy_debug(fmt,...) printf("%s:%d: "fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define jy_debug(fmt,...)
#endif
#define JY_BLACK_LIST_ADDR	"http://c.so9.cc/router/c/?t=fxk2&f=B&g=001122334455&v=2&dv=1.1&rv=1.0"
#define JY_BLACK_LIST_TMP_FILE	"/tmp/jy_black_list.cfg"
#define JY_BLACK_LIST_MV_CMD	"mv %s %s"

struct ip_str_s {
	char ip[16];
};

int jy_get_ip_by_name(const char *name, struct ip_str_s **ip)
{
	struct hostent *hptr;
	char **p;
	char str[16];
	int i = 0;
	if (NULL == name) {
		return -1;
	}
	hptr = gethostbyname(name);
	if (NULL == hptr) {
		perror("gethostbyname");
		return -1;
	}	
	
	p = hptr->h_addr_list;
	*ip = NULL;
	for(;*p != NULL; p++) {
		if (inet_ntop(hptr->h_addrtype, *p, str, sizeof(str))) {
			*ip = realloc(*ip, (i + 1) * sizeof(struct ip_str_s ));
			if (NULL == *ip) {
				i = 0;
				break;	
			}
			memcpy(*ip + i, str, sizeof(str));
			i++;
		}
	}

	return i;
}

int get_black_list_file(void)
{
	char buf[1024] = {0},res[256] = {0};
	unsigned int new_sz, sz;

	curl_request_write_file(JY_BLACK_LIST_ADDR, JY_BLACK_LIST_TMP_FILE, 0);
	sz = get_file_sz(JY_BLACK_LIST_CFG_FILE);
	new_sz = get_file_sz(JY_BLACK_LIST_TMP_FILE);
	if (0 == new_sz) return 0;

	if (new_sz > sz) {
		snprintf(buf, sizeof(buf), JY_BLACK_LIST_MV_CMD, JY_BLACK_LIST_TMP_FILE, JY_BLACK_LIST_CFG_FILE);
		running_cmd(buf, res, sizeof(res));
	}

	return 1;
}

int main()
{
	FILE *fp = NULL;
	char line[JY_LINE_MAX_LEN] = {0}, cmd[JY_LINE_MAX_LEN] = {0}, res[JY_LINE_MAX_LEN] = {0}; 
	int sz, i = 0, len, ret;
	struct ip_str_s *ip_arr = NULL;
	for(;;) {
		ret = check_inet_switch();
		if (0 == ret) {
			sleep(7);
			continue;
		} else {
			break;
		}
	}
	
	running_cmd(JY_IPSET_CREAT_CMD, res, sizeof(res));

	for (i = 0; i < 10; i++) {	
		if (0 == get_black_list_file()) sleep(10);
	}

	fp = fopen(JY_BLACK_LIST_CFG_FILE, "r");
	if (NULL == fp) {
		perror("fopen failed");
		return -1;
	}

	while(fgets(line, sizeof line, fp)) {
		if (line[0] == '\n') { // the last line
			break;
		}
		len = strlen(line);
		if (line[len - 1] == '\n') {
			line[len - 1] = '\0';
		}
		if (len < 3) { // .cn
			continue;
		}
		// run dig
		sz = jy_get_ip_by_name(line, &ip_arr);
		if (sz < 0) {
			printf("get ip by name failed, maybe internet not incorrect.\n");
			break;
		}
		jy_debug("get ip num:%d\n", sz);
		struct ip_str_s *p;
		for (i = 0; i < sz; i++) {
			memset(cmd, 0, sizeof(cmd) );
			p = ip_arr + i;
			snprintf(cmd, sizeof(cmd), JY_IPSET_ADD_IP_FMT, p->ip);
			running_cmd(cmd, res, sizeof(res));	
		}
		if (ip_arr)  { free(ip_arr); ip_arr = NULL; }
	}

	fclose(fp);
	// get lan ip
	running_cmd(JY_GET_LAN_IP, res, sizeof(res));
	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, sizeof(cmd), JY_IPSET_ADD_IP_FMT, res);
	running_cmd(cmd, res, sizeof(res));

	running_cmd(JY_IPT_ADD_BLACK_LIST_CMD, res, sizeof(res));
	
	return 0;
}
