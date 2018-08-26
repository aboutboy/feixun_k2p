#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>

#define JY_BLACK_LIST_CFG_FILE	"/etc/config/jy_black_list.cfg"
#define JY_LINE_MAX_LEN			(128)
#define JY_IPT_BLACK_LIST_CMD_FMT	"/usr/sbin/iptables -t nat -I PREROUTING -i %s -p tcp -d %s -j ACCEPT"
#define JY_GW_INTERFACE			"br-lan"
#define JY_DEBUG
#ifdef JY_DEBUG
#define	jy_debug(fmt,...) printf("%s:%d: "fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define jy_debug(fmt,...)
#endif

struct ip_str_s {
	char ip[16];
};

int jy_run_cmd(const char *cmd)
{
	FILE *fp;
	char buf[128] = {0};
	if (NULL == cmd) {
		return -1;
	}
		
	fp = popen(cmd, "r");
	if (NULL == fp) {
		perror("popen failed");
		return -1;
	}
	while(!feof(fp)) {
		fread(buf, sizeof(char), sizeof(buf), fp);
	}
	if (buf[0] != '\0') {
		printf("cmd:%s failed. %s\n",cmd, buf);
	}
	pclose(fp);

	return 0;
}

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

int main()
{
	FILE *fp = NULL;
	char line[JY_LINE_MAX_LEN] = {0}, cmd[JY_LINE_MAX_LEN * 2] = {0}; 
	int sz, i, len;
	int netconnect_flag;
	struct ip_str_s *ip_arr = NULL;
	for(;;) {

		netconnect_flag = 0;

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
				netconnect_flag = -1;
				break;
			}
			jy_debug("get ip num:%d\n", sz);
			struct ip_str_s *p;
			for (i = 0; i < sz; i++) {
				memset(cmd, 0, sizeof cmd );
				p = ip_arr + i;
				snprintf(cmd, sizeof cmd, JY_IPT_BLACK_LIST_CMD_FMT, 
					JY_GW_INTERFACE, p->ip);
				jy_run_cmd(cmd);	
			}
			memset(cmd, 0, sizeof cmd);
		}

		fclose(fp);
		if (netconnect_flag == 0) {
			break;
		} else {
			sleep(10);
		}
	}
	return 0;
}
