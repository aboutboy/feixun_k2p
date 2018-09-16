#include "surffer_net.h"

#define INET_SWITCH	"ubus call rth.inet get_inet_link"
/*0 : no inet, 1: inet suffer*/
int check_inet_switch(void)
{
	int ret = 1;
	char res[128] = {0};
	char *p;
	running_cmd(INET_SWITCH, res, sizeof(res));	

	p = strstr(res, "up");
	if (p) {
		ret = 1;
	} else {
		ret = 0;
	}

	return ret;
}

