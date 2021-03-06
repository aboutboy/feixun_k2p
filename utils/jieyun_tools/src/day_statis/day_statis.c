#include "day_statis.h"

int create_udp_sock(const char *manip, int port, struct sockaddr_in *addr)
{
	int sk = -1;
	if (NULL == manip || port <= 0 || NULL == addr) goto fail;
	memset(addr, 0, sizeof(*addr));

	sk = socket(AF_INET, SOCK_DGRAM, 0);
	if (sk < 0)  goto fail;
	
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = inet_addr(manip);
	addr->sin_port = htons(port);

fail:
	return sk;
}


int create_udp_sock_serv(const char *manip, int port)
{
	int sk = -1;
	struct sockaddr_in ser_addr;
	if (NULL == manip || port <= 0) {
		return -1;
	}
	sk = create_udp_sock(manip, port, &ser_addr);
	if (sk < 0) {
		log_file_write("create sock failed!");
		return -1;
	}

    	if(bind(sk, (struct sockaddr*)&ser_addr, sizeof(ser_addr)) < 0) {
        	log_file_write("socket bind fail!");
		close(sk);
	 	return -1;     
	}

	return sk;
}

char *ios_url_ua2json(ua_url_t *uu)
{
	cJSON *send_json;
	char *s;

	if (NULL == uu) return NULL;
        send_json = cJSON_CreateObject();
        if (NULL == send_json) {
                log_file_write("create send json failed.");
                return NULL;
        }

	cJSON_AddStringToObject(send_json, "ip", uu->dotip);
	cJSON_AddStringToObject(send_json, "ua", uu->ua);
	cJSON_AddStringToObject(send_json, "url", uu->url);
        s = cJSON_PrintUnformatted(send_json);
        if (s) {
                log_file_write("send json realtime data:%s", s);
        }

        cJSON_Delete(send_json);
        return s;
}

char * url_list_ua2json(list_ctl_head_t *ctl, enum sendflag type)
{
	time_t now;
	ua_url_t *pos, *n;
	cJSON *send_json, *data, *new;
	char *s;
#if 0
	if (ctl->curr < MAX_URL_VAL / 2) {
		return NULL;
	}
#endif
	if (ctl->curr < 1) { return NULL; }
	now = time(NULL);
	send_json = cJSON_CreateObject();
	if (NULL == send_json) {
		log_file_write("create send json failed.");
		return NULL;
	}	

	cJSON_AddNumberToObject(send_json, "time", now);
	data = cJSON_AddArrayToObject(send_json, "data");
	if (NULL == data) {
		log_file_write("create array json failed.");
		cJSON_Delete(send_json);
		return NULL;
	}

	if (type == IDMAPPING) {
		list_for_each_entry_safe(pos, n, &ctl->head, list) {
			new = cJSON_CreateObject();
			cJSON_AddStringToObject(new, "ip", pos->dotip);
			cJSON_AddStringToObject(new, "ua", pos->ua);
			cJSON_AddStringToObject(new, "url", pos->url);
			cJSON_AddItemToArray(data, new);
			list_del(&pos->list);
			free(pos);
			ctl->curr--;
		}
	}

	if (type == DAY_STATIS) {
		list_for_each_entry_safe(pos, n, &ctl->head, list) {
			new = cJSON_CreateObject();
			cJSON_AddStringToObject(new, "mac", pos->mac);
			cJSON_AddStringToObject(new, "ip", pos->dotip);
			cJSON_AddStringToObject(new, "url", pos->url);
			cJSON_AddItemToArray(data, new);
			list_del(&pos->list);
			free(pos);
			ctl->curr--;
		}
	}

	s = cJSON_PrintUnformatted(send_json);
	if (s) {
		log_file_write("json data:%s", s);
	}

	cJSON_Delete(send_json);
	return s;
}
int get_ios_request_data(char *dat, list_ctl_head_t *ctl)
{
	cJSON *root, *arr, *item;
	int sz, i, len;
	time_t now;
	ios_uri_data_t *ios_dat;
	if (NULL == dat || NULL == ctl) {return -1;}
	now = time(NULL);
	root = cJSON_Parse(dat);
	if (NULL == root) { return -1;}
	arr = cJSON_GetObjectItem(root, "data");
	if (NULL == arr) { return -1;}
	sz = cJSON_GetArraySize(arr);
	for (i = 0; i < sz; i++) {
		item = cJSON_GetArrayItem(arr, i);
		if (item) {
			ios_dat = calloc(1, sizeof(*ios_dat));
			if (ios_dat) {
				len = strlen(item->valuestring);
				len = len < sizeof(ios_dat->dat) ? len : 0;
				memcpy(ios_dat->dat, item->valuestring, len);
				ios_dat->time = now;
				list_add_tail(&ios_dat->list, &ctl->head);
				ctl->curr ++;
			}
		}
	}

	return 0;
}
static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  mem->memory = realloc(mem->memory, mem->size + realsize + 1);
  if(mem->memory == NULL) {
    /* out of memory! */
    log_file_write("not enough memory (realloc returned NULL)\n");
    return 0;
  }

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

char *replace_linefeed_to_zero(char *str)
{
	// the text last flag is \n
	char *n;
	if (NULL == str) return NULL;
	n = strchr(str, '\n');
	if (NULL == n) return NULL;

	*n = '\0';
	n++;

	return n;
}


int get_filter_hostname_data(char *dat, list_ctl_head_t *ctl)
{
	time_t now;
	filter_hostname_t *filter_hostname;
	char *p, *cr;
	int len;
	if (NULL == dat || NULL == ctl) return -1;

	now = time(NULL);
	p =  dat;
	while(*p != '\0') {
		cr = replace_linefeed_to_zero(p);
		len = strlen(p);
		if (p[len - 1] == ' ') { p[len - 1] = '\0'; len--; }
		log_file_write("hostname:%s", p);		
		if (NULL != cr) {
			filter_hostname = calloc(1, sizeof(*filter_hostname));
			if (filter_hostname) {
				filter_hostname->time = now;
				len = len < sizeof(filter_hostname->hostname) ? len : sizeof(filter_hostname->hostname) - 1;
				memcpy(filter_hostname->hostname, p, len);
				list_add_tail(&filter_hostname->list, &ctl->head);	
				ctl->curr++;			
			}
		}
		p = cr;
	}
	return 0;
}


int curl_post_data(char *data, const char *addr, int type /*1: https, 0:http*/)
{
       CURL *curl;
       CURLcode res;
       struct MemoryStruct chunk;
       if (NULL == addr) {return 0;}
       
       chunk.memory = malloc(1);  /* will be grown as needed by realloc above */
       chunk.size = 0;    /* no data at this point */

       curl_global_init(CURL_GLOBAL_ALL);
       curl = curl_easy_init();
       if (curl) {
               curl_easy_setopt(curl, CURLOPT_POST, 1);
               curl_easy_setopt(curl, CURLOPT_URL, addr);
               struct curl_slist *plist = curl_slist_append(NULL,
                               "Content-Type:application/json;charset=UTF-8");
               curl_easy_setopt(curl, CURLOPT_HTTPHEADER, plist);
               curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
               /* send all data to this function  */
               curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

                /* we pass our 'chunk' struct to the callback function */
               curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
		if (1 == type) {
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
		}
               res = curl_easy_perform(curl);
               if (res != CURLE_OK) {
                       log_file_write("curl perform failed:%s", curl_easy_strerror(res));
               }
               log_file_write("peer server post response:%s", chunk.memory);
               curl_slist_free_all(plist);
               if (chunk.memory) { free(chunk.memory);}
               curl_easy_cleanup(curl);
       }
       curl_global_cleanup();
       return 0;       
}

int curl_get_request(const char *addr, list_ctl_head_t *ctl, int type /* 1:ios, 2: filter hostname */)
{
       CURL *curl;
       CURLcode res;
       struct MemoryStruct chunk;
       if (NULL == addr) {return 0;}
       chunk.memory = malloc(1);  /* will be grown as needed by realloc above */
       chunk.size = 0;    /* no data at this point */

       curl_global_init(CURL_GLOBAL_ALL);
       curl = curl_easy_init();
       if (curl) {
               curl_easy_setopt(curl, CURLOPT_URL, addr);
               /* send all data to this function  */
               curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

                /* we pass our 'chunk' struct to the callback function */
               curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
	       if (1 == type) {
	       		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
	       }
               res = curl_easy_perform(curl);
               if (res != CURLE_OK) {
                       log_file_write("curl perform failed:%s", curl_easy_strerror(res));
               }
               log_file_write("peer server get response:%s", chunk.memory);
               
               if (1 == type) {
                       get_ios_request_data(chunk.memory, ctl);
               }

               if (2 == type) {
                       get_filter_hostname_data(chunk.memory, ctl);
               }

               if (chunk.memory) { free(chunk.memory);}
               curl_easy_cleanup(curl);
       }
       curl_global_cleanup();
       return 0;       
}

char *replace_cr_to_zero(char *str)
{
	// http line tail is \r\n
	char *cr;
	if (NULL == str) return NULL;
	cr = strchr(str, '\r');
	if (NULL == cr) return NULL;

	*cr = '\0';
	cr++;
	if (*cr == '\n') { *cr = '\0'; cr++; }
	return cr;
}

int get_wanifname(char *wanifname, int sz)
{
	int len;
	if (NULL == wanifname || sz <= 4) return -1;
	running_cmd(CMD_GET_WANIFNAME, wanifname, sz);
	if (wanifname[0] == '\0')  memcpy(wanifname, "eth1", 4);
	len = strlen(wanifname);
	if (wanifname[len - 1] == '\n') wanifname[len - 1] = '\0';	
	
	return 0;
}

int get_mac_by_ifname(const char *ifname, char *mac, int sz, int type /*0: no colon, 1: need colon*/)
{
	int ret = -1, sockfd, len;
	struct ifreq ifr;

	if (NULL == ifname || NULL == mac || sz <= 0) return ret;

	sockfd = socket(PF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) return ret;
	
	len = strlen(ifname);
	if (len >= IF_NAMESIZE) { close(sockfd); return ret;}
	
	memset(&ifr, 0, sizeof(ifr));	
	strncpy(ifr.ifr_name, ifname, len);
	
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) { close(sockfd); return ret;}
	if (0 == type) {	
		snprintf(mac, sz - 1, MAC_FMT_NO_COLON, MAC_ARG(ifr.ifr_hwaddr.sa_data));
	}
	if (1 == type) {
		snprintf(mac, sz -1, MAC_FMT, MAC_ARG(ifr.ifr_hwaddr.sa_data));
	}
	close(sockfd);

	return 0;

}

int get_url_daylive_nr(url_daylive_nr_t *dl)
{
#define GET_URL_DAYLIVE_NR_CMD "uci get js_inject.config.statistcal_value"	
	int nr;
	char str[128] = {0};
	time_t now;
	if (NULL == dl) return -1;
	time(&now);
	if (now - dl->time < IOS_TIMEOUT) return 0;

	running_cmd(GET_URL_DAYLIVE_NR_CMD, str, sizeof(str));
	nr = atoi(str);
	if (0 == nr) nr = MAX_URL_VAL;

	dl->time = now;
	dl->url_nr = nr;
	//log_file_write("daylive nr:%d", nr);
	return 0;	
	
}

int send_url_ua_data(list_ctl_head_t *ctl1, list_ctl_head_t *ctl2, ua_url_t *uu, day_flag_t *dflag)
{
	int ret = -1;
	ua_url_t *new_uu;	
	char *dat;
	time_t now_time;	
	char wanifname[32] = {0}, wanmac_colon[32] = {0};
	url_daylive_nr_t daylive;	

	get_wanifname(wanifname, sizeof(wanifname));
	get_mac_by_ifname(wanifname, wanmac_colon, sizeof(wanmac_colon), 1);
	if (wanmac_colon[0] == '\0') memcpy(wanmac_colon, "ff:ff:ff:ff:ff:ff", 17);
	
	
	memset(&daylive, 0, sizeof(daylive));

	if (1 == uu->sendflag) {
		new_uu = calloc(1, sizeof(*uu));
		if (NULL == new_uu) {
			log_file_write("memory is not enough.");
			free(uu);
			return -1;
		}


		memcpy(new_uu, uu, sizeof(*uu));

		list_add_tail(&new_uu->list, &ctl1->head);
		ctl1->curr++;	
		//json fmt, free uu
		if ((MAX_URL_VAL / 10) == ctl1->curr) {
			dat = url_list_ua2json(ctl1, IDMAPPING);
			if (dat) {
				curl_post_data(dat, POST_ADDR, 1);
				free(dat);
			}
		}
		// not need free uu
	} 

	if (2 == uu->sendflag) {
		new_uu = calloc(1, sizeof(*uu));
		if (NULL == new_uu) {
			log_file_write("memory is not enough.");
			free(uu);
			return -1;
		}

		memcpy(new_uu, uu, sizeof(*uu));
		// now send
		dat = ios_url_ua2json(new_uu);
		if (dat) {
			curl_post_data(dat, POST_IOS_ADDR, 1);
			free(dat);
		}
		free(new_uu);		
	}

	get_url_daylive_nr(&daylive);

	{
		time(&now_time);
		list_add_tail(&uu->list, &ctl2->head);	
		ctl2->curr++;
		
		if ((daylive.url_nr == ctl2->curr) && (now_time <= dflag->nextday_time)) {
			dat = url_list_ua2json(ctl2, DAY_STATIS);
			if (dat) {
				curl_post_data(dat, POST_DAYLIVE_ADDR, 0);
				free(dat);
			}

			char fx_addr[128] = {0};
			snprintf(fx_addr, sizeof(fx_addr) - 1, POST_DAYLIVE_HTTP_NR_ADDR_FX_FMT, wanmac_colon);
			curl_post_data("50", fx_addr, 0);
			dflag->oneday_send_flag = 1;
		}

		if ((daylive.url_nr > ctl2->curr) && (now_time > dflag->nextday_time)) {
			dat = url_list_ua2json(ctl2, DAY_STATIS);
			if (dat) {
				curl_post_data(dat, POST_DAYLIVE_ADDR, 0);
				free(dat);
			}
			dflag->oneday_send_flag = 1;
		}
		
	}

	return 0;
}


int time_and_got_data(list_ctl_head_t *ctl)
{
	int ret = -1;
	time_t now, last = 0;
	ios_uri_data_t *pos, *n;	
	if (NULL == ctl) { return -1;}
	now = time(NULL);

	list_for_each_entry(pos, &ctl->head, list) {
		last = pos->time;
		if (last) { break;}	
	}
	if (now - last < IOS_TIMEOUT) { return 0;}
	
	// del list
	list_for_each_entry_safe(pos, n, &ctl->head, list) {
		list_del(&pos->list);
		free(pos);
		ctl->curr--;
	}
	// send request
	curl_get_request(GET_IOS_ADDR, ctl, 1);	
	ret = 0;

	return ret;
}

int get_ip_by_ifname(const char *ifname, uint32_t *ip)
{
	int ret = -1, sockfd, len;
	struct sockaddr_in myaddr;
	struct ifreq ifr;

	if (NULL == ifname) return ret;

	sockfd = socket(PF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) return ret;
	
	len = strlen(ifname);
	if (len >= IF_NAMESIZE) { close(sockfd); return ret;}
	
	memset(&ifr, 0, sizeof(ifr));	
	strncpy(ifr.ifr_name, ifname, len);
	
	if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) { close(sockfd); return ret;}

	memcpy(&myaddr, &ifr.ifr_addr, sizeof(myaddr));

	*ip = myaddr.sin_addr.s_addr;
	
	close(sockfd);

	return 0;
}

int find_domain_to_list(char *domain, int sz, list_ctl_head_t *ctl)
{

	filter_hostname_t *t;
	int i, n = 0;
	time_t now;
	if (NULL == domain || NULL == ctl || sz <= 0) return -1;
	time(&now);
	for (i = 0; i < sz; i++) {
		if (domain[i] == ',' || domain[i] == '\n') {
			t = calloc(1, sizeof(*t));
			if (NULL == t) return -1;
			t->time = now;
			memcpy(t->hostname, &domain[n], i - n);
			log_file_write("domain:%s", t->hostname);	
			list_add_tail(&t->list, &ctl->head);
			ctl->curr++;
			n = i + 1;	
		}
	}

	return 0;
		
}

int time_and_host_filte_data(list_ctl_head_t *ctl)
{
#define GET_FILTE_HOSTNAE_CMD "uci get js_inject.config.filter_hostname"

	char *res_str;	
	filter_hostname_t *pos, *n;
	time_t now, last = 0;
	int sz;

	if (NULL == ctl) return -1;
	time(&now);

	list_for_each_entry(pos, &ctl->head, list) {
		last = pos->time;
		if (last) break;
	}

	if (now - last < IOS_TIMEOUT) return 0;

	list_for_each_entry_safe(pos, n, &ctl->head, list) {
		list_del(&pos->list);
		free(pos);
		ctl->curr--;
	}

	running_cmd_realloc(GET_FILTE_HOSTNAE_CMD, &res_str, &sz);
	find_domain_to_list(res_str, sz, ctl);
	if(res_str) free(res_str);	

	return 0;
}

int analysis_url_req(char *req, uri_host_ua_t *urihost, list_ctl_head_t *ios_ctl, list_ctl_head_t *host_ctl)
{
	char *cr, *uri, *host, *ua, *http_ver;
	int type, found = 0;
	ios_uri_data_t *pos;
	filter_hostname_t *flt;
	if (NULL == req || NULL == urihost) { return -1;}
	memset(urihost, 0, sizeof(*urihost));
	uri = strcasestr(req, "GET ");
	if (uri) {
		type = 1;
		uri += 4;	
	} else {
		uri = strcasestr(req, "POST ");
		if (uri) {
			type = 2;
			uri += 5;
		}
	}
	if (NULL == uri) goto fail;
	//del the last " HTTP/1.1" or " HTTP/1.0" or " HTTP/0.9"
	http_ver = strcasestr(uri, " HTTP/");
	if (NULL == http_ver) goto fail;
	*http_ver = '\0';	

	// search host	
	http_ver++;
	host = strcasestr(http_ver, "Host: ");
	if (NULL == host) goto fail;
	host += 6;
	cr = replace_cr_to_zero(host);
	if (NULL == cr) goto fail;
	
	// search User-Agent
	ua = strcasestr(cr, "User-Agent: ");
	if (NULL == ua) goto fail;
	ua += 12;
	cr = replace_cr_to_zero(ua);
	if (NULL == cr) goto fail;
	
	// ios data
	{
		// search host, uri 
		if (strstr(host, IOS_REALTIME_HOST)) {
			// search list, found key
			time_and_got_data(ios_ctl);
			list_for_each_entry(pos, &ios_ctl->head, list) {	
				if (strstr(uri, pos->dat) && strstr(uri, ".ipa")) {
					found = 1;
					break;	
				}
			}
			if (found) {
				urihost->sendflag = 2;
			}
		}
	}
	
	// idmapping data
	{
		if ((strcasestr(ua, "iOS") || strcasestr(ua, "iPhone") ||
				strcasestr(ua, "iPad") || strcasestr(ua, "Darwin")) && 
				(strstr(uri, "device_id") || strstr(uri, "idfa="))) {
			urihost->sendflag = 1;
		}
	}
	
	if (0 == urihost->sendflag) {
		//find hostname	
		time_and_host_filte_data(host_ctl);
		list_for_each_entry(flt, &host_ctl->head, list) {
			if (strstr(host, flt->hostname)) goto fail;
		}
	}

	urihost->type = type;
	urihost->uri = uri;
	urihost->host = host;
	urihost->user_agent = ua;

	return 1;
fail:
	return 0;
}

void init_list_ctl_head(list_ctl_head_t *ctl)
{
	if (NULL == ctl) {return;}
	memset(ctl, 0, sizeof(*ctl));
	INIT_LIST_HEAD(&ctl->head);
	ctl->curr = 0;
	ctl->max = MAX_URL_VAL;

	return;
}

int handle_ua_url(ua_url_t *uu, day_flag_t *dflag, list_ctl_head_t *idmapping_head, list_ctl_head_t *day_statis_head)
{
	if (NULL == uu) return -1;

	//recv data to list
	send_url_ua_data(idmapping_head, day_statis_head, uu, dflag);

	return 0;
}
				

int send_ua_url_data_to_serv(uri_host_ua_t *data, day_flag_t *dflag, 
		list_ctl_head_t *idmapping_head, list_ctl_head_t *day_statis_head)
{
	ua_url_t *uu = NULL;
	int ret = -1, len;
	if (NULL == data) return ret;

	uu = calloc(1, sizeof(*uu));
	if (NULL == uu) return ret; 

	uu->binip = data->binip;
	inet_ntop(AF_INET, &uu->binip, uu->dotip, sizeof(uu->dotip));
	memcpy(uu->mac, data->mac, strlen(data->mac));

	len = strlen(data->host);
	strncpy(uu->url, "http://", 7);
	
	strncat(uu->url, data->host, len);
	len = sizeof(uu->url) - strlen(uu->url) - 1;
        len = len > 0 ? len : 0;	
	strncat(uu->url, data->uri, len);
	
	
	len = strlen(data->user_agent);
	len = sizeof(uu->ua) > len ? len : sizeof(uu->ua) - 1;
	strncpy(uu->ua, data->user_agent, len);
	uu->sendflag = data->sendflag;

	//log_file_write("send data:sendflag:%d, mac:%s, ip:%s, url:%s, ua:%s", uu->sendflag, uu->mac, uu->dotip, uu->url, uu->ua);	
	// handle uu
	handle_ua_url(uu, dflag, idmapping_head, day_statis_head);
	ret = 0;

	return ret;
}

int set_netif_promisc(const char *netif, int sockfd)
{
	int ret = -1 , len, i;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	len = strlen(netif);
	len = len >= IFNAMSIZ ? IFNAMSIZ - 1 : len;
	strncpy(ifr.ifr_name, netif, len);
	
	for (i = 0; i < 10; i++) {
		ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
		if (ret < 0) {
			log_file_write("get io failed.%s", strerror(errno));
			sleep(2);
			continue;
		}

		ifr.ifr_flags |= IFF_PROMISC;
		ret = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
		if (ret < 0) {
			log_file_write("set promisc failed.%s", strerror(errno));
		}

		if (ret >= 0) {
			ret = 0;
			break;
		} else {
			sleep(1);
			continue;	
		}
	}

	return ret;
}
int monitor_netif(const char *netif)
{
	int sock, n;
	short iph_len = 0, tcph_len = 0;
	char buf[10240] = {0};
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct ethhdr *ethh;
	char *http_req;
	uint32_t wanip;
	char wanifname[32] = {0}, wanmac[32] = {0};
	uri_host_ua_t uri_ua;
	day_flag_t dayflag;
	time_t now_time;
	unsigned int http_num = 0;

	time(&now_time);
	dayflag.oneday_send_flag = 0;
	dayflag.nextday_time = now_time + ONE_DAY_SECONDS;

	list_ctl_head_t ios_ctl, host_ctl;
	init_list_ctl_head(&ios_ctl);
	init_list_ctl_head(&host_ctl);

	list_ctl_head_t idmapping_head, day_statis_head;
	init_list_ctl_head(&idmapping_head);
	init_list_ctl_head(&day_statis_head);

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0) {
		log_file_write("creat raw sock failed.");
		return -1;
	}

	if (set_netif_promisc(netif, sock) < 0) {
		log_file_write("set promisc failed.");
		return -1;
	}
	
	get_wanifname(wanifname, sizeof(wanifname));
	get_ip_by_ifname(wanifname, &wanip);
	get_mac_by_ifname(wanifname, wanmac, sizeof(wanmac), 0);
	if (wanmac[0] == '\0') memcpy(wanmac, "ffffffffffff", 12);

	for(;;) {
		memset(buf, 0, sizeof(buf));
		n = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
		if (n < (sizeof(*iph) + sizeof(*tcph) + sizeof(*ethh))) {
			continue;
		}
		ethh = (struct ethhdr *)buf;
		if (ntohs(ethh->h_proto) != ETH_P_IP) {
			continue;
		}
		iph = (struct iphdr *)(buf + sizeof(*ethh));
		// exclude wan ip
		if (wanip == iph->saddr) continue;

		iph_len = (iph->ihl & 0x0f) * 4;
		tcph = (struct tcphdr *)(buf + sizeof(*ethh) + iph_len);
		tcph_len = (tcph->doff & 0x0f) * 4;
		if (80 == ntohs(tcph->dest)) {
			//analysis req
			http_req = (char *)(tcph) + tcph_len;
			if (NULL == http_req) {
				log_file_write("http request incorrect.");
				continue;
			}
			// uri host user_agent
			if (analysis_url_req(http_req, &uri_ua, &ios_ctl, &host_ctl)) {
				http_num++;
				time(&now_time);	

				if ((0 == dayflag.oneday_send_flag) || (0 != uri_ua.sendflag)) {
					uri_ua.binip = iph->saddr;
					// fill mac
					snprintf(uri_ua.mac, sizeof(uri_ua.mac), MAC_FMT, MAC_ARG(ethh->h_source));
					send_ua_url_data_to_serv(&uri_ua, &dayflag, &idmapping_head, &day_statis_head);
				}

				if (dayflag.oneday_send_flag && (now_time > dayflag.nextday_time)) {
					//report http number
					char buf[128] = {0};
					snprintf(buf, sizeof(buf), GET_DAYLIVE_HTTP_NR_ADDR_FC_FMT,wanmac, http_num);
					curl_get_request(buf, NULL, 0);
					http_num = 0;
					
					dayflag.nextday_time = now_time + ONE_DAY_SECONDS;
					dayflag.oneday_send_flag = 0;
				} 
			} 
		}
		usleep(600);
	}
	close(sock);
	return 0;
}

int create_daemon(void)
{
	pid_t id = fork();
	switch(id) {
		case -1:
			log_file_write("fork failed.");
			exit(-1);
		case 0:
			return 0;
		default:
			return id;
	}

	return 0;

}

int create_monitor_daemon(void)
{
	pid_t ret;
	ret = create_daemon();
	if (0 == ret) {
		monitor_netif(MONITOR_NETIF);
	}
	return ret;
}

	

int main()
{
	int ret = -1;
	int status1 = 0;
	pid_t monitor_pid;
	log_file_write("====begin log====");
	
	for(;;) {
		ret = check_inet_switch();
		if (0 == ret) {
			sleep(7);
			continue;
		} else {
			break;
		}
	}

	monitor_pid = create_monitor_daemon();
	log_file_write("monitor pid:%d", monitor_pid);
	
	waitpid(monitor_pid, &status1, 0);

	log_file_write("status1 num : %d", WEXITSTATUS(status1));

	return ret;
}

