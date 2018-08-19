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

struct MemoryStruct {
  char *memory;
  size_t size;
};

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

int post_send_jsondata(char *data, const char *addr)
{
	CURL *curl;
	CURLcode res;
  	struct MemoryStruct chunk;
	if (NULL == data || NULL == addr) {return 0;}
      	
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

		res = curl_easy_perform(curl);
		if (res != CURLE_OK) {
			log_file_write("curl perform failed:%s", curl_easy_strerror(res));
		}
		log_file_write("peer server response:%s", chunk.memory);
		curl_slist_free_all(plist);
		if (chunk.memory) { free(chunk.memory);}
		curl_easy_cleanup(curl);
	}
	curl_global_cleanup();
	return 0;	
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

int curl_get_request(const char *addr, list_ctl_head_t *ctl)
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

		res = curl_easy_perform(curl);
		if (res != CURLE_OK) {
			log_file_write("curl perform failed:%s", curl_easy_strerror(res));
		}
		log_file_write("peer server response:%s", chunk.memory);
		get_ios_request_data(chunk.memory, ctl);
		if (chunk.memory) { free(chunk.memory);}
		curl_easy_cleanup(curl);
	}
	curl_global_cleanup();
	return 0;	
}


int recv_url_ua_data(list_ctl_head_t *ctl1, list_ctl_head_t *ctl2)
{
	int sock, ret = -1, i;
	ua_url_t *uu;	
	char *dat;
	time_t next_time, now_time;	
	int oneday_send_flag = 0;
	for (i = 0; i < 10; i++) {
		sock = create_udp_sock_serv(SERV_IP, UDP_PORT);
		if (sock < 0) { 
			sleep(1);
			continue;
		}
		if (sock > 0) break;
	}
	if (sock < 0) return -1;
	time(&now_time);	
	next_time = now_time + ONE_DAY_SECONDS;
	for(;;) {
		uu = calloc(1, sizeof(*uu));
		if (NULL == uu) {
			log_file_write("memory is not enough.");
			break;
		}
		ret = recvfrom(sock, uu, sizeof(*uu), 0, NULL, NULL);
		if (0 == ret) {
			log_file_write("recv 0 bytes");
			free(uu);
			continue;
		}
		if (ret < 0) {
			log_file_write("recvfrom failed.");
			free(uu);
			continue;
		}

		if (1 == uu->sendflag) {
			list_add_tail(&uu->list, &ctl1->head);
			ctl1->curr++;	
			//json fmt, free uu
			dat = url_list_ua2json(ctl1, IDMAPPING);
			//send json
			if (dat) {
				post_send_jsondata(dat, POST_ADDR);
				free(dat);
			}
			// not need free uu
		} 
		if (2 == uu->sendflag) {
			// now send
			dat = ios_url_ua2json(uu);
			if (dat) {
				post_send_jsondata(dat, POST_IOS_ADDR);
				free(dat);
			}
			free(uu);		
		}
		if (0 == uu->sendflag) {
			time(&now_time);
			if (oneday_send_flag && (now_time <= next_time)) {
				free(uu);
				continue;
			}

			list_add_tail(&uu->list, &ctl2->head);	
			ctl2->curr++;
			
			//if ((MAX_URL_VAL == ctl2->curr) && (now_time <= next_time)) {
				dat = url_list_ua2json(ctl2, DAY_STATIS);
				if (dat) {
					//send data
					free(dat);
				}
			//	oneday_send_flag = 1;
			//}
			
			if (oneday_send_flag && (now_time > next_time)) {
				next_time = now_time + ONE_DAY_SECONDS;
				oneday_send_flag = 0;
			} 
		}
	}
	close(sock);
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
	curl_get_request(GET_IOS_ADDR, ctl);	
	ret = 0;

	return ret;
}

int analysis_url_req(char *req, uri_host_ua_t *urihost, list_ctl_head_t *ios_ctl)
{
	char *cr, *uri, *host, *ua, *http_ver;
	int type, found = 0;
	ios_uri_data_t *pos;
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
	}

	urihost->type = type;
	urihost->uri = uri;
	urihost->host = host;
	urihost->user_agent = ua;

	return 1;
fail:
	return 0;
}

int send_ua_url_data_to_serv(uri_host_ua_t *data)
{
	ua_url_t *uu = NULL;
	int ret = -1, len, sockfd;
	struct sockaddr_in addr;
	if (NULL == data) goto fail;

	uu = calloc(1, sizeof(*uu));
	if (NULL == uu) goto fail;

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

	log_file_write("send data:sendflag:%d, mac:%s, ip:%s, url:%s, ua:%s", uu->sendflag, uu->mac, uu->dotip, uu->url, uu->ua);	
	// send to serv
	sockfd = create_udp_sock(SERV_IP, UDP_PORT, &addr);
	if (sockfd < 0) goto fail;
	sendto(sockfd, uu, sizeof(*uu), 0, (struct sockaddr *)&addr, sizeof(addr));
	close(sockfd);
	ret = 0;
fail:
	if (uu) free(uu);
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
	uri_host_ua_t uri_ua;
	list_ctl_head_t ios_ctl, host_ctl;
	init_list_ctl_head(&ios_ctl);
	init_list_ctl_head(&host_ctl);
	
	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0) {
		log_file_write("creat raw sock failed.");
		return -1;
	}

	if (set_netif_promisc(netif, sock) < 0) {
		log_file_write("set promisc failed.");
		return -1;
	}

	get_ip_by_ifname("eth1", &wanip);

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
			if (analysis_url_req(http_req, &uri_ua, &ios_ctl)) {
				uri_ua.binip = iph->saddr;
				// fill mac
				snprintf(uri_ua.mac, sizeof(uri_ua.mac), MAC_FMT, MAC_ARG(ethh->h_source));
				send_ua_url_data_to_serv(&uri_ua);			
			} 
		}
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

void init_list_ctl_head(list_ctl_head_t *ctl)
{
	if (NULL == ctl) {return;}
	memset(ctl, 0, sizeof(*ctl));
	INIT_LIST_HEAD(&ctl->head);
	ctl->curr = 0;
	ctl->max = MAX_URL_VAL;

	return;
}

int create_recv_send_daemon(void)
{
	pid_t ret;
	ret = create_daemon();
	if (0 == ret) {

		list_ctl_head_t idmapping_head, day_statis_head;
		init_list_ctl_head(&idmapping_head);
		init_list_ctl_head(&day_statis_head);
		//recv data to list
		recv_url_ua_data(&idmapping_head, &day_statis_head);
	}

	return ret;
}

int main()
{
	int ret = -1;
	int status1 = 0, status2 = 0;
	pid_t monitor_pid, recv_send_pid;
	log_file_write("====begin log====");
	monitor_pid = create_monitor_daemon();
	log_file_write("monitor pid:%d", monitor_pid);
	recv_send_pid = create_recv_send_daemon();
	log_file_write("recv send pid:%d", recv_send_pid);
	
	waitpid(monitor_pid, &status1, 0);
	waitpid(recv_send_pid, &status2, 0);

	log_file_write("status1 num : %d", WEXITSTATUS(status1));
	log_file_write("status2 num : %d", WEXITSTATUS(status2));

	return ret;
}

