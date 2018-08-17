
#include "wifi_update.h"

int conn_serv(char *domain, uint16_t port)
{
	int sock_cli;
	struct sockaddr_in servaddr;
	struct hostent *he = NULL;
	char *p = NULL;
	if (NULL == domain || *domain == 0 || port <= 0) {
		log_file_write("param is incorrect.\n");
		return -1;
	}
	he = gethostbyname(domain);
	if (NULL == he)	{
		log_file_write("gethostbyname failed.");
		return -1;
	}

	p = *he->h_addr_list; // only one ip

	sock_cli = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_cli < 0) {
		log_file_write("%s: socket failed!\n", strerror(errno));
		return -1;
	}

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	servaddr.sin_addr.s_addr = ((struct in_addr *)p)->s_addr;

	if (connect(sock_cli, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
		log_file_write("%s: connect failed!\n", strerror(errno));
		close(sock_cli);
		return -1;
	}

	return sock_cli;
}


int write_qm_dev_file(char *file, char *buf, int len)
{
	int write_len;
    int fd;

	if (NULL == file || NULL == buf || len <= 0) {
		return -1;
	}

	fd = open(file, O_WRONLY);
    if (fd < 0) {
        log_file_write("open %s failed.\n", file);
        return -1;
    }
	
    if (lseek(fd, 0, SEEK_SET) < 0) {
        close(fd);
        log_file_write("lseek %s failed.\n", file);
        return -1;
    }

    write_len = write(fd, buf, len);
    if (write_len < 0) {
        log_file_write("write %s filed.\n", file);
        close(fd);
        return -1;
    }

    close(fd);
    
	return write_len;
}

int run_shell_cmd(char *cmd)
{
	char buf[PROPERTY_VALUE_MAX] = {0};
	FILE *fp;

	if (NULL == cmd) {
		return -1;
	}

	fp = popen(cmd, "r");
	if (NULL == fp) {
		log_file_write("%s: popen failed.", strerror(errno));
		return -1;
	}
	
	while(read(fileno(fp), buf, PROPERTY_VALUE_MAX) > 0) {
		log_file_write("get cmd output:%s", buf);
	}

	pclose(fp);

	return 0;
}

int write_sys_update_file(const char *path, void *data, int len)
{
	int fd, w_len = 0;
	if (NULL == path || NULL == data || len <= 0) {
		return -1;
	}

	fd = open(path, O_WRONLY | O_CREAT |O_APPEND);
	if (fd < 0) {
		log_file_write("%s: open file %s failed!", strerror(errno), path);
		return -1;
	}

	w_len = write(fd, data, len);
	if (w_len < 0) {
		log_file_write("%s: write file %s failed!", strerror(errno), path);
		close(fd);
		return -1;
	}

	if (fsync(fd) < 0) {
		log_file_write("%s: syncfs failed.", strerror(errno));
		return -1;
	}

	close(fd);
	
	return w_len;
}

pro_head_t *padding_pro_req(unsigned int pro, void *data, int len)
{
	int total_len;

	if (pro < (unsigned int)0x20000000 || len < 0) { // maybe data is NULL or  len == 0
		return NULL;
	}	

	total_len = sizeof(pro_head_t) + len; // protocol head and content len
	pro_head_t *h = calloc(1, total_len);
	if (NULL == h) {
		log_file_write("%s: calloc %d failed!\n", strerror(errno), total_len);
		return h;
	}

	h->len = total_len;
	h->ver = PROTOL_VER;
	h->pro_num = pro;
	if (len > 0 && NULL != data) {
		h->data_len = len;
		memcpy(h->data, data, len); 	
	}

	return h;
}

int padding_usrname_passwd(usrname_passwd_t *u)
{
	int usrname_len, passwd_len;
	if (NULL == u) {
		return -1;
	}

	usrname_len = sizeof(USRNAME);
	passwd_len = sizeof(PASSWD);
	
	if (usrname_len > USR_PWD_MAX_LEN && passwd_len > USR_PWD_MAX_LEN) {
		log_file_write("QM_USR_PWD_MAX_LEN is short.\n");
		return -1;
	} 

	strncpy(u->usrname, USRNAME, sizeof(USRNAME));
	strncpy(u->passwd, PASSWD, sizeof(PASSWD));
	return 0;
}

int send_usr_passwd_request(int fd, unsigned int pro)
{
	int len = 0;
	usrname_passwd_t u;
	if (fd < 0 || pro < (unsigned int)0x20000000) {
		return -1;
	}

	len = sizeof(usrname_passwd_t);
	memset(&u, 0, len);
	if (padding_usrname_passwd(&u) < 0) {
		log_file_write("padding_usrname_passwd() failed.\n");
		return -1;
	}

	pro_head_t *h = padding_pro_req(pro, &u, len);
	if (NULL == h) {
		log_file_write("padding_pro_req() failed.\n");
		return -1;
	}

	if (send(fd, h, h->len, 0) < 0) {
		log_file_write("%s: send failed.\n", strerror(errno));
		free(h);
		return -1;
	}
	
	free(h);
	
	log_file_write("send usr passwd ok.");
	return 0;
}

int cat_file_path(char *buf, unsigned int len, char *path, char *filename)
{
	if (NULL == buf || len == 0 || NULL == path || NULL == filename) {
		return -1;
	}

	if (len <= strlen(path) + strlen(filename)) {
		log_file_write("buf len too short!\n");
		return -1;
	}

	memset(buf, 0, len);
	strncpy(buf, path, strlen(path));
	strncat(buf, "/", 1);
	strncat(buf, filename, strlen(filename));

	return 0;
}

int get_ker_shell_ipk_content(int fd, unsigned int ack_pro, ack_t *ack, char *filename) 
{
	trans_file_content_t *c = NULL;

	if (fd < 0 || NULL == ack || ack_pro < (unsigned int)0xf0000000 || NULL == filename) {
		return -1;
	}
	
	c = (trans_file_content_t *)ack->data;

	if (write_sys_update_file(filename, c->f_content, c->f_content_len) < 0) {
		log_file_write("write_sys_update_file() failed!");
		return -1;
	}

	return 0;
}


int get_ack_content(int fd, ack_t *ack, unsigned int pro, char *filename, char *ver)
{
	char *new_ver = NULL;
	
	if (fd < 0 || NULL == ack || pro < (unsigned int)0xf0000000) {
		return -1;
	}

	// get sys new ver
	if (pro == (unsigned int)VER_UPDATE_ACK && ack->result == 1 && NULL != ver) {
		new_ver = (char *)(ack->data);
		if (NULL != new_ver && ack->data_len <= VER_BUFFER_LEN) {
			strncpy(ver, new_ver, ack->data_len);
			// del '\n'
			if (ver[ack->data_len - 1] == '\n') {
				ver[ack->data_len - 1] = '\0';
			}
			log_file_write("get new sys ver:%s", new_ver);
		}
	}
	
	// get download file
	if (pro == (unsigned int)VER_DL_ACK && ack->result > 0 && NULL != filename) {
		if (get_ker_shell_ipk_content(fd, pro, ack, filename) < 0) {
			log_file_write("get_ker_shell_ipk_content() failed.");
			return -1;
		}
	}

	return 0;
}

int recv_ack_general(int fd, unsigned int pro, char *filename, char *ver) 
{
	char buf[MAX_TRANS_LEN] = {0};
	int len = 0, tmp = 0;
	if (fd < 0 || pro < (unsigned int)0xf0000000) {
		return -1;
	}
	
	
	len = recv(fd, buf, sizeof(buf), 0);
	if (len < 0) {
		log_file_write("%s: recv failed!\n", strerror(errno));
		return -1;
	}

	if (0 == len) {
		log_file_write("maybe peer socket close.");
		return -1;
	}
	
	ack_t *ack = (ack_t *)buf;
	if (ack->pro_num != pro) {
		log_file_write("pro:%x, ack pro:%x, protocal is mismatch!\n", pro, ack->pro_num);
		return -1;
	}

	if (ack->len > MAX_TRANS_LEN) {
		log_file_write("pro: %x, too long info!\n", ack->pro_num);
		return -1;
	}
	
	// maybe no need, because block
	while((unsigned int)len < ack->len) {
		tmp = recv(fd, &buf[len], sizeof(buf)-len, 0);
		if (tmp < 0) {
			log_file_write("%s: recv error!\n",strerror(errno));
			return -1;
		}
		len += tmp;
	}

	if (ack->result < 0) {
		log_file_write("server return err info: %s\n", ack->data);
		return -1;
	}
	
	if (0 == ack->result) {
		switch(pro) {
			case (unsigned int)LOGIN_ACK:
				log_file_write("login success.\n");
				break;
			case (unsigned int)VER_UPDATE_ACK:
				log_file_write("no new sys ver.\n");
				break;
			case (unsigned int)VER_DL_ACK:
				log_file_write("the new sys ver file download over.\n");
				break;
		}
		return ack->result;
	}

	if (ack->data_len > 0) {
		if (get_ack_content(fd, ack, pro, filename, ver) < 0) {
			log_file_write("get_ack_content() failed.\n");
			return -1;
		}
	}

	return ack->result;
}

int send_login_request_and_rcv_ack(int fd, unsigned int send_pro, unsigned int rcv_pro)
{
	if (fd < 0 || send_pro < (unsigned int)0x20000000 || rcv_pro < (unsigned int)0xf0000000) {
		return -1;
	}

	if (send_usr_passwd_request(fd, send_pro) < 0) {
		log_file_write("send usrname passwd failed!\n");
		return -1;
	}

	if (recv_ack_general(fd, rcv_pro, NULL, NULL) < 0) {
		log_file_write("rcv ack failed!\n");
		return -1;
	}

	return 0;
}

int read_ver_file(const char *file, char *buf, int sz)
{
	int ret = 0;
	FILE *fp = NULL;
	if (NULL == file || NULL == buf || sz <= 0) {
		ret = -1;
		return ret;
	}

	fp = fopen(file, "r");
	if (NULL == fp) {
		ret = -1;
		return ret;
	}

	fgets(buf, sz, fp);
	
	fclose(fp);	
	return ret;
}

int send_ver_request(int fd, unsigned int pro_num)
{
	int len;
	char cur_ver[VER_BUFFER_LEN] = {0};
	pro_head_t *h = NULL;
	
	if (fd < 0 || pro_num < (unsigned int)0x20000000 || (unsigned int)VER_UPDATE_REQ != pro_num) {
		return -1;
	}

	if (read_ver_file(NEW_VER_FILE, cur_ver, sizeof(cur_ver)) < 0) {
		log_file_write("read sys ver file failed!");
		exit(1);
	}

	len = strlen(cur_ver);
	if (len > 1) {
		h = padding_pro_req(VER_UPDATE_REQ, cur_ver, len);
		if (NULL == h) {
			log_file_write("padding ver request head failed!");
			return -1;
		}
	
		if (send(fd, h, h->len, 0) < 0) {
			free(h);
			log_file_write("send failed!");
			return -1;
		}
		free(h);
	}
	return 0;
}


int check_ver_update(int fd, char *ver)
{
	if (fd < 0 || NULL == ver) {
		return -1;
	}

	if (send_ver_request(fd, VER_UPDATE_REQ) < 0) {
		log_file_write("send sys update request failed!\n");
		return -1;
	}
	
	if (recv_ack_general(fd, VER_UPDATE_ACK, NULL, ver) < 0) {
		log_file_write("recv sys update failed!\n");
		return -1;
	}

	return 0;
}

int check_update_and_download_perform(void)
{
	int cli_sk;
	char new_ver[VER_BUFFER_LEN] = {0};
	char new_ver_file[PATH_MAX_LEN]= {0};

	cli_sk = conn_serv(SERV_DOMAIN, SERV_PORT);
	if (cli_sk < 0) {
		log_file_write("conn_serv() failed.");
		return -1;
	}

	if (send_login_request_and_rcv_ack(cli_sk, LOGIN_REQ, LOGIN_ACK) < 0) {
		log_file_write("send_login_request_and_rcv_ack() LOGIN_REQ failed.");
		close(cli_sk);
		return -1;
	}

	if (check_ver_update(cli_sk, new_ver) < 0) {
		log_file_write("check_ver_update() failed.");
        close(cli_sk);
		return -1;
	}

	if (new_ver[0] != '\0') {
		if (download_update_file(cli_sk, new_ver, new_ver_file, sizeof(new_ver_file)) < 0) {
			log_file_write("download_update_file() failed!");
			close(cli_sk);
			return -1;
		}
		if (perform_update(new_ver, new_ver_file) < 0) {
			log_file_write("perform_update failed.\n");
			close(cli_sk);
			return -1;
		}
	}
	
	close(cli_sk);

	return 0;
}

int g_log_fd;

int main()
{
	int ret = 0;
	g_log_fd = log_file_open(WIFI_UPDATE_LOG_FILE);
	if (g_log_fd < 0) {
		printf("open log file failed.\n");
		return -1;
	}

	while(1) {
		ret = check_update_and_download_perform();
		if (ret < 0) {
			log_file_write("check_update failed.");
			sleep(5);
			continue;
		}
		sleep(3600);
	}

	close(g_log_fd);
	return ret;
}
