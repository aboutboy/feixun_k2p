#include "get_js.h"

static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
	size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
	return written;
}

int curl_request(char *url)
{
	CURL *curl_handle;
	FILE *fp;
	if (NULL == url) { return -1;}
	curl_global_init(CURL_GLOBAL_ALL);
	curl_handle = curl_easy_init();
	curl_easy_setopt(curl_handle, CURLOPT_URL, url);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_data);

	fp = fopen(JS_FILE_TMP, "wb");
	if (fp) {
		curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, fp);
		curl_easy_perform(curl_handle);
		fclose(fp);
	}

	curl_easy_cleanup(curl_handle);
	curl_global_cleanup();

	return 0;
}

int get_file_content(const char *file, char *buf, int sz)
{
	FILE *fp;
	fp = fopen(file, "r");
	if (NULL == fp) { return -1;}
	fread(buf, sz, 1, fp);
	fclose(fp);

	return 0;
}

int compare_md5(const char *oldfile, const char *newfile)
{
	off_t old_sz, new_sz;
	unsigned char md5_old_output[16] = {0}, md5_new_output[16] = {0};
	char *new, *old;
	int i, ret = 0;

	old_sz = get_file_sz(oldfile);
	new_sz = get_file_sz(newfile);

	if (0 == new_sz) {
		log_file_write("get js file size is 0.");
		return 0;
	}

	old = calloc(1, old_sz);
	if (NULL == old) { return 0;}
	new = calloc(1, new_sz);
	if (NULL == new) { free(old); return 0;}

	get_file_content(oldfile, old, old_sz);
	get_file_content(newfile, new, new_sz);

	md5_digest(old, old_sz, md5_old_output);
	md5_digest(new, new_sz, md5_new_output);

	for(i = 0; i < sizeof(md5_new_output); i++) {
		if (md5_old_output[i] != md5_new_output[i]) {
			ret = 1;
			break;
		}
	}

	free(old); free(new);

	return ret;
}

int js_action(char *url)
{
	char buf[512] = {0}, ping_cmd[64] = {0}, res[64] = {0};
	if (NULL == url) { return -1;}
	snprintf(ping_cmd, sizeof(ping_cmd), PING_CMD_FMT, HTTP_DOMAIN);
	running_cmd(ping_cmd, buf, sizeof(buf));
	if (strstr(buf, "from")) { // ping ok
		curl_request(url);
		if (compare_md5(JS_FILE, JS_FILE_TMP)) {
			memset(buf, 0, sizeof(buf));
			snprintf(buf, sizeof(buf), MV_RELOAD_NGX_FMT, JS_FILE_TMP, JS_FILE, NGX_FILE);
			running_cmd(buf, res, sizeof(res));	
		}	
	}

	return 0;
}

int get_js(void)
{
	char wan_mac[64] = {0};
	char hw_ver[64] = {0};
	char fw_ver[64] = {0};
	char http_addr[512] = {0};

	running_cmd(CMD_GET_WANMAC, wan_mac, sizeof(wan_mac));
	running_cmd(CMD_GET_HW_VER, hw_ver, sizeof(hw_ver));
	running_cmd(CMD_GET_FW_VER, fw_ver, sizeof(fw_ver));
	if (wan_mac[0] == '\0' || hw_ver[0] == '\0' || fw_ver[0] == '\0') {
		log_file_write("can not get ver info.");
		return -1;
	}

	snprintf(http_addr, sizeof(http_addr), HTTP_ADDR_FMT, HTTP_DOMAIN, wan_mac, hw_ver, fw_ver);
	log_file_write("http_addr:%s", http_addr);
	js_action(http_addr);

	return 0;

}