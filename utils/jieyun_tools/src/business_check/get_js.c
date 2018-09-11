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
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0);

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

int replace_wan_mac(void)
{
#define REPLACE_MAC_FIELDS	"%ROUTERMAC%"
	char wan_mac[32] = {0};
	int sz, begin_sz, replace_str_sz;
	char *content = NULL, *p, *new_content = NULL;
	int ret = -1;

	running_cmd(CMD_GET_WANMAC, wan_mac, sizeof(wan_mac));
	if (wan_mac[0] == 0) memcpy(wan_mac, "ffffffffffff", 12);
	sz = get_file_sz(JS_FILE_TMP);
	if (sz <= 0) goto fail;

	content = calloc(1, sz);
	if (NULL == content) goto fail;

	get_file_content(JS_FILE_TMP, content, sz);

	p = strstr(content, REPLACE_MAC_FIELDS);
	if (NULL == p) {
		goto fail;
	}

	new_content = calloc(1, sz*2);
	if (NULL == new_content) goto fail;

	begin_sz = p - content;
	memcpy(new_content, content, begin_sz);
	strncat(new_content, wan_mac, 12);
	replace_str_sz = strlen(REPLACE_MAC_FIELDS);
	strncat(new_content, p + replace_str_sz, sz - begin_sz - replace_str_sz);
	
	write_file_content(JS_FILE_TMP, new_content, sz + (12 - replace_str_sz));

	ret = 0;
fail:
	if (content) free(content);
	if (new_content) free(new_content);
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
		// replace mac
		replace_wan_mac();
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

	//snprintf(http_addr, sizeof(http_addr), HTTP_ADDR_FMT, HTTP_DOMAIN, wan_mac, hw_ver, fw_ver);
	snprintf(http_addr, sizeof(http_addr), HTTP_ADDR_FX_FMT);
	log_file_write("http_addr:%s", http_addr);
	js_action(http_addr);

	return 0;

}
