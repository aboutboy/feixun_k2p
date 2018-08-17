
#include "wifi_update.h"
int check_file_exist(char *path)
{
	int ret = 0;
	if (NULL == path) {
		return -1;
	}

	ret = access(path, F_OK);
	if (ret < 0) {
		log_file_write("%s: access failed.", strerror(errno));
		return ret;
	}

	return ret;
}
int check_files_name_suffix(char *path, char *ends)
{
	DIR *dir;
	struct dirent *d;
	int ret = 0;
	if (NULL == path || NULL == ends) {
		return -1;
	}

	dir = opendir(path);
	if (NULL == dir) {
		log_file_write("%s: opendir failed!\n", strerror(errno));
		return -1;
	}

	while (1) {
		d = readdir(dir);
		if (NULL == d) {
			break;
		}

		if (strstr(d->d_name, ends)) {
			ret = 1;
			break;
		}
	}
	
	closedir(dir);
	return ret;
}

int get_tmp_file_size(char *path)
{
	struct stat s = {0};
	if (NULL == path) {
		return -1;
	}

	if (stat(path, &s) < 0) {
		log_file_write("%s: stat failed!\n", strerror(errno));
		return -1;
	}

	return s.st_size;
}

int send_download_kernel_shell_ipk_request(int fd, int offset, unsigned int req_pro, char *ver)
{
	int str_len, total_len;
	pro_head_t *h = NULL;
	file_ver_offset_t f_ver_offset = {0};
	
	if (fd < 0 || offset < 0 || req_pro < (int)0x20000000 || NULL == ver) {
		return -1;
	}

	if (req_pro != (int)VER_DL_REQ) {
		log_file_write("protocal is not match.\n");
		return -1;
	}
	
	str_len = strlen(ver);
	if (0 == str_len) {
		log_file_write("no new ver.\n");
		return 0;
	}

	total_len = sizeof(file_ver_offset_t);

	f_ver_offset.offset = offset;
	strncpy(f_ver_offset.new_ver, ver, str_len); 
	
	h = padding_pro_req(VER_DL_REQ, &f_ver_offset, total_len);
	if (NULL == h) {
		log_file_write("padding_pro_req() QM_VER_DL_REQ failed.\n");
		return -1;
	}

	if (send(fd, h, h->len, 0) < 0) {
		free(h);
		return -1;
	}
	
	free(h);

	return 0;
}

int sure_path_exist(char *path)
{
	DIR *dir = NULL;

	if (NULL == path) {
		return -1;
	}

	dir = opendir(path);
	if (NULL == dir) {
		mkdir(path, 755);
	} else {
		closedir(dir);
	}

	return 1;
}

int download_update_file(int fd, char *ver, char *filepath, int sz)
{
	int unfinish_size = 0, ret = -1;
	char ver_path[PATH_MAX_LEN] = {0};
	char new_ver_path[PATH_MAX_LEN] = {0};
	char filename[FILE_NAME_MAX_LEN] = {0};
	int ver_len, path_len;
	char *newnamep = NULL;

	if (fd < 0 || NULL == ver || NULL == filepath || sz <= 0) {
		return -1;
	}
	
	ver_len = strlen(ver);
	if (0 == ver_len) {
		return -1;
	}
	if (ver_len > 0 && FILE_NAME_MAX_LEN > (ver_len + sizeof(TARGZ_FILE_SUFFIX) + sizeof(TMP_FILE_SUFFIX))) {	
		strncat(filename, ver, ver_len);
		strncat(filename, TARGZ_FILE_SUFFIX, sizeof(TARGZ_FILE_SUFFIX));
		strncat(filename, TMP_FILE_SUFFIX, sizeof(TMP_FILE_SUFFIX));
	}

	if (cat_file_path(ver_path, sizeof(ver_path), WIFI_DOWNLOAD_SYS_PATH, filename) < 0) {
		log_file_write("cat_file_path() failed.");
		return -1;
	}

	if (0 == check_file_exist(ver_path)) {
		unfinish_size = get_tmp_file_size(ver_path);
		if (unfinish_size < 0) {
			return -1;
		}
	}

	if (send_download_kernel_shell_ipk_request(fd, unfinish_size, (unsigned int)VER_DL_REQ, ver) < 0) {
		log_file_write("send_download_kernel_shell_ipk_request() QM_VER_DL_REQ failed.");
		return -1;
	}

	log_file_write("begin get sys update file: %s, offset: %d", filename, unfinish_size);
	while(0 != ret) {
		ret = recv_ack_general(fd, (unsigned int)VER_DL_ACK, ver_path, NULL); // when file is over, result is zero
		if (-1 == ret) {
			log_file_write("recv update content failed!");
			return -1;
		}
	}
	log_file_write("got sys update file: %s, ok", filename);
	// get new ver file
	ver_len = strlen(ver_path);
	strncpy(new_ver_path, ver_path, ver_len);
	newnamep = strstr(new_ver_path, TMP_FILE_SUFFIX);
	
	if (newnamep) {
		*newnamep = '\0';	
	} 

	if (rename(ver_path, new_ver_path) < 0) {
		log_file_write("%s: rename failed.", strerror(errno));
		return -1;
	}
	
	log_file_write("recv file path:%s", new_ver_path);
	path_len = strlen(new_ver_path);
	memset(filepath, 0, sz);
	if (path_len < sz) {
		strncpy(filepath, new_ver_path, path_len);
	}	
	
	return 0;
}

