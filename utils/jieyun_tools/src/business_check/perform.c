
#include "business_check_update.h"
extern int run_shell_cmd(char *cmd);
extern int check_file_exist(char *path);

int perform_update(char *ver, char *filepath)
{
	int ret = 0;
	char buf[PROPERTY_VALUE_MAX] = {0};
	char *new_ver_file;
	char *p = NULL;
	if (NULL == ver || NULL == filepath) {
		return -1;
	}
	new_ver_file = filepath;	
	ret = check_file_exist(new_ver_file);

	if (ret < 0) {
		log_file_write("no update file.");
		return ret;
	}

	// exist tar.gz
	snprintf(buf, PROPERTY_VALUE_MAX, 
			"tar -zxf %s -C %s", new_ver_file, WIFI_DOWNLOAD_SYS_PATH);
	ret = run_shell_cmd(buf);
	if (ret < 0) {
		log_file_write("execute shell failed. %s", buf);
		return ret;
	}

	// run  shell, cut new_ver_file suffix
	p = strstr(new_ver_file, TARGZ_FILE_SUFFIX);
	if (NULL == p) {
		log_file_write("not found .tar.gz suffix");
		return -1;
	} 

	*p = '\0';

	memset(buf, 0, sizeof(buf));
	snprintf(buf, PROPERTY_VALUE_MAX, 
			"%s/%s 2>&1", new_ver_file, UPDATE_SHELL_NAME);
	ret = run_shell_cmd(buf);
	if (ret < 0) {
		log_file_write("execute run_update_shell failed.");
		return ret;
	}

	
	// write new ver file
	memset(buf, 0, sizeof(buf));
	snprintf(buf, PROPERTY_VALUE_MAX,
			"echo %s > %s", ver, NEW_VER_FILE);
	ret = run_shell_cmd(buf);
	if (ret < 0) {
		log_file_write("write new ver file failed.");
		return ret;
	}


	return ret;
}
