#include "file_ops.h"

int running_cmd(const char *cmd, char *res, int sz)
{
	FILE *fp;
	if (NULL == cmd || NULL == res || sz <= 0) {
		return -1;
	}

	memset(res, 0, sz);

	fp = popen(cmd, "r");
	if (NULL == fp) {
		perror("run cmd failed.");
		return -1;
	}
	fread(res, sz, 1, fp);
	pclose(fp);

	return 0;
}

off_t get_file_sz(const char *file) 
{
	struct stat st;
	if (NULL == file) { return -1;}
	memset(&st, 0, sizeof(st));
	stat(file, &st);

	return st.st_size;
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

int write_file_content(const char *file, char *buf, int sz)
{
	FILE *fp;
	fp = fopen(file, "w");
	if (NULL == fp) return -1;
	fwrite(buf, sz, 1, fp);
	fclose(fp);

	return 0;
}

