#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>

int running_cmd(const char *cmd, char *res, int sz);
int running_cmd_realloc(const char *cmd, char **res, int *sz);
off_t get_file_sz(const char *file);
int get_file_content(const char *file, char *buf, int sz);
int write_file_content(const char *file, char *buf, int sz);
