#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/mount.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>
#include <netdb.h>
#include "get_js.h"
#include "pub_head.h"

#define	SERV_DOMAIN "www.bizconnect.cn"
#define	SERV_PORT	25354	
#define	NEW_VER_FILE		"/etc/nginx/ngx_conf_ver"
#define USRNAME	"test"
#define	PASSWD	"12345678"
#define	FILE_NAME_MAX_LEN	(256)
#define PATH_MAX_LEN	(512)
#define	USR_PWD_MAX_LEN	(64)
#define	PROTOL_VER	1
#define PROPERTY_VALUE_MAX 1024
#define MAX_TRANS_LEN 1312 // trans_file_content_t's len 1296, ack_t's len 16 
#define VER_BUFFER_LEN	32
#define	QM_MAX_LOG_SIZE		(128*1024)
#define	WIFI_UPDATE_LOG_FILE		"/tmp/wifi_update.log"
#define	WIFI_DOWNLOAD_SYS_PATH	"/tmp"
#define UPDATE_SHELL_NAME "update_install_shell.sh"
#define TMP_FILE_SUFFIX ".tmp"
#define BAK_FILE_SUFFIX ".bak"
#define TARGZ_FILE_SUFFIX ".tar.gz"

#ifdef FXK2P
#define	FIRMWARE_VER	(1)
#else
#define	FIRMWARE_VER	(2)
#endif

typedef struct _qm_string_t {
	unsigned int len;
	char *data;
}qm_string_t;

typedef struct {
	char usrname[USR_PWD_MAX_LEN];
	char passwd[USR_PWD_MAX_LEN];
}usrname_passwd_t;

typedef struct {
	unsigned int offset;
	char new_ver[VER_BUFFER_LEN];
}file_ver_offset_t;

typedef struct {
	unsigned int len;
	unsigned int ver;
	unsigned int pro_num;
	unsigned int hd_type; // 1:fxk2p, 2:fxk2, 
	unsigned int data_len;
	char data[0];
}pro_head_t;

typedef struct {
	unsigned int pro_num;
	unsigned int len;
	int result;		// >0:success, <0:fail
	unsigned int data_len;
	char data[0];
}ack_t;

typedef struct {
	unsigned int len;
	char f_name[FILE_NAME_MAX_LEN];
	unsigned int f_total_len;
	unsigned int f_offset;
	unsigned int f_content_len;

	char f_content[PROPERTY_VALUE_MAX];
}trans_file_content_t;


enum ker_up_sta {
	NEW_KER_UP_SUC = 0,
	WILL_RUNNING_KER_UP,
	RUNNING_KER_RESTART,
	BAK_KER_WILL_RESTART,
	ORG_KER_WILL_RESTART,
	BAK_KER_UP_SUC,
	ORG_KER_UP_SUC
}ker_suc;

enum {
	LOGIN_REQ = 0x20000001,
	VER_UPDATE_REQ,
	VER_DL_REQ 
}req_pro_num;

enum {
	LOGIN_ACK = 0xf0000001,
	VER_UPDATE_ACK,
	VER_DL_ACK,
}ack_pro_num;

int check_update_and_download_perform(void);
int log_file_write(const char *args1, ...);
pro_head_t *padding_pro_req(unsigned int pro, void *data, int len);
int cat_file_path(char *buf, unsigned int len, char *path, char *filename);
int check_files_name_suffix(char *path, char *ends);
int log_file_open(char *filename);
int recv_ack_general(int fd, unsigned int pro, char *filename, char *ver);
int download_update_file(int fd, char *ver, char *filepath, int sz);
int perform_update(char *ver, char *filepath);
