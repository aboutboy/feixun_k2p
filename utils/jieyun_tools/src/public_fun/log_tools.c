#include "log_tools.h"
static pthread_mutex_t fileMutex = PTHREAD_MUTEX_INITIALIZER;

static int log_file_open(char *filename)
{
    int fd;
    if (NULL == filename) {
        printf("%s  params error!\n", __FUNCTION__);
        return -1;
    }
    fd = open(filename, O_CREAT|O_RDWR| O_APPEND);
    if (fd < 0) {
        perror("open");
        return -1;
    }
    return fd;
}

static int log_file_close(int fd)
{
    if (fd < 0) {
        return -1;
    }
    close(fd);
    return 0;
}

int safe_vasprintf(char **strp, const char *fmt, va_list ap) 
{
    int retval;

    retval = vasprintf(strp, fmt, ap);
    if (retval == -1) 
    {
        printf("Failed to vasprintf: %s.  Bailing out\n", strerror(errno));
        return 1;
    }
    return retval;
}

int log_file_write(const char *format, ...)
{
    char log_buf[PROPERTY_LOG_VALUE_MAX] = {0};
    int fd = -1;
    va_list args;
    char *fmt = NULL;
    int ret = -1;
    
    if (NULL == format) { return -1;}

    pthread_mutex_lock(&fileMutex);
    fd = log_file_open(LOG_FILE);
    if (fd < 0) {
	    goto fail;
    }
    
    va_start(args, format);
    safe_vasprintf(&fmt, format, args);
    va_end(args);
    if (NULL == fmt) {
    	goto fail;
    }

    struct stat f_stat;
    if (fstat(fd, &f_stat) < 0) {
	perror("state failed.");
    	goto fail;
    }

    if (f_stat.st_size >= MAX_LOG_SIZE) {
        if (ftruncate(fd, 0) < 0) {
	    	perror("ftruncate failed.");
        	goto fail;
	}
        if (lseek(fd, 0, SEEK_SET) < 0) {
	    perror("lseek failed.");
            goto fail;
        }
    }

    time_t now;
    time(&now);
    struct tm *local = localtime(&now);
    snprintf(log_buf, sizeof(log_buf) - 1, "[%04d-%02d-%02d %02d:%02d:%02d] %s\n",
            local->tm_year + 1900, local->tm_mon + 1, local->tm_mday,
            local->tm_hour, local->tm_min, local->tm_sec,
            fmt);


    if (write(fd, log_buf, strlen(log_buf)) < 0) {
    	goto fail;	
    }

    ret = 0;

fail:
    pthread_mutex_unlock(&fileMutex);
    if (fd > 0) log_file_close(fd);
    if (fmt) free(fmt);
    return ret;
}
