#include "wifi_update.h"

extern int g_log_fd;
int log_file_open(char *filename)
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

int log_file_close(int fd)
{
    if (fd < 0) {
        return -1;
    }
    close(fd);
    return 0;
}

int log_file_write(const char *args1, ...)
{
    char log_buf[PROPERTY_VALUE_MAX] = {0};
    char args_buf[PROPERTY_VALUE_MAX] = {0};
    if (NULL == args1) {
        return -1;
    }

    va_list args;
    va_start(args, args1);
    vsnprintf(args_buf, PROPERTY_VALUE_MAX, args1, args);
    va_end(args);

    struct stat f_stat;
    if (fstat(g_log_fd, &f_stat) < 0) {
        return -1;
    }

    if (f_stat.st_size >= QM_MAX_LOG_SIZE) {
        if (ftruncate(g_log_fd, 0) < 0) {
            return -1;
        }
        if (lseek(g_log_fd, 0, SEEK_SET) < 0) {
            return -1;
        }

    }
    time_t now;
    time(&now);
    struct tm *local = localtime(&now);
    snprintf(log_buf, PROPERTY_VALUE_MAX, "%04d-%02d-%02d %02d:%02d:%02d %s\n",
            local->tm_year+1900, local->tm_mon, local->tm_mday,
            local->tm_hour, local->tm_min, local->tm_sec,
            args_buf);

    int log_len = strlen(log_buf);
    if (log_len >= PROPERTY_VALUE_MAX) {
        log_len = PROPERTY_VALUE_MAX - 1;
        log_buf[PROPERTY_VALUE_MAX - 1] = '\0';
    }

    if (write(g_log_fd, log_buf, log_len) < 0) {
        return -1;
    }
    return 0;
}


