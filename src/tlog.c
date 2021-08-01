/*
 * tinylog
 * Copyright (C) 2018-2020 Nick Peng <pymumu@gmail.com>
 * https://github.com/pymumu/tinylog
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "tlog.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define TLOG_BUFF_SIZE (1024 * 128)
#define TLOG_TMP_LEN 128
#define TLOG_LOG_SIZE (1024 * 1024 * 50)
#define TLOG_LOG_COUNT 32
#define TLOG_LOG_NAME_LEN 128
#define TLOG_BUFF_LEN (PATH_MAX + TLOG_LOG_NAME_LEN * 3)
#define TLOG_SUFFIX_GZ ".gz"
#define TLOG_SUFFIX_LOG ""
#define TLOG_MAX_LINE_SIZE_SET (1024 * 8)
#define TLOG_MIN_LINE_SIZE_SET (128)

#define TLOG_SEGMENT_MAGIC 0xFF446154

struct tlog_log {
    char *buff;
    int buffsize;
    int start;
    int end;
    int ext_end;

    int fd;
    int fd_lock;

    off_t filesize;
    char logdir[PATH_MAX];
    char logname[TLOG_LOG_NAME_LEN];
    char suffix[TLOG_LOG_NAME_LEN];
    char pending_logfile[PATH_MAX];
    int rename_pending;
    int fail;
    int logsize;
    int logcount;
    int block;
    int dropped;
    int nocompress;
    int zip_pid;
    int multi_log;
    int logscreen;
    int segment_log;
    unsigned int max_line_size;

    tlog_output_func output_func;
    void *private_data;

    time_t last_try;
    time_t last_waitpid;
    mode_t file_perm;
    mode_t archive_perm;

    int waiters;
    int is_exit;
    struct tlog_log *next;
    pthread_mutex_t lock;
    pthread_cond_t client_cond;
};

struct tlog {
    struct tlog_log *root;
    struct tlog_log *log;
    struct tlog_log *notify_log;
    int run;
    pthread_t tid;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    tlog_log_output_func output_func;
    struct tlog_log *wait_on_log;
    int is_wait;
};

struct tlog_segment_log_head {
    struct tlog_loginfo info;
    unsigned short len;
    char data[0];
} __attribute__((packed));

struct tlog_segment_head {
    unsigned int magic;
    unsigned short len;
    char data[0];
} __attribute__((packed));

struct oldest_log {
    char name[TLOG_LOG_NAME_LEN];
    time_t mtime;
    struct tlog_log *log;
};

struct count_log {
    int lognum;
    struct tlog_log *log;
};

struct tlog_info_inter {
    struct tlog_loginfo info;
    void *userptr;
};

typedef int (*list_callback)(const char *name, struct dirent *entry, void *user);
typedef int (*vprint_callback)(char *buff, int maxlen, void *userptr, const char *format, va_list ap);

static struct tlog tlog;
static int tlog_disable_early_print = 0;
static tlog_level tlog_set_level = TLOG_INFO;
static tlog_format_func tlog_format;
static unsigned int tlog_localtime_lock = 0;

static const char *tlog_level_str[] = {
    "DEBUG",
    "INFO",
    "NOTICE",
    "WARN",
    "ERROR",
    "FATAL",
};

static inline void _tlog_spin_lock(unsigned int *lock)
{
    while (1) {
        int i;
        for (i = 0; i < 10000; i++) {
            if (__sync_bool_compare_and_swap(lock, 0, 1)) {
                return;
            }
        }
        sched_yield();
    }
}

static inline void _tlog_spin_unlock(unsigned int *lock)
{
    __sync_bool_compare_and_swap(lock, 1, 0);
}

static int _tlog_mkdir(const char *path)
{
    char path_c[PATH_MAX];
    char *path_end;
    char str;
    int len;
    if (access(path, F_OK) == 0) {
        return 0;
    }

    while (*path == ' ' && *path != '\0') {
        path++;
    }

    strncpy(path_c, path, sizeof(path_c) - 1);
    path_c[sizeof(path_c) - 1] = '\0';
    len = strnlen(path_c, sizeof(path_c) - 1);
    path_c[len] = '/';
    path_c[len + 1] = '\0';
    path_end = path_c;

    /* create directory recursively */
    while (*path_end != 0) {
        if (*path_end != '/') {
            path_end++;
            continue;
        }

        if (path_end == path_c) {
            path_end++;
            continue;
        }

        str = *path_end;
        *path_end = '\0';
        if (access(path_c, F_OK) == 0) {
            *path_end = str;
            path_end++;
            continue;
        }

        if (mkdir(path_c, 0750) != 0) {
            fprintf(stderr, "create directory %s failed, %s\n", path_c, strerror(errno));
            return -1;
        }

        *path_end = str;
        path_end++;
    }

    return 0;
}

static struct tm *_tlog_localtime(time_t *timep, struct tm *tm)
{
    static time_t last_time;
    static struct tm last_tm;

    /* localtime_r has a global timezone lock, it's about 8 times slower than gmtime
     * this code is used to speed up localtime_r call.
     */
    _tlog_spin_lock(&tlog_localtime_lock);
    if (*timep == last_time) {
        *tm = last_tm;
    } else {
        _tlog_spin_unlock(&tlog_localtime_lock);
        tm = localtime_r(timep, tm);
        _tlog_spin_lock(&tlog_localtime_lock);
        if (tm) {
            last_time = *timep;
            last_tm = *tm;
        }
    }
    _tlog_spin_unlock(&tlog_localtime_lock);

    return tm;
}

static int _tlog_getmtime(struct tlog_time *log_mtime, const char *file)
{
    struct tm tm;
    struct stat sb;

    if (stat(file, &sb) != 0) {
        return -1;
    }

    if (_tlog_localtime(&sb.st_mtime, &tm) == NULL) {
        return -1;
    }

    log_mtime->year = tm.tm_year + 1900;
    log_mtime->mon = tm.tm_mon + 1;
    log_mtime->mday = tm.tm_mday;
    log_mtime->hour = tm.tm_hour;
    log_mtime->min = tm.tm_min;
    log_mtime->sec = tm.tm_sec;
    log_mtime->usec = 0;

    return 0;
}

static int _tlog_gettime(struct tlog_time *cur_time)
{
    struct tm tm;
    struct timeval tmval;

    if (gettimeofday(&tmval, NULL) != 0) {
        return -1;
    }

    if (_tlog_localtime(&tmval.tv_sec, &tm) == NULL) {
        return -1;
    }

    cur_time->year = tm.tm_year + 1900;
    cur_time->mon = tm.tm_mon + 1;
    cur_time->mday = tm.tm_mday;
    cur_time->hour = tm.tm_hour;
    cur_time->min = tm.tm_min;
    cur_time->sec = tm.tm_sec;
    cur_time->usec = tmval.tv_usec;

    return 0;
}

void tlog_set_maxline_size(struct tlog_log *log, int size)
{
    if (log == NULL) {
        return;
    }

    if (size < TLOG_MIN_LINE_SIZE_SET) {
        size = TLOG_MIN_LINE_SIZE_SET;
    } else if (size > TLOG_MAX_LINE_SIZE_SET) {
        size = TLOG_MAX_LINE_SIZE_SET;
    }

    log->max_line_size = size;
}

void tlog_set_permission(struct tlog_log *log, unsigned int file, unsigned int archive)
{
    log->file_perm = file;
    log->archive_perm = archive;
}

int tlog_localtime(struct tlog_time *tm)
{
    return _tlog_gettime(tm);
}

tlog_log *tlog_get_root()
{
    return tlog.root;
}

void tlog_set_private(tlog_log *log, void *private_data)
{
    if (log == NULL) {
        return;
    }

    log->private_data = private_data;
}

void *tlog_get_private(tlog_log *log)
{
    if (log == NULL) {
        return NULL;
    }

    return log->private_data;
}

static int _tlog_format(char *buff, int maxlen, struct tlog_loginfo *info, void *userptr, const char *format, va_list ap)
{
    int len = 0;
    int total_len = 0;
    struct tlog_time *tm = &info->time;
    void *unused __attribute__((unused));

    unused = userptr;

    if (tlog.root->multi_log) {
        /* format prefix */
        len = snprintf(buff, maxlen, "[%.4d-%.2d-%.2d %.2d:%.2d:%.2d,%.3d][%5d][%4s][%17s:%-4d] ",
            tm->year, tm->mon, tm->mday, tm->hour, tm->min, tm->sec, tm->usec / 1000, getpid(),
            tlog_get_level_string(info->level), info->file, info->line);
    } else {
        /* format prefix */
        len = snprintf(buff, maxlen, "[%.4d-%.2d-%.2d %.2d:%.2d:%.2d,%.3d][%5s][%17s:%-4d] ",
            tm->year, tm->mon, tm->mday, tm->hour, tm->min, tm->sec, tm->usec / 1000,
            tlog_get_level_string(info->level), info->file, info->line);
    }

    if (len < 0 || len >= maxlen) {
        return -1;
    }
    buff += len;
    total_len += len;
    maxlen -= len;

    /* format log message */
    len = vsnprintf(buff, maxlen, format, ap);
    if (len < 0 || len == maxlen) {
        return -1;
    }
    buff += len;
    total_len += len;

    /* return total length */
    return total_len;
}

static int _tlog_root_log_buffer(char *buff, int maxlen, void *userptr, const char *format, va_list ap)
{
    int len = 0;
    int log_len = 0;
    struct tlog_info_inter *info_inter = (struct tlog_info_inter *)userptr;
    struct tlog_segment_log_head *log_head = NULL;
    int max_format_len = 0;

    if (tlog_format == NULL) {
        return -1;
    }

    if (tlog.root->segment_log) {
        log_head = (struct tlog_segment_log_head *)buff;
        len += sizeof(*log_head);
        memcpy(&log_head->info, &info_inter->info, sizeof(log_head->info));
    }

    max_format_len = maxlen - len - 2;
    buff[maxlen - 1] = 0;
    log_len = tlog_format(buff + len, max_format_len, &info_inter->info, info_inter->userptr, format, ap);
    if (log_len < 0) {
        return -1;
    } else if (log_len >= max_format_len) {
        buff[len + max_format_len - 2] = '.';
        buff[len + max_format_len - 3] = '.';
        buff[len + max_format_len - 4] = '.';
        log_len = max_format_len - 1;
    }
    len += log_len;

    /* add new line character*/
    if (*(buff + len - 1) != '\n' && len + 1 < maxlen - 1) {
        *(buff + len) = '\n';
        len++;
        log_len++;
    }

    if (tlog.root->segment_log) {
        if (len + 1 < maxlen - 1) {
            *(buff + len) = '\0';
            len++;
            log_len++;
        }
        log_head->len = log_len;
    }

    return len;
}

static int _tlog_print_buffer(char *buff, int maxlen, void *userptr, const char *format, va_list ap)
{
    int len;
    int total_len = 0;
    void *unused __attribute__((unused));

    unused = userptr;

    /* format log message */
    len = vsnprintf(buff, maxlen, format, ap);
    if (len < 0 || len == maxlen) {
        return -1;
    }
    buff += len;
    total_len += len;

    /* return total length */
    return total_len;
}

static int _tlog_need_drop(struct tlog_log *log)
{
    int maxlen = 0;
    int ret = -1;
    if (log->block) {
        return -1;
    }

    pthread_mutex_lock(&tlog.lock);
    if (log->end == log->start) {
        if (log->ext_end == 0) {
            /* if buffer is empty */
            maxlen = log->buffsize - log->end;
        }
    } else if (log->end > log->start) {
        maxlen = log->buffsize - log->end;
    } else {
        /* if reverse */
        maxlen = log->start - log->end;
    }

    /* if free buffer length is less than min line length */
    if (maxlen < log->max_line_size) {
        log->dropped++;
        ret = 0;
    }
    pthread_mutex_unlock(&tlog.lock);
    return ret;
}

static int _tlog_vprintf(struct tlog_log *log, vprint_callback print_callback, void *userptr, const char *format, va_list ap)
{
    int len;
    int maxlen = 0;
    struct tlog_segment_head *segment_head = NULL;

    if (log == NULL || format == NULL) {
        return -1;
    }

    char buff[log->max_line_size];

    if (log->buff == NULL) {
        return -1;
    }

    if (_tlog_need_drop(log) == 0) {
        return -1;
    }

    len = print_callback(buff, sizeof(buff), userptr, format, ap);
    if (len <= 0) {
        return -1;
    } else if (len >= log->max_line_size) {
        strncpy(buff, "[LOG TOO LONG, DISCARD]\n", sizeof(buff));
        buff[sizeof(buff) - 1] = '\0';
        len = strnlen(buff, sizeof(buff));
    }

    pthread_mutex_lock(&tlog.lock);
    do {
        if (log->end == log->start) {
            if (log->ext_end == 0) {
                /* if buffer is empty */
                maxlen = log->buffsize - log->end;
            }
        } else if (log->end > log->start) {
            maxlen = log->buffsize - log->end;
        } else {
            /* if reverse */
            maxlen = log->start - log->end;
        }

        /* if free buffer length is less than min line length */
        if (maxlen < log->max_line_size) {
            if (log->end != log->start) {
                tlog.notify_log = log;
                pthread_cond_signal(&tlog.cond);
            }

            /* if drop message, increase statistics and return */
            if (log->block == 0) {
                log->dropped++;
                pthread_mutex_unlock(&tlog.lock);
                return -1;
            }

            pthread_mutex_unlock(&tlog.lock);
            pthread_mutex_lock(&log->lock);
            log->waiters++;
            /* block wait for free buffer */
            int ret = pthread_cond_wait(&log->client_cond, &log->lock);
            log->waiters--;
            pthread_mutex_unlock(&log->lock);
            if (ret < 0) {
                return -1;
            }

            pthread_mutex_lock(&tlog.lock);
        }
    } while (maxlen < log->max_line_size);

    if (log->segment_log) {
        segment_head = (struct tlog_segment_head *)(log->buff + log->end);
        memcpy(segment_head->data, buff, len);
        log->end += len + sizeof(*segment_head) + 1;
        segment_head->len = len + 1;
        segment_head->data[len] = '\0';
        segment_head->magic = TLOG_SEGMENT_MAGIC;
    } else {
        /* write log to buffer */
        memcpy(log->buff + log->end, buff, len);
        log->end += len;
    }

    /* if remain buffer is not enough for a line, move end to start of buffer. */
    if (log->end > log->buffsize - log->max_line_size) {
        log->ext_end = log->end;
        log->end = 0;
    }
    if (tlog.is_wait) {
        tlog.notify_log = log;
        pthread_cond_signal(&tlog.cond);
    }
    pthread_mutex_unlock(&tlog.lock);

    return len;
}

int tlog_vprintf(struct tlog_log *log, const char *format, va_list ap)
{
    return _tlog_vprintf(log, _tlog_print_buffer, NULL, format, ap);
}

int tlog_printf(struct tlog_log *log, const char *format, ...)
{
    int len;
    va_list ap;

    va_start(ap, format);
    len = tlog_vprintf(log, format, ap);
    va_end(ap);

    return len;
}

static int _tlog_early_print(const char *format, va_list ap)
{
    char log_buf[TLOG_MAX_LINE_LEN];
    size_t len = 0;
    size_t out_len = 0;
    int unused __attribute__((unused));

    if (tlog_disable_early_print) {
        return 0;
    }

    len = vsnprintf(log_buf, sizeof(log_buf), format, ap);
    out_len = len;
    if (len <= 0) {
        return -1;
    } else if (len >= sizeof(log_buf)) {
        out_len = sizeof(log_buf);
    }

    unused = write(STDOUT_FILENO, log_buf, out_len);
    if (log_buf[out_len - 1] != '\n') {
        unused = write(STDOUT_FILENO, "\n", 1);
    }

    return len;
}

int tlog_vext(tlog_level level, const char *file, int line, const char *func, void *userptr, const char *format, va_list ap)
{
    struct tlog_info_inter info_inter;

    if (level < tlog_set_level) {
        return 0;
    }

    if (tlog.root == NULL) {
        return _tlog_early_print(format, ap);
    }

    if (unlikely(tlog.root->logsize <= 0)) {
        return 0;
    }

    if (level >= TLOG_END) {
        return -1;
    }

    info_inter.info.file = file;
    info_inter.info.line = line;
    info_inter.info.func = func;
    info_inter.info.level = level;
    info_inter.userptr = userptr;
    if (_tlog_gettime(&info_inter.info.time) != 0) {
        return -1;
    }

    return _tlog_vprintf(tlog.root, _tlog_root_log_buffer, &info_inter, format, ap);
}

int tlog_ext(tlog_level level, const char *file, int line, const char *func, void *userptr, const char *format, ...)
{
    int len;
    va_list ap;

    va_start(ap, format);
    len = tlog_vext(level, file, line, func, userptr, format, ap);
    va_end(ap);

    return len;
}

static int _tlog_rename_logfile(struct tlog_log *log, const char *log_file)
{
    char archive_file[TLOG_BUFF_LEN];
    struct tlog_time logtime;
    int i = 0;

    if (_tlog_getmtime(&logtime, log_file) != 0) {
        return -1;
    }

    snprintf(archive_file, sizeof(archive_file), "%s/%s-%.4d%.2d%.2d-%.2d%.2d%.2d%s",
        log->logdir, log->logname, logtime.year, logtime.mon, logtime.mday,
        logtime.hour, logtime.min, logtime.sec, log->suffix);

    while (access(archive_file, F_OK) == 0) {
        i++;
        snprintf(archive_file, sizeof(archive_file), "%s/%s-%.4d%.2d%.2d-%.2d%.2d%.2d-%d%s",
            log->logdir, log->logname, logtime.year, logtime.mon,
            logtime.mday, logtime.hour, logtime.min, logtime.sec, i, log->suffix);
    }

    if (rename(log_file, archive_file) != 0) {
        return -1;
    }

    chmod(archive_file, log->archive_perm);

    return 0;
}

static int _tlog_list_dir(const char *path, list_callback callback, void *userptr)
{
    DIR *dir = NULL;
    struct dirent *ent;
    int ret = 0;
    const char *unused __attribute__((unused)) = path;

    dir = opendir(path);
    if (dir == NULL) {
        fprintf(stderr, "open directory failed, %s\n", strerror(errno));
        goto errout;
    }

    while ((ent = readdir(dir)) != NULL) {
        if (strncmp(".", ent->d_name, 2) == 0 || strncmp("..", ent->d_name, 3) == 0) {
            continue;
        }
        ret = callback(path, ent, userptr);
        if (ret != 0) {
            goto errout;
        }
    }

    closedir(dir);
    return 0;
errout:
    if (dir) {
        closedir(dir);
        dir = NULL;
    }
    return -1;
}

static int _tlog_count_log_callback(const char *path, struct dirent *entry, void *userptr)
{
    struct count_log *count_log = (struct count_log *)userptr;
    struct tlog_log *log = count_log->log;
    char logname[TLOG_LOG_NAME_LEN * 2];
    const char *unused __attribute__((unused)) = path;

    if (strstr(entry->d_name, log->suffix) == NULL) {
        return 0;
    }

    snprintf(logname, sizeof(logname), "%s-", log->logname);
    int len = strnlen(logname, sizeof(logname));
    if (strncmp(logname, entry->d_name, len) != 0) {
        return 0;
    }

    count_log->lognum++;
    return 0;
}

static int _tlog_get_oldest_callback(const char *path, struct dirent *entry, void *userptr)
{
    struct stat sb;
    char filename[TLOG_BUFF_LEN];
    struct oldest_log *oldestlog = (struct oldest_log *)userptr;
    struct tlog_log *log = oldestlog->log;
    char logname[TLOG_LOG_NAME_LEN * 2];

    /* if not a log file, skip */
    if (strstr(entry->d_name, log->suffix) == NULL) {
        return 0;
    }

    /* if not tlog log file, skip */
    snprintf(logname, sizeof(logname), "%s-", log->logname);
    int len = strnlen(logname, sizeof(logname));
    if (strncmp(logname, entry->d_name, len) != 0) {
        return 0;
    }

    /* get log file mtime */
    snprintf(filename, sizeof(filename), "%s/%s", path, entry->d_name);
    if (stat(filename, &sb) != 0) {
        return -1;
    }

    if (oldestlog->mtime == 0 || oldestlog->mtime > sb.st_mtime) {
        oldestlog->mtime = sb.st_mtime;
        strncpy(oldestlog->name, entry->d_name, sizeof(oldestlog->name) - 1);
        oldestlog->name[sizeof(oldestlog->name) - 1] = '\0';
        return 0;
    }

    return 0;
}

static int _tlog_remove_oldestlog(struct tlog_log *log)
{
    struct oldest_log oldestlog;
    oldestlog.name[0] = 0;
    oldestlog.mtime = 0;
    oldestlog.log = log;

    /* get oldest log file name */
    if (_tlog_list_dir(log->logdir, _tlog_get_oldest_callback, &oldestlog) != 0) {
        return -1;
    }

    char filename[PATH_MAX * 2];
    snprintf(filename, sizeof(filename), "%s/%s", log->logdir, oldestlog.name);

    /* delete */
    unlink(filename);

    return 0;
}

static int _tlog_remove_oldlog(struct tlog_log *log)
{
    struct count_log count_log;
    int i = 0;
    count_log.lognum = 0;
    count_log.log = log;

    /* get total log file number */
    if (_tlog_list_dir(log->logdir, _tlog_count_log_callback, &count_log) != 0) {
        fprintf(stderr, "get log file count failed.\n");
        return -1;
    }

    /* remove last N log files */
    for (i = 0; i < count_log.lognum - log->logcount; i++) {
        _tlog_remove_oldestlog(log);
    }

    return 0;
}

static void _tlog_log_unlock(struct tlog_log *log)
{
    char lock_file[PATH_MAX * 2];
    if (log->fd_lock <= 0) {
        return;
    }

    snprintf(lock_file, sizeof(lock_file), "%s/%s.lock", log->logdir, log->logname);
    unlink(lock_file);
    close(log->fd_lock);
    log->fd_lock = -1;
}

static int _tlog_log_lock(struct tlog_log *log)
{
    char lock_file[PATH_MAX * 2];
    int fd;

    if (log->multi_log == 0) {
        return 0;
    }

    snprintf(lock_file, sizeof(lock_file), "%s/%s.lock", log->logdir, log->logname);
    fd = open(lock_file, O_RDWR | O_CREAT | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        fprintf(stderr, "create pid file failed, %s", strerror(errno));
        return -1;
    }

    if (lockf(fd, F_TLOCK, 0) < 0) {
        goto errout;
    }

    log->fd_lock = fd;
    return 0;

errout:
    if (fd > 0) {
        close(fd);
    }
    return -1;
}

static void _tlog_wait_pid(struct tlog_log *log, int wait_hang)
{
    int status;
    if (log->zip_pid <= 0) {
        return;
    }

    int option = (wait_hang == 0) ? WNOHANG : 0;
    /* check and obtain gzip process status*/
    if (waitpid(log->zip_pid, &status, option) <= 0) {
        return;
    }

    /* gzip process exited */
    log->zip_pid = -1;
    char gzip_file[PATH_MAX * 2];

    /* rename ziped file */
    snprintf(gzip_file, sizeof(gzip_file), "%s/%s.pending.gz", log->logdir, log->logname);
    if (_tlog_rename_logfile(log, gzip_file) != 0) {
        _tlog_log_unlock(log);
        return;
    }

    /* remove oldes file */
    _tlog_remove_oldlog(log);
    _tlog_log_unlock(log);
}

static void _tlog_close_all_fd_by_res(void)
{
    struct rlimit lim;
    int maxfd = 0;
    int i = 0;

    getrlimit(RLIMIT_NOFILE, &lim);

    maxfd = lim.rlim_cur;
    if (maxfd > 4096) {
        maxfd = 4096;
    }

    for (i = 3; i < maxfd; i++) {
        close(i);
    }
}

static void _tlog_close_all_fd(void)
{
    char path_name[PATH_MAX];
    DIR *dir = NULL;
    struct dirent *ent;
    int dir_fd = -1;

    snprintf(path_name, sizeof(path_name), "/proc/self/fd/");
    dir = opendir(path_name);
    if (dir == NULL) {
        goto errout;
    }

    dir_fd = dirfd(dir);

    while ((ent = readdir(dir)) != NULL) {
        int fd = atoi(ent->d_name);
        if (fd < 0 || dir_fd == fd) {
            continue;
        }
        switch (fd) {
        case STDIN_FILENO:
        case STDOUT_FILENO:
        case STDERR_FILENO:
            continue;
            break;
        default:
            break;
        }

        close(fd);
    }

    closedir(dir);

    return;
errout:
    if (dir) {
        closedir(dir);
    }

    _tlog_close_all_fd_by_res();
    return;
}

static int _tlog_archive_log_compressed(struct tlog_log *log)
{
    char gzip_file[TLOG_BUFF_LEN];
    char gzip_cmd[PATH_MAX * 2];
    char log_file[TLOG_BUFF_LEN];
    char pending_file[TLOG_BUFF_LEN];

    snprintf(gzip_file, sizeof(gzip_file), "%s/%s.pending.gz", log->logdir, log->logname);
    snprintf(pending_file, sizeof(pending_file), "%s/%s.pending", log->logdir, log->logname);

    if (_tlog_log_lock(log) != 0) {
        return -1;
    }

    /* if pending.zip exists */
    if (access(gzip_file, F_OK) == 0) {
        /* rename it to standard name */
        if (_tlog_rename_logfile(log, gzip_file) != 0) {
            goto errout;
        }
    }

    if (access(pending_file, F_OK) != 0) {
        /* rename current log file to pending */
        snprintf(log_file, sizeof(log_file), "%s/%s", log->logdir, log->logname);
        if (rename(log_file, pending_file) != 0) {
            goto errout;
        }
    }

    /* start gzip process to compress log file */
    snprintf(gzip_cmd, sizeof(gzip_cmd), "gzip -1 %s", pending_file);
    if (log->zip_pid <= 0) {
        int pid = vfork();
        if (pid == 0) {
            _tlog_close_all_fd();
            execl("/bin/sh", "sh", "-c", gzip_cmd, NULL);
            _exit(1);
        } else if (pid < 0) {
            goto errout;
        }
        log->zip_pid = pid;
    }

    return 0;

errout:
    _tlog_log_unlock(log);
    return -1;
}

static int _tlog_archive_log_nocompress(struct tlog_log *log)
{
    char log_file[TLOG_BUFF_LEN];
    char pending_file[TLOG_BUFF_LEN];

    snprintf(pending_file, sizeof(pending_file), "%s/%s.pending", log->logdir, log->logname);

    if (_tlog_log_lock(log) != 0) {
        return -1;
    }

    if (access(pending_file, F_OK) != 0) {
        /* rename current log file to pending */
        snprintf(log_file, sizeof(log_file), "%s/%s", log->logdir, log->logname);
        if (rename(log_file, pending_file) != 0) {
            goto errout;
        }
    }

    /* rename pending file */
    if (_tlog_rename_logfile(log, pending_file) != 0) {
        goto errout;
    }

    /* remove oldes file */
    _tlog_remove_oldlog(log);
    _tlog_log_unlock(log);

    return 0;

errout:
    _tlog_log_unlock(log);
    return -1;
}

static int _tlog_archive_log(struct tlog_log *log)
{
    if (log->nocompress) {
        return _tlog_archive_log_nocompress(log);
    } else {
        return _tlog_archive_log_compressed(log);
    }
}

void _tlog_get_log_name_dir(struct tlog_log *log)
{
    char log_file[PATH_MAX];
    if (log->fd > 0) {
        close(log->fd);
        log->fd = -1;
    }

    pthread_mutex_lock(&tlog.lock);
    strncpy(log_file, log->pending_logfile, sizeof(log_file) - 1);
    log_file[sizeof(log_file) - 1] = '\0';
    strncpy(log->logdir, dirname(log_file), sizeof(log->logdir));
    log->logdir[sizeof(log->logdir) - 1] = '\0';
    strncpy(log_file, log->pending_logfile, PATH_MAX);
    log_file[sizeof(log_file) - 1] = '\0';
    strncpy(log->logname, basename(log_file), sizeof(log->logname));
    log->logname[sizeof(log->logname) - 1] = '\0';
    pthread_mutex_unlock(&tlog.lock);
}

static int _tlog_write(struct tlog_log *log, const char *buff, int bufflen)
{
    int len;
    int unused __attribute__((unused));

    if (bufflen <= 0 || log->fail) {
        return 0;
    }

    if (log->rename_pending) {
        _tlog_get_log_name_dir(log);
        log->rename_pending = 0;
    }

    /* output log to screen */
    if (log->logscreen) {
        unused = write(STDOUT_FILENO, buff, bufflen);
    }

    /* if log file size exceeds threshold, start to compress */
    if (log->multi_log && log->fd > 0) {
        log->filesize = lseek(log->fd, 0, SEEK_END);
    }

    if (log->filesize > log->logsize && log->zip_pid <= 0) {
        if (log->filesize < lseek(log->fd, 0, SEEK_END) && log->multi_log == 0) {
            const char *msg = "[Auto enable multi-process write mode, log may be lost, please enable multi-process write mode manually]\n";
            log->multi_log = 1;
            unused = write(log->fd, msg, strlen(msg));
        }
        close(log->fd);
        log->fd = -1;
        log->filesize = 0;
        _tlog_archive_log(log);
    }

    if (log->fd <= 0) {
        /* open a new log file to write */
        static int print_errmsg = 1;
        time_t now;

        time(&now);
        if (now == log->last_try) {
            return -1;
        }
        log->last_try = now;

        char logfile[PATH_MAX * 2];
        if (_tlog_mkdir(log->logdir) != 0) {
            fprintf(stderr, "create log dir %s failed.\n", log->logdir);
            return -1;
        }
        snprintf(logfile, sizeof(logfile), "%s/%s", log->logdir, log->logname);
        log->filesize = 0;
        log->fd = open(logfile, O_APPEND | O_CREAT | O_WRONLY | O_CLOEXEC, log->file_perm);
        if (log->fd < 0) {
            if (print_errmsg == 0) {
                return -1;
            }

            fprintf(stderr, "open log file %s failed, %s\n", logfile, strerror(errno));
            print_errmsg = 0;
            return -1;
        }

        log->last_try = 0;
        print_errmsg = 1;
        /* get log file size */
        log->filesize = lseek(log->fd, 0, SEEK_END);
    }

    /* write log to file */
    len = write(log->fd, buff, bufflen);
    if (len > 0) {
        log->filesize += len;
    } else {
        if (log->fd > 0 && errno == ENOSPC) {
            close(log->fd);
            log->fd = -1;
        }
    }
    return len;
}

int tlog_write(struct tlog_log *log, const char *buff, int bufflen)
{
    return _tlog_write(log, buff, bufflen);
}

static int _tlog_has_data(struct tlog_log *log)
{
    if (log->end != log->start || log->ext_end > 0) {
        return 1;
    }

    return 0;
}

static int _tlog_any_has_data_locked(void)
{
    struct tlog_log *next = NULL;

    next = tlog.log;
    while (next) {
        if (_tlog_has_data(next) == 1) {
            return 1;
        }
        next = next->next;
    }

    return 0;
}

static int _tlog_any_has_data(void)
{
    int ret = 0;
    pthread_mutex_lock(&tlog.lock);
    ret = _tlog_any_has_data_locked();
    pthread_mutex_unlock(&tlog.lock);

    return ret;
}

static int _tlog_wait_pids(void)
{
    time_t now = time(NULL);
    struct tlog_log *next = NULL;
    static struct tlog_log *last_log = NULL;

    pthread_mutex_lock(&tlog.lock);
    for (next = tlog.log; next != NULL; next = next->next) {
        if (next->zip_pid <= 0) {
            continue;
        }

        if (next == last_log) {
            continue;
        }

        if (next->last_waitpid == now) {
            continue;
        }

        last_log = next;
        next->last_waitpid = now;
        pthread_mutex_unlock(&tlog.lock);
        _tlog_wait_pid(next, 0);
        return 0;
    }
    last_log = NULL;
    pthread_mutex_unlock(&tlog.lock);

    return 0;
}

static int _tlog_close(struct tlog_log *log, int wait_hang)
{
    struct tlog_log *next = tlog.log;

    if (log == NULL) {
        return -1;
    }

    if (log->zip_pid > 0) {
        _tlog_wait_pid(log, wait_hang);
        if (log->zip_pid > 0) {
            return -1;
        }
    }

    if (log->fd > 0) {
        close(log->fd);
        log->fd = -1;
    }

    _tlog_log_unlock(log);

    if (log->buff != NULL) {
        free(log->buff);
        log->buff = NULL;
    }

    if (next == log) {
        tlog.log = next->next;
        free(log);
        return 0;
    }

    while (next) {
        if (next->next == log) {
            next->next = log->next;
            free(log);
            return -1;
        }
        next = next->next;
    }

    pthread_cond_destroy(&log->client_cond);
    pthread_mutex_destroy(&log->lock);

    return 0;
}

static struct tlog_log *_tlog_next_log(struct tlog_log *last_log)
{
    if (last_log == NULL) {
        return tlog.log;
    }

    return last_log->next;
}

static struct tlog_log *_tlog_wait_log_locked(struct tlog_log *last_log)
{
    int ret = 0;
    struct timespec tm;
    struct tlog_log *log = NULL;

    clock_gettime(CLOCK_REALTIME, &tm);
    tm.tv_sec += 2;
    tlog.is_wait = 1;
    tlog.wait_on_log = last_log;
    ret = pthread_cond_timedwait(&tlog.cond, &tlog.lock, &tm);
    tlog.is_wait = 0;
    tlog.wait_on_log = NULL;
    errno = ret;
    if (ret == 0 || ret == ETIMEDOUT) {
        log = tlog.notify_log;
        tlog.notify_log = NULL;
    }

    return log;
}

static void _tlog_wakeup_waiters(struct tlog_log *log)
{
    pthread_mutex_lock(&log->lock);
    if (log->waiters > 0) {
        /* if there are waiters, wakeup */
        pthread_cond_broadcast(&log->client_cond);
    }
    pthread_mutex_unlock(&log->lock);
}

static void _tlog_write_one_segment_log(struct tlog_log *log, char *buff, int bufflen)
{
    struct tlog_segment_head *segment_head = NULL;
    int write_len = 0;

    segment_head = (struct tlog_segment_head *)buff;
    for (write_len = 0; write_len < bufflen;) {
        if (segment_head->magic != TLOG_SEGMENT_MAGIC) {
            return;
        }

        log->output_func(log, segment_head->data, segment_head->len - 1);
        write_len += segment_head->len + sizeof(*segment_head);
        segment_head = (struct tlog_segment_head *)(buff + write_len);
    }
}

static void _tlog_write_segments_log(struct tlog_log *log, int log_len, int log_extlen)
{
    _tlog_write_one_segment_log(log, log->buff + log->start, log_len);
    if (log_extlen > 0) {
        /* write extend buffer log */
        _tlog_write_one_segment_log(log, log->buff, log_extlen);
    }
}

static void _tlog_write_buff_log(struct tlog_log *log, int log_len, int log_extlen)
{
    log->output_func(log, log->buff + log->start, log_len);
    if (log_extlen > 0) {
        /* write extend buffer log */
        log->output_func(log, log->buff, log_extlen);
    }
}

static void _tlog_work_write(struct tlog_log *log, int log_len, int log_extlen, int log_dropped)
{
    /* write log */
    if (log->segment_log) {
        _tlog_write_segments_log(log, log_len, log_extlen);
    } else {
        _tlog_write_buff_log(log, log_len, log_extlen);
    }

    if (log_dropped > 0) {
        /* if there is dropped log, record dropped log number */
        char dropmsg[TLOG_TMP_LEN];
        snprintf(dropmsg, sizeof(dropmsg), "[Totoal Dropped %d Messages]\n", log_dropped);
        log->output_func(log, dropmsg, strnlen(dropmsg, sizeof(dropmsg)));
    }
}

static int _tlog_root_write_log(struct tlog_log *log, const char *buff, int bufflen)
{
    struct tlog_segment_log_head *head = NULL;
    static struct tlog_segment_log_head empty_info;
    if (tlog.output_func == NULL) {
        if (log->segment_log) {
            head = (struct tlog_segment_log_head *)buff;
            return _tlog_write(log, head->data, head->len);
        }
        return _tlog_write(log, buff, bufflen);
    }

    if (log->segment_log && tlog.root == log) {
        head = (struct tlog_segment_log_head *)buff;
        return tlog.output_func(&head->info, head->data, head->len - 1, tlog_get_private(log));
    }

    return tlog.output_func(&empty_info.info, buff, bufflen, tlog_get_private(log));
}

static void *_tlog_work(void *arg)
{
    int log_len = 0;
    int log_extlen = 0;
    int log_end = 0;
    int log_extend = 0;
    int log_dropped = 0;
    struct tlog_log *log = NULL;
    struct tlog_log *loop_log = NULL;
    void *unused __attribute__((unused));

    unused = arg;

    while (1) {
        log_len = 0;
        log_extlen = 0;
        log_extend = 0;
        if (tlog.run == 0) {
            if (_tlog_any_has_data() == 0) {
                break;
            }
        }

        _tlog_wait_pids();

        pthread_mutex_lock(&tlog.lock);
        if (loop_log == NULL) {
            loop_log = log;
        }

        log = _tlog_next_log(log);
        if (log == NULL) {
            pthread_mutex_unlock(&tlog.lock);
            continue;
        }

        /* if buffer is empty, wait */
        if (_tlog_any_has_data_locked() == 0 && tlog.run) {
            log = _tlog_wait_log_locked(log);
            if (log == NULL) {
                pthread_mutex_unlock(&tlog.lock);
                if (errno != ETIMEDOUT && tlog.run) {
                    sleep(1);
                }
                continue;
            }
        }

        if (_tlog_has_data(log) == 0) {
            if (log->is_exit) {
                if (_tlog_close(log, 0) == 0) {
                    log = NULL;
                    loop_log = NULL;
                };
            }
            pthread_mutex_unlock(&tlog.lock);
            continue;
        }

        loop_log = NULL;

        if (log->ext_end > 0) {
            log_len = log->ext_end - log->start;
            log_extend = log->ext_end;
        }
        if (log->end < log->start) {
            log_extlen = log->end;
        } else if (log->end > log->start) {
            log_len = log->end - log->start;
        }
        log_end = log->end;
        log_dropped = log->dropped;
        log->dropped = 0;
        pthread_mutex_unlock(&tlog.lock);

        /* start write log work */
        _tlog_work_write(log, log_len, log_extlen, log_dropped);

        pthread_mutex_lock(&tlog.lock);
        /* release finished buffer */
        log->start = log_end;
        if (log_extend > 0) {
            log->ext_end = 0;
        }
        pthread_mutex_unlock(&tlog.lock);

        _tlog_wakeup_waiters(log);
    }

    return NULL;
}

void tlog_set_early_printf(int enable)
{
    tlog_disable_early_print = (enable == 0) ? 1 : 0;
}

const char *tlog_get_level_string(tlog_level level)
{
    if (level >= TLOG_END) {
        return NULL;
    }

    return tlog_level_str[level];
}

static void _tlog_log_setlogscreen(struct tlog_log *log, int enable)
{
    if (log == NULL) {
        return;
    }

    log->logscreen = (enable != 0) ? 1 : 0;
}

void tlog_setlogscreen(int enable)
{
    _tlog_log_setlogscreen(tlog.root, enable);
}

int tlog_write_log(char *buff, int bufflen)
{
    if (unlikely(tlog.root == NULL)) {
        return -1;
    }

    return _tlog_write(tlog.root, buff, bufflen);
}

void tlog_logscreen(tlog_log *log, int enable)
{
    if (log == NULL) {
        return;
    }

    _tlog_log_setlogscreen(log, enable);
}

int tlog_reg_output_func(tlog_log *log, tlog_output_func output)
{
    if (log == NULL) {
        return -1;
    }

    if (output == NULL) {
        log->output_func = _tlog_write;
        return 0;
    }

    log->output_func = output;

    return 0;
}

int tlog_reg_format_func(tlog_format_func callback)
{
    tlog_format = callback;
    return 0;
}

int tlog_reg_log_output_func(tlog_log_output_func output, void *private_data)
{
    tlog.output_func = output;
    tlog_set_private(tlog.root, private_data);
    return 0;
}

int tlog_setlevel(tlog_level level)
{
    if (level >= TLOG_END) {
        return -1;
    }

    tlog_set_level = level;
    return 0;
}

tlog_level tlog_getlevel(void)
{
    return tlog_set_level;
}

void tlog_set_logfile(const char *logfile)
{
    tlog_rename_logfile(tlog.root, logfile);
}

tlog_log *tlog_open(const char *logfile, int maxlogsize, int maxlogcount, int buffsize, unsigned int flag)
{
    struct tlog_log *log = NULL;

    if (tlog.run == 0) {
        fprintf(stderr, "tlog is not initialized.");
        return NULL;
    }

    log = (struct tlog_log *)malloc(sizeof(*log));
    if (log == NULL) {
        fprintf(stderr, "malloc log failed.");
        return NULL;
    }

    memset(log, 0, sizeof(*log));
    log->start = 0;
    log->end = 0;
    log->ext_end = 0;
    log->dropped = 0;
    log->buffsize = (buffsize > 0) ? buffsize : TLOG_BUFF_SIZE;
    log->logsize = (maxlogsize >= 0) ? maxlogsize : TLOG_LOG_SIZE;
    log->logcount = (maxlogcount > 0) ? maxlogcount : TLOG_LOG_COUNT;
    log->fd = -1;
    log->filesize = 0;
    log->zip_pid = -1;
    log->is_exit = 0;
    log->fail = 0;
    log->waiters = 0;
    log->block = ((flag & TLOG_NONBLOCK) == 0) ? 1 : 0;
    log->nocompress = ((flag & TLOG_NOCOMPRESS) == 0) ? 0 : 1;
    log->logscreen = ((flag & TLOG_SCREEN) == 0) ? 0 : 1;
    log->multi_log = ((flag & TLOG_MULTI_WRITE) == 0) ? 0 : 1;
    log->segment_log = ((flag & TLOG_SEGMENT) == 0) ? 0 : 1;
    log->max_line_size = TLOG_MAX_LINE_LEN;
    log->output_func = _tlog_write;
    log->file_perm = S_IRUSR | S_IWUSR | S_IRGRP;
    log->archive_perm = S_IRUSR | S_IRGRP;

    tlog_rename_logfile(log, logfile);
    if (log->nocompress) {
        strncpy(log->suffix, TLOG_SUFFIX_LOG, sizeof(log->suffix));
    } else {
        strncpy(log->suffix, TLOG_SUFFIX_GZ, sizeof(log->suffix));
    }

    log->buff = (char *)malloc(log->buffsize);
    if (log->buff == NULL) {
        fprintf(stderr, "malloc log buffer failed, %s\n", strerror(errno));
        goto errout;
    }

    pthread_mutex_lock(&tlog.lock);
    if (tlog.log == NULL) {
        tlog.log = log;
    } else {
        log->next = tlog.log;
        tlog.log = log;
    }
    pthread_mutex_unlock(&tlog.lock);

    return log;

errout:
    if (log) {
        pthread_cond_destroy(&log->client_cond);
        pthread_mutex_destroy(&log->lock);
        free(log);
        log = NULL;
    }

    return NULL;
}

void tlog_close(tlog_log *log)
{
    if (log == NULL) {
        return;
    }

    log->is_exit = 1;
}

void tlog_rename_logfile(struct tlog_log *log, const char *logfile)
{
    pthread_mutex_lock(&tlog.lock);
    strncpy(log->pending_logfile, logfile, sizeof(log->pending_logfile) - 1);
    pthread_mutex_unlock(&tlog.lock);
    log->rename_pending = 1;
}

static void tlog_fork_prepare(void)
{
    if (tlog.root == NULL) {
        return;
    }

    pthread_mutex_lock(&tlog.lock);
}

static void tlog_fork_parent(void)
{
    if (tlog.root == NULL) {
        return;
    }

    pthread_mutex_unlock(&tlog.lock);
}

static void tlog_fork_child(void)
{
    pthread_attr_t attr;
    tlog_log *next;
    if (tlog.root == NULL) {
        return;
    }

    pthread_attr_init(&attr);
    int ret = pthread_create(&tlog.tid, &attr, _tlog_work, NULL);
    if (ret != 0) {
        fprintf(stderr, "create tlog work thread failed, %s\n", strerror(errno));
        goto errout;
    }

    goto out;
errout:
    next = tlog.log;
    while (next) {
        next->fail = 1;
        next = next->next;
    }
out:
    pthread_mutex_unlock(&tlog.lock);
}

int tlog_init(const char *logfile, int maxlogsize, int maxlogcount, int buffsize, unsigned int flag)
{
    pthread_attr_t attr;
    int ret;
    struct tlog_log *log = NULL;

    if (tlog_format != NULL) {
        fprintf(stderr, "tlog already initilized.\n");
        return -1;
    }

    if (buffsize > 0 && buffsize < TLOG_MAX_LINE_SIZE_SET * 2) {
        fprintf(stderr, "buffer size is invalid.\n");
        return -1;
    }

    tlog_format = _tlog_format;

    memset(&tlog, 0, sizeof(tlog));
    tlog.is_wait = 0;

    pthread_attr_init(&attr);
    pthread_cond_init(&tlog.cond, NULL);
    pthread_mutex_init(&tlog.lock, NULL);
    tlog.run = 1;

    log = tlog_open(logfile, maxlogsize, maxlogcount, buffsize, flag);
    if (log == NULL) {
        fprintf(stderr, "init tlog root failed.\n");
        goto errout;
    }
    tlog_reg_output_func(log, _tlog_root_write_log);

    ret = pthread_create(&tlog.tid, &attr, _tlog_work, NULL);
    if (ret != 0) {
        fprintf(stderr, "create tlog work thread failed, %s\n", strerror(errno));
        goto errout;
    }

    tlog.root = log;
    if (flag & TLOG_SUPPORT_FORK) {
        pthread_atfork(&tlog_fork_prepare, &tlog_fork_parent, &tlog_fork_child);
    }
    return 0;
errout:
    if (tlog.tid > 0) {
        void *retval = NULL;
        tlog.run = 0;
        pthread_join(tlog.tid, &retval);
    }

    pthread_cond_destroy(&tlog.cond);
    pthread_mutex_destroy(&tlog.lock);
    tlog.run = 0;

    _tlog_close(log, 1);

    return -1;
}

void tlog_exit(void)
{
    if (tlog.tid > 0) {
        void *ret = NULL;
        tlog.run = 0;
        pthread_mutex_lock(&tlog.lock);
        pthread_cond_signal(&tlog.cond);
        pthread_mutex_unlock(&tlog.lock);
        pthread_join(tlog.tid, &ret);
    }

    tlog.root = NULL;
    while (tlog.log) {
        _tlog_close(tlog.log, 1);
    }

    pthread_cond_destroy(&tlog.cond);
    pthread_mutex_destroy(&tlog.lock);
}
