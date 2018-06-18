/*
 * Copyright (C) 2018 Ruilin Peng (Nick) <pymumu@gmail.com>
 */
#define _GNU_SOURCE 
#include "tlog.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define TLOG_BUFF_SIZE (1024 * 128)
#define TLOG_MAX_LINE_LEN (1024)
#define TLOG_TMP_LEN 128
#define TLOG_LOG_SIZE (1024 * 1024 * 50)
#define TLOG_LOG_COUNT 32

struct oldest_log {
    char name[TLOG_TMP_LEN];
    time_t mtime;
};

struct tlog {
    char *buff;
    int buffsize;
    int start;
    int end;
    int ext_end;

    int run;
    pthread_t tid;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    pthread_cond_t client_cond;
    int waiters;
    int is_wait;

    int fd;
    int fd_lock;

    off_t filesize;
    char logdir[PATH_MAX];
    char logname[PATH_MAX];
    int logsize;
    int logcount;
    int block;
    int dropped;
    int zip_pid;
    int multi_log;
    int logscreen;
};

typedef int (*list_callback)(const char *name, struct dirent *entry, void *user);

struct tlog tlog;
static tlog_level tlog_set_level = TLOG_INFO;
tlog_format_func tlog_format;
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

    strncpy(path_c, path, sizeof(path_c) - 1);
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
    static time_t last_time = {0};
    static struct tm last_tm = {0};

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

static int _tlog_format(char *buff, int maxlen, struct tlog_info *info, void *userptr, const char *format, va_list ap)
{
    int len = 0;
    int total_len = 0;
    struct tlog_time *tm = &info->time;

    if (tlog.multi_log) {
        /* format prefix */
        len = snprintf(buff, maxlen, "[%.4d-%.2d-%.2d %.2d:%.2d:%.2d,%.3d][%5d][%4s][%17s:%-4d] ",
            tm->year, tm->mon, tm->mday, tm->hour, tm->min, tm->sec, tm->usec / 1000, getpid(),
            info->level, info->file, info->line);
    } else {
        /* format prefix */
        len = snprintf(buff, maxlen, "[%.4d-%.2d-%.2d %.2d:%.2d:%.2d,%.3d][%5s][%17s:%-4d] ",
            tm->year, tm->mon, tm->mday, tm->hour, tm->min, tm->sec, tm->usec / 1000,
            info->level, info->file, info->line);
    }

    if (len < 0 || len == maxlen) {
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

static int _tlog_log_buffer(char *buff, int maxlen, tlog_level level, const char *file, int line, const char *func, void *userptr, const char *format, va_list ap)
{
    int len;
    struct tlog_info info;

    if (tlog_format == NULL) {
        return -1;
    }

    if (level >= TLOG_END) {
        return -1;
    }

    info.file = file;
    info.line = line;
    info.func = func;
    info.level = tlog_level_str[level];

    if (_tlog_gettime(&info.time) != 0) {
        return -1;
    }

    len = tlog_format(buff, maxlen, &info, userptr, format, ap);
    if (len < 0) {
        return -1;
    }

    /* add new line character*/
    if (*(buff + len - 1) != '\n' && len + 1 < maxlen - len) {
        *(buff + len) = '\n';
        len++;
    }

    return len;
}

int tlog_vext(tlog_level level, const char *file, int line, const char *func, void *userptr, const char *format, va_list ap)
{
    int len;
    int maxlen = 0;

    if (tlog.buff == NULL) {
        return -1;
    }

    if (level < tlog_set_level) {
        return 0;
    }

    pthread_mutex_lock(&tlog.lock);
    do {
        if (tlog.end == tlog.start) {
            if (tlog.ext_end == 0) {
                /* if buffer is empty */
                maxlen = tlog.buffsize - tlog.end;
            }
        } else if (tlog.end > tlog.start) {
            maxlen = tlog.buffsize - tlog.end;
        } else {
            /* if reverse */
            maxlen = tlog.start - tlog.end;
        }

        /* if free buffer length is less than min line length */
        if (maxlen < TLOG_MAX_LINE_LEN) {
            if (tlog.end != tlog.start) {
                pthread_cond_signal(&tlog.cond);
            }

            /* if drop message, increase statistics and return */
            if (tlog.block == 0) {
                tlog.dropped++;
                pthread_mutex_unlock(&tlog.lock);
                return -1;
            }
            tlog.waiters++;
            /* block wait for free buffer */
            int ret = pthread_cond_wait(&tlog.client_cond, &tlog.lock);
            tlog.waiters--;
            if (ret < 0) {
                pthread_mutex_unlock(&tlog.lock);
                return -1;
            }
        }
    } while (maxlen < TLOG_MAX_LINE_LEN);

    /* write log to buffer */
    len = _tlog_log_buffer(tlog.buff + tlog.end, maxlen, level, file, line, func, userptr, format, ap);
    if (len <= 0) {
        pthread_mutex_unlock(&tlog.lock);
        return -1;
    }
    tlog.end += len;
    /* if remain buffer is not enough for a line, move end to start of buffer. */
    if (tlog.end > tlog.buffsize - TLOG_MAX_LINE_LEN) {
        tlog.ext_end = tlog.end;
        tlog.end = 0;
    }
    if (tlog.is_wait) {
        pthread_cond_signal(&tlog.cond);
    }
    pthread_mutex_unlock(&tlog.lock);
    return len;
}

int tlog_ext(tlog_level level, const char *file, int line, const char *func, void *userptr,
    const char *format, ...)
{
    int len;
    va_list ap;

    va_start(ap, format);
    len = tlog_vext(level, file, line, func, userptr, format, ap);
    va_end(ap);

    return len;
}

static int _tlog_rename_logfile(const char *gzip_file)
{
    char archive_file[PATH_MAX];
    struct tlog_time logtime;
    int i = 0;

    if (_tlog_getmtime(&logtime, gzip_file) != 0) {
        return -1;
    }

    snprintf(archive_file, sizeof(archive_file), "%s/%s-%.4d%.2d%.2d-%.2d%.2d%.2d.gz",
        tlog.logdir, tlog.logname, logtime.year, logtime.mon, logtime.mday,
        logtime.hour, logtime.min, logtime.sec);

    while (access(archive_file, F_OK) == 0) {
        i++;
        snprintf(archive_file, sizeof(archive_file), "%s/%s-%.4d%.2d%.2d-%.2d%.2d%.2d-%d.gz",
            tlog.logdir, tlog.logname, logtime.year, logtime.mon, logtime.mday,
            logtime.hour, logtime.min, logtime.sec, i);
    }

    if (rename(gzip_file, archive_file) != 0) {
        return -1;
    }

    return 0;
}

static int _tlog_list_dir(const char *path, list_callback callback, void *userptr)
{
    DIR *dir = NULL;
    struct dirent *ent;
    int ret = 0;

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
    int *lognum = (int *)userptr;

    if (strstr(entry->d_name, ".gz") == NULL) {
        return 0;
    }

    int len = strnlen(tlog.logname, sizeof(tlog.logname));
    if (strncmp(tlog.logname, entry->d_name, len) != 0) {
        return 0;
    }

    (*lognum)++;
    return 0;
}

static int _tlog_get_oldest_callback(const char *path, struct dirent *entry, void *userptr)
{
    struct stat sb;
    char filename[PATH_MAX];
    struct oldest_log *oldestlog = userptr;

    /* if not a gz file, skip */
    if (strstr(entry->d_name, ".gz") == NULL) {
        return 0;
    }

    /* if not tlog gz file, skip */
    int len = strnlen(tlog.logname, sizeof(tlog.logname));
    if (strncmp(tlog.logname, entry->d_name, len) != 0) {
        return 0;
    }

    /* get log file mtime */
    snprintf(filename, sizeof(filename), "%s/%s", path, entry->d_name);
    if (stat(filename, &sb) != 0) {
        return -1;
    }

    if (oldestlog->mtime == 0 || oldestlog->mtime > sb.st_mtime) {
        oldestlog->mtime = sb.st_mtime;
        strncpy(oldestlog->name, entry->d_name, sizeof(oldestlog->name));
        return 0;
    }

    return 0;
}

static int _tlog_remove_oldestlog(void)
{
    struct oldest_log oldestlog;
    oldestlog.name[0] = 0;
    oldestlog.mtime = 0;

    /* get oldest log file name */
    if (_tlog_list_dir(tlog.logdir, _tlog_get_oldest_callback, &oldestlog) != 0) {
        return -1;
    }

    char filename[PATH_MAX];
    snprintf(filename, sizeof(filename), "%s/%s", tlog.logdir, oldestlog.name);

    /* delete */
    unlink(filename);

    return 0;
}

static int _tlog_remove_oldlog(void)
{
    int lognum = 0;
    int i = 0;

    /* get total log file number */
    if (_tlog_list_dir(tlog.logdir, _tlog_count_log_callback, &lognum) != 0) {
        fprintf(stderr, "get log file count failed.\n");
        return -1;
    }

    /* remove last N log files */
    for (i = 0; i < lognum - tlog.logcount; i++) {
        _tlog_remove_oldestlog();
    }

    return 0;
}

static void _tlog_log_unlock(void)
{
    char lock_file[PATH_MAX];
    if (tlog.fd_lock <= 0) {
        return;
    }

    snprintf(lock_file, sizeof(lock_file), "%s/%s.lock", tlog.logdir, tlog.logname);
    unlink(lock_file);
    close(tlog.fd_lock);
    tlog.fd_lock = -1;
}

static int _tlog_log_lock(void)
{
    char lock_file[PATH_MAX];
    int fd;

    if (tlog.multi_log == 0) {
        return 0;
    }

    snprintf(lock_file, sizeof(lock_file), "%s/%s.lock", tlog.logdir, tlog.logname);
    fd = open(lock_file, O_RDWR | O_CREAT | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        fprintf(stderr, "create pid file failed, %s", strerror(errno));
        return -1;
    }

    if (lockf(fd, F_TLOCK, 0) < 0) {
        goto errout;
    }

    tlog.fd_lock = fd;
    return 0;

errout:
    if (fd > 0) {
        close(fd);
    }
    return -1;
}

static void _tlog_wait_pid(int wait_hang)
{
    int status;
    if (tlog.zip_pid <= 0) {
        return;
    }

    int option = (wait_hang == 0) ? WNOHANG : 0;
    /* check and obtain gzip process status*/
    if (waitpid(tlog.zip_pid, &status, option) <= 0) {
        return;
    }

    /* gzip process exited */
    tlog.zip_pid = -1;
    char gzip_file[PATH_MAX];

    /* rename ziped file */
    snprintf(gzip_file, sizeof(gzip_file), "%s/%s.pending.gz", tlog.logdir, tlog.logname);
    if (_tlog_rename_logfile(gzip_file) != 0) {
        _tlog_log_unlock();
        return;
    }

    /* remove oldes file */
    _tlog_remove_oldlog();
    _tlog_log_unlock();
}

static int _tlog_archive_log(void)
{
    char gzip_file[PATH_MAX];
    char gzip_cmd[PATH_MAX];
    char log_file[PATH_MAX];
    char pending_file[PATH_MAX];

    snprintf(gzip_file, sizeof(gzip_file), "%s/%s.pending.gz", tlog.logdir, tlog.logname);
    snprintf(pending_file, sizeof(pending_file), "%s/%s.pending", tlog.logdir, tlog.logname);

    if (_tlog_log_lock() != 0) {
        return -1;
    }

    /* if pending.zip exists */
    if (access(gzip_file, F_OK) == 0) {
        /* rename it to standard name */
        if (_tlog_rename_logfile(gzip_file) != 0) {
            goto errout;
        }
    }

    if (access(pending_file, F_OK) != 0) {
        /* rename current log file to pending */
        snprintf(log_file, sizeof(log_file), "%s/%s", tlog.logdir, tlog.logname);
        if (rename(log_file, pending_file) != 0) {
            goto errout;
        }
    }

    /* start gzip process to compress log file */
    snprintf(gzip_cmd, sizeof(gzip_cmd), "gzip -1 %s", pending_file);
    if (tlog.zip_pid <= 0) {
        int pid = vfork();
        if (pid == 0) {
            execl("/bin/sh", "sh", "-c", gzip_cmd, NULL);
            _exit(1);
        } else if (pid < 0) {
            goto errout;
        }
        tlog.zip_pid = pid;
    }

    return 0;

errout:
    _tlog_log_unlock();
    return -1;
}

static int _tlog_write_log(char *buff, int bufflen)
{
    int len;

    /* if log file size exceeds threshold, start to compress */
    if (tlog.multi_log) {
        tlog.filesize = lseek(tlog.fd, 0, SEEK_END);
    }

    if (tlog.filesize > tlog.logsize && tlog.zip_pid <= 0) {
        if (tlog.filesize < lseek(tlog.fd, 0, SEEK_END) && tlog.multi_log == 0) {
            const char *msg = "[Auto enable multi-process write mode, log may be lost, please enable multi-process write mode manually]\n";
            tlog.multi_log = 1;
            write(tlog.fd, msg, strlen(msg));
        }
        close(tlog.fd);
        tlog.fd = -1;
        tlog.filesize = 0;
        _tlog_archive_log();
    }

    if (tlog.fd <= 0) {
        /* open a new log file to write */
        char logfile[PATH_MAX];
        if (_tlog_mkdir(tlog.logdir) != 0) {
            fprintf(stderr, "create log dir %s failed.\n", tlog.logdir);
            return -1;
        }
        snprintf(logfile, sizeof(logfile), "%s/%s", tlog.logdir, tlog.logname);
        tlog.filesize = 0;
        tlog.fd = open(logfile, O_APPEND | O_CREAT | O_WRONLY | O_CLOEXEC, 0640);
        if (tlog.fd < 0) {
            fprintf(stderr, "open log file %s failed, %s\n", logfile, strerror(errno));
            return -1;
        }

        /* get log file size */
        tlog.filesize = lseek(tlog.fd, 0, SEEK_END);
    }

    /* output log to screen */
    if (tlog.logscreen) {
        write(STDOUT_FILENO, buff, bufflen);
    }

    /* write log to file */
    len = write(tlog.fd, buff, bufflen);
    if (len > 0) {
        tlog.filesize += len;
    }

    return len;
}

static void *_tlog_work(void *arg)
{
    int ret = 0;
    int log_len;
    int log_extlen;
    int log_end;
    int log_extend;
    int log_dropped;
    struct timespec tm;
    time_t now = time(0);
    time_t last = now;

    while (tlog.run || tlog.end != tlog.start || tlog.ext_end > 0) {
        log_len = 0;
        log_end = 0;
        log_extlen = 0;
        log_extend = 0;

        /* if compressing */
        if (tlog.zip_pid > 0) {
            now = time(0);
            if (now != last) {
                /* try to archive compressed file */
                _tlog_wait_pid(0);
                last = now;
            }
        }

        pthread_mutex_lock(&tlog.lock);
        if (tlog.end == tlog.start && tlog.ext_end == 0) {
            /* if buffer is empty, wait */
            clock_gettime(CLOCK_REALTIME, &tm);
            tm.tv_sec += 5;
            tlog.is_wait = 1;
            ret = pthread_cond_timedwait(&tlog.cond, &tlog.lock, &tm);
            tlog.is_wait = 0;
            if (ret < 0 || ret == ETIMEDOUT) {
                pthread_mutex_unlock(&tlog.lock);
                if (ret == ETIMEDOUT) {
                    continue;
                }
                sleep(1);
                continue;
            }
        }

        if (tlog.ext_end > 0) {
            log_len = tlog.ext_end - tlog.start;
            log_extend = tlog.ext_end;
        }
        if (tlog.end < tlog.start) {
            log_extlen = tlog.end;
        } else if (tlog.end > tlog.start) {
            log_len = tlog.end - tlog.start;
        }
        log_end = tlog.end;
        log_dropped = tlog.dropped;
        tlog.dropped = 0;
        pthread_mutex_unlock(&tlog.lock);

        /* write log */
        _tlog_write_log(tlog.buff + tlog.start, log_len);
        if (log_extlen > 0) {
            /* write extend buffer log */
            _tlog_write_log(tlog.buff, log_extlen);
        }

        if (log_dropped > 0) {
            /* if there is dropped log, record dropped log number */
            char dropmsg[TLOG_TMP_LEN];
            snprintf(dropmsg, sizeof(dropmsg), "[Totoal Dropped %d Messages]\n", log_dropped);
            _tlog_write_log(dropmsg, strnlen(dropmsg, sizeof(dropmsg)));
        }

        pthread_mutex_lock(&tlog.lock);
        /* release finished buffer */
        tlog.start = log_end;
        if (log_extend > 0) {
            tlog.ext_end = 0;
        }

        if (tlog.waiters > 0) {
            /* if there are waiters, wakeup */
            pthread_cond_broadcast(&tlog.client_cond);
        }
        pthread_mutex_unlock(&tlog.lock);

        /* sleep for a while to reduce cpu usage */
        usleep(20 * 1000);
    }
    return NULL;
}

void tlog_setlogscreen(int enable)
{
    tlog.logscreen = (enable != 0) ? 1 : 0;
}

int tlog_reg_format_func(tlog_format_func callback)
{
    tlog_format = callback;
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

int tlog_init(const char *logdir, const char *logname, int maxlogsize, int maxlogcount, int block, int buffsize, int multiwrite)
{
    pthread_attr_t attr;
    int ret;

    if (tlog_format != NULL) {
        fprintf(stderr, "tlog already initilized.\n");
        return -1;
    }

    if (buffsize > 0 && buffsize < TLOG_MAX_LINE_LEN * 2) {
        fprintf(stderr, "buffer size is invalid.\n");
        return -1;
    }

    tlog_format = _tlog_format;
    tlog.logscreen = 0;
    tlog.buffsize = (buffsize > 0) ? buffsize : TLOG_BUFF_SIZE;
    tlog.start = 0;
    tlog.end = 0;
    tlog.ext_end = 0;
    tlog.block = (block != 0) ? 1 : 0;
    tlog.waiters = 0;
    tlog.dropped = 0;
    tlog.logsize = (maxlogsize > 0) ? maxlogsize : TLOG_LOG_SIZE;
    tlog.logcount = (maxlogcount > 0) ? maxlogcount : TLOG_LOG_COUNT;
    tlog.fd = -1;
    tlog.filesize = 0;
    tlog.zip_pid = -1;
    tlog.logscreen = 0;
    tlog.multi_log = (multiwrite != 0) ? 1 : 0;
    tlog.is_wait = 0;

    pthread_attr_init(&attr);
    pthread_mutex_init(&tlog.lock, 0);
    pthread_cond_init(&tlog.cond, 0);
    pthread_cond_init(&tlog.client_cond, 0);
    tlog.buff = malloc(tlog.buffsize);
    if (tlog.buff == NULL) {
        fprintf(stderr, "malloc tlog buffer failed, %s\n", strerror(errno));
        goto errout;
    }

    strncpy(tlog.logdir, logdir, sizeof(tlog.logdir));
    strncpy(tlog.logname, logname, sizeof(tlog.logname));

    tlog.run = 1;
    ret = pthread_create(&tlog.tid, &attr, _tlog_work, NULL);
    if (ret != 0) {
        fprintf(stderr, "create tlog work thread failed, %s\n", strerror(errno));
        goto errout;
    }

    return 0;
errout:
    if (tlog.buff) {
        free(tlog.buff);
        tlog.buff = NULL;
    }
    if (tlog.tid > 0) {
        void *retval = NULL;
        tlog.run = 0;
        pthread_join(tlog.tid, &retval);
    }

    pthread_cond_destroy(&tlog.client_cond);
    pthread_mutex_destroy(&tlog.lock);
    pthread_cond_destroy(&tlog.cond);
    tlog.run = 0;

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

    if (tlog.zip_pid > 0) {
        _tlog_wait_pid(1);
    }

    if (tlog.buff) {
        free(tlog.buff);
        tlog.buff = NULL;
    }

    if (tlog.fd > 0) {
        close(tlog.fd);
        tlog.fd = -1;
    }

    _tlog_log_unlock();

    pthread_cond_destroy(&tlog.client_cond);
    pthread_mutex_destroy(&tlog.lock);
    pthread_cond_destroy(&tlog.cond);
}