/*
 * tinylog
 * Copyright (C) 2018 Nick Peng <pymumu@gmail.com>
 * https://github.com/pymumu/tinylog
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <libgen.h>
#include <unistd.h>

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define TLOG_BUFF_SIZE (1024 * 128)
#define TLOG_MAX_LINE_LEN (1024)
#define TLOG_TMP_LEN 128
#define TLOG_LOG_SIZE (1024 * 1024 * 50)
#define TLOG_LOG_COUNT 32
#define TLOG_LOG_NAME_LEN 128
#define TLOG_BUFF_LEN (PATH_MAX + TLOG_LOG_NAME_LEN * 2)

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
    int logsize;
    int logcount;
    int block;
    int dropped;
    int zip_pid;
    int multi_log;
    int logscreen;
    
    int is_exit;
    struct tlog_log *next;
};

struct tlog {
    struct tlog_log *root;
    struct tlog_log *log;
    struct tlog_log *notify_log;
    int run;
    pthread_t tid;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    pthread_cond_t client_cond;
    int waiters;
    int is_wait;
};

struct oldest_log {
    char name[TLOG_TMP_LEN];
    time_t mtime;
    struct tlog_log *log;
};

struct count_log {
    int lognum;
    struct tlog_log *log;
};

struct tlog_info_inter {
    struct tlog_info info;
    void *userptr;
};

typedef int (*list_callback)(const char *name, struct dirent *entry, void *user);
typedef int (*vprint_callback)(char *buff, int maxlen, void *userptr, const char *format, va_list ap);

struct tlog tlog;
static int tlog_disable_early_print = 0;
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

int tlog_localtime(struct tlog_time *tm)
{
    return _tlog_gettime(tm);
}

static int _tlog_format(char *buff, int maxlen, struct tlog_info *info, void *userptr, const char *format, va_list ap)
{
    int len = 0;
    int total_len = 0;
    struct tlog_time *tm = &info->time;

    if (tlog.root->multi_log) {
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

static int _tlog_root_log_buffer(char *buff, int maxlen, void *userptr, const char *format, va_list ap)
{
    int len;
    struct tlog_info_inter *info_inter = userptr;

    if (tlog_format == NULL) {
        return -1;
    }

    if (_tlog_gettime(&info_inter->info.time) != 0) {
        return -1;
    }

    len = tlog_format(buff, maxlen, &info_inter->info, info_inter->userptr, format, ap);
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

static int _tlog_print_buffer(char *buff, int maxlen, void *userptr, const char *format, va_list ap)
{
    int len;
    int total_len = 0;

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

int _tlog_vprintf(struct tlog_log *log, vprint_callback print_callback, void *userptr, const char *format, va_list ap)
{
    int len;
    int maxlen = 0;

    if (log == NULL || format == NULL) {
        return -1;
    }

    if (log->buff == NULL) {
        return -1;
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
        if (maxlen < TLOG_MAX_LINE_LEN) {
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
    len = print_callback(log->buff + log->end, maxlen, userptr, format, ap);
    if (len <= 0) {
        pthread_mutex_unlock(&tlog.lock);
        return -1;
    }
    log->end += len;
    /* if remain buffer is not enough for a line, move end to start of buffer. */
    if (log->end > log->buffsize - TLOG_MAX_LINE_LEN) {
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
    return _tlog_vprintf(log, _tlog_print_buffer, 0, format, ap);
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

int _tlog_early_print(const char *format, va_list ap) 
{
    char log_buf[TLOG_MAX_LINE_LEN];
    int len = 0;
    int out_len = 0;

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

    write(STDOUT_FILENO, log_buf, out_len);
    if (log_buf[out_len - 1] != '\n') {
        write(STDOUT_FILENO, "\n", 1);
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
    info_inter.info.level = tlog_level_str[level];
    info_inter.userptr = userptr;

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

static int _tlog_rename_logfile(struct tlog_log *log, const char *gzip_file)
{
    char archive_file[TLOG_BUFF_LEN];
    struct tlog_time logtime;
    int i = 0;

    if (_tlog_getmtime(&logtime, gzip_file) != 0) {
        return -1;
    }

    snprintf(archive_file, sizeof(archive_file), "%s/%s-%.4d%.2d%.2d-%.2d%.2d%.2d.gz", 
        log->logdir, log->logname, logtime.year, logtime.mon, logtime.mday,
        logtime.hour, logtime.min, logtime.sec);

    while (access(archive_file, F_OK) == 0) {
        i++;
        snprintf(archive_file, sizeof(archive_file), "%s/%s-%.4d%.2d%.2d-%.2d%.2d%.2d-%d.gz", 
            log->logdir, log->logname, logtime.year, logtime.mon,
            logtime.mday, logtime.hour, logtime.min, logtime.sec, i);
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
    struct count_log *count_log = (struct count_log *)userptr;
    struct tlog_log *log = count_log->log;

    if (strstr(entry->d_name, ".gz") == NULL) {
        return 0;
    }

    int len = strnlen(log->logname, sizeof(log->logname));
    if (strncmp(log->logname, entry->d_name, len) != 0) {
        return 0;
    }

    count_log->lognum++;
    return 0;
}

static int _tlog_get_oldest_callback(const char *path, struct dirent *entry, void *userptr)
{
    struct stat sb;
    char filename[TLOG_BUFF_LEN];
    struct oldest_log *oldestlog = userptr;
    struct tlog_log *log = oldestlog->log;

    /* if not a gz file, skip */
    if (strstr(entry->d_name, ".gz") == NULL) {
        return 0;
    }

    /* if not tlog gz file, skip */
    int len = strnlen(log->logname, sizeof(log->logname));
    if (strncmp(log->logname, entry->d_name, len) != 0) {
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

static int _tlog_archive_log(struct tlog_log *log)
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

static int _tlog_write_log(struct tlog_log *log, char *buff, int bufflen)
{
    int len;

    if (bufflen <= 0) {
        return 0;
    }

     /* output log to screen */
    if (log->logscreen) {
        write(STDOUT_FILENO, buff, bufflen);
    }

    /* if log file size exceeds threshold, start to compress */
    if (log->multi_log) {
        log->filesize = lseek(log->fd, 0, SEEK_END);
    }

    if (log->filesize > log->logsize && log->zip_pid <= 0) {
        if (log->filesize < lseek(log->fd, 0, SEEK_END) && log->multi_log == 0) {
            const char *msg = "[Auto enable multi-process write mode, log may be lost, please enable multi-process write mode manually]\n";
            log->multi_log = 1;
            write(log->fd, msg, strlen(msg));
        }
        close(log->fd);
        log->fd = -1;
        log->filesize = 0;
        _tlog_archive_log(log);
    }

    if (log->fd <= 0) {
        /* open a new log file to write */
		static time_t last_try = 0;
		static int print_errmsg = 1;
		time_t now;

		time(&now);
        if (now == last_try) {
			return -1;
		}
		last_try = now;

		char logfile[PATH_MAX * 2];
		if (_tlog_mkdir(log->logdir) != 0) {
            fprintf(stderr, "create log dir %s failed.\n", log->logdir);
            return -1;
        }
        snprintf(logfile, sizeof(logfile), "%s/%s", log->logdir, log->logname);
        log->filesize = 0;
        log->fd = open(logfile, O_APPEND | O_CREAT | O_WRONLY | O_CLOEXEC, 0640);
        if (log->fd < 0) {
            if (print_errmsg == 0) {
				return -1;
			}

			fprintf(stderr, "open log file %s failed, %s\n", logfile, strerror(errno));
			print_errmsg = 0;
			return -1;
		}

		print_errmsg = 1;
		/* get log file size */
		log->filesize = lseek(log->fd, 0, SEEK_END);
    }

    /* write log to file */
    len = write(log->fd, buff, bufflen);
    if (len > 0) {
        log->filesize += len;
    }

    return len;
}

int _tlog_has_data(void)
{
    struct tlog_log *next = NULL;

    pthread_mutex_lock(&tlog.lock);
    next = tlog.log;
    while (next) {
        if (next->end != next->start || next->ext_end > 0) {
            pthread_mutex_unlock(&tlog.lock);
            return 1;
        }
        next = next->next;
    }
    pthread_mutex_unlock(&tlog.lock);

    return 0;
}

int _tlog_wait_pids(void)
{
    static time_t last = -1;
    time_t now = 0;

    struct tlog_log *next = NULL;

    pthread_mutex_lock(&tlog.lock);
    next = tlog.log;
    while (next) {
        if (next->zip_pid > 0) {
            if (now == 0) {
                now = time(0);
            }

            if (now != last) {
                pthread_mutex_unlock(&tlog.lock);
                /* try to archive compressed file */
                _tlog_wait_pid(next, 0);
                last = now;
                return 0;
            }
        }
        next = next->next;
    }
    pthread_mutex_unlock(&tlog.lock);

    if (now != 0) {
        last = now;
    }

    return 0;
}

int _tlog_close(struct tlog_log *log, int wait_hang)
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

    return 0;
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
    struct tlog_log *log = NULL;
    struct tlog_log *loop_log = NULL;

    while (1) {
        log_len = 0;
        log_end = 0;
        log_extlen = 0;
        log_extend = 0;

        if (tlog.run == 0) {
            if (_tlog_has_data() == 0) {
                break;
            }
        }

        /* if compressing */
        _tlog_wait_pids();

        pthread_mutex_lock(&tlog.lock);
        if (loop_log == NULL) {
            loop_log = log;
        }

        if (log == NULL) {
            log = tlog.log;
        } else {
            log = log->next;
            if (log == NULL) {
                pthread_mutex_unlock(&tlog.lock);
                continue;
            }
        }

        if ((log == loop_log || log == NULL) && tlog.run) {
            /* if buffer is empty, wait */
            if ((log == NULL) || (log && (log->end == log->start) && (log->ext_end <= 0))) {
                clock_gettime(CLOCK_REALTIME, &tm);
                tm.tv_sec += 2;
                tlog.is_wait = 1;
                ret = pthread_cond_timedwait(&tlog.cond, &tlog.lock, &tm);
                tlog.is_wait = 0;
                if (ret < 0 && ret != ETIMEDOUT) {
                    pthread_mutex_unlock(&tlog.lock);
                    sleep(1);
                    continue;
                } else if (ret == ETIMEDOUT) {
                    log = tlog.notify_log;
                    tlog.notify_log = NULL;
                }

                if (log == NULL) {
                    pthread_mutex_unlock(&tlog.lock);
                    continue;
                }
            }
        }

        if (log && (log->end == log->start) && (log->ext_end <= 0)) {
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

        /* write log */
        _tlog_write_log(log, log->buff + log->start, log_len);
        if (log_extlen > 0) {
            /* write extend buffer log */
            _tlog_write_log(log, log->buff, log_extlen);
        }

        if (log_dropped > 0) {
            /* if there is dropped log, record dropped log number */
            char dropmsg[TLOG_TMP_LEN];
            snprintf(dropmsg, sizeof(dropmsg), "[Totoal Dropped %d Messages]\n", log_dropped);
            _tlog_write_log(log, dropmsg, strnlen(dropmsg, sizeof(dropmsg)));
        }

        pthread_mutex_lock(&tlog.lock);
        /* release finished buffer */
        log->start = log_end;
        if (log_extend > 0) {
            log->ext_end = 0;
        }

        if (tlog.waiters > 0) {
            /* if there are waiters, wakeup */
            pthread_cond_broadcast(&tlog.client_cond);
        }
        pthread_mutex_unlock(&tlog.lock);
    }
    return NULL;
}

void tlog_set_early_printf(int enable)
{
    tlog_disable_early_print = (enable == 0) ? 1 : 0;    
}

void _tlog_log_setlogscreen(struct tlog_log *log, int enable)
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

void tlog_logscreen(tlog_log *log, int enable)
{
    if (log == NULL) {
        return;
    }

    _tlog_log_setlogscreen(log, enable);
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

tlog_log *tlog_open(const char *logfile, int maxlogsize, int maxlogcount, int block, int buffsize, int multiwrite)
{
    struct tlog_log *log = NULL;
    char log_file[PATH_MAX];

    if (tlog.run == 0) {
        fprintf(stderr, "tlog is not initialized.");
        return NULL;
    }

    log = malloc(sizeof(*log));
    if (log == NULL) {
        fprintf(stderr, "malloc log failed.");
        return NULL;
    }

    memset(log, 0, sizeof(*log));
    log->buffsize = (buffsize > 0) ? buffsize : TLOG_BUFF_SIZE;
    log->start = 0;
    log->end = 0;
    log->ext_end = 0;
    log->block = (block != 0) ? 1 : 0;
    log->dropped = 0;
    log->logsize = (maxlogsize >= 0) ? maxlogsize : TLOG_LOG_SIZE;
    log->logcount = (maxlogcount > 0) ? maxlogcount : TLOG_LOG_COUNT;
    log->fd = -1;
    log->filesize = 0;
    log->zip_pid = -1;
    log->logscreen = 0;
    log->is_exit = 0;
    log->multi_log = (multiwrite != 0) ? 1 : 0;

    strncpy(log_file, logfile, PATH_MAX);
    strncpy(log->logdir, dirname(log_file), sizeof(log->logdir));
    strncpy(log_file, logfile, PATH_MAX);
    strncpy(log->logname, basename(log_file), sizeof(log->logname));

    log->buff = malloc(log->buffsize);
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

int tlog_init(const char *logfile, int maxlogsize, int maxlogcount, int block, int buffsize, int multiwrite)
{
    pthread_attr_t attr;
    int ret;
    struct tlog_log *log = NULL;

    if (tlog_format != NULL) {
        fprintf(stderr, "tlog already initilized.\n");
        return -1;
    }

    if (buffsize > 0 && buffsize < TLOG_MAX_LINE_LEN * 2) {
        fprintf(stderr, "buffer size is invalid.\n");
        return -1;
    }

    tlog_format = _tlog_format;

    memset(&tlog, 0, sizeof(tlog));
    tlog.waiters = 0;
    tlog.is_wait = 0;

    pthread_attr_init(&attr);
    pthread_mutex_init(&tlog.lock, 0);
    pthread_cond_init(&tlog.cond, 0);
    pthread_cond_init(&tlog.client_cond, 0);
    tlog.run = 1;

    log = tlog_open(logfile, maxlogsize, maxlogcount, block, buffsize, multiwrite);
    if (log == NULL) {
        fprintf(stderr, "init tlog root failed.\n");
        goto errout;
    }

    ret = pthread_create(&tlog.tid, &attr, _tlog_work, NULL);
    if (ret != 0) {
        fprintf(stderr, "create tlog work thread failed, %s\n", strerror(errno));
        goto errout;
    }

    tlog.root = log;
    return 0;
errout:
    if (tlog.tid > 0) {
        void *retval = NULL;
        tlog.run = 0;
        pthread_join(tlog.tid, &retval);
    }

    pthread_cond_destroy(&tlog.client_cond);
    pthread_mutex_destroy(&tlog.lock);
    pthread_cond_destroy(&tlog.cond);
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

    pthread_cond_destroy(&tlog.client_cond);
    pthread_mutex_destroy(&tlog.lock);
    pthread_cond_destroy(&tlog.cond);
}
