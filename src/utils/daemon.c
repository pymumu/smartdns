/*************************************************************************
 *
 * Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
 *
 * smartdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * smartdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE

#include "smartdns/util.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

enum daemon_msg_type {
	DAEMON_MSG_KICKOFF,
	DAEMON_MSG_KEEPALIVE,
	DAEMON_MSG_DAEMON_PID,
};

struct daemon_msg {
	enum daemon_msg_type type;
	int value;
};

static int pidfile_fd;
static int daemon_fd;

static void _close_all_fd_by_res(void)
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

void close_all_fd(int keepfd)
{
	DIR *dirp;
	int dir_fd = -1;
	struct dirent *dentp;

	dirp = opendir("/proc/self/fd");
	if (dirp == NULL) {
		goto errout;
	}

	dir_fd = dirfd(dirp);

	while ((dentp = readdir(dirp)) != NULL) {
		int fd = atol(dentp->d_name);
		if (fd < 0) {
			continue;
		}

		if (fd == dir_fd || fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO || fd == keepfd) {
			continue;
		}
		close(fd);
	}

	closedir(dirp);
	return;
errout:
	if (dirp) {
		closedir(dirp);
	}
	_close_all_fd_by_res();
	return;
}

void daemon_close_stdfds(void)
{
	int fd_null = open("/dev/null", O_RDWR);
	if (fd_null < 0) {
		fprintf(stderr, "open /dev/null failed, %s\n", strerror(errno));
		return;
	}

	dup2(fd_null, STDIN_FILENO);
	dup2(fd_null, STDOUT_FILENO);
	dup2(fd_null, STDERR_FILENO);

	if (fd_null > 2) {
		close(fd_null);
	}
}

int daemon_kickoff(int status, int no_close)
{
	struct daemon_msg msg;

	if (daemon_fd <= 0) {
		return -1;
	}

	msg.type = DAEMON_MSG_KICKOFF;
	msg.value = status;

	int ret = write(daemon_fd, &msg, sizeof(msg));
	if (ret != sizeof(msg)) {
		fprintf(stderr, "notify parent process failed, %s\n", strerror(errno));
		return -1;
	}

	if (no_close == 0) {
		daemon_close_stdfds();
	}

	close(daemon_fd);
	daemon_fd = -1;

	return 0;
}

int daemon_keepalive(void)
{
	struct daemon_msg msg;
	static time_t last = 0;
	time_t now = time(NULL);

	if (daemon_fd <= 0) {
		return -1;
	}

	if (now == last) {
		return 0;
	}

	last = now;

	msg.type = DAEMON_MSG_KEEPALIVE;
	msg.value = 0;

	int ret = write(daemon_fd, &msg, sizeof(msg));
	if (ret != sizeof(msg)) {
		return -1;
	}

	return 0;
}

daemon_ret daemon_run(int *wstatus)
{
	pid_t pid = 0;
	int fds[2] = {0};

	if (pipe(fds) != 0) {
		fprintf(stderr, "run daemon process failed, pipe failed, %s\n", strerror(errno));
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "run daemon process failed, fork failed, %s\n", strerror(errno));
		close(fds[0]);
		close(fds[1]);
		return -1;
	} else if (pid > 0) {
		struct pollfd pfd;
		int ret = 0;

		close(fds[1]);

		pfd.fd = fds[0];
		pfd.events = POLLIN;
		pfd.revents = 0;

		do {
			ret = poll(&pfd, 1, 3000);
			if (ret <= 0) {
				fprintf(stderr, "run daemon process failed, wait child timeout, kill child.\n");
				goto errout;
			}

			if (!(pfd.revents & POLLIN)) {
				goto errout;
			}

			struct daemon_msg msg;

			ret = read(fds[0], &msg, sizeof(msg));
			if (ret != sizeof(msg)) {
				goto errout;
			}

			if (msg.type == DAEMON_MSG_KEEPALIVE) {
				continue;
			} else if (msg.type == DAEMON_MSG_DAEMON_PID) {
				pid = msg.value;
				continue;
			} else if (msg.type == DAEMON_MSG_KICKOFF) {
				if (wstatus != NULL) {
					*wstatus = msg.value;
				}
				return DAEMON_RET_PARENT_OK;
			} else {
				goto errout;
			}
		} while (1);

		return DAEMON_RET_ERR;
	}

	setsid();

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "double fork failed, %s\n", strerror(errno));
		_exit(1);
	} else if (pid > 0) {
		struct daemon_msg msg;
		int unused __attribute__((unused));
		msg.type = DAEMON_MSG_DAEMON_PID;
		msg.value = pid;
		unused = write(fds[1], &msg, sizeof(msg));
		_exit(0);
	}

	umask(0);
	if (chdir("/") != 0) {
		goto errout;
	}
	close(fds[0]);

	daemon_fd = fds[1];
	return DAEMON_RET_CHILD_OK;
errout:
	kill(pid, SIGKILL);
	if (wstatus != NULL) {
		*wstatus = -1;
	}
	return DAEMON_RET_ERR;
}

int create_pid_file(const char *pid_file)
{
	int fd = 0;
	int flags = 0;
	char buff[TMP_BUFF_LEN_32];

	/*  create pid file, and lock this file */
	fd = open(pid_file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		fprintf(stderr, "create pid file %s failed, %s\n", pid_file, strerror(errno));
		return -1;
	}

	flags = fcntl(fd, F_GETFD);
	if (flags < 0) {
		fprintf(stderr, "Could not get flags for PID file %s\n", pid_file);
		goto errout;
	}

	flags |= FD_CLOEXEC;
	if (fcntl(fd, F_SETFD, flags) == -1) {
		fprintf(stderr, "Could not set flags for PID file %s\n", pid_file);
		goto errout;
	}

	if (lockf(fd, F_TLOCK, 0) < 0) {
		memset(buff, 0, TMP_BUFF_LEN_32);
		if (read(fd, buff, TMP_BUFF_LEN_32) <= 0) {
			buff[0] = '\0';
		}
		fprintf(stderr, "Server is already running, pid is %s", buff);
		goto errout;
	}

	snprintf(buff, TMP_BUFF_LEN_32, "%d\n", getpid());

	if (write(fd, buff, strnlen(buff, TMP_BUFF_LEN_32)) < 0) {
		fprintf(stderr, "write pid to file failed, %s.\n", strerror(errno));
		goto errout;
	}

	if (pidfile_fd > 0) {
		close(pidfile_fd);
	}

	pidfile_fd = fd;

	return 0;
errout:
	if (fd > 0) {
		close(fd);
	}
	return -1;
}