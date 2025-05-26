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

#include "smartdns/dns.h"
#include "smartdns/util.h"

#include <libgen.h>
#include <linux/limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

unsigned long get_tick_count(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

unsigned long long get_utc_time_ms(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);

	unsigned long long millisecondsSinceEpoch =
		(unsigned long long)(tv.tv_sec) * 1000 + (unsigned long long)(tv.tv_usec) / 1000;

	return millisecondsSinceEpoch;
}

char *dir_name(char *path)
{
	if (strstr(path, "/") == NULL) {
		safe_strncpy(path, "./", PATH_MAX);
		return path;
	}

	return dirname(path);
}

int create_dir_with_perm(const char *dir_path)
{
	uid_t uid = 0;
	gid_t gid = 0;
	struct stat sb;
	char data_dir[PATH_MAX] = {0};
	int unused __attribute__((unused)) = 0;

	safe_strncpy(data_dir, dir_path, PATH_MAX);
	dir_name(data_dir);

	if (get_uid_gid(&uid, &gid) != 0) {
		return -1;
	}

	if (stat(data_dir, &sb) == 0) {
		if (sb.st_uid == uid && sb.st_gid == gid && (sb.st_mode & 0700) == 0700) {
			return 0;
		}

		if (sb.st_gid == gid && (sb.st_mode & 0070) == 0070) {
			return 0;
		}

		if (sb.st_uid != uid && sb.st_gid != gid && (sb.st_mode & 0007) == 0007) {
			return 0;
		}
	}

	mkdir(data_dir, 0750);
	if (chown(data_dir, uid, gid) != 0) {
		return -2;
	}

	unused = chmod(data_dir, 0750);
	unused = chown(dir_path, uid, gid);

	return 0;
}

char *reverse_string(char *output, const char *input, int len, int to_lower_case)
{
	char *begin = output;
	if (len <= 0) {
		*output = 0;
		return output;
	}

	len--;
	while (len >= 0) {
		*output = *(input + len);
		if (to_lower_case) {
			if (*output >= 'A' && *output <= 'Z') {
				/* To lower case */
				*output = *output + 32;
			}
		}
		output++;
		len--;
	}

	*output = 0;

	return begin;
}

char *to_lower_case(char *output, const char *input, int len)
{
	char *begin = output;
	int i = 0;
	if (len <= 0) {
		*output = 0;
		return output;
	}

	len--;
	while (i < len && *(input + i) != '\0') {
		*output = *(input + i);
		if (*output >= 'A' && *output <= 'Z') {
			/* To lower case */
			*output = *output + 32;
		}
		output++;
		i++;
	}

	*output = 0;

	return begin;
}

int full_path(char *normalized_path, int normalized_path_len, const char *path)
{
	const char *p = path;

	if (path == NULL || normalized_path == NULL) {
		return -1;
	}

	while (*p == ' ') {
		p++;
	}

	if (*p == '\0' || *p == '/') {
		return -1;
	}

	char buf[PATH_MAX];
	snprintf(normalized_path, normalized_path_len, "%s/%s", getcwd(buf, sizeof(buf)), path);
	return 0;
}

void get_compiled_time(struct tm *tm)
{
	char s_month[5];
	int month = 0;
	int day = 0;
	int year = 0;
	int hour = 0;
	int min = 0;
	int sec = 0;
	static const char *month_names = "JanFebMarAprMayJunJulAugSepOctNovDec";

	sscanf(__DATE__, "%4s %d %d", s_month, &day, &year);
	month = (strstr(month_names, s_month) - month_names) / 3;
	sscanf(__TIME__, "%d:%d:%d", &hour, &min, &sec);
	tm->tm_year = year - 1900;
	tm->tm_mon = month;
	tm->tm_mday = day;
	tm->tm_isdst = -1;
	tm->tm_hour = hour;
	tm->tm_min = min;
	tm->tm_sec = sec;
}

unsigned long get_system_mem_size(void)
{
	struct sysinfo memInfo;
	sysinfo(&memInfo);
	long long totalMem = memInfo.totalram;
	totalMem *= memInfo.mem_unit;

	return totalMem;
}

int is_numeric(const char *str)
{
	while (*str != '\0') {
		if (*str < '0' || *str > '9') {
			return -1;
		}
		str++;
	}
	return 0;
}

int has_network_raw_cap(void)
{
	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (fd < 0) {
		return 0;
	}

	close(fd);
	return 1;
}

uint64_t get_free_space(const char *path)
{
	uint64_t size = 0;
	struct statvfs buf;
	if (statvfs(path, &buf) != 0) {
		return 0;
	}

	size = (uint64_t)buf.f_frsize * buf.f_bavail;

	return size;
}

int parser_mac_address(const char *in_mac, uint8_t mac[6])
{
	int fileld_num = 0;

	if (in_mac == NULL) {
		return -1;
	}

	fileld_num =
		sscanf(in_mac, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
	if (fileld_num == 6) {
		return 0;
	}

	fileld_num =
		sscanf(in_mac, "%2hhx-%2hhx-%2hhx-%2hhx-%2hhx-%2hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
	if (fileld_num == 6) {
		return 0;
	}

	return -1;
}

int set_http_host(const char *uri_host, int port, int default_port, char *host)
{
	int is_ipv6;

	if (uri_host == NULL || port <= 0 || host == NULL) {
		return -1;
	}

	is_ipv6 = check_is_ipv6(uri_host);
	if (port == default_port) {
		snprintf(host, DNS_MAX_CNAME_LEN, "%s%s%s", is_ipv6 == 0 ? "[" : "", uri_host, is_ipv6 == 0 ? "]" : "");
	} else {
		snprintf(host, DNS_MAX_CNAME_LEN, "%s%s%s:%d", is_ipv6 == 0 ? "[" : "", uri_host, is_ipv6 == 0 ? "]" : "",
				 port);
	}
	return 0;
}

int decode_hex(int ch)
{
	if ('0' <= ch && ch <= '9') {
		return ch - '0';
	} else if ('A' <= ch && ch <= 'F') {
		return ch - 'A' + 0xa;
	} else if ('a' <= ch && ch <= 'f') {
		return ch - 'a' + 0xa;
	} else {
		return -1;
	}
}
