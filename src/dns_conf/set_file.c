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

#include "set_file.h"
#include "smartdns/lib/idna.h"
#include "smartdns/lib/stringutil.h"
#include "smartdns/util.h"

#include <errno.h>
#include <getopt.h>
#include <glob.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>

int _config_domain_rule_each_from_geosite(const char *file, int type, set_rule_add_func callback, void *priv)
{
	FILE *fp = NULL;
	char line[MAX_LINE_LEN];
	char domain[DNS_MAX_CNAME_LEN];
	int ret = 0;
	int line_no = 0;
	int filed_num = 0;

	fp = fopen(file, "r");
	if (fp == NULL) {
		tlog(TLOG_WARN, "open file %s error, %s", file, strerror(errno));
		return 0;
	}

	line_no = 0;
	while (fgets(line, MAX_LINE_LEN, fp)) {
		line_no++;
		filed_num = sscanf(line, "%255s", domain);
		if (filed_num <= 0) {
			continue;
		}

		if (domain[0] == '#' || domain[0] == '\n') {
			continue;
		}

		char buf[DNS_MAX_CNAME_LEN];
		memset(buf, 0 ,sizeof(buf));
		if (strncmp(domain, "full:", 5)==0) {
			safe_strncpy(buf, &domain[5], DNS_MAX_CNAME_LEN);
			sprintf(domain,"%s",buf);
		}

		if (strncmp(domain, "domain:", 7)==0) {
			safe_strncpy(buf, &domain[7], DNS_MAX_CNAME_LEN);
			sprintf(domain,"%s",buf);
		}

		if (strncmp(domain, "keyword:", 8)==0) {
		    if (type==DNS_DOMAIN_SET_GEOSITELIST)
		       continue;
			   
			safe_strncpy(buf, &domain[8], DNS_MAX_CNAME_LEN);
			sprintf(domain,"^.*%s.*$", buf);
			if (dns_regexp_insert(domain) !=0 ) {
			    tlog(TLOG_WARN, "insert regexp %s failed at file %s line %d.", domain, file, line_no);
				continue;
			}
		}

		if (strncmp(domain, "regexp:", 7)==0) {
		    if (type==DNS_DOMAIN_SET_GEOSITELIST)
		       continue;

			safe_strncpy(buf, &domain[7], DNS_MAX_CNAME_LEN);
			sprintf(domain,"%s",buf);
			if (dns_regexp_insert(domain) !=0 ) {
			    tlog(TLOG_WARN, "insert regexp %s failed at file %s line %d.", domain, file, line_no);
				continue;
			}
		}

		ret = callback(domain, priv);
		if (ret != 0) {
			tlog(TLOG_WARN, "process file %s failed at line %d.", file, line_no);
			continue;
		}
	}

	fclose(fp);
	return ret;
}

int _config_set_rule_each_from_list(const char *file, set_rule_add_func callback, void *priv)
{
	FILE *fp = NULL;
	char line[MAX_LINE_LEN];
	char value[DNS_MAX_CNAME_LEN];
	int ret = 0;
	int line_no = 0;
	int filed_num = 0;

	fp = fopen(file, "r");
	if (fp == NULL) {
		tlog(TLOG_ERROR, "open file %s error, %s", file, strerror(errno));
		return -1;
	}

	line_no = 0;
	while (fgets(line, MAX_LINE_LEN, fp)) {
		line_no++;
		filed_num = sscanf(line, "%255s", value);
		if (filed_num <= 0) {
			continue;
		}

		if (value[0] == '#' || value[0] == '\n') {
			continue;
		}

		ret = callback(value, priv);
		if (ret != 0) {
			tlog(TLOG_WARN, "process file %s failed at line %d.", file, line_no);
			continue;
		}
	}

	fclose(fp);
	return ret;
}

int _config_foreach_file(const char *file_pattern, int (*callback)(const char *file, void *priv), void *priv)
{
	char file_path[PATH_MAX];
	char file_path_dir[PATH_MAX];
	glob_t globbuf = {0};

	if (file_pattern == NULL) {
		return -1;
	}

	if (file_pattern[0] != '/') {
		safe_strncpy(file_path_dir, conf_get_conf_file(), DNS_MAX_PATH);
		dir_name(file_path_dir);
		if (strncmp(file_path_dir, conf_get_conf_file(), sizeof(file_path_dir)) == 0) {
			if (snprintf(file_path, DNS_MAX_PATH, "%s", file_pattern) < 0) {
				return -1;
			}
		} else {
			if (snprintf(file_path, DNS_MAX_PATH, "%s/%s", file_path_dir, file_pattern) < 0) {
				return -1;
			}
		}
	} else {
		safe_strncpy(file_path, file_pattern, DNS_MAX_PATH);
	}

	errno = 0;
	if (glob(file_path, 0, NULL, &globbuf) != 0) {
		if (errno == 0) {
			return 0;
		}

		tlog(TLOG_ERROR, "open config file '%s' failed, %s", file_path, strerror(errno));
		return -1;
	}

	for (size_t i = 0; i != globbuf.gl_pathc; ++i) {
		const char *file = globbuf.gl_pathv[i];
		struct stat statbuf;

		if (stat(file, &statbuf) != 0) {
			continue;
		}

		if (!S_ISREG(statbuf.st_mode)) {
			continue;
		}

		if (callback(file, priv) != 0) {
			tlog(TLOG_ERROR, "load config file '%s' failed.", file);
			globfree(&globbuf);
			return -1;
		}
	}

	globfree(&globbuf);

	return 0;
}
