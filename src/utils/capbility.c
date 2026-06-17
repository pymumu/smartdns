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

#include "smartdns/util.h"

#include "smartdns/dns_conf.h"
#include <linux/capability.h>
#include <linux/limits.h>
#include <pwd.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/types.h>

int get_uid_gid(uid_t *uid, gid_t *gid)
{
	struct passwd *result = NULL;
	struct passwd pwd;
	char *buf = NULL;
	ssize_t bufsize = 0;
	int ret = -1;

	if (dns_conf.user[0] == '\0') {
		*uid = getuid();
		*gid = getgid();
		return 0;
	}

	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize == -1) {
		bufsize = 1024 * 16;
	}

	buf = malloc(bufsize);
	if (buf == NULL) {
		goto out;
	}

	ret = getpwnam_r(dns_conf.user, &pwd, buf, bufsize, &result);
	if (ret != 0) {
		goto out;
	}

	if (result == NULL) {
		ret = -1;
		goto out;
	}

	*uid = result->pw_uid;
	*gid = result->pw_gid;

out:
	if (buf) {
		free(buf);
	}

	return ret;
}

int capget(struct __user_cap_header_struct *header, struct __user_cap_data_struct *cap);
int capset(struct __user_cap_header_struct *header, struct __user_cap_data_struct *cap);

static int _cap_has(struct __user_cap_data_struct cap[2], int capability)
{
	int index = CAP_TO_INDEX(capability);

	if (index < 0 || index >= 2) {
		return 0;
	}

	return (cap[index].permitted & CAP_TO_MASK(capability)) != 0;
}

static void _cap_keep_permitted(struct __user_cap_data_struct keep[2], struct __user_cap_data_struct current[2],
								const int *capabilities, int capability_num)
{
	for (int i = 0; i < capability_num; i++) {
		int capability = capabilities[i];
		int index = CAP_TO_INDEX(capability);

		if (index < 0 || index >= 2 || _cap_has(current, capability) == 0) {
			continue;
		}

		keep[index].effective |= CAP_TO_MASK(capability);
		keep[index].permitted |= CAP_TO_MASK(capability);
	}
}

int drop_root_privilege(void)
{
	struct __user_cap_data_struct cap[2];
	struct __user_cap_data_struct keep_cap[2];
	struct __user_cap_header_struct header;
#ifdef _LINUX_CAPABILITY_VERSION_3
	header.version = _LINUX_CAPABILITY_VERSION_3;
#else
	header.version = _LINUX_CAPABILITY_VERSION;
#endif
	header.pid = 0;
	uid_t uid = 0;
	gid_t gid = 0;
	int unused __attribute__((unused)) = 0;
	const int keep_capabilities[] = {CAP_NET_RAW, CAP_NET_ADMIN, CAP_NET_BIND_SERVICE, CAP_DAC_READ_SEARCH};

	if (get_uid_gid(&uid, &gid) != 0) {
		return -1;
	}

	memset(cap, 0, sizeof(cap));
	if (capget(&header, cap) < 0) {
		return -1;
	}

	prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);
	memset(keep_cap, 0, sizeof(keep_cap));
	_cap_keep_permitted(keep_cap, cap, keep_capabilities, sizeof(keep_capabilities) / sizeof(keep_capabilities[0]));

	unused = setgid(gid);
	unused = setuid(uid);
	if (capset(&header, keep_cap) < 0) {
		return -1;
	}

	prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0);
	return 0;
}
