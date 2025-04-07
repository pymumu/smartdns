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

#include "smartdns.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
	const char *smartdns_workdir = getenv("SMARTDNS_WORKDIR");
	if (smartdns_workdir != NULL) {
		if (chdir(smartdns_workdir) != 0) {
			fprintf(stderr, "chdir to %s failed: %s\n", smartdns_workdir, strerror(errno));
			return 1;
		}
	}

	return smartdns_main(argc, argv);
}
