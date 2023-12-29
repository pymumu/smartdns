/*************************************************************************
 *
 * Copyright (C) 2018-2023 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

#include "gtest/gtest.h"

int main(int argc, char **argv)
{
	if (WEXITSTATUS(system("which dig >/dev/null 2>&1")) != 0) {
		std::cerr << "dig not found, please install it first." << std::endl;
		return 1;
	}

	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}