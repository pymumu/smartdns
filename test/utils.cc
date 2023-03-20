#include "include/utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

namespace smartdns
{

bool IsCommandExists(const std::string &cmd)
{
	char *copy_path = nullptr;
	char cmd_path[4096];
	const char *env_path = getenv("PATH");
	char *save_ptr = nullptr;

	if (env_path == nullptr) {
		env_path = "/bin:/usr/bin:/usr/local/bin";
	}

	copy_path = strdup(env_path);
	if (copy_path == nullptr) {
		return false;
	}

	Defer
	{
		free(copy_path);
	};

	for (char *tok = strtok_r(copy_path, ":", &save_ptr); tok; tok = strtok_r(nullptr, ":", &save_ptr)) {
		snprintf(cmd_path, sizeof(cmd_path), "%s/%s", tok, cmd.c_str());
		if (access(cmd_path, X_OK) != 0) {
			continue;
		}

		return true;
	}

	return false;
}

std::string GenerateRandomString(int len)
{
    std::string result;
	static const char alphanum[] = "0123456789"
								   "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
								   "abcdefghijklmnopqrstuvwxyz";
    result.resize(len);

    for (int i = 0; i < len; ++i) {
        result[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    return result;
}

} // namespace smartdns