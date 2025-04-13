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

#include "smartdns/tlog.h"
#include "smartdns/util.h"

#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <signal.h>

void bug_ext(const char *file, int line, const char *func, const char *errfmt, ...)
{
	va_list ap;

	va_start(ap, errfmt);
	tlog_vext(TLOG_FATAL, file, line, func, NULL, errfmt, ap);
	va_end(ap);

	print_stack();
	/* trigger BUG */
	sleep(1);
	raise(SIGSEGV);

	while (1) {
		sleep(1);
	};
}

#ifdef HAVE_UNWIND_BACKTRACE

#include <unwind.h>

struct backtrace_state {
	void **current;
	void **end;
};

static _Unwind_Reason_Code unwind_callback(struct _Unwind_Context *context, void *arg)
{
	struct backtrace_state *state = (struct backtrace_state *)(arg);
	uintptr_t pc = _Unwind_GetIP(context);
	if (pc) {
		if (state->current == state->end) {
			return _URC_END_OF_STACK;
		}

		*state->current++ = (void *)(pc);
	}
	return _URC_NO_REASON;
}

void print_stack(void)
{
	const size_t max_buffer = 30;
	void *buffer[max_buffer];
	int idx = 0;

	struct backtrace_state state = {buffer, buffer + max_buffer};
	_Unwind_Backtrace(unwind_callback, &state);
	int frame_num = state.current - buffer;
	if (frame_num == 0) {
		return;
	}

	tlog(TLOG_FATAL, "Stack:");
	for (idx = 0; idx < frame_num; ++idx) {
		const void *addr = buffer[idx];
		const char *symbol = "";

		Dl_info info;
		memset(&info, 0, sizeof(info));
		if (dladdr(addr, &info) && info.dli_sname) {
			symbol = info.dli_sname;
		}

		void *offset = (void *)((char *)(addr) - (char *)(info.dli_fbase));
		tlog(TLOG_FATAL, "#%.2d: %p %s() from %s+%p", idx + 1, addr, symbol, info.dli_fname, offset);
	}
}
#else
void print_stack(void) {}
#endif