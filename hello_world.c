// SPDX-License-Identifier: LGPL-2.1-or-later OR BSD-3-Clause

#include "hello_world_lib.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// bss
/* Flawfinder: ignore */
char foo[8192];

// relocations
const char msg[] = "Hello World from ld-so-daemon!\n/proc/self/maps:\n";
size_t msg_size = sizeof(msg);
const char *ptr = msg;

// First function started from kernel
void _start(void) {
	sys_write(STDOUT_FILENO, ptr, msg_size);

	int fd = sys_open("/proc/self/maps", O_RDONLY | O_NOCTTY | O_CLOEXEC, 0);
	if (fd < 0) {
		sys_write(STDERR_FILENO, "Can't open /proc/self/maps\n", sizeof("Can't open /proc/self/maps\n"));
		sys_exit(EXIT_FAILURE);
	}

	int r;
	do {
		/* Flawfinder: ignore */
		char buf[4096];
		r = sys_read(fd, buf, sizeof(buf));
		if (r > 0)
			sys_write(STDOUT_FILENO, buf, r);
	} while (r > 0);

	sys_close(fd);

	sys_exit(EXIT_SUCCESS);
}
