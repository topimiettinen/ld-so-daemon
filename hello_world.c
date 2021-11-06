// SPDX-License-Identifier: LGPL-2.1-or-later OR BSD-3-Clause

#include "hello_world_lib.h"

#include <unistd.h>

// bss
char foo[8192];

// relocations
const char msg[] = "Hello World from ld-so-daemon!\n";
size_t msg_size = sizeof(msg);
const char *ptr = msg;

// First function started from kernel
void _start(void) {
	sys_write(STDERR_FILENO, ptr, msg_size);
	sys_exit(EXIT_SUCCESS);
}
