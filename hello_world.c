// SPDX-License-Identifier: LGPL-2.1-or-later OR BSD-3-Clause

#include <asm/unistd.h>
#include <stdlib.h>
#include <unistd.h>

/*
  Local system call implementations
*/

// bss
int foo;

// void exit(int status)
static void sys_exit(int status) {
	int r;
	asm volatile("syscall"
		     : "=a"(r)
		     : "0"(__NR_exit), "D"(status)
		     : "rcx", "r11", "memory");
}

// ssize_t write(int fd, const void *buf, size_t count)
static ssize_t sys_write(int fd, const void *buf, size_t count) {
	ssize_t r;
	asm volatile("syscall"
		     : "=a"(r)
		     : "0"(__NR_write), "D"(fd), "S"(buf), "d"(count)
		     : "rcx", "r11", "memory");
	return r;
}

// First function started from kernel
void _start(void) {
	static const char msg[] = "Hello World from ld-so-daemon!\n";
	sys_write(STDERR_FILENO, msg, sizeof(msg));
	sys_exit(EXIT_SUCCESS);
}
