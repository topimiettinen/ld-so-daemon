// SPDX-License-Identifier: LGPL-2.1-or-later OR BSD-3-Clause

#include "hello_world_lib.h"

#include <asm/unistd.h>
#include <stdlib.h>
#include <unistd.h>

/*
  Local system call implementations
*/

// int close(int fd)
int sys_close(int fd) {
	int r;
	asm volatile("syscall"
		     : "=a"(r)
		     : "0"(__NR_close), "D"(fd)
		     : "rcx", "r11", "memory");
	return r;
}

// void exit(int status)
void sys_exit(int status) {
	int r;
	asm volatile("syscall"
		     : "=a"(r)
		     : "0"(__NR_exit), "D"(status)
		     : "rcx", "r11", "memory");
}

// int open(const char *pathname, int flags, mode_t mode)
int sys_open(const char *pathname, int flags, mode_t mode) {
	int r;
	asm volatile("syscall"
		     : "=a"(r)
		     : "0"(__NR_open), "D"(pathname), "S"(flags), "d"(mode)
		     : "rcx", "r11", "memory");
	return r;
}

// ssize_t read(int fd, void *buf, size_t count)
ssize_t sys_read(int fd, void *buf, size_t count) {
	ssize_t r;
	asm volatile("syscall"
		     : "=a"(r)
		     : "0"(__NR_read), "D"(fd), "S"(buf), "d"(count)
		     : "rcx", "r11", "memory");
	return r;
}

// ssize_t write(int fd, const void *buf, size_t count)
ssize_t sys_write(int fd, const void *buf, size_t count) {
	ssize_t r;
	asm volatile("syscall"
		     : "=a"(r)
		     : "0"(__NR_write), "D"(fd), "S"(buf), "d"(count)
		     : "rcx", "r11", "memory");
	return r;
}
