// SPDX-License-Identifier: LGPL-2.1-or-later OR BSD-3-Clause

#pragma once

#include <stdlib.h>

int sys_close(int fd);
void sys_exit(int status);
int sys_open(const char *pathname, int flags, mode_t mode);
ssize_t sys_read(int fd, void *buf, size_t count);
ssize_t sys_write(int fd, const void *buf, size_t count);
