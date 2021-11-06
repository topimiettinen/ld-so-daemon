// SPDX-License-Identifier: LGPL-2.1-or-later OR BSD-3-Clause

#pragma once

#include <stdlib.h>

void sys_exit(int status);
ssize_t sys_write(int fd, const void *buf, size_t count);
