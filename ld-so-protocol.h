// SPDX-License-Identifier: LGPL-2.1-or-later OR BSD-3-Clause

#define LD_SO_DAEMON_SOCKET_NICE "ld-so-daemon"
#define LD_SO_DAEMON_SOCKET "\0"LD_SO_DAEMON_SOCKET_NICE

struct packet {
	char code;
	union {
		struct mmap_args {
			void *addr;
			size_t length;
			int prot;
			int flags;
			int fd;
			off_t offset;
		} mmap;
		struct mprotect_args {
			void *addr;
			size_t length;
			int prot;
		} mprotect;
		struct munmap_args {
			void *addr;
			size_t length;
		} munmap;
		struct stack_args {
			void *dst, *src;
			size_t length;
			unsigned long delta;
		} stack;
		struct write_args {
			char buf[128];
			size_t count;
		} write;
		unsigned long longval;
	};
};
