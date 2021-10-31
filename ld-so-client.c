// SPDX-License-Identifier: LGPL-2.1-or-later OR BSD-3-Clause

#include <asm/unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "ld-so-protocol.h"

static int sys_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	int r;
	asm volatile("syscall"
		     : "=a" (r)
		     : "0"(__NR_connect), "D"(sockfd), "S"(addr), "d"(addrlen)
		     : "rcx", "r11", "memory"
		     );
	return r;
}

static void sys_exit(int status) {
	int r;
	asm volatile("syscall"
		     : "=a" (r)
		     : "0"(__NR_exit), "D"(status)
		     : "rcx", "r11", "memory"
		     );
}

static void *sys_mmap(void *addr, size_t length, int prot, int flags,
		      int fd, off_t offset) {
	void *r;
	register void *_addr asm("rdi") = addr;
	register size_t _length asm("rsi") = length;
	register int _prot asm("rdx") = prot;
	register int _flags asm("r10") = flags;
	register int _fd asm("r8") = fd;
	register off_t _offset asm("r9") = offset;
	asm volatile("syscall"
		     : "=a" (r)
		     : "0"(__NR_mmap), "r"(_addr), "r"(_length), "r"(_prot), "r"(_flags), "r"(_fd), "r"(_offset)
		     : "rcx", "r11", "memory"
		     );
	return r;
}

static int sys_munmap(void *addr, size_t length) {
	int r;
	asm volatile("syscall"
		     : "=a" (r)
		     : "0"(__NR_munmap), "r"(addr), "r"(length)
		     : "rcx", "r11", "memory"
		     );
	return r;
}

static ssize_t sys_recvmsg(int sockfd, struct msghdr *msg, int flags) {
	ssize_t r;
	asm volatile("syscall"
		     : "=a" (r)
		     : "0"(__NR_recvmsg), "D"(sockfd), "S"(msg), "d"(flags)
		     : "rcx", "r11", "memory"
		     );
	return r;
}

static int sys_socket(int domain, int type, int protocol) {
	int r;
	asm volatile("syscall"
		     : "=a" (r)
		     : "0"(__NR_socket), "D"(domain), "S"(type), "d"(protocol)
		     : "rcx", "r11", "memory"
		     );
	return r;
}

static ssize_t sys_write(int fd, const void *buf, size_t count) {
	ssize_t r;
	asm volatile("syscall"
		     : "=a" (r)
		     : "0"(__NR_write), "D"(fd), "S"(buf), "d"(count)
		     : "rcx", "r11", "memory"
		     );
	return r;
}

static void xmemcpy(void *dst, void *src, size_t count) {
	char *d = dst, *s =src;
	while (count-- > 0)
		*d++ = *s++;
}

static struct cmsghdr *xCMSG_NXTHDR(struct msghdr *mhdr, struct cmsghdr *cmsg) {
	if ((size_t)cmsg->cmsg_len < sizeof(struct cmsghdr))
		return NULL;

	cmsg = (struct cmsghdr *)((unsigned char *)cmsg
				  + CMSG_ALIGN(cmsg->cmsg_len));
	if ((unsigned char *)(cmsg + 1) > ((unsigned char *)mhdr->msg_control
					   + mhdr->msg_controllen)
	    || ((unsigned char *) cmsg + CMSG_ALIGN(cmsg->cmsg_len)
		> ((unsigned char *) mhdr->msg_control + mhdr->msg_controllen)))
		return NULL;
	return cmsg;
}

void _start(void) {
	int r;

	static const struct sockaddr_un sa = {
		.sun_family = AF_UNIX,
		.sun_path = LD_SO_DAEMON_SOCKET
	};
	int fd = sys_socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		static const char fail[] = "Can't create sockets, exiting\n";
		sys_write(2, fail, sizeof(fail));
		sys_exit(-1);
	}

	r = sys_connect(fd, (const struct sockaddr *)&sa, sizeof(sa));
	if (r < 0) {
		static const char fail[] = "Can't connect to " LD_SO_DAEMON_SOCKET_NICE ", exiting\n";
		sys_write(2, fail, sizeof(fail));
		sys_exit(-1);
	}

	int fds[1024];

	for (;;) {
		char buf[4096];
		struct packet p;
		struct iovec iov = {
			.iov_base = &p,
			.iov_len = sizeof(p),
		};
		struct msghdr msg = {
			.msg_iov = &iov,
			.msg_iovlen = sizeof(iov) / sizeof(struct iovec),
			.msg_control = buf,
			.msg_controllen = sizeof(buf)
		};
		r = sys_recvmsg(fd, &msg, 0);
		if (r <= 0)
			sys_exit(-1);

		switch (p.code) {
		case 'C': // call
			asm volatile("call *%0\n"
				     : 
				     : "r"(p.longval)
				     : "memory"
				     );
			break;
		case 'E': // exit
			for(;;);
			sys_exit(p.longval);
			break;
		case 'F': { // File descriptors
			for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = xCMSG_NXTHDR(&msg, cmsg)) {
				if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
					xmemcpy(&fds, &CMSG_DATA(cmsg), cmsg->cmsg_len);
					break;
				}
			}
			break;
		}
		case 'M': // mmap
			sys_mmap(p.mmap.addr, p.mmap.length, p.mmap.prot, p.mmap.flags,
				 p.mmap.fd == -1? -1: fds[p.mmap.fd], p.mmap.offset);
			break;
		case 'S': // Switch stack
			xmemcpy(p.stack.dst, p.stack.src, p.stack.length);
			asm volatile("subq %%rsp, %%rbp\n"
				     "subq %0, %%rsp\n"
				     "addq %%rsp, %%rbp\n"
				     : 
				     : "r"(p.stack.delta)
				     : "memory"
				     );
			break;
		case 'U': // munmap
			sys_munmap(p.munmap.addr, p.munmap.length);
			break;
		case 'W': // write
			sys_write(2, &p.write.buf, p.write.count);
			break;
		}
	}
}
