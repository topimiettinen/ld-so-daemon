// SPDX-License-Identifier: LGPL-2.1-or-later OR BSD-3-Clause

#include "ld-so-protocol.h"

#include <asm/unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/*
  Local system call implementations
*/

// int close(int fd)
static int sys_close(int fd) {
	int r;
	asm volatile("syscall"
		     : "=a"(r)
		     : "0"(__NR_close), "D"(fd)
		     : "rcx", "r11", "memory");
	return r;
}

// int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
static int sys_connect(int sockfd, const struct sockaddr *addr,
		       socklen_t addrlen) {
	int r;
	asm volatile("syscall"
		     : "=a"(r)
		     : "0"(__NR_connect), "D"(sockfd), "S"(addr), "d"(addrlen)
		     : "rcx", "r11", "memory");
	return r;
}

// void exit(int status)
static void sys_exit(int status) {
	int r;
	asm volatile("syscall"
		     : "=a"(r)
		     : "0"(__NR_exit), "D"(status)
		     : "rcx", "r11", "memory");
}

// void *sys_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
static void *sys_mmap(void *addr, size_t length, int prot, int flags, int fd,
		      off_t offset) {
	void *r;
	register void *_addr asm("rdi") = addr;
	register size_t _length asm("rsi") = length;
	register int _prot asm("rdx") = prot;
	register int _flags asm("r10") = flags;
	register int _fd asm("r8") = fd;
	register off_t _offset asm("r9") = offset;
	asm volatile("syscall"
		     : "=a"(r)
		     : "0"(__NR_mmap), "r"(_addr), "r"(_length), "r"(_prot),
		       "r"(_flags), "r"(_fd), "r"(_offset)
		     : "rcx", "r11", "memory");
	return r;
}

// int munmap(void *addr, size_t length) {
static int sys_munmap(void *addr, size_t length) {
	int r;
	asm volatile("syscall"
		     : "=a"(r)
		     : "0"(__NR_munmap), "r"(addr), "r"(length)
		     : "rcx", "r11", "memory");
	return r;
}

// ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)
static ssize_t sys_recvmsg(int sockfd, struct msghdr *msg, int flags) {
	ssize_t r;
	asm volatile("syscall"
		     : "=a"(r)
		     : "0"(__NR_recvmsg), "D"(sockfd), "S"(msg), "d"(flags)
		     : "rcx", "r11", "memory");
	return r;
}

// int socket(int domain, int type, int protocol)
static int sys_socket(int domain, int type, int protocol) {
	int r;
	asm volatile("syscall"
		     : "=a"(r)
		     : "0"(__NR_socket), "D"(domain), "S"(type), "d"(protocol)
		     : "rcx", "r11", "memory");
	return r;
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

/*
  Local library function implementations
*/

// void memcpy(void *dest, const void *src, size_t n)
static void xmemcpy(void *dst, const void *src, size_t count) {
	char *d = dst;
	const char *s = src;
	while (count-- > 0)
		*d++ = *s++;
}

// For some reason, macro CMSG_NXTHDR() doesn't get inlined, so we provide it here
static struct cmsghdr *xCMSG_NXTHDR(struct msghdr *mhdr, struct cmsghdr *cmsg) {
	if ((size_t)cmsg->cmsg_len < sizeof(struct cmsghdr))
		return NULL;

	cmsg = (struct cmsghdr *)((unsigned char *)cmsg +
				  CMSG_ALIGN(cmsg->cmsg_len));
	if ((unsigned char *)(cmsg + 1) >
		    ((unsigned char *)mhdr->msg_control + mhdr->msg_controllen) ||
	    ((unsigned char *)cmsg + CMSG_ALIGN(cmsg->cmsg_len) >
	     ((unsigned char *)mhdr->msg_control + mhdr->msg_controllen)))
		return NULL;
	return cmsg;
}

// First function started from kernel
void _start(void) {
	int r;

	// Connect to server's UNIX socket
	static const struct sockaddr_un sa = { .sun_family = AF_UNIX,
					       .sun_path = LD_SO_DAEMON_SOCKET };
	int fd = sys_socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		static const char fail[] = "Can't create sockets, exiting\n";
		sys_write(2, fail, sizeof(fail));
		sys_exit(-1);
	}

	r = sys_connect(fd, (const struct sockaddr *)&sa, sizeof(sa));
	if (r < 0) {
		static const char fail[] = "Can't connect to " LD_SO_DAEMON_SOCKET_NICE
					   ", exiting\n";
		sys_write(2, fail, sizeof(fail));
		sys_exit(-1);
	}

	int fds[1024];

	for (;;) {
		// Get commands from server
		char buf[4096];
		struct packet p;
		struct iovec iov = {
			// TBD the pointers may be stale after stack switch
			.iov_base = &p,
			.iov_len = sizeof(p),
		};
		struct msghdr msg = {
			// TBD the pointers may be stale after stack switch
			.msg_iov = &iov,
			.msg_iovlen = sizeof(iov) / sizeof(struct iovec),
			// TBD the pointers may be stale after stack switch
			.msg_control = buf,
			.msg_controllen = sizeof(buf)
		};
		r = sys_recvmsg(fd, &msg, 0);
		if (r <= 0)
			sys_exit(-1);

		// Process commands from server
		switch (p.code) {
		case 'C': // Call
			asm volatile("call *%0\n"
				     :
				     : "r"(p.longval)
				     : "memory");
			break;
		case 'E': // Exit
			sys_exit(p.longval);
			break;
		case 'F': { // File descriptors
			for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
			     cmsg != NULL; cmsg = xCMSG_NXTHDR(&msg, cmsg)) {
				if (cmsg->cmsg_level == SOL_SOCKET &&
				    cmsg->cmsg_type == SCM_RIGHTS) {
					xmemcpy(&fds, &CMSG_DATA(cmsg),
						cmsg->cmsg_len);
					break;
				}
			}
			break;
		}
		case 'L': // cLose
			sys_close(fds[p.longval]);
			break;
		case 'M': // Mmap
			sys_mmap(p.mmap.addr, p.mmap.length, p.mmap.prot,
				 p.mmap.flags,
				 p.mmap.fd == -1 ? -1 : fds[p.mmap.fd],
				 p.mmap.offset);
			break;
		case 'S': // Switch stack
			// TBD the switch may make the pointers stale
			xmemcpy(p.stack.dst, p.stack.src, p.stack.length);
			asm volatile(
				"subq %%rsp, %%rbp\n"
				"subq %0, %%rsp\n"
				"addq %%rsp, %%rbp\n"
				:
				: "r"(p.stack.delta)
				: "memory");
			break;
		case 'U': // mUnmap
			sys_munmap(p.munmap.addr, p.munmap.length);
			break;
		case 'W': // Write
			sys_write(2, &p.write.buf, p.write.count);
			break;
		}
	}
}
