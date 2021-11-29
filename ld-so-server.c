// SPDX-License-Identifier: LGPL-2.1-or-later OR BSD-3-Clause

#define _GNU_SOURCE
#include "config.h"
#include "ld-so-protocol.h"

#include <assert.h>
#include <errno.h>
#include <cpuid.h>
#include <elf.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <selinux/selinux.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-login.h>
#include <sys/random.h>
#include <unistd.h>

#define MAX_EVENTS 10
#define MAX_FILES 256
#define STD_MAPS 4 // vvar + vdso + stack + heap
#define MAX_MAPS (MAX_FILES + STD_MAPS)

//#define DEBUG 1
//#define DEBUG_RND_ADDR 1
//#define DEBUG_PID_MAPS 1
#if DEBUG
#define DPRINTF(format, ...)						\
	fprintf(stderr, "%s: " format, __FUNCTION__, ##__VA_ARGS__)

#if DEBUG_RND_ADDR
#define DPRINTF_RND_ADDR DPRINTF
#else // DEBUG_RND_ADDR
#define DPRINTF_RND_ADDR(format, ...) do { } while (0)
#endif // DEBUG_RND_ADDR

#if DEBUG_PID_MAPS
#define DPRINTF_PID_MAPS DPRINTF
#else // DEBUG_PID_MAPS
#define DPRINTF_PID_MAPS(format, ...) do { } while (0)
#endif // DEBUG_PID_MAPS

#else // DEBUG
#define DPRINTF(format, ...) do { } while (0)
#define DPRINTF_RND_ADDR DPRINTF
#define DPRINTF_PID_MAPS DPRINTF
#endif // DEBUG

// TODO assumes page size of 4096
#define PAGE_BITS 12
#define PAGE_SIZE (1 << PAGE_BITS)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define PAGE_ALIGN_UP(size) (((size) + (PAGE_SIZE - 1)) & PAGE_MASK)

// TODO assumes x86-64
#define ELF_MACHINE EM_X86_64

#ifdef FORCE_CLIENT
#undef CLIENT
#define CLIENT FORCE_CLIENT
#endif

struct mapping {
	unsigned long start, stop;
};

struct mmap_list {
	struct mmap_args mmap;
	int our_fd;
	void *our_mmap;
	struct mmap_list *next;
};

struct symtab_list {
	const Elf64_Sym *symtab;
	const char *strtab;
	unsigned int n_symbols;
	unsigned long their_base;
	void *image;
	unsigned long image_size;
	struct symtab_list *next;
};

struct client_info {
	int fd;
	struct ucred creds;
	char *unit;
	char *pidcon, *peercon;
	struct mapping maps[MAX_MAPS];
	struct mapping exec_maps[MAX_MAPS];
	int n_maps, n_exec_maps;
	struct mmap_list *mmaps;
	struct symtab_list *symtabs;
};

static unsigned long random_address_mask;
static int getrandom_bytes;
static int user_va_space_bits;

// Set socket nonblocking
static void set_nonblock(int fd) {
	int r;

	r = fcntl(fd, F_SETFL, O_NONBLOCK);
	if (r < 0) {
		perror("fcntl");
		exit(EXIT_FAILURE);
	}
}

// Register new file descriptors for epoll()ing
static void epoll_register(int epollfd, int fd, int events) {
	int r;

	struct epoll_event ev;
	ev.events = events;
	ev.data.fd = fd;
	r = epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev);
	if (r < 0) {
		perror("epoll_ctl: add listen_sock");
		exit(EXIT_FAILURE);
	}
}

// Enable socket options SO_PASSCRED, SO_PASSSEC
static void set_options(int fd) {
	int r;
	static const int one = 1;
	static const int options[] = { SO_PASSCRED, SO_PASSSEC };

	for (unsigned int i = 0; i < sizeof(options) / sizeof(int); i++) {
		r = setsockopt(fd, SOL_SOCKET, options[i], &one, sizeof(one));
		if (r < 0) {
			perror("setsockopt");
			exit(EXIT_FAILURE);
		}
	}
}

// Get client's PID, UID, GID
static void get_cred(int fd, size_t size, struct ucred *ret_ucred) {
	int r;
	socklen_t ret_size = size;
	r = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, ret_ucred, &ret_size);
	if (r < 0 || ret_size != size) {
		perror("getsockopt");
		exit(EXIT_FAILURE);
	}
}

/*
  Get needed random bytes, never giving up.
*/
static void get_random(void *data, size_t bytes) {
	for (;;) {
		ssize_t r = getrandom(data, bytes, GRND_RANDOM);
		if (r == bytes)
			return;
	}
}

// Find a random free address range
static unsigned long get_free_address(const struct client_info *client, size_t size) {
	for (;;) {
		unsigned long addr;
retry:
		get_random(&addr, getrandom_bytes);

		addr <<= PAGE_BITS;
		addr &= random_address_mask;

		DPRINTF_RND_ADDR("checking %lx + %zx < %lx\n",
				 addr, size, random_address_mask);
		if (addr + size >= random_address_mask)
			goto retry;

		for (unsigned int i = 0; i < client->n_maps; i++) {
			DPRINTF_RND_ADDR("checking %lx < %lx + %zx < %lx\n",
					 client->maps[i].start, addr, size,
					 client->maps[i].stop);
			if ((addr >= client->maps[i].start &&
			     addr <= client->maps[i].stop) ||
			    (addr + size >= client->maps[i].start &&
			     addr + size <= client->maps[i].stop))
				goto retry;
		}
		DPRINTF_RND_ADDR("found %lx\n", addr);
		return addr;
	}
}

// Send a packet, possibly also file descriptors (one ATM)
static void send_packet(struct client_info *client, struct packet *p, int fd) {
	union {
		char buf[CMSG_SPACE(sizeof(fd))];
		struct cmsghdr align;
	} u;

	struct iovec iov = {
		.iov_base = p,
		.iov_len = sizeof(*p),
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = sizeof(iov) / sizeof(struct iovec),
	};

	if (fd >= 0) {
		msg.msg_control = u.buf;
		msg.msg_controllen = sizeof(u.buf);

		struct cmsghdr *cmsg;
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
		memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
	}
	sendmsg(client->fd, &msg, MSG_NOSIGNAL);
}

// Send a file descriptor
static void send_fd(struct client_info *client, int fd) {
	struct packet p;
	memset(&p, 0, sizeof(p));
	p.code = 'F';
	send_packet(client, &p, fd);
}

static void dump_symbols(const struct client_info *client) {
#if DEBUG
	for (struct symtab_list *p = client->symtabs; p; p = p->next) {
		for (unsigned int i = 0; i < p->n_symbols; i++) {
			const Elf64_Sym *symbol = &p->symtab[i];
			DPRINTF("Symbol %u name %s (%u) value %lx shndx %x addr %lx\n", i,
				&p->strtab[symbol->st_name],
				symbol->st_name, symbol->st_value, symbol->st_shndx,
				p->their_base + symbol->st_value);
		}
	}
#endif
}

static unsigned long get_global_symbol_value(const struct client_info *client, const char *name) {
	for (struct symtab_list *p = client->symtabs; p; p = p->next) {
		for (unsigned int i = 0; i < p->n_symbols; i++) {
			const Elf64_Sym *symbol = &p->symtab[i];
			DPRINTF("Checking symbol %u name %s (%u) value %lx shndx %x addr %lx\n", i,
				&p->strtab[symbol->st_name],
				symbol->st_name, symbol->st_value, symbol->st_shndx,
				p->their_base + symbol->st_value);
			if (symbol->st_shndx != SHN_UNDEF &&
			    strcmp(&p->strtab[symbol->st_name], name) == 0)
				return p->their_base + symbol->st_value;
		}
	}
	return 0;
}

// Get value of ELF symbol
static unsigned long get_symbol_value(const struct client_info *client,
				      unsigned int index,
				      unsigned long their_base) {
	unsigned long ret = 0;
	const Elf64_Sym *symbol = &client->symtabs->symtab[index];
	DPRINTF("Symbol %u name %s (%u) value %lx shndx %x\n", index,
		&client->symtabs->strtab[symbol->st_name],
		symbol->st_name, symbol->st_value, symbol->st_shndx);
	if (symbol->st_shndx == SHN_UNDEF)
		ret = get_global_symbol_value(client, &client->symtabs->strtab[symbol->st_name]);
	else
		ret = their_base + symbol->st_value;
	DPRINTF("Returning %lx\n", ret);
	return ret;
}

// RELocate with Addend type
static int process_rela(const struct client_info *client,
			struct mmap_list *list,
			const Elf64_Shdr *elf_section,
			void *image, unsigned long their_base) {
	int ret = -1;
	unsigned int n_relocs = elf_section->sh_size /
		elf_section->sh_entsize;
	Elf64_Rela *elf_rela;
	for (unsigned int i = 0; i < n_relocs; i++) {
		elf_rela = (void *)((unsigned long)image +
				    elf_section->sh_offset +
				    elf_section->sh_entsize * i);
		unsigned long offset = elf_rela->r_offset;
		unsigned int symbol = ELF64_R_SYM(elf_rela->r_info);
		unsigned int type = ELF64_R_TYPE(elf_rela->r_info);
		unsigned long addend = elf_rela->r_addend;
		unsigned long *ptr = (void *)((unsigned long)image + offset);
		DPRINTF("Got reloc off %lx sym %x type %x addend %lx their_base %lx\n",
			offset, symbol, type, addend, their_base);

		switch (type) {
		case R_X86_64_64: {
			unsigned long value = get_symbol_value(client, symbol, their_base);
			*ptr = value + addend;
			break;
		}
		case R_X86_64_JUMP_SLOT:
		case R_X86_64_GLOB_DAT: {
			unsigned long value = get_symbol_value(client, symbol, their_base);
			*ptr = value;
			break;
		}
		case R_X86_64_RELATIVE:
			*ptr = their_base + addend;
			break;
		default:
			fprintf(stderr, "Unhandled relocation type %x, aborting\n",
				type);
			abort();
		}
		ret = 0;
	}

	return ret;
}

// Create a writable memory region with memfd and copy initial data
static int copy_maps(struct mmap_list *p, void *base) {
	int r, ret = -1;

	assert(p);
	assert(base);

	int orig_fd = p->our_fd;

	p->our_fd = memfd_create("ld-so-server relocations", MFD_CLOEXEC);
	if (p->our_fd < 0) {
		goto finish;
	}
	r = ftruncate(p->our_fd, p->mmap.length);
	if (r < 0) {
		perror("ftruncate");
		goto finish;
	}

	base = (void *)((unsigned long)base + p->mmap.addr);
	DPRINTF("mmapping memfd %p + %lx\n", base, p->mmap.length);

	p->our_mmap = mmap(base, p->mmap.length, p->mmap.prot,
			   p->mmap.flags, p->our_fd, 0);
	if (p->our_mmap == MAP_FAILED) {
		perror("mmap");
		goto finish;
	}
	if (orig_fd != -1)
		pread(orig_fd, base, p->mmap.length, p->mmap.offset);

	p->mmap.offset = 0;

	// All OK
	ret = 0;
finish:
	return ret;
}

// Send mUnmap command
static unsigned long send_munmap(struct client_info *client,
				    unsigned long start, size_t length) {
	struct packet p;
	memset(&p, 0, sizeof(p));
	p.code = 'U';
	p.munmap.addr = (void *)start;
	p.munmap.length = length;
	send_packet(client, &p, -1);
	return 0;
}

/*
  Install seccomp filters to only allow system calls from executable
  segments.
*/
static void add_seccomp(struct client_info *client) {
	struct sock_filter *filter = NULL;
	unsigned int count = 0;
	int r;

	for (unsigned int i = 0; i < client->n_exec_maps; i++) {
		DPRINTF("seccomping %lx ... %lx\n",
				 client->exec_maps[i].start, client->exec_maps[i].stop);
		unsigned long start = client->exec_maps[i].start;
		unsigned long stop = client->exec_maps[i].stop;
		count += 7;
		filter = realloc(filter, sizeof(struct sock_filter) * count);
		// TODO endianness
		// Compare MSW of IP to this segment
		filter[count - 7] = (struct sock_filter)
			BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
				 (offsetof(struct seccomp_data, instruction_pointer)) + sizeof(int));
		filter[count - 6] = (struct sock_filter)
			BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K,
				 start >> 32, 0, 5);
		filter[count - 5] = (struct sock_filter)
			BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K,
				 stop >> 32, 4, 0);

		// Compare LSW of IP to this segment
		filter[count - 4] = (struct sock_filter)
			BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
				 (offsetof(struct seccomp_data, instruction_pointer)));
		filter[count - 3] = (struct sock_filter)
			BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K,
				 start & 0xffffffff, 0, 2);
		filter[count - 2] = (struct sock_filter)
			BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K,
				 stop & 0xffffffff, 1, 0);

		// All OK: allow
		filter[count - 1] = (struct sock_filter)
			BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW);
	}
	count++;
	filter = realloc(filter, sizeof(struct sock_filter) * count);
	// No match: kill
	filter[count - 1] = (struct sock_filter)
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS);

	for (unsigned int i = 0; i < count; i++)
		DPRINTF("code 0x%x jt %d jf %d k %x\n", filter[i].code, filter[i].jt, filter[i].jf, filter[i].k);

	int seccomp_fd = memfd_create("ld-so-server seccomp", MFD_CLOEXEC);
	if (seccomp_fd < 0) {
		perror("memfd_create");
		return;
	}

	size_t seccomp_length = sizeof(struct sock_filter) * count;
	r = ftruncate(seccomp_fd, seccomp_length);
	if (r < 0) {
		perror("ftruncate");
		return;
	}

	pwrite(seccomp_fd, filter, seccomp_length, 0);

	send_fd(client, seccomp_fd);

	close(seccomp_fd);

	unsigned long seccomp_base = get_free_address(client, seccomp_length);

	// Mmap command
	struct packet p;
	memset(&p, 0, sizeof(p));
	p.code = 'M';
	p.mmap.addr = (void *)seccomp_base;
	p.mmap.length = seccomp_length;
	p.mmap.prot = PROT_READ;
	p.mmap.flags = MAP_FIXED_NOREPLACE | MAP_PRIVATE;
	p.mmap.fd = 0;
	p.mmap.offset = 0;
	send_packet(client, &p, -1);

	// cLose command
	memset(&p, 0, sizeof(p));
	p.code = 'L';
	p.longval = 0;
	send_packet(client, &p, -1);

	// seccOmp command
	memset(&p, 0, sizeof(p));
	p.code = 'O';
	p.seccomp.len = count;
	p.seccomp.filter = (void *)seccomp_base;
	p.seccomp.flags = SECCOMP_FILTER_FLAG_LOG;
	send_packet(client, &p, -1);

	send_munmap(client, seccomp_base, seccomp_length);
}

// Process ELF relocations
static unsigned long process_relocations(struct client_info *client, int fd,
					 size_t stat_length, bool call) {
	int r;
	unsigned long ret = -1;
	void *image = mmap(NULL, stat_length, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (image == MAP_FAILED)
		goto finish;

	// We should only get valid ELF executables here
	Elf64_Ehdr *elf_header = image;
	if (memcmp(elf_header->e_ident, ELFMAG, SELFMAG) != 0 ||
	    elf_header->e_machine != ELF_MACHINE) {
		fprintf(stderr, "Not a valid ELF file\n");
		goto finish;
	}

	// Check ELF segments
	unsigned long max_addr = 0;
	struct mmap_list *list = NULL, *tail = NULL;
	for (unsigned int i = 0; i < elf_header->e_phnum; i++) {
		Elf64_Phdr *elf_segment = (void *)((unsigned long)image +
						   elf_header->e_phoff + elf_header->e_phentsize * i);

		// TODO check if ELF headers and dynamic stuff is only
		// needed by server and not in client
		if (elf_segment->p_type == PT_LOAD) {
			// Loadable segment
			unsigned long offset = elf_segment->p_offset;
			unsigned long vaddr = elf_segment->p_vaddr;
			unsigned long align = vaddr & ~PAGE_MASK;
			unsigned long length = elf_segment->p_memsz;
			unsigned long file_length = elf_segment->p_filesz;
			if (max_addr < vaddr + length)
				max_addr = vaddr + length;
			vaddr -= align;
			offset -= align;
			length += align;
			file_length += align;
			struct mmap_list *new = malloc(sizeof(*new));
			new->mmap.addr = (void *)vaddr;
			new->mmap.length = file_length;
			new->mmap.prot = 0;
			if (elf_segment->p_flags & PF_X)
				new->mmap.prot |= PROT_EXEC;
			if (elf_segment->p_flags & PF_W)
				new->mmap.prot |= PROT_WRITE;
			if (elf_segment->p_flags & PF_R)
				new->mmap.prot |= PROT_READ;
			new->mmap.flags = MAP_FIXED_NOREPLACE | MAP_PRIVATE;
			new->mmap.fd = 0;
			new->mmap.offset = offset;
			new->our_fd = fd;
			new->next = list;
			list = new;
			if (!tail)
				tail = new;

			/*
			  If the file size is smaller than in memory
			  size, we may have some BSS.
			*/
			if (PAGE_ALIGN_UP(file_length) < PAGE_ALIGN_UP(length)) {
				struct mmap_list *bss = malloc(sizeof(*bss));
				bss->mmap.addr = (void *)(vaddr + PAGE_ALIGN_UP(file_length));
				bss->mmap.length = PAGE_ALIGN_UP(length) - PAGE_ALIGN_UP(file_length);
				bss->mmap.prot = new->mmap.prot;
				bss->mmap.flags = MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | MAP_PRIVATE;
				bss->mmap.fd = -1;
				bss->mmap.offset = 0;
				bss->our_fd = -1;
				bss->next = list;
				list = bss;
			}
		}
	}

	if (!list)
		goto finish;

	/*
	  Mmap() the segments in correct in memory positions instead
	  of raw file order. Allocate a large block first to find an
	  address which won't conflict with other mappings later, even
	  when run from GDB.
	*/
	void *our_base = mmap(NULL, max_addr, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (our_base == MAP_FAILED)
		goto finish;
	r = munmap(our_base, max_addr);
	if (r < 0)
		goto finish;

	unsigned long their_base = get_free_address(client, max_addr);
	//unsigned long their_base = 0x10000000;

	DPRINTF("our_base %p + %lx, their_base %lx\n", our_base, max_addr, their_base);

	for (struct mmap_list *p = list; p; p = p->next) {
		DPRINTF("M addr %p len %lx prot %d flags %d fd %d off %lx our_fd %d\n",
			p->mmap.addr, p->mmap.length, p->mmap.prot, p->mmap.flags,
			p->mmap.fd, p->mmap.offset, p->our_fd);
		if (p->mmap.prot & PROT_WRITE) {
			r = copy_maps(p, our_base);
			if (r < 0)
				goto finish;
		} else {
			void *base = (void *)((unsigned long)our_base + (unsigned long)p->mmap.addr);
			DPRINTF("mmapping %p + %lx\n", base, p->mmap.length);
			p->our_mmap = mmap(base, p->mmap.length, p->mmap.prot,
					  p->mmap.flags | MAP_FIXED_NOREPLACE, p->our_fd, p->mmap.offset);
			if (p->our_mmap == MAP_FAILED)
				goto finish;
		}
	}

	// Check ELF sections
	Elf64_Sym *dynamic_symtab = NULL;
	char *dynamic_strtab = NULL;
	unsigned int n_symbols;
	for (unsigned int i = 0; i < elf_header->e_shnum; i++) {
		Elf64_Shdr *elf_section = (void *)((unsigned long)image +
						   elf_header->e_shoff + elf_header->e_shentsize * i);
		if (elf_section->sh_type == SHT_DYNSYM) {
			dynamic_symtab = (void *)((unsigned long)image +
						  elf_section->sh_offset);
			n_symbols = elf_section->sh_size /
				elf_section->sh_entsize;
			Elf64_Word strtab_link = elf_section->sh_link;
			Elf64_Shdr *strtab_section = (void *)((unsigned long)image +
							      elf_header->e_shoff +
							      elf_header->e_shentsize * strtab_link);
			dynamic_strtab = (void *)((unsigned long)image +
						  strtab_section->sh_offset);
		}
	}

	if (dynamic_strtab && dynamic_symtab) {
		struct symtab_list *new = malloc(sizeof(*new));
		new->strtab = dynamic_strtab;
		new->symtab = dynamic_symtab;
		new->n_symbols = n_symbols;
		new->their_base = their_base;
		new->image = image;
		new->image_size = stat_length;
		new->next = client->symtabs;
		client->symtabs = new;
		dump_symbols(client);
	}

	// Handle relocations
	for (unsigned int i = 0; i < elf_header->e_shnum; i++) {
		Elf64_Shdr *elf_section = (void *)((unsigned long)image +
						   elf_header->e_shoff + elf_header->e_shentsize * i);
		// x86_64: RELA only
		if (elf_section->sh_type == SHT_RELA) {
			r = process_rela(client, list, elf_section, our_base, their_base);
			if (r < 0)
				goto finish;
		}
	}

	unsigned long low = ULONG_MAX, high = 0;
	unsigned long exec_low = ULONG_MAX, exec_high = 0;
	struct packet p;
	// Send file descriptors and mmap commands to client
	for (struct mmap_list *l = list; l; l = l->next) {
		DPRINTF("M addr %p len %lx prot %d flags %d fd %d off %lx our_fd %d\n",
			l->mmap.addr, l->mmap.length, l->mmap.prot, l->mmap.flags,
			l->mmap.fd, l->mmap.offset, l->our_fd);

		// Flush in memory modifications to memfd
		if (l->mmap.prot & PROT_WRITE && l->our_fd != -1 && l->our_mmap != NULL)
			pwrite(l->our_fd, l->our_mmap, l->mmap.length, 0);

		// TODO only send descriptors once, there's probably
		// only two per file
		if (l->mmap.fd != -1)
			send_fd(client, l->our_fd);

		// Mmap command
		memset(&p, 0, sizeof(p));
		p.code = 'M';
		memcpy(&p.mmap, &l->mmap, sizeof(p.mmap));
		p.mmap.addr = (void *)(their_base + (unsigned long)l->mmap.addr);
		send_packet(client, &p, -1);

		if (low > (unsigned long)p.mmap.addr)
			low = (unsigned long)p.mmap.addr;
		if (high < (unsigned long)p.mmap.addr + p.mmap.length)
			high = (unsigned long)p.mmap.addr + p.mmap.length;

		if (l->mmap.prot & PROT_EXEC) {
			if (exec_low > (unsigned long)p.mmap.addr)
				exec_low = (unsigned long)p.mmap.addr;
			if (exec_high < (unsigned long)p.mmap.addr + p.mmap.length)
				exec_high = (unsigned long)p.mmap.addr + p.mmap.length;
		}

		// cLose command
		if (l->mmap.fd != -1) {
			memset(&p, 0, sizeof(p));
			p.code = 'L';
			p.longval = l->mmap.fd;
			send_packet(client, &p, -1);
		}
	}

	// Map guard pages
	memset(&p, 0, sizeof(p));
	p.code = 'M';
	p.mmap.addr = (void *)(low - PAGE_SIZE);
	p.mmap.length = PAGE_SIZE;
	p.mmap.prot = PROT_NONE;
	p.mmap.flags = MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | MAP_PRIVATE;
	p.mmap.fd = -1;
	send_packet(client, &p, -1);

	p.mmap.addr = (void *)high;
	send_packet(client, &p, -1);

	if (list) {
		tail->next = client->mmaps;
		client->mmaps = list;

		client->maps[client->n_maps].start = low - PAGE_SIZE;
		client->maps[client->n_maps].stop = high + PAGE_SIZE;
		client->n_maps++;

		if (exec_low != ULONG_MAX) {
			DPRINTF("exec start %lx stop %lx\n", exec_low, exec_high);
			client->exec_maps[client->n_exec_maps].start = exec_low;
			client->exec_maps[client->n_exec_maps].stop = exec_high;
			client->n_exec_maps++;
		}
	}

	if (call) {
		add_seccomp(client);

		// Call command
		struct packet p;
		memset(&p, 0, sizeof(p));
		p.code = 'C';
		p.longval = their_base + elf_header->e_entry;
		send_packet(client, &p, -1);
	}

	ret = their_base;
finish:
	return ret;
}

// Check file properties and send a file descriptor of it if OK
static unsigned long process_file(struct client_info *client, const char *file, bool call) {
	int r;
	unsigned long ret = -1;

	int fd = open(file, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Bad file %s, ignoring\n", file);
		return -1;
	}

	struct stat st;
	r = fstat(fd, &st);
	if (r < 0) {
		fprintf(stderr, "Can't stat %s, ignoring\n", file);
		goto finish;
	}

	// The file must be a regular file or a symlink
	if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) {
		fprintf(stderr, "Bad file type for %s, ignoring\n", file);
		goto finish;
	}

	/*
	  The file must be world readable (in case the server runs
	  with different privileges than the client)
	*/
	if ((st.st_mode & S_IROTH) != S_IROTH) {
		fprintf(stderr, "File %s isn't world readable, ignoring\n", file);
		goto finish;
	}

	// Check if client domain is allowed to execute the file
	char *filecon;
	r = fgetfilecon_raw(fd, &filecon);
	if (r < 0)
		goto finish;

	r = selinux_check_access(client->pidcon, filecon, "file", "execute",
				 NULL);
	// TODO maybe more checks like:
	// file { open read map }
	// process { execheap execmem execmod execstack }

	// TODO remove #if 0: fix check above to consider also
	// whether the domain is permissive
#if 0
	if (r < 0)
		goto finish;
#endif

	ret = process_relocations(client, fd, st.st_size, call);
	if (ret < 0)
		goto finish;

	send_fd(client, fd);

finish:
	close(fd);

	return ret;
}

// Load a profile file
static bool process_profile(struct client_info *client, const char *prefix) {
#ifdef FORCE_UNIT
	// Test use
	FILE *f = fopen(FORCE_UNIT, "r");
	DPRINTF("Forced profile %s\n", FORCE_UNIT);
#else
	char path[4096];

	int r = snprintf(path, sizeof(path), "%s/ld.so.daemon/%s.profile",
			 prefix, client->unit);
	if (r < 0 || r > sizeof(path))
		return false;

	FILE *f = fopen(path, "r");
#endif

	if (!f)
		return false;

	unsigned long base[MAX_FILES];
	memset(base, 0, sizeof(base));
	for (;;) {
		char line[BUFSIZ];
		char *s = fgets(line, sizeof(line), f);
		if (!s)
			goto finish;

		if (line[strlen(line) - 1] == '\n')
			line[strlen(line) - 1] = '\0';

		size_t len = strlen(line);
		DPRINTF("Got line %s\n", line);
		switch (*line) {
		case '#':
		case '\0':
			continue;
		case 'E':    // Executable
		case 'L': {  // Library
			assert(len > 2);
			char *endptr;
			int file_id = strtoul(line + 2, &endptr, 0);
			assert(endptr > line + 2);
			assert(file_id >= 0 && file_id < MAX_FILES);
			assert(*endptr != '\0');
			endptr++;
			assert(*endptr != '\0');
			bool call = false;
			if (*line == 'E')
				call = true;
			base[file_id] = process_file(client, endptr, call);
			DPRINTF("mmap base[%d] %lx\n", file_id, base[file_id]);
			break;
		}
		default:
			goto finish;
		}
	}

	// TODO mappings are never unmapped.

finish:
	fclose(f);
	return true;
}

/*
  Load a profile named `service.profile` using the name of the
  service. The profiles are loaded from directories

  `/etc/ld.so.daemon` (local admin)
  `/usr/lib/ld.so.daemon/` (distro),
  `/run/ld.so.daemon` (generators)

  The first found wins and further directories are not read: it
  wouldn't make sense to merge the files.
*/
static void process_profiles(struct client_info *client) {
#ifdef PROFILE_DIR
	// Test use
	if (process_profile(client, PROFILE_DIR))
		return;
#endif
	if (process_profile(client, "/run"))
		return;
	if (process_profile(client, SYSCONFDIR))
		return;
	if (process_profile(client, LIBDIR))
		return;
}

// Install guard pages around DSOs with mmap(..., PROT_NONE, ...)
static void add_guards(struct client_info *client,
		       unsigned long start, size_t length) {
	struct packet p;

	memset(&p, 0, sizeof(p));
	p.code = 'M';
	p.mmap.addr = (void *)(start - PAGE_SIZE);
	p.mmap.length = PAGE_SIZE;
	p.mmap.prot = PROT_NONE;
	p.mmap.flags = MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | MAP_PRIVATE;
	p.mmap.fd = -1;
	send_packet(client, &p, -1);

	if (length) {
		p.mmap.addr = (void *)(start + length);
		send_packet(client, &p, -1);
	}
}

/*
  Switch stacks:
  - map a new area for new stack
  - order client to copy the old stack and switch to new stack
  - unmap old stack
*/
static unsigned long process_stack(struct client_info *client,
				   unsigned long start, size_t length) {
	struct packet p;
	// TODO check RLIMIT_STACK but 2MB should be good enough for
	// all apps and a fully allocated stack is better for
	// randomization, or make this configurable per client
	size_t new_length = 2 * 1024 * 1024;
	unsigned long addr = get_free_address(client, new_length);

	// Map a new stack
	memset(&p, 0, sizeof(p));
	p.code = 'M';
	p.mmap.addr = (void *)addr;
	p.mmap.length = new_length;
	p.mmap.prot = PROT_READ | PROT_WRITE;
	p.mmap.flags = MAP_PRIVATE | MAP_ANONYMOUS;
	p.mmap.fd = -1;
	send_packet(client, &p, -1);

	// Switch to new stack
	memset(&p, 0, sizeof(p));
	p.code = 'S';
	p.stack.dst = (void *)(addr + new_length - length);
	p.stack.src = (void *)start;
	p.stack.length = length;
	// delta = old_stack_top - new_stack_top
	p.stack.delta = (start + length) - (addr + new_length);
	send_packet(client, &p, -1);

	// Unmap old stack
	send_munmap(client, start, length);

	add_guards(client, addr, new_length);
	return 0;
}

/*
  Check that /proc/$CLIENT/exe points to our client.
*/
static int check_pid_exe(struct client_info *client, pid_t pid) {
	int r;
	char path[4096];

	r = snprintf(path, sizeof(path), "/proc/%d/exe", pid);
	if (r >= sizeof(path))
		return -1;

	char buf[PATH_MAX];
	r = readlink(path, buf, sizeof(buf));
	if (r < 0 || r == sizeof(buf))
		return false;

	// TBD: assumes that the server can access the client exe,
	// need not be true
	r = access(buf, R_OK | X_OK);
	if (r < 0)
		return false;

	if (strcmp(buf, CLIENT) != 0) {
		DPRINTF("Bad exe %s, want %s\n", buf, CLIENT);
		return false;
	}

	return true;
}

/*
  Read /proc/$CLIENT/maps and check for unexpected segments.

  [heap] segments are unmapped (TBD, assumes libaslrmalloc)

  [stack] segments are relocated (TBD, could be too fragile)

  [vvar] and [vdso] segments are not touched (TBD, check if they are
  relocatable)

  Other segments must point to our client executable.

  Guard pages are added around segments.
*/
static int check_pid_maps(struct client_info *client, pid_t pid, bool process) {
	int r;
	char path[4096];

	r = snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	if (r >= sizeof(path))
		return -1;

	FILE *f = fopen(path, "r");
	if (!f)
		return false;

	for (;;) {
		char line[BUFSIZ];
		char *s = fgets(line, sizeof(line), f);
		if (line[strlen(line) - 1] == '\n')
			line[strlen(line) - 1] = '\0';

		if (!s)
			goto finish;

		DPRINTF_PID_MAPS("Got line %s\n", line);

		unsigned long start, stop, offset;
		int pos;
		char x;
		r = sscanf(line, "%lx-%lx %*c%*c%c%*c %lx %*x:%*x %*d %n",
			   &start, &stop, &x, &offset, &pos);
		if (r == EOF)
			return -1;
		char *name = &line[pos];
		DPRINTF_PID_MAPS("start %lx stop %lx x %c offset %lx %s\n", start,
				 stop, x, offset, name);

		// On the second pass, don't process but just output
		// TODO could verify that changes are applied correctly
		if (!process)
			continue;

		client->maps[client->n_maps].start = start;
		client->maps[client->n_maps].stop = stop;
		client->n_maps++;
		assert(client->n_maps < MAX_MAPS);

		if (x == 'x') {
			client->exec_maps[client->n_exec_maps].start = start;
			client->exec_maps[client->n_exec_maps].stop = stop;
			client->n_exec_maps++;
			assert(client->n_exec_maps < MAX_MAPS);
			DPRINTF_PID_MAPS("exec start %lx stop %lx %s\n", start,
					 stop, name);
		}

		// TODO unmapping would assume libaslrmalloc
		if (strcmp(name, "[heap]") == 0) {
			//send_munmap(client, start, stop - start);
			//add_guards(client, start, stop - start);
			continue;
		}

		// TODO check if these can be relocated
		if (strcmp(name, "[vvar]") == 0 || strcmp(name, "[vdso]") == 0) {
			add_guards(client, start, stop - start);
			continue;
		}

		// TODO maybe switching stacks is too fragile
		if (strcmp(name, "[stack]") == 0) {
			process_stack(client, start, stop - start);
			continue;
		}

		// Does this point to our client executable?
		if (strcmp(name, CLIENT) == 0) {
			// TODO no guard page is mapped at the end to
			// allow for heap
			add_guards(client, start, 0);
			continue;
		}

		// Bad segments
		fprintf(stderr, "Bad segment %s, want %s\n", name, CLIENT);
		fclose(f);
		return false;
	}

finish:
	fclose(f);
	return true;
}

// Identify client
static void process_client(int client_fd) {
	int r;

	struct client_info client;
	memset(&client, 0, sizeof(client));

	client.fd = client_fd;

	get_cred(client_fd, sizeof(client.creds), &client.creds);

	sd_pid_get_unit(client.creds.pid, &client.unit);

	r = getpidcon_raw(client.creds.pid, &client.pidcon);
	if (r < 0)
		goto finish;

	r = getpeercon_raw(client_fd, &client.peercon);
	if (r < 0)
		goto finish;

	DPRINTF("PID %u UID %u GID %u unit %s pidcon %s peercon %s\n",
		client.creds.pid, client.creds.uid, client.creds.gid,
		client.unit, client.pidcon, client.peercon);

	r = check_pid_exe(&client, client.creds.pid);
	if (!r)
		goto finish;

	// First pass: process segments
	r = check_pid_maps(&client, client.creds.pid, true);
	if (!r)
		goto finish;

	// Second pass: only output (should verify)
	r = check_pid_maps(&client, client.creds.pid, false);
	if (!r)
		goto finish;

	// Load profile
	process_profiles(&client);

finish:
	free(client.unit);
	freecon(client.pidcon);
	freecon(client.peercon);

	close(client_fd);
}

int main(void) {
	int r;

	/*
	   Get number of virtual address bits with CPUID
	   instruction. There are lots of different values from 36 to
	   57 (https://en.wikipedia.org/wiki/X86).
	 */
	unsigned int eax, unused;
	r = __get_cpuid(0x80000008, &eax, &unused, &unused, &unused);

	/*
	  Calculate a mask for requesting random addresses so that the
	  kernel should accept them.
	*/
	user_va_space_bits = 36;
	if (r == 1)
		user_va_space_bits = ((eax >> 8) & 0xff) - 1;
	random_address_mask = ((1UL << user_va_space_bits) - 1) &
		PAGE_MASK;

	// Also calculate number of random bytes needed for each address
	getrandom_bytes = (user_va_space_bits - PAGE_BITS + 7) / 8;

	// Set up listening socket
	int listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		sd_notifyf(0,
			   "STATUS=Failed to start up: %s\n"
			   "ERRNO=%i",
			   strerror(errno), errno);
		perror("Can't create sockets, exiting\n");
		exit(EXIT_FAILURE);
	}

	struct sockaddr_un sa = { .sun_family = AF_UNIX,
				  .sun_path = LD_SO_DAEMON_SOCKET };
	r = bind(listen_fd, (const struct sockaddr *)&sa, sizeof(LD_SO_DAEMON_SOCKET) + 1);
	if (r < 0) {
		sd_notifyf(0,
			   "STATUS=Failed to start up: %s\n"
			   "ERRNO=%i",
			   strerror(errno), errno);
		perror("Can't bind sockets, exiting\n");
		exit(EXIT_FAILURE);
	}

	r = listen(listen_fd, SOMAXCONN);
	if (r < 0) {
		sd_notifyf(0,
			   "STATUS=Failed to start up: %s\n"
			   "ERRNO=%i",
			   strerror(errno), errno);
		perror("Can't listen to sockets, exiting\n");
		exit(EXIT_FAILURE);
	}

	int epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		sd_notifyf(0,
			   "STATUS=Failed to start up: %s\n"
			   "ERRNO=%i",
			   strerror(errno), errno);
		perror("epoll_create1");
		exit(EXIT_FAILURE);
	}

	set_nonblock(listen_fd);
	set_options(listen_fd);
	epoll_register(epoll_fd, listen_fd, EPOLLIN | EPOLLHUP | EPOLLET);

	sd_notify(0, "READY=1");

	// Main event loop
	for (;;) {
		struct epoll_event events[MAX_EVENTS];
		int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
		if (nfds < 0 && errno == EINTR)
			continue;
		if (nfds < 0) {
			perror("epoll_wait");
			exit(EXIT_FAILURE);
		}
		if (nfds == 0) {
			fprintf(stderr, "epoll_wait: timeout");
			exit(EXIT_FAILURE);
		}

		for (int n = 0; n < nfds; ++n) {
			int fd = events[n].data.fd;
			if (fd == listen_fd) {
				DPRINTF("event on listen fd %d\n", fd);

				int client_fd = accept4(listen_fd, NULL, NULL,
							SOCK_CLOEXEC);
				if (client_fd < 0) {
					perror("Can't accept sockets, exiting\n");
					exit(EXIT_FAILURE);
				}
				process_client(client_fd);
			}
		}
	}
	return -1;
}
