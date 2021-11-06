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
#include <selinux/selinux.h>
#include <stdbool.h>
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
#if DEBUG
#define DPRINTF(format, ...)						\
	fprintf(stderr, "%s: " format, __FUNCTION__, ##__VA_ARGS__)
#else
#define DPRINTF(format, ...) do { } while (0)
#endif

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

struct client_info {
	int fd;
	struct ucred creds;
	char *unit;
	char *pidcon, *peercon;
	struct mapping maps[MAX_MAPS];
	int n_maps;
	struct mmap_list *mmaps;
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

		DPRINTF("checking %lx + %zx < %lx\n",
			addr, size, random_address_mask);
		if (addr + size >= random_address_mask)
			goto retry;

		for (unsigned int i = 0; i < client->n_maps; i++) {
			DPRINTF("checking %lx < %lx + %zx < %lx\n",
				client->maps[i].start, addr, size,
				client->maps[i].stop);
			if ((addr >= client->maps[i].start &&
			     addr <= client->maps[i].stop) ||
			    (addr + size >= client->maps[i].start &&
			     addr + size <= client->maps[i].stop))
				goto retry;
		}
		DPRINTF("found %lx\n", addr);
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
	sendmsg(client->fd, &msg, 0);
}

// Send a file descriptor
static void send_fd(struct client_info *client, int fd) {
	struct packet p;
	memset(&p, 0, sizeof(p));
	p.code = 'F';
	send_packet(client, &p, fd);
}

// Get value of ELF symbol
static unsigned long get_symbol_value(unsigned int index, void *image,
				      const Elf64_Sym *symtab,
				      const char *strtab) {
	const Elf64_Sym *symbol = &symtab[index];
	DPRINTF("Symbol %u name %s (%u) value %lx\n", index,
		strtab[symbol->st_name];
		symbol->st_name, symbol->st_value);
	return symbol->st_value;
}

// RELocate with Addend type
static int process_rela(struct client_info *client,
			struct mmap_list *list,
			const Elf64_Shdr *elf_section,
			void *image, size_t stat_length,
			const Elf64_Sym *symtab,
			const char *strtab,
			unsigned long their_base) {
	int ret = -1;
	unsigned int n_relocs = elf_section->sh_size /
		elf_section->sh_entsize;
	Elf64_Rela *elf_rela;
	for (unsigned int i = 0; i < n_relocs; i++) {
		elf_rela = (void *)((unsigned long)image +
				    elf_section->sh_offset +
				    elf_section->sh_entsize * i);
		DPRINTF("Got reloc off %lx sym %lx type %lx addend %lx their_base %lx\n",
			elf_rela->r_offset, ELF64_R_SYM(elf_rela->r_info),
			ELF64_R_TYPE(elf_rela->r_info), elf_rela->r_addend,
			their_base);

		switch (ELF64_R_TYPE(elf_rela->r_info)) {
		case R_X86_64_64: {
			uint64_t value = get_symbol_value(ELF64_R_SYM(elf_rela->r_info),
							  image, symtab, strtab);
			// TODO fancier pointer arithmetic
			*(uint64_t *)((unsigned long)image +
				      elf_rela->r_offset) = their_base + value + elf_rela->r_addend;
			break;
		}
		case R_X86_64_GLOB_DAT: {
			uint64_t value = get_symbol_value(ELF64_R_SYM(elf_rela->r_info),
							  image, symtab, strtab);
			// TODO fancier pointer arithmetic
			*(uint64_t *)((unsigned long)image +
				      elf_rela->r_offset) = their_base + value;
			break;
		}
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

// Process ELF relocations
static unsigned long process_relocations(struct client_info *client, int fd,
					 size_t stat_length) {
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
	Elf64_Phdr *elf_segment;
	unsigned long max_addr = 0;
	struct mmap_list *list = NULL, *tail = NULL;
	Elf64_Sym *dynamic_symtab = NULL;
	char *dynamic_strtab = NULL;
	for (unsigned int i = 0; i < elf_header->e_phnum; i++) {
		elf_segment = (void *)((unsigned long)image +
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
		} else if (elf_segment->p_type == PT_DYNAMIC) {
			// Dynamic symbols and strings for relocations
			Elf64_Dyn *dynamic = (void *)((unsigned long)image +
						      elf_segment->p_offset);
			for (unsigned int j = 0; j < elf_segment->p_memsz / sizeof(Elf64_Dyn); j++) {
				if (dynamic[j].d_tag == DT_STRTAB)
					dynamic_strtab = (void *)((unsigned long)image +
								  dynamic[j].d_un.d_ptr);
				else if (dynamic[j].d_tag == DT_SYMTAB)
					dynamic_symtab = (void *)((unsigned long)image +
								  dynamic[j].d_un.d_ptr);
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
	DPRINTF("our_base %p + %lx\n", our_base, max_addr);

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

	unsigned long their_base = get_free_address(client, max_addr);
	//unsigned long their_base = 0x10000000;

	// Handle relocations
	Elf64_Shdr *elf_section;
	for (unsigned int i = 0; i < elf_header->e_shnum; i++) {
		elf_section = (void *)((unsigned long)image +
					      elf_header->e_shoff + elf_header->e_shentsize * i);

		// x86_64: RELA only
		if (elf_section->sh_type == SHT_RELA) {
			r = process_rela(client, list, elf_section, our_base, stat_length,
					 dynamic_symtab, dynamic_strtab, their_base);
			if (r < 0)
				goto finish;
		}
	}

	// Pass 3: flush in memory modifications to memfd
	for (struct mmap_list *p = list; p; p = p->next)
		if (p->mmap.prot & PROT_WRITE && p->our_fd != -1 && p->our_mmap != NULL)
			pwrite(p->our_fd, p->our_mmap, p->mmap.length, 0);

	// Send file descriptors and mmap commands to client
	for (struct mmap_list *l = list; l; l = l->next) {
		DPRINTF("M addr %p len %lx prot %d flags %d fd %d off %lx our_fd %d\n",
			l->mmap.addr, l->mmap.length, l->mmap.prot, l->mmap.flags,
			l->mmap.fd, l->mmap.offset, l->our_fd);

		// TODO only send descriptors once, there's probably
		// only two per file
		if (l->mmap.fd != -1)
			send_fd(client, l->our_fd);

		struct packet p;
		// Mmap command
		memset(&p, 0, sizeof(p));
		p.code = 'M';
		memcpy(&p.mmap, &l->mmap, sizeof(p.mmap));
		p.mmap.addr = (void *)(their_base + (unsigned long)l->mmap.addr);
		send_packet(client, &p, -1);

		// cLose command
		if (l->mmap.fd != -1) {
			memset(&p, 0, sizeof(p));
			p.code = 'L';
			p.longval = l->mmap.fd;
			send_packet(client, &p, -1);
		}
	}

	if (list) {
		tail->next = client->mmaps;
		client->mmaps = list;
	}

	// Call command
	struct packet p;
	memset(&p, 0, sizeof(p));
	p.code = 'C';
	p.longval = their_base + elf_header->e_entry;
	send_packet(client, &p, -1);

	// Cleanup
	r = munmap(image, stat_length);
	if (r < 0)
		goto finish;

	// TODO mappings are never unmapped. They may be needed by
	// other relocations from other files later.
	ret = their_base;
finish:
	return ret;
}

// Check file properties and send a file descriptor of it if OK
static unsigned long process_file(struct client_info *client, const char *file) {
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

	ret = process_relocations(client, fd, st.st_size);
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
		case 'F': { // File
			assert(len > 2);
			char *endptr;
			int file_id = strtoul(line + 2, &endptr, 0);
			assert(endptr > line + 2);
			assert(file_id >= 0 && file_id < MAX_FILES);
			assert(*endptr != '\0');
			endptr++;
			assert(*endptr != '\0');
			base[file_id] = process_file(client, endptr);
			DPRINTF("mmap base[%d] %lx\n", file_id, base[file_id]);
			break;
		}
		default:
			goto finish;
		}
	}

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

// Send mUnmap command
static unsigned long process_munmap(struct client_info *client,
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
	memset(&p, 0, sizeof(p));
	p.code = 'U';
	p.munmap.addr = (void *)start;
	p.munmap.length = length;
	send_packet(client, &p, -1);
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

		DPRINTF("Got line %s\n", line);

		unsigned long start, stop, offset;
		int pos;
		r = sscanf(line, "%lx-%lx %*c%*c%*c%*c %lx %*x:%*x %*d %n",
			   &start, &stop, &offset, &pos);
		if (r == EOF)
			return -1;
		char *name = &line[pos];
		DPRINTF("start %lx stop %lx offset %lx %s\n", start,
			stop, offset, name);

		// On the second pass, don't process but just output
		// TODO could verify that changes are applied correctly
		if (!process)
			continue;

		client->n_maps++;
		assert(client->n_maps < MAX_MAPS);
		client->maps[client->n_maps].start = start;
		client->maps[client->n_maps].stop = stop;

		// TODO assumes libaslrmalloc
		if (strcmp(name, "[heap]") == 0) {
			process_munmap(client, start, stop - start);
			continue;
		}

		// TODO check if these can be relocated
		if (strcmp(name, "[vvar]") == 0 || strcmp(name, "[vdso]") == 0)
			continue;

		// TODO maybe switching stacks is too fragile
		if (strcmp(name, "[stack]") == 0) {
			process_stack(client, start, stop - start);
			continue;
		}

		// Does this point to our client executable?
		if (strcmp(name, CLIENT) == 0)
			continue;

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
	r = bind(listen_fd, (const struct sockaddr *)&sa, sizeof(sa));
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
