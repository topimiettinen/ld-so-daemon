# ld-so-daemon

`ld-so-daemon` replaces dynamic loader `ld.so` with a very simple client and more complex server.
The server does all ELF relocation processing based on predefined configuration profiles.
The purpose of all this is to allow a scenario, where the client doesn't have access to any programs or libraries at all.
Also the server doesn't need access to anything else than the served programs and libraries but not for example client's configuration files or user data.
Configuration for the server can be generated when the programs or libraries are installed or updated.
This should be useful for hardening systemd services or it could be integrated into [Firejail](https://github.com/netblue30/firejail).

The server listens to a UNIX socket.
It is used to pass file descriptors to the client and send the client commands to:
- `mmap()` or `munmap()` memory areas
- switch stack pointer to a new memory area
- call a function at an address
- `exit()`
- `close()` received file descriptors
- install system call filters with `seccomp()`

Using these primitives, dynamic loading can be achieved.

Client is extremely simple and just executes the commands, it doesn't even send anything to the server.

The server could also perform checks on the client, such as:
- verify process memory map (partially done)
- check systemd service name
- check SELinux domain and whether the domain is allowed to access the files, since the server is doing the operations on behalf of the client  (partially done)

The above items are used to select the profile for the client.

Features include:
- server randomizes the address space
  ([ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization))
  of the client (mostly done, TBD for relocating heap, stack etc.)
- guard pages are installed around DSOs with mmap(..., PROT_NONE, ...)
- system calls are allowed only from known executable segments

Future features should include:
- make GOT and PLT read-only for the client when possible
- extremely fine grained seccomp filters which check also the instruction pointer, so the check only applies to one ELF library:
for example, only allow certain system calls from a single library or don't allow a certain library to perform a set of system calls but others are not affected
- possibly an extension where data from client (for example argv[0]) can be allowed to select a profile for non-systemd scenarios
- using FUSE or `userfaultfd()`, analyze in a test run which parts of the ELF objects are actually used during program execution and only map those for production runs
- possibly client authentication (for example, use a different UNIX
  socket for each client with random names, assuming that they can't
  enumerate them)
- batch requests

The current proof of concept can execute a dynamically linked, hand
crafted 'Hello world' binary with ELF relocations resolved between
shared objects.

```bash
$ meson setup builddir
$ meson compile -C builddir
$ ./builddir/test_2 &
$ ./builddir/ld-so-client
Hello World from ld-so-daemon!
/proc/self/maps:
b26bc027000-b26bc028000 ---p 00000000 00:00 0 
b26bc028000-b26bc029000 r--p 00000000 fe:03 5901936                      /home/topi/ld-so-daemon.git/builddir/test_1
b26bc029000-b26bc02a000 r-xp 00001000 fe:03 5901936                      /home/topi/ld-so-daemon.git/builddir/test_1
b26bc02a000-b26bc02b000 r--p 00002000 fe:03 5901936                      /home/topi/ld-so-daemon.git/builddir/test_1
b26bc02b000-b26bc02d000 rw-p 00000000 00:01 5223                         /memfd:ld-so-server relocations (deleted)
b26bc02d000-b26bc02f000 rw-p 00000000 00:00 0 
b26bc02f000-b26bc030000 ---p 00000000 00:00 0 
3e4f27627000-3e4f27628000 ---p 00000000 00:00 0 
3e4f27628000-3e4f27828000 rw-p 00000000 00:00 0 
3e4f27828000-3e4f27829000 ---p 00000000 00:00 0 
7acab441f000-7acab4420000 ---p 00000000 00:00 0 
7acab4420000-7acab4421000 r--p 00000000 fe:03 5902760                    /home/topi/ld-so-daemon.git/builddir/libtest_1_lib.so
7acab4421000-7acab4422000 r-xp 00001000 fe:03 5902760                    /home/topi/ld-so-daemon.git/builddir/libtest_1_lib.so
7acab4422000-7acab4423000 r--p 00002000 fe:03 5902760                    /home/topi/ld-so-daemon.git/builddir/libtest_1_lib.so
7acab4423000-7acab4424000 rw-p 00000000 00:01 5221                       /memfd:ld-so-server relocations (deleted)
7acab4424000-7acab4425000 ---p 00000000 00:00 0 
7ffff7ff4000-7ffff7ff5000 ---p 00000000 00:00 0 
7ffff7ff5000-7ffff7ff9000 r--p 00000000 00:00 0                          [vvar]
7ffff7ff9000-7ffff7ffb000 r-xp 00000000 00:00 0                          [vdso]
7ffff7ffb000-7ffff7ffc000 r--p 00000000 fe:03 5901909                    /home/topi/ld-so-daemon.git/builddir/ld-so-client
7ffff7ffc000-7ffff7ffd000 r-xp 00001000 fe:03 5901909                    /home/topi/ld-so-daemon.git/builddir/ld-so-client
7ffff7ffd000-7ffff7ffe000 r--p 00002000 fe:03 5901909                    /home/topi/ld-so-daemon.git/builddir/ld-so-client
7ffff7ffe000-7ffff7fff000 rw-p 00002000 fe:03 5901909                    /home/topi/ld-so-daemon.git/builddir/ld-so-client
```

# Previous implementations

- [Glibc](https://sourceware.org/git/?p=glibc.git;a=tree;f=elf;hb=HEAD)
- [Musl](https://git.musl-libc.org/cgit/musl/tree/ldso)

ELF documentation:
- [Wikipedia](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)
- [System V Application Binary Interface](http://www.sco.com/developers/devspecs/gabi41.pdf)
- [System V Application Binary Interface - DRAFT - 10 June 2013](http://www.sco.com/developers/gabi/latest/contents.html)
- [System V Application Binary Interface - AMD64 Architecture Processor Supplement](https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf)
- [ELF Handling For Thread-Local Storage](https://uclibc.org/docs/tls.pdf)

Excellent article about TLS: [A Deep dive into (implicit) Thread Local Storage](https://chao-tic.github.io/blog/2018/12/25/tls).
Tutorial of [Linux program startup](http://dbp-consulting.com/tutorials/debugging/linuxProgramStartup.html).

UPDATE: glibc uses ifunc symbols (`STT_GNU_IFUNC`) which are evaluated by executing code as part of symbol resolution process.
Executing code from possibly untrusted library in the more privileged server context isn't OK, so the current architecture needs to be rethought.

One possibility is to make the client by hacking glibc `ld.so` so that it would make relocations and execute the ifuncs but it would ask the server for file descriptors to library files.
The server would just pass file descriptors to library files as needed.
Privilege separation would be much weaker in this model.

Another idea is keep current architecture but push evaluating ifuncs to client.

The server could also try to sandbox running the ifuncs with another privilege separated process.
