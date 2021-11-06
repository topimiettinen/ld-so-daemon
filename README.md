# ld-so-daemon

`ld-so-daemon` replaces dynamic loader `ld.so` with a very simple client and more complex server.
The server does all ELF relocation processing (not implemented yet) based on predefined configuration profiles.
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

Future features should include:
- extremely fine grained seccomp filters which check also the instruction pointer, so the check only applies to one ELF library:
for example, only allow certain system calls from a single library or don't allow a certain library to perform a set of system calls but others are not affected
- possibly an extension where data from client (for example argv[0]) can be allowed to select a profile for non-systemd scenarios
- using FUSE or `userfaultfd()`, analyze in a test run which parts of the ELF objects are actually used during program execution and only map those for production runs
- possibly client authentication (for example, use a different UNIX
  socket for each client with random names, assuming that they can't
  enumerate them)

The current proof of concept can execute a dynamically linked, hand
crafted 'Hello world' binary with ELF relocations resolved between
shared objects.

```bash
$ meson setup builddir
$ meson compile -C builddir
$ ./builddir/test_2 &
$ ./builddir/ld-so-client
Hello World from ld-so-daemon!
```
