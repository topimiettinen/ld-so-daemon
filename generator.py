#!/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later OR BSD-3-Clause

import argparse
import io
import mmap
import os
import re

MAP_FIXED = 0x10

PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
PAGE_MASK = ~(PAGE_SIZE - 1)

parser = argparse.ArgumentParser(description='Process ELF executable and produce output suitable for ld-so-daemon profile.')
parser.add_argument('file')
args = parser.parse_args()

file_id = 0

entry_re = re.compile(r"^.*Entry point *(0x[0-9a-f]*)$")

#  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
#  [26] .bss              NOBITS          000000000012dd60 12cd44 00b038 00  WA  0   0 32
section_re = re.compile(r"^\s+\[\s*[0-9]+\]\s+\S+\s+(\S+)\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)\s[0-9a-f]+\s+(.)(.)\s+[0-9a-f]+\s+[0-9a-f]+\s+[0-9a-f]+$")

#  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
#  LOAD           0x02e000 0x000000000002e000 0x000000000002e000 0x0ba38d 0x0ba38d R E 0x1000
load_re = re.compile(r"^\s*LOAD\s*(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+0x[0-9a-f]+\s+(0x[0-9a-f]+)\s+0x[0-9a-f]+\s+(.)(.)(.)\s+0x[0-9a-f]+")

f = os.popen("readelf --section-headers --wide %s" % args.file, mode='r', buffering=-1)

max_addr = 0
bss_addr = 0
bss_size = 0
while True:
    header = f.readline()
    if header:
        match = section_re.match(header)
        if match:
#            print(header)
            stype = match.group(1)
            addr = int(match.group(2), base=16)
            size = int(match.group(3), base=16)
            flag1 = match.group(4)
            flag2 = match.group(5)
            if flag1 == 'A' or flag2 == 'A':
#                print("section %lx+%lx = %lx flags %s %s" % (addr, size, addr + size, flag1, flag2))
                if (max_addr < addr + size):
                    max_addr = addr + size
            if stype == 'NOBITS':
                bss_addr = addr
                bss_size = size
                align = bss_addr & ~PAGE_MASK
                if align > 0:
                    bss_addr = (bss_addr & PAGE_MASK) + PAGE_SIZE
                    bss_size = bss_size - (PAGE_SIZE - align)
#                print("section bss align %lx %lx+%lx = %lx" % (align, bss_addr, bss_size, bss_addr + bss_size))
    else:
        break
f.close()

f = os.popen("readelf --program-headers --wide %s" % args.file, mode='r', buffering=-1)

maps = ""
while True:
    header = f.readline()
    if header:
        match = entry_re.match(header)
        if match:
            entry = match.group(1)
        else:
            match = load_re.match(header)
            if match:
                offset = int(match.group(1), base=16)
                virtaddr = int(match.group(2), base=16)
                align = virtaddr & ~PAGE_MASK
                virtaddr -= align
                offset -= align
                filesiz = int(match.group(3), base=16)
                r = match.group(4)
                w = match.group(5)
                e = match.group(6)
                prot = 0
                if (r == 'R'): prot |= mmap.PROT_READ
                if (w == 'W'): prot |= mmap.PROT_WRITE
                if (e == 'E'): prot |= mmap.PROT_EXEC

                # Mmap delta length prot flags offset
                mapline = "M %d 0x%x 0x%x %s %d 0x%x\n" % (file_id, virtaddr, filesiz, prot, mmap.MAP_PRIVATE|MAP_FIXED, offset)
                maps += mapline
    else:
        break
f.close()

# Load File
print("F", file_id, max_addr, args.file)

# Mmap
print(maps, end="")

if (bss_size > 0):
    # Mmap delta length prot flags offset
    print("M %d 0x%x 0x%x %s %d 0x%x" % (file_id, bss_addr, bss_size, mmap.PROT_READ | mmap.PROT_WRITE, mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS | MAP_FIXED, 0))

#cLose fd
print("L", file_id)

# Call entry_point
print("C", file_id, entry)
