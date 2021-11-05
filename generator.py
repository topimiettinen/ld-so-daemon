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

# Load File
print("F", file_id, args.file)
