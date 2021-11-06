#!/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later OR BSD-3-Clause

import argparse
import io
import os
import re

parser = argparse.ArgumentParser(description='Process ELF executable and produce output suitable for ld-so-daemon profile.')
parser.add_argument('file')
args = parser.parse_args()

file_id = 0

#  Tag        Type                         Name/Value
# 0x0000000000000001 (NEEDED)             Shared library: [libtest_1_lib.so]
# 0x000000000000001d (RUNPATH)            Library runpath: [$ORIGIN/]
dso_re = re.compile(r"^\s*0x[0-9a-f]+\s*\(\S*\)\s+Shared library: \[(.*)\]$")
runpath_re = re.compile(r"^\s*0x[0-9a-f]+\s*\(\S*\)\s+Library runpath: \[(.*)\]$")

runpaths = []
ld_library_path = os.getenv('LD_LIBRARY_PATH')
if ld_library_path:
    runpaths = ld_library_path.split(':')

f = os.popen("readelf --dynamic --wide %s" % args.file, mode='r', buffering=-1)
libs=[]
while True:
    header = f.readline()
    if header:
        match = dso_re.match(header)
        if match:
#            print(header)
            name = match.group(1)
            libs.append(name)
        else:
            match = runpath_re.match(header)
            if match:
#            print(header)
                runpaths.append(match.group(1))
    else:
        break
f.close()

for lib in libs:
    for runpath in runpaths:
        if runpath == '$ORIGIN/':
            runpath = os.path.dirname(args.file)
        path = runpath + '/' + lib
        if os.access(path, os.R_OK):
            # load Library
            print("L", file_id, path)
            break

# load Executable
print("E", file_id, args.file)
