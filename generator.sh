#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later OR BSD-3-Clause

(echo F $1
 find $1 -printf 'M 0 %s 7 2 0 0\n'
 echo L 0
 readelf --all --wide $1 | sed -n -e 's/.*Entry point address: *\(0x.*\)$/C \1/gp'
     )> $2
