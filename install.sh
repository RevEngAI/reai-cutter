#!/bin/sh
set -x
set -e
#R2HOME=$(r2 -H R2_USER_PLUGINS)
#cp -f -v ./r2reait.py $R2HOME/

# OS X install
cp -v reai.py "/Users/`whoami`/Library/Application Support/rizin/cutter/plugins/python/"
