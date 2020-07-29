#!/usr/bin/env bash
set -e
cur_pwd=$1
echo "Passed parameter $cur_pwd or $1"
dir=$(dirname "$cur_pwd")
echo "Installing python to $dir"
# echo "cleaning make"
# make clean
echo "configuring python"
"$cur_pwd/configure" --prefix="$dir"
echo "create makefile"
make
echo "make install"
make install