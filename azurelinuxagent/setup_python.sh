#!/usr/bin/env bash
set -e
dir=$(dirname "$(pwd)")
echo "Installing python to $dir"
# echo "cleaning make"
# make clean
echo "configuring python"
"$(pwd)/configure" --prefix="$dir"
echo "create makefile"
make
echo "make install"
make install