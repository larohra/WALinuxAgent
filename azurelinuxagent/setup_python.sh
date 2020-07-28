#!/usr/bin/env bash

dir=$(pwd)
echo "Installing python to $dir"
echo "cleaning make"
make clean
echo "configuring python"
./configure --prefix="$dir"
echo "create makefile"
make
echo "make install"
make install