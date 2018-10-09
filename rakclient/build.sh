#!/bin/sh

cmake ./ && make clean && make
cp librakclient.so ../../trunk/release/server/luaclib/rakclient.so
