#!/bin/sh
set -x
lsmod
rmmod syscallhijack.ko
insmod syscallhijack.ko
lsmod
