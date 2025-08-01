#!/bin/bash

# Expand the root partition and file system to use all available space.

source /opt/adsb/scripts/lib-common.bash

DEVICE=/dev/mmcblk0
ROOT_PARTITION_NUMBER=2
ROOT_PARTITION_DEVICE=/dev/mmcblk0p2

# First, just print the partition table, because for gpt table parted actually
# offers to maximize the last partition, which we can accept via --fix.
parted --script --fix ${DEVICE} print
if [ $? -ne 0 ] ; then
    log_and_exit_sync 1 $0 "Failed to print the partition table."
fi

echo yes | parted ---pretend-input-tty ${DEVICE} resizepart ${ROOT_PARTITION_NUMBER} 100%
if [ $? -ne 0 ] ; then
    log_and_exit_sync 1 $0 "Failed to resize root partition."
fi

resize2fs ${ROOT_PARTITION_DEVICE}
if [ $? -ne 0 ] ; then
    log_and_exit_sync 1 $0 "Failed to resize root file system."
fi
