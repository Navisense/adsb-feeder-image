#!/bin/bash

set -e

# Install utils specific to the Raspberry Pi.
pmbootstrap --as-root chroot -r -- bash -c \
    "apk add --no-cache raspberrypi-userland raspberrypi-utils"

# Add settings to the boot config file that are required to get /dev/ttyAMA0 to
# appear. This is technically a bit overkill, since it adds the overlay that
# gets the Pi to use the mini UART for bluetooth (which we don't actually need).
# The force_turbo parameter is necessary since the mini UART's baud rate is
# dependent on the CPU clock speed, so we need to fix it to something (the
# maximum).
pmbootstrap --as-root chroot -r -- bash -c \
    "echo 'dtoverlay=miniuart-bt' >> /boot/usercfg.txt"
pmbootstrap --as-root chroot -r -- bash -c \
    "echo 'enable_uart=1' >> /boot/usercfg.txt"
pmbootstrap --as-root chroot -r -- bash -c \
    "echo 'force_turbo=1' >> /boot/usercfg.txt"
