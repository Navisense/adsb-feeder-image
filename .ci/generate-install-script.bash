#!/bin/bash

# This script only exists to replace the sourcing of the install bash library in
# the install script with the contents of that script, so we have one
# self-contained script we can use to install, while not having to copy-paste
# around the functions to install and uninstall.

if [ ! -f src/modules/adsb-feeder/filesystem/root/opt/adsb/scripts/lib-install.bash ] ; then
    echo "Install bash library doesn't exist."
    exit 1
fi
if [ ! grep "source ../src/modules/adsb-feeder/filesystem/root/opt/adsb/scripts/lib-install.bash" src/tools/app-install.sh ] ; then
    echo "Source of install bash library not found in install script."
    exit 1
fi

sed -e '
    /source ..\/src\/modules\/adsb-feeder\/filesystem\/root\/opt\/adsb\/scripts\/lib-install.bash/{
    s/source ..\/src\/modules\/adsb-feeder\/filesystem\/root\/opt\/adsb\/scripts\/lib-install.bash//g
    r src/modules/adsb-feeder/filesystem/root/opt/adsb/scripts/lib-install.bash
    }' src/tools/app-install.bash > app-install.bash
