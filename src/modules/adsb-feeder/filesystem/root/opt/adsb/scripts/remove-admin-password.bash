#!/bin/bash

# Remove the feeder's admin password.

if [ ! -f /opt/adsb/scripts/lib-common.bash ] ; then
    echo "Missing /opt/adsb/scripts/lib-common.bash, unable to continue."
    exit 1
else
    source /opt/adsb/scripts/lib-common.bash
    rootcheck
fi

systemctl stop adsb-setup

/opt/adsb/adsb-setup/config.py unset admin_login.password_bcrypt

systemctl restart adsb-setup

echo "Admin password removed."
