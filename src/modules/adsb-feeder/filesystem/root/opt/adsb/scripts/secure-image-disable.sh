#!/bin/bash

# this needs to run as root
if [ "$(id -u)" != "0" ] ; then
    echo "this command requires superuser privileges - please run as sudo bash $0"
    exit 1
fi

systemctl stop adsb-setup

/opt/adsb/adsb-setup/config.py set secure_image False
/opt/adsb/adsb-setup/config.py ensure_config_exists

systemctl restart adsb-setup

echo "----------------------"
echo "Secure Image DISABLED!"
echo "----------------------"
