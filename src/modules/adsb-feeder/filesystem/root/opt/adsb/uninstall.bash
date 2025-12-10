#!/bin/bash

# This script uninstalls the Porttracker SDR Feeder application.


exit_with_message() { echo "$1"; exit; }

if [ ! "$(id -u)" == "0" ] ; then
    exit_with_message "Please run this as superuser, e.g. as sudo bash $0"
fi

# Stop adsb-setup first, so it doesn't get the idea of restarting any docker
# containers.
echo "Stopping main application..."
systemctl stop adsb-setup

echo "Shutting down running docker containers..."
/opt/adsb/docker-compose-adsb down -t 30 --remove-orphans

echo "Stopping and removing remaining system services..."
systemctl list-units --all | grep '^\s*adsb-*' | awk '{print $1}' | \
while read -r unit; do
    echo "Stopping and removing $unit..."
    systemctl disable --now "$unit" &> /dev/null
done

echo "Removing system service files..."
rm -f /usr/lib/systemd/system/adsb*

systemctl daemon-reload

echo "Removing logrotate configuration..."
rm /etc/logrotate.d/porttracker-sdr-feeder

echo "Removing log files..."
rm /var/log/porttracker-sdr-feeder*

echo "Removing configuration..."
rm -rf /etc/adsb

echo "Removing application files..."
rm -rf /opt/adsb

echo ""
echo "Uninstall complete."
echo ""
echo "Note: The following were NOT removed:"
echo "  - Docker itself and other docker images you may have installed"
echo "  - System packages that were installed as dependencies"
echo "If you want to remove these, you will need to do so manually."
