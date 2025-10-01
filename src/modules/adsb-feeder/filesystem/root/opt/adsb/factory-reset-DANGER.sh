#!/bin/bash
systemctl stop adsb-setup

echo "FACTORY RESET" >> /run/porttracker-sdr-feeder.log

/opt/adsb/docker-compose-adsb down
rm -rf /etc/adsb
rm -f /opt/adsb/init-complete
[ "$1" = "-prune" ] && docker system prune -a -f

echo "FACTORY RESET DONE" >> /run/porttracker-sdr-feeder.log

systemctl stop adsb-docker
systemctl restart adsb-setup adsb-docker
