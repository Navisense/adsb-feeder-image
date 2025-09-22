#!/bin/bash

if [[ -f /run/porttracker-feeder.log ]]; then
    TIMESTAMP=$(date +%Y-%m-%d+%H:%M:%S)
    mkdir -p /opt/adsb/logs
    zstd /run/porttracker-feeder.log -o /opt/adsb/logs/adsb-setup.log."$TIMESTAMP".zst
    truncate -s 0 /run/porttracker-feeder.log
    find /opt/adsb/logs -name adsb-setup.log.\* -ctime +7 | xargs rm -f
fi
