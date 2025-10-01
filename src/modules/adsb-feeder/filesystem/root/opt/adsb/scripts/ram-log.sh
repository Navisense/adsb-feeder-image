#!/bin/bash

# this script shouldn't be needed - the feeder update should take care of this
# it's provided in case that somehow failed and we end up wanting to manually switch
# to logging to /run

if [ ! -f /opt/adsb/scripts/lib-common.bash ] ; then
    echo "Missing /opt/adsb/scripts/lib-common.bash, unable to continue."
    exit 1
else
    . /opt/adsb/scripts/lib-common.bash
    rootcheck
    logparent
fi

if [ -L /opt/adsb/adsb-setup.log ] && [ -e /opt/adsb/adsb-setup.log ]
then
    # this is already a symlink, so likely this is redundant
    target=$(realpath /opt/adsb/adsb-setup.log)
    if [ "$target" = "/run/porttracker-sdr-feeder.log" ]
    then
        echo "looks like we already switched to logging to /run"
        exit 0
    else
        echo "logfile is symlink to $target, giving up"
        exit 1
    fi
else
    TIMESTAMP=$(date +%Y-%m-%d+%H:%M)
    # stop both adsb-setup and the adsb-setup-proxy
    systemctl stop adsb-setup
    /opt/adsb/docker-compose-adsb stop adsb-setup-proxy
    # copy the log file and create a symlink to tmpfs log
    if [ -f /run/porttracker-sdr-feeder.log ]
    then
        cp /run/porttracker-sdr-feeder.log /run/adsb-feeder-image/adsb-setup.log."$TIMESTAMP"
    fi
    cp /opt/adsb/adsb-setup.log /opt/adsb/adsb-setup.log."$TIMESTAMP"
    truncate -s 0 /run/porttracker-sdr-feeder.log
    ln -sf /run/porttracker-sdr-feeder.log /opt/adsb/adsb-setup.log
    systemctl start adsb-setup
    /opt/adsb/docker-compose-adsb start adsb-setup-proxy
fi
