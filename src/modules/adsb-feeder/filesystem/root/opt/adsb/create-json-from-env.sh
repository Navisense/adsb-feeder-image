#!/bin/bash
#
# if there is no config.json file in /etc/adsb, then we need to
# piece one together...

if [ ! -f /opt/adsb/scripts/lib-common.bash ] ; then
    echo "Missing /opt/adsb/scripts/lib-common.bash, unable to continue."
    exit 1
else
    . /opt/adsb/scripts/lib-common.bash
    rootcheck
    logparent
fi

if [ ! -f /etc/adsb/config.json ] ; then
    if [ ! -f /etc/adsb/.env ] ; then
        log $0 "Creating config.json file from scratch."
        lines=$(cat /opt/adsb/docker.image.versions)
        lines+=$'\n'"_ADSBIM_BASE_VERSION=$(cat /opt/adsb/adsb.im.version)"
        lines+=$'\n'"_ADSBIM_CONTAINER_VERSION=$(cat /opt/adsb/adsb.im.version)"
    else
        log $0 "Creating config.json file from .env."
        lines=$(cat /etc/adsb/.env)
    fi
    echo -n "{" > /etc/adsb/config.json
    has_first_entry=false
    for line in $(echo "${lines}" | grep -v '^#.*' | grep '^[^= ]*=[^= ]*$') ; do
        if [ "${has_first_entry}" = "true" ] ; then
            echo -n "," >> /etc/adsb/config.json
        fi
        key=$(echo $line | cut -d= -f1)
        value=$(echo $line | cut -d= -f2)
        echo -n "\"${key}\":\"${value}\"" >> /etc/adsb/config.json
        has_first_entry=true
    done
    echo -n "}" >> /etc/adsb/config.json
fi
