#!/bin/bash
#
# if there is no config.json file in /opt/adsb/config, then we need to
# piece one together...

if [ ! -f /opt/adsb/scripts/lib-common.bash ] ; then
    echo "missing /opt/adsb/scripts/lib-common.bash -- that's generally a bad sign"
else
    . /opt/adsb/scripts/lib-common.bash
    rootcheck
    logparent
fi

if [ ! -f /opt/adsb/config/config.json ] ; then
    if [ ! -f /opt/adsb/config/.env ] ; then
        echo "create config.json file from scratch" >> /run/adsb-feeder-image.log
        lines=$(cat /opt/adsb/docker.image.versions)
        lines+=$'\n'"_ADSBIM_BASE_VERSION=$(cat /opt/adsb/adsb.im.version)"
        lines+=$'\n'"_ADSBIM_CONTAINER_VERSION=$(cat /opt/adsb/adsb.im.version)"
    else
        echo "create config.json file from .env" >> /run/adsb-feeder-image.log
        lines=$(cat /opt/adsb/config/.env)
    fi
    echo -n "{" > /opt/adsb/config/config.json
    has_first_entry=false
    for line in $(echo "${lines}" | grep -v '^#.*' | grep '^[^= ]*=[^= ]*$') ; do
        if [ "${has_first_entry}" = "true" ] ; then
            echo -n "," >> /opt/adsb/config/config.json
        fi
        key=$(echo $line | cut -d= -f1)
        value=$(echo $line | cut -d= -f2)
        echo -n "\"${key}\":\"${value}\"" >> /opt/adsb/config/config.json
        has_first_entry=true
    done
    echo -n "}" >> /opt/adsb/config/config.json
fi
