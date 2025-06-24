#!/bin/bash
#
# if there is no config.json file in /opt/adsb/config, then we need to
# piece one together...

if [ ! -f /opt/adsb/scripts/common.sh ]
then
    echo "missing /opt/adsb/scripts/common.sh -- that's generally a bad sign"
else
    . /opt/adsb/scripts/common.sh
    rootcheck
    logparent
fi

# TODO this thing is meant to run right after install and initialize the
# config.json from the .env written by the install script. this whole procedure
# is insane on several levels.
# - it would be better if the install script wrote the config directly.
# - it would be better if the python code responsible for maintaining the json
# file had a small cli interface to safely write such a file.
# - it would be better if the .env file didn't exist as a permanent fixture at
# all and instead was generated on-demand by the python code
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
