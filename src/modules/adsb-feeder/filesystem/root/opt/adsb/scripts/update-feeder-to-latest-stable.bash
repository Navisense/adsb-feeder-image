#!/bin/bash

# Update the Porttracker SDR Feeder to the latest stable version.

if [ ! -f /opt/adsb/scripts/lib-common.bash ] ; then
    echo "Missing /opt/adsb/scripts/lib-common.bash, unable to continue."
    exit 1
else
    . /opt/adsb/scripts/lib-common.bash
    . /opt/adsb/scripts/lib-install.bash
    rootcheck
fi

# First check if there is even an update available.
current_version=$(/opt/adsb/adsb-setup/config.py get base_version)
latest_version=$(find_latest_stable_version)
if [ "${current_version}" = "${latest_version}" ] ; then
    log $0 "No new feeder version available."
else
    log $0 "Starting nightly feeder update from ${current_version}"\
        "to ${latest_version}."
    /opt/adsb/scripts/update-feeder.bash $latest_version
    log $0 "Nightly feeder update done."
fi
