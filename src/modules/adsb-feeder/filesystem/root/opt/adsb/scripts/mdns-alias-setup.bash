#!/bin/bash

# Start system services advertising mDNS names for this machine.
#
# This script ensures that the adsb-avahi-alias@ service runs exactly for each
# of the mDNS domains specified as arguments. All other ones are stopped and
# disabled. Arguments must be valid mDNS domains.

if [ ! -f /opt/adsb/scripts/lib-common.bash ] ; then
    echo "Missing /opt/adsb/scripts/lib-common.bash, unable to continue."
    exit 1
else
    source /opt/adsb/scripts/lib-common.bash
    rootcheck
fi

log $0 "Setting up mDNS aliases for $@"
service_names=()
for name in $@; do
    service_name="adsb-avahi-alias@${name}.service"
    service_names+=("${service_name}")
    # Make sure the service is enabled, and restart it in case it is already
    # running but our IP changed since it started.
    systemctl enable "${service_name}"
    systemctl restart "${service_name}"
done

systemctl list-units | grep '^\s*adsb-avahi-alias@' | awk '{print $1}' | \
    while read -r unit; do
        wanted="no"
        for service_name in "${service_names[@]}"; do
            if [[ "${service_name}" == "${unit}" ]]; then
                wanted="yes"
            fi
        done
        if [[ "${wanted}" == "no" ]]; then
            # unit no longer needed, disable it
            systemctl disable --now "${unit}"
        fi
    done
