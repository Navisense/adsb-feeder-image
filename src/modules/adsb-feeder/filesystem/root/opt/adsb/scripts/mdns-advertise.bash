#!/bin/bash

# Advertise this machine with an mDNS name.
#
# The name to advertise must be given as the only argument, and must be a domain
# name ending in .local.

if [ ! -f /opt/adsb/scripts/lib-common.bash ] ; then
    echo "Missing /opt/adsb/scripts/lib-common.bash, unable to continue."
    exit 1
else
    source /opt/adsb/scripts/lib-common.bash
    rootcheck
fi

mdns_name="${1}"

own_ip=$(ip --json route get 8.8.8.8 | jq -r '.[0].prefsrc')
if [ -z "${own_ip}" ] || [ "${own_ip}" == "null" ] ; then
    log_and_exit_sync 1 $0 "Unable to find our own IP."
fi

/usr/bin/avahi-publish-address -R "${mdns_name}" "${own_ip}"
