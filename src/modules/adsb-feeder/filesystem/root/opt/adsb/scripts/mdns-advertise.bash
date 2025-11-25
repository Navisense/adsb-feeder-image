#!/bin/bash

# Advertise this machine with an mDNS service and address.
#
# The hostname to advertise must be given as the only argument, the .local
# suffix will be added for the address. The advertised service will be
# <hostname>._http._tcp on the port given by the envrionment variable
# AF_WEBPORT, or 80 by default if that is unset.
#
# Advertising automatically stops after 60 seconds, at which point this script
# has to be restarted. This is just a low-tech way of ensuring that the correct
# IP is advertised eventually in case it changes.

if [ ! -f /opt/adsb/scripts/lib-common.bash ] ; then
    echo "Missing /opt/adsb/scripts/lib-common.bash, unable to continue."
    exit 1
else
    source /opt/adsb/scripts/lib-common.bash
    rootcheck
fi

mdns_hostname="${1}"

own_ip=$(ip --json route get 8.8.8.8 | jq -r '.[0].prefsrc')
if [ -z "${own_ip}" ] || [ "${own_ip}" == "null" ] ; then
    log $0 "Unable to find our own IP through a route to the public internet."
    # We may be in hotspot mode, where our IP will be 192.168.199.1.
    own_ip=$(ip --json route show \
        | jq -r '.[].prefsrc | select (.=="192.168.199.1")')
    if [ -n "${own_ip}" ] ; then
        log $0 "Found our own IP, we appear to be in hotspot mode."
    fi
fi
if [ -z "${own_ip}" ] || [ "${own_ip}" == "null" ] ; then
    log_and_exit_sync 1 $0 "Unable to find our own IP."
fi

avahi-publish-address -R "${mdns_hostname}.local" "${own_ip}" &
avahi-publish-service "${mdns_hostname}" _http._tcp ${AF_WEBPORT:-80} &
sleep 60
