#!/bin/bash

# this needs to run as root
if [ "$(id -u)" != "0" ] ; then
    echo "this command requires superuser privileges - please run as sudo bash $0"
    exit 1
fi

names=("porttracker-feeder.local")
if [ "$1" != "" ] ; then
    host_name="$1"
    host_name_no_dash="${host_name//-/}"
    # ensure that the local hosts file includes the hostname
    if ! grep -q "$host_name" /etc/hosts ; then
        echo "127.0.2.1 $host_name" >> /etc/hosts
    fi

    names+=("${host_name}.local")
    names+=("${host_name_no_dash}.local")
fi

echo "set up mDNS aliases: ${names[@]}"
service_names=()
for name in "${names[@]}"; do
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
