#!/bin/bash

mdns_name="${1}"

/usr/bin/avahi-publish-address -R "${mdns_name}" $(avahi-resolve -4 -n $(hostname).local > /dev/null && ip -json addr show dev wlan0 | jq -r '[.[0].addr_info[] | select(.family=="inet")][0].local')
