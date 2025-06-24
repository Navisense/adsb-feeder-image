#!/bin/bash

function test_network() {
    gateway="$(ip route get 1.2.3.4 | awk '/via/ { print $3 }')"
    if ping -i 0 -c2 -w5 "${gateway}" &>/dev/null; then
        return 0
    fi
    if ping -c2 -w5 8.8.8.8 &>/dev/null; then
        return 0
    fi
    if curl --max-time 5 akamai.com &>/dev/null; then
        return 0
    fi
    return 1
}

FAILS=0

while sleep 120; do
    if test_network; then
        # network is working, reset failure count
        FAILS=0
        continue
    fi

    # network is down!

    FAILS=$(( FAILS + 1 ))

    echo "Network doesn't seem to be working! Successive Failures: $FAILS"
    if (( FAILS >= 6 )); then
        echo "Rebooting"
        echo "$(date --rfc-3339=seconds): Rebooting after ${FAILS} failed attempts" >> /opt/adsb/logs/netdog.log
        reboot
    elif (( FAILS == 3 )); then
        if systemctl is-enabled NetworkManager &>/dev/null; then
            echo "Restarting NetworkManager"
            systemctl restart NetworkManager
        else
            echo "Restarting networking"
            systemctl restart networking
        fi
    fi
done
