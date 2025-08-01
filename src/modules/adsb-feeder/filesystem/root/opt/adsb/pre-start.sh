#!/bin/bash
#
# this script can do some housekeeping tasks before the adsb-setup
# is (re)started

if [ -f /opt/adsb/verbose ] ; then
    mkdir -p /etc/adsb
    mv /opt/adsb/verbose /etc/adsb/verbose
fi

echo "$(date -u +"%FT%T.%3NZ") adsb-setup: pre-start.sh"

kill_wait_app() {
    PORT=$(grep AF_WEBPORT /etc/adsb/.env | cut -d= -f2)
    PORTHEX=$(printf "%04x" "$PORT")

    # figure out if something is listening to that port and give it some time to stop running
    # keep killing the wait the app while waiting for the port
    for i in {1..100}; do
        pkill -f 'python3 /opt/adsb.*/adsb-setup/waiting-app.py' || true
        sleep 0.1
        if ! grep /proc/net/tcp -F -e ": 00000000:${PORTHEX}" -qs; then
            return
        fi
    done
    # let's complain loudly once we've been unsuccessful for 10 seconds
    echo "$(date -u +"%FT%T.%3NZ") FATAL: There's still something running on port $PORT but not waiting anymore"
    netstat -tlpn
}

# browser caching helper script (will only do anything if /opt/adsb/.cachebust_done doesn't exist)
bash /opt/adsb/scripts/cachebust.sh

# if the waiting app is running, stop it
kill_wait_app

ACTION="update to"
if [[ -f "/opt/adsb/porttracker_feeder_install_metadata/finish-update.done" ]]; then
    # so we have completed one of the 'post 0.15' updates already.
    # let's see if the version changed (i.e. if this is another new update)
    # if not, then we ran this script already and can exit
    if cmp /opt/adsb/porttracker_feeder_install_metadata/finish-update.done /opt/adsb/porttracker_feeder_install_metadata/version.txt > /dev/null 2>&1; then
        echo "$(date -u +"%FT%T.%3NZ") adsb-setup: pre-start.sh done"
        exit 0
    fi
else
    ACTION="initial install of"
    if ! [[ -f /opt/adsb/porttracker_feeder_install_metadata/previous_version.txt ]]; then
        echo "unknown-install" > /opt/adsb/porttracker_feeder_install_metadata/previous_version.txt
    fi
fi

NEW_VERSION=$(</opt/adsb/porttracker_feeder_install_metadata/version.txt)
echo "$(date -u +"%FT%T.%3NZ") final housekeeping for the $ACTION $NEW_VERSION" >> /run/adsb-feeder-image.log

# remove any left-over apps and files from previous versions
USR_BIN_APPS=('docker-compose-start' 'docker-compose-adsb' 'docker-update-adsb-im' \
              'nightly-update-adsb-im' 'secure-image' 'identify-airspt' 'feeder-update')

for app in "${USR_BIN_APPS[@]}"; do
    [[ -f "/usr/bin/$app" ]] || continue
    [[ -f "/opt/adsb/$app" ]] && rm -f "/usr/bin/$app"
done

# make sure that we have a .env file so the setup app will start
# first make sure we have an /opt/adsb/config directory (or a link to one)
# once we have those two things in place, the setup app will successfully
# start and finish the rest of the work
[[ -d /etc/adsb ]] || mkdir -p /etc/adsb
cd /etc/adsb
if [ ! -f .env ] ; then
    cp /opt/adsb/docker.image.versions .env
    echo "_ADSBIM_BASE_VERSION=$(cat /opt/adsb/porttracker_feeder_install_metadata/version.txt)" >> .env
    echo "_ADSBIM_CONTAINER_VERSION=$(cat /opt/adsb/porttracker_feeder_install_metadata/version.txt)" >> .env
fi
if [ ! -f config.json ] ; then
    bash /opt/adsb/create-json-from-env.sh
fi

# remember that we handled the housekeeping for this version
cp /opt/adsb/porttracker_feeder_install_metadata/version.txt /opt/adsb/porttracker_feeder_install_metadata/finish-update.done

echo "$(date -u +"%FT%T.%3NZ") adsb-setup: pre-start.sh done"
