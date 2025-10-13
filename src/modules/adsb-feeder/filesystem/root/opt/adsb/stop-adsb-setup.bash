#!/bin/bash

# This script exists to gracefully shut down Porttracker SDR Feeder. The systemd
# unit file wraps it into a systemd-inhibit call, which means when systemd wants
# to shut it down, it sends a signal to systemd-inhibit (which seems to not pass
# the signal along). Instead, the application writes a PID file which we read
# and send the process a graceful SIGTERM. In case that doesn't work, just
# exiting will get systemd to unceremoniously kill the process anyway.
source /opt/adsb/scripts/lib-common.bash

PID_FILE="/run/porttracker-sdr-feeder.pid"

if [ ! -f ${PID_FILE} ] ; then
    log_and_exit_sync 1 $0 "Wanted to shut down Porttracker SDR Feeder"\
        "cleanly, but ${PID_FILE} doesn't exist. Exiting so systemd can kill"\
        "the wrapping systemd-inhibit."
fi

pid=$(cat ${PID_FILE})
log $0 "Sending SIGTERM to Porttracker SDR Feeder PID ${pid}."
kill -s TERM ${pid}

for i in $(seq 1 20) ; do
    if ! kill -s 0 "$pid" 2>/dev/null; then
        # Process doesn't exist anymore.
        exit 0
    fi
    sleep 1
done

log_and_exit_sync 1 $0 "Tried to shut down Porttracker SDR Feeder cleanly,"\
    "but the process won't go away after a SIGTERM. Exiting so systemd can"\
    "kill the wrapping systemd-inhibit."
exit 1
