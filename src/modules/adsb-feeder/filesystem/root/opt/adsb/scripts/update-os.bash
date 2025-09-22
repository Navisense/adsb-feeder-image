#!/bin/bash

# Do a system update.
#
# This script does a simple operating system update using apk update && apk
# upgrade. All output is sent to the feeder's log file.

if [ ! -f /opt/adsb/scripts/lib-common.bash ] ; then
    echo "Missing /opt/adsb/scripts/lib-common.bash, unable to continue."
    exit 1
else
    . /opt/adsb/scripts/lib-common.bash
    rootcheck
fi

# Log all output to the log file.
exec &>> ${LOG_FILE}

log $0 "Starting OS update."

log $0 "Running apk update."
if ! apk update ; then
    log_and_exit_sync 1 $0 "Error running apk update, exiting."
fi

log $0 "Running apk upgrade."
if ! apk upgrade ; then
    log_and_exit_sync 1 $0 "Error running apk upgrade, exiting."
fi

log $0 "OS update completed successfully."
