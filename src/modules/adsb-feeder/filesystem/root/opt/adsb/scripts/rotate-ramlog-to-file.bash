#!/bin/bash

# Rotate the in-memory log file to disk.
#
# Append the contents of the in-memory log file in /run to the permanent log
# file in /var/log. The optional first argument gives a minimum number of lines
# in the log file to do this (to reduce memory writes if there are only a few
# lines).

if [ ! -f /opt/adsb/scripts/lib-common.bash ] ; then
    echo "Missing /opt/adsb/scripts/lib-common.bash, unable to continue."
    exit 1
fi
source /opt/adsb/scripts/lib-common.bash

min_lines_to_do_rotation=$1

if [ ! -f "${LOG_FILE}" ] ; then
    echo "Log file doesn't exist, nothing to do."
    exit 0
fi

if [ -n $min_lines_to_do_rotation ] ; then min_lines_to_do_rotation=0 ; fi
if (( $(wc -l < "${LOG_FILE}") < "${min_lines_to_do_rotation}" )); then
    echo "Not enough lines to rotate the log file."
    exit 0
fi

cat "${LOG_FILE}" >> /var/log/porttracker-sdr-feeder.log
truncate -s 0 "${LOG_FILE}"
