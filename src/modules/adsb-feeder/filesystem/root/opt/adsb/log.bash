#!/bin/bash

LOG_FILE="/run/adsb-feeder-image.log"

# Log a message in a nice format.
# log <logger_name> <message>...
function log() {
    logger_name=$1
    shift
    message="$@"
    echo "$(date -u -Iseconds)|||shell|||${logger_name}|||${message}" >> ${LOG_FILE}
}

# Log a message and exit. Sync the log file.
# log_and_exit_sync <exit_code> <logger_name> <message>...
function log_and_exit_sync() {
    exit_code=$1
    shift
    log "$@"
    sync ${LOG_FILE}
    sleep 1
    exit $exit_code
}
