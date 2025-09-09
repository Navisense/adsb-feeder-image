#!/bin/bash

# Push metrics from the Prometheus node exporter.
#
# Takes the output of the Prometheus node exporter and pushes it to
# Porttracker's pushgateway. If the shipfeeder container is running, includes
# its metrics.

ENV_FILE=$1

source ${ENV_FILE}

LOCKFILE=/var/lock/push-prometheus-metrics.lock
PUSH_URL="https://pushgateway.porttracker.co/metrics/job/sharing_devices/instance/${SITE_NAME}/station_id/${FEEDER_PORTTRACKER_STATION_ID}"

source /opt/adsb/scripts/lib-common.bash

if [ -e $LOCKFILE ] ; then
    log_and_exit_sync 1 $0 "A metrics push is already in progress, quitting."
fi

touch $LOCKFILE
trap "rm -f $LOCKFILE" EXIT

log $0 "Preparing to push metrics."
if [ -n "${FEEDER_SERIAL_AIS}" ] ; then
    # An AIS serial device is set, which means the shipfeeder container with
    # AIS-catcher should be running and exposing metrics.
    log $0 "Getting AIS-catcher metrics."
    curl -s http://localhost:${AF_AIS_CATCHER_PORT}/metrics > ${AF_PROMETHEUS_TEXTFILE_DIR}/ais-catcher.prom.tmp
    mv ${AF_PROMETHEUS_TEXTFILE_DIR}/ais-catcher.prom.tmp ${AF_PROMETHEUS_TEXTFILE_DIR}/ais-catcher.prom
fi

log $0 "Start pushing metrics."
curl -s http://localhost:9100/metrics | curl -X "PUT" --data-binary @- --fail "${PUSH_URL}"
ret=$?
log $0 "Done pushing metrics with code $ret"
exit $ret
