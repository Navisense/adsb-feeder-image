#!/bin/bash

LOCKFILE=/var/lock/push-prometheus-metrics.lock
PUSH_URL="https://pushgateway.porttracker.co/metrics/job/sharing_devices/instance/testtest"

source /opt/adsb/log.bash

if [ -e $LOCKFILE ] ; then
    log_and_exit_sync 1 $0 "A metrics push is already in progress, quitting."
fi

touch $LOCKFILE
log $0 "Start pushing metrics."
curl -s http://localhost:9100/metrics | curl -X "PUT" --data-binary @- --fail "${PUSH_URL}"
ret=$?
log $0 "Done pushing metrics with code $ret"
rm $LOCKFILE
exit $ret
