#!/bin/bash

# Apply a config restore from the restore staging directory. Stop and restart
# services appropriately so the changes take effect.

source /opt/adsb/scripts/lib-common.bash

RESTORE_STAGING_DIR="/run/adsb-restore-stage"

if [ ! -d ${RESTORE_STAGING_DIR} ] ; then
    log_and_exit_sync 1 $0 "Restore staging directory doesn't exist."
fi

log $0 "Stopping services before restoring config."
systemctl stop adsb-setup.service
systemctl stop adsb-docker.service

cp -r ${RESTORE_STAGING_DIR}/* ${CONFIG_DIR}

if [ $? -ne 0 ] ; then
    log $0 "Error copying the restore directory to the config directory."
fi

if ! systemctl start adsb-setup.service ; then
    log_and_exit_sync 1 $0 "Error starting adsb-setup after restoring config."
fi

log $0 "Restored the config."
