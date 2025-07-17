#!/bin/bash

# Update the running feeder to a given ref. This works by cloning the repo at
# the given ref (e.g. a tag or a branch), and replacing the current files with
# the checked-out version. Beforehand, all system services starting with adsb
# are stopped. After the copy, a systemctl daemon-reload is executed in case
# anything changed, and adsb-setup is started.

source /opt/adsb/scripts/lib-common.bash
source /opt/adsb/scripts/lib-install.bash

ref=$1

if [ -z "${ref}" ] ; then
    log_and_exit_sync 1 $0 "No ref given."
fi

log $0 "Running feeder update to ${ref}."

distro=$(get_distro)

staging_dir=$(clone_staging_dir ${ref})
if [ $? -ne 0 ] ; then
    exit_message "Cannot check out repository ref ${ref}"
fi
trap "rm -rf ${staging_dir}" EXIT
log $0 "Downloaded version ${ref} to ${staging_dir}."

# We source the install library of the new version here, since it may contain
# updated versions of the functions. E.g., we want to install dependencies for
# the new version (in case any have been added).
source ${staging_dir}/src/modules/adsb-feeder/filesystem/root/opt/adsb/scripts/lib-install.bash

missing_packages=$(find_missing_packages ${distro})
if [[ "${missing_packages}" != "" ]] ; then
    log $0 "Installing missing dependencies ${missing_packages}"
    if ! eval $(install_command ${distro} "${missing_packages}") > /dev/null ; then
        log_and_exit_sync 1 $0 "Error installing packages using ${cmd}".
    fi
fi

# This is our current version, which we want to write into the previous version
# file.
old_version=$(cat ${METADATA_DIR}/version.txt)

# Stop all of our services.
if ! systemctl stop 'adsb*' ; then
    # It failed to stop, try to start it back up.
    systemctl start adsb-setup.service
    log_and_exit_sync 1 $0 "Unable to stop current services."
fi
log $0 "Shut down current version."

rm -rf ${APP_DIR}
mkdir -p ${APP_DIR}

log $0 "Deleted old version, installing new one."
install_files ${staging_dir} ${distro}
write_install_metadata ${ref} "${old_version}"
log $0 "Installed new version."

systemctl daemon-reload

# Start adsb-setup again, which should take care of starting anything else
# that's needed.
if ! systemctl start adsb-setup.service ; then
    log $0 "Error starting the new adsb-setup."
fi
log $0 "Started new version."
