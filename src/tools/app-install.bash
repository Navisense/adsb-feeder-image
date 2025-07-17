#!/bin/bash

# This script installs the adsb-setup app, and sets up config files and systemd
# services for use of the adsb-feeder on top of another OS.

# The following line sources a library with functions we need. The CI pipeline
# will replace it with the contents of that library to get a fully
# self-contained install script. If the line following this comment doesn't
# begin with "source", you're looking at such a script.
source ../src/modules/adsb-feeder/filesystem/root/opt/adsb/scripts/lib-install.bash

USAGE="
 $0 arguments
  --ref ref                   # the ref (e.g. branch or tag) to install (default: main)
  --web-port port             # the port for the web interface (default: 1099)
  --enable-mdns               # enable the mDNS server (off by default)
  --expand-rootfs             # enable a service to expand the root file system
  --auto-install-dependencies # automatically install needed dependencies (off by default)
"

ROOT_REQUIRED="
 $0 needs to be run with superuser permissions, typically as
 sudo bash $0 arguments
"

exit_message() {
    echo "$1"
    exit 1
}

[ "$(id -u)" != "0" ] && exit_message "$ROOT_REQUIRED"

REF="main"
WEB_PORT="1099"
ENABLE_MDNS="False"
EXPAND_ROOTFS="False"
AUTO_INSTALL_DEPENDENCIES="False"

while (( $# ))
do
    case $1 in
        '--ref') shift; REF=$1
            ;;
        '--web-port') shift; WEB_PORT=$1
            ;;
        '--enable-mdns') ENABLE_MDNS="True"
            ;;
        '--expand-rootfs') EXPAND_ROOTFS="True"
            ;;
        '--auto-install-dependencies') AUTO_INSTALL_DEPENDENCIES="True"
            ;;
        *) exit_message "$USAGE"
    esac
    shift
done

if [[ ! -d "${APP_DIR}" ]] ; then
    if ! mkdir -p "${APP_DIR}" ; then
        exit_message "Failed to create ${APP_DIR}"
    fi
fi

distro=$(get_distro)
echo "You appear to be on a ${distro}-style distribution"

missing_packages=$(find_missing_packages ${distro})
if [[ "${missing_packages}" != "" ]] ; then
    cmd=$(install_command ${distro} "${missing_packages}")
    if [ "${AUTO_INSTALL_DEPENDENCIES}" == "False" ] ; then
        echo "Please install the missing packages before re-running this script:"
        echo "${cmd}"
        exit 1
    elif ! ${cmd} > /dev/null ; then
        echo "Error installing packages using ${cmd}".
        exit 1
    fi
fi

# ok, now we should have all we need, let's get started
staging_dir=$(clone_staging_dir ${REF})
if [ $? -ne 0 ] ; then
    exit_message "Cannot check out repository ref ${REF}"
fi
trap "rm -rf ${staging_dir}" EXIT

install_files ${staging_dir} ${distro}
write_install_metadata ${REF} "fresh install"

mkdir -p /etc/adsb
{
    cat ${APP_DIR}/docker.image.versions
    echo "_ADSBIM_BASE_VERSION=$(cat /opt/adsb/porttracker_feeder_install_metadata/version.txt)"
    echo "_ADSBIM_CONTAINER_VERSION=$(cat /opt/adsb/porttracker_feeder_install_metadata/version.txt)"
    echo "AF_WEBPORT=${WEB_PORT}"
    echo "AF_TAR1090_PORT=1090"
    echo "AF_UAT978_PORT=1091"
    echo "AF_PIAWAREMAP_PORT=1092"
    echo "AF_PIAWARESTAT_PORT=1093"
    echo "AF_DAZZLE_PORT=1094"
    echo "AF_IS_MDNS_ENABLED=${ENABLE_MDNS}"
 } >> /etc/adsb/.env

# run the final steps of the setup and then enable the service
systemctl daemon-reload
systemctl enable adsb-setup
systemctl start adsb-setup

if [ "${EXPAND_ROOTFS}" == "True" ] ; then
    systemctl enable adsb-expand-rootfs
    systemctl start adsb-expand-rootfs
fi

# while the user is getting ready, let's try to pull the key docker
# containers in the background -- that way startup will feel quicker
systemd-run -u adsb-docker-pull bash ${APP_DIR}/docker-pull.sh

echo "done installing"
echo "you can uninstall this software by running"
echo "sudo bash ${APP_DIR}/app-uninstall"
echo ""
local_ip=$(ip route get 1 | grep -oP 'src \K\S+')
echo "you can access the web interface at http://localhost:${WEB_PORT} or http://${local_ip}:${WEB_PORT}"
