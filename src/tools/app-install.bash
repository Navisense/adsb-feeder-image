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
  --ref ref        # the ref (e.g. branch or tag) to install (default: main)
  --web-port port  # the port for the web interface (default: 1099)
  --enable-mdns    # enable the mDNS server (off by default)
  --expand-rootfs  # enable a service to expand the root file system
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
    inst=""
        [ "$distro" == "fedora" ] && inst="dnf install -y"
        [ "$distro" == "suse" ] && inst="zypper install -y"
        [ "$distro" == "debian" ] && inst="apt-get install -y"
        [ "$distro" == "postmarketos" ] && inst="apk add"

    echo "Please install the missing packages before re-running this script:"
    echo "$inst ${missing_packages}"
    exit 1
fi

# ok, now we should have all we need, let's get started
staging_dir=$(clone_staging_dir ${REF})
if [ $? -n 0 ] ; then
    exit_message "Cannot check out repository ref ${REF}"
fi

# determine the version
SRC_ROOT="${staging_dir}/src/modules/adsb-feeder/filesystem/root"
cd "$SRC_ROOT" || exit_message "can't cd to $SRC_ROOT"
ADSB_IM_VERSION=$(bash "${staging_dir}"/src/get_version.sh)

install_files ${staging_dir} ${distro}
# Remove the bootstrap service, only for image installs.
rm -f "/usr/lib/systemd/system/adsb-bootstrap.service"

# set the 'image name' and version that are shown in the footer of the Web UI
cd "$APP_DIR" || exit_message "can't cd to $APP_DIR"
if [[ -f /etc/dist_variant ]] ; then
    OS=$(</etc/dist_variant)
elif [[ -f /etc/os-release ]] ; then
    # shellcheck disable=SC1091
    source /etc/os-release
    if [[ $PRETTY_NAME != '' ]] ; then
        OS="$PRETTY_NAME"
    elif [[ $NAME != '' ]] ; then
        OS="$NAME"
    else
        OS="unrecognized OS"
    fi
else
    OS="unrecognized OS"
fi
echo "app-install" > ${APP_DIR}/adsb.im.previous-version
echo "Porttracker Feeder app running on ${OS}" > feeder-image.name
echo "$ADSB_IM_VERSION" > adsb.im.version

mkdir -p /etc/adsb
{
    cat ${APP_DIR}/docker.image.versions
    echo "_ADSBIM_BASE_VERSION=$(cat ${APP_DIR}/adsb.im.version)"
    echo "_ADSBIM_CONTAINER_VERSION=$(cat ${APP_DIR}/adsb.im.version)"
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
