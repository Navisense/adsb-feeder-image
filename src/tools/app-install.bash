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
  --ref ref                   # the ref (e.g. branch or tag) to install
                              # (default: latest available stable version)
  --web-port port             # the port for the web interface (default: 1099)
  --enable-mdns               # enable the mDNS server (off by default)
  --expand-rootfs             # enable a service to expand the root file system
  --auto-install-dependencies # automatically install needed dependencies (off
                              # by default)
  --enable-hotspot            # Enable or disable the wifi hotspot that is
  --disable-hotspot           # started when there is no internet connection, to
                              # connect to a wifi network without a display
                              # attached. The default is to only start the
                              # hotspot if no window manager is detected. These
                              # options can be used to override this and force
                              # the hotspot to always or never be used.
  --managed-user username     # Modify the config to indicate that this install
                              # comes with a user account with default password
                              # on the device, e.g. on a ready-made image. This
                              # will enable warnings in the interface that a
                              # default password is in use, along with an option
                              # to change it.
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

REF=""
WEB_PORT="1099"
ENABLE_MDNS="False"
EXPAND_ROOTFS="False"
AUTO_INSTALL_DEPENDENCIES="False"
ENABLE_HOTSPOT=""
MANAGED_USER=""

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
        '--enable-hotspot')
            if [ -n "${ENABLE_HOTSPOT}" ] ; then
                exit_message "Both enable/disable hotspot specified."
            fi
            ENABLE_HOTSPOT="True"
            ;;
        '--disable-hotspot')
            if [ -n "${ENABLE_HOTSPOT}" ] ; then
                exit_message "Both enable/disable hotspot specified."
            fi
            ENABLE_HOTSPOT="False"
            ;;
        '--managed-user') shift; MANAGED_USER=$1
            ;;
        *) exit_message "$USAGE"
    esac
    shift
done

if [ -z "${REF}" ] ; then
    REF=$(find_latest_stable_version)
    if [ -n "${REF}" ] ; then
        echo "Using latest available stable version ${REF}."
    else
        echo "Error finding latest stable version, using main instead."
        REF="main"
    fi
fi

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
    else
        echo "Installing packages ${missing_packages}."
        if ! ${cmd} > /dev/null ; then
            echo "Error installing packages using ${cmd}".
            exit 1
        fi
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
if [ -f /etc/adsb/config.json ] ; then
    backup_file="/etc/adsb/config.json.backup.install.$(date -Is)"
    echo "A config file already exists. Moving it to ${backup_file}."
    mv /etc/adsb/config.json $backup_file
fi

echo "Creating a default config at /etc/adsb/config.json."
/opt/adsb/adsb-setup/config.py ensure_config_exists
/opt/adsb/adsb-setup/config.py set ports.web ${WEB_PORT}
/opt/adsb/adsb-setup/config.py set mdns.is_enabled ${ENABLE_MDNS}
if [ -n "${ENABLE_HOTSPOT}" ] ; then
    /opt/adsb/adsb-setup/config.py set enable_hotspot ${ENABLE_HOTSPOT}
fi
if [ -n "${MANAGED_USER}" ] ; then
    /opt/adsb/adsb-setup/config.py set managed_user ${MANAGED_USER}
fi

# Run the final steps of the setup and then enable the service.
systemctl daemon-reload
systemctl enable adsb-setup
systemctl start adsb-setup

if [ "${EXPAND_ROOTFS}" == "True" ] ; then
    systemctl enable adsb-expand-rootfs
    systemctl start adsb-expand-rootfs
fi

echo "done installing"
echo "you can uninstall this software by running"
echo "sudo bash ${APP_DIR}/app-uninstall"
echo ""
local_ip=$(ip route get 1 | grep -oP 'src \K\S+')
echo "you can access the web interface at http://localhost:${WEB_PORT} or http://${local_ip}:${WEB_PORT}"
