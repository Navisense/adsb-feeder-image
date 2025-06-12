#!/bin/bash

# install the adsb-setup app, the config files, and the services for use of
# the adsb-feeder on top of another OS.
# the script assumes that the dependencies are installed by the caller

USAGE="
 $0 arguments
  -s srcdir        # the git checkout parent dir
  -b branch        # the branch to use (default: main)
  -t tag           # alternatively the tag to use
  -f               # finish an install on DietPi using dietpi-software
  --web-port port  # the port for the web interface (default: 1099)
  --enable-mdns    # enable the mDNS server (off by default)
"

ROOT_REQUIRED="
 $0 needs to be run with superuser permissions, typically as
 sudo bash $0 arguments
"

# simple way to provide a message and exit with an error code
exit_message() {
    echo "$1"
    exit 1
}

get_distro() {
    local distro="unknown"
    grep -i fedora /etc/os-release &> /dev/null && distro="fedora"
    grep -i centos /etc/os-release &> /dev/null && distro="fedora"
    grep -i suse /etc/os-release &> /dev/null && distro="suse"
    grep -i debian /etc/os-release &> /dev/null && distro="debian"
    grep -i postmarketos /etc/os-release &> /dev/null && distro="postmarketos"
    echo $distro
}

[ "$(id -u)" != "0" ] && exit_message "$ROOT_REQUIRED"

APP_DIR="/opt/adsb"
BRANCH=""
GIT_PARENT_DIR=""
TAG=""
FINISH_DIETPI=""
WEB_PORT="1099"
ENABLE_MDNS="False"

while (( $# ))
do
    case $1 in
        '-s') shift; GIT_PARENT_DIR=$1
            ;;
        '-b') shift; BRANCH=$1
            ;;
        '-t') shift; TAG=$1
            ;;
        '-f') FINISH_DIETPI="1"
            ;;
        '--web-port') shift; WEB_PORT=$1
            ;;
        '--enable-mdns') ENABLE_MDNS="True"
            ;;
        *) exit_message "$USAGE"
    esac
    shift
done

if [[ $FINISH_DIETPI == "1" ]] ; then
    # are we just finishing up the install from dietpi-software?
    if [[ -d /boot/dietpi && -f /boot/dietpi/.version ]] ; then
        # shellcheck disable=SC1091
        source /boot/dietpi/.version
        OS="DietPi ${G_DIETPI_VERSION_CORE}.${G_DIETPI_VERSION_SUB}"
        echo "app-install from $OS" > ${APP_DIR}/adsb.im.previous-version
        # and for now that's all we need
        exit 0
    else
        exit_message "do not use '-f' outside of installing via dietpi-software on DietPi"
    fi
fi

if [[ $GIT_PARENT_DIR == '' ]] ; then
    GIT_PARENT_DIR=$(mktemp -d)
    # shellcheck disable=SC2064
    trap "rm -rf $GIT_PARENT_DIR" EXIT
fi
if [[ $TAG == '' && $BRANCH == '' ]] ; then
    BRANCH="main"
elif [[ $TAG != '' && $BRANCH != '' ]] ; then
    exit_message "Please set either branch or tag, not both"
fi
if [[ ! -d "$APP_DIR" ]] ; then
    if ! mkdir -p "$APP_DIR" ; then
        exit_message "failed to create $APP_DIR"
    fi
fi
if [[ ! -d "$APP_DIR"/config ]] ; then
    mkdir -p "$APP_DIR"/config
fi

distro=$(get_distro)
echo "You appear to be on a ${distro}-style distribution"

# now that we know that there isn't anything obviously wrong with
# the command line arguments, let's check if all the dependencies
# are installed
# - Python 3.6 or later and Flask 2 or later
# - git
# - docker
# - docker compose
# - jq
# - usbutils
# - avahi (if mDNS is enabled)
PKG_NAME_PYTHON3="python3"
PKG_NAME_PYTHON3_FLASK="python3-flask"
PKG_NAME_PYTHON3_REQUESTS="python3-requests"
PKG_NAME_GIT="git"
PKG_NAME_DOCKER="docker"
PKG_NAME_DOCKER_COMPOSE="docker-compose"
PKG_NAME_USBUTILS="usbutils"
PKG_NAME_JQ="jq"
PKG_NAME_AVAHI="avahi"
PKG_NAME_AVAHI_TOOLS="avahi-tools"
if [ "$distro" == "debian" ]; then
    PKG_NAME_DOCKER="docker.io"
    PKG_NAME_AVAHI="avahi-daemon"
    PKG_NAME_AVAHI_TOOLS="avahi-utils"
elif [ "$distro" == "suse" ]; then
    PKG_NAME_AVAHI_TOOLS="avahi-utils"
elif [ "$distro" == "postmarketos" ]; then
    PKG_NAME_PYTHON3_FLASK="py3-flask"
    PKG_NAME_PYTHON3_REQUESTS="py3-requests"
    PKG_NAME_DOCKER_COMPOSE="docker-cli-compose"
fi
missing=""
if which python3 &> /dev/null ; then
    python3 -c "import sys; sys.exit(1) if sys.version_info.major != 3 or sys.version_info.minor < 6" &> /dev/null && missing+="${PKG_NAME_PYTHON3} "
    python3 -c "import requests" &>/dev/null || missing+="${PKG_NAME_PYTHON3_REQUESTS} "
    python3 -c "import flask" &>/dev/null || missing+="${PKG_NAME_PYTHON3_FLASK} "
    python3 -c "import sys; import flask; sys.exit(1) if flask.__version__ < '2.0' else sys.exit(0)" &> /dev/null || missing+="${PKG_NAME_PYTHON3_FLASK} "
else
    missing+="${PKG_NAME_PYTHON3} ${PKG_NAME_PYTHON3_FLASK} ${PKG_NAME_PYTHON3_REQUESTS} "
fi

which git &> /dev/null || missing+="${PKG_NAME_GIT} "

if which docker &> /dev/null ; then
	 ! docker compose version &> /dev/null && ! docker-compose version &> /dev/null && missing+="${PKG_NAME_DOCKER_COMPOSE} "
else
    missing+="${PKG_NAME_DOCKER} ${PKG_NAME_DOCKER_COMPOSE} "
fi

if ! which lsusb &> /dev/null; then
    missing+="${PKG_NAME_USBUTILS} "
fi

if ! which jq &> /dev/null; then
    missing+="${PKG_NAME_JQ} "
fi

if [ "${ENABLE_MDNS}" == "True" ] ; then
    if ! which avahi-daemon &> /dev/null; then
        missing+="${PKG_NAME_AVAHI} "
    fi
    if ! which avahi-publish &> /dev/null; then
        missing+="${PKG_NAME_AVAHI_TOOLS} "
    fi
fi

if [ "$distro" == "postmarketos" ]; then
    # PostmarketOS is based on Alpine, which is missing some tools and uses
    # busybox instead of full-featured versions that we need.

    # busybox' lsusb doesn't have a real -v option (just doesn't show details).
    # The real verbose output has the word "Descriptor" in it a bunch of times.
    if ! lsusb -v 2> /dev/null | grep Descriptor &> /dev/null; then
        missing+="${PKG_NAME_USBUTILS} "
    fi

    # busybox' grep is missing the -P option.
    if ! grep -P postmarketos /etc/os-release &> /dev/null ; then
        missing+="grep "
    fi

    # busybox' ps is missing the -q option.
    if ! ps -q1 &> /dev/null ; then
        missing+="procps "
    fi

    if ! which bash &> /dev/null; then
        missing+="bash "
    fi
fi

if [[ $missing != "" ]] ; then
    inst=""
        [ "$distro" == "fedora" ] && inst="dnf install -y"
        [ "$distro" == "suse" ] && inst="zypper install -y"
        [ "$distro" == "debian" ] && inst="apt-get install -y"
        [ "$distro" == "postmarketos" ] && inst="apk add"

    echo "Please install the missing packages before re-running this script:"
    echo "$inst $missing"
    exit 1
fi

if [ "$distro" == "postmarketos" ]; then
    # Alpine-based PostmarketOS doesn't have a /etc/timezone (which is a glibc
    # thing), but we need it to mount into containers. Parse the timezone out of
    # timedatectl.
    if [ ! -f /etc/timezone ] ; then
        timedatectl show | grep Timezone | cut -d= -f2 > /etc/timezone
    fi
fi

# ok, now we should have all we need, let's get started

if ! git clone 'https://github.com/dirkhh/adsb-feeder-image.git' "$GIT_PARENT_DIR"/adsb-feeder ; then
    exit_message "cannot check out the git repo to ${GIT_PARENT_DIR}"
fi

cd "$GIT_PARENT_DIR"/adsb-feeder || exit_message "can't find $GIT_PARENT_DIR/adsb-feeder"

if [[ $BRANCH != '' ]] ; then
    if ! git checkout "$BRANCH" ; then
        exit_message "cannot check out the branch ${BRANCH}"
    fi
else  # because of the sanity checks above we know that we have a tag
    if ! git checkout "$TAG" ; then
        exit_message "cannot check out the tag ${TAG}"
    fi
fi

# determine the version
SRC_ROOT="${GIT_PARENT_DIR}/adsb-feeder/src/modules/adsb-feeder/filesystem/root"
cd "$SRC_ROOT" || exit_message "can't cd to $SRC_ROOT"
ADSB_IM_VERSION=$(bash "${GIT_PARENT_DIR}"/adsb-feeder/src/get_version.sh)

# copy the software in place
cp -a "${SRC_ROOT}/opt/adsb/"* "${APP_DIR}/"
rm -f "${SRC_ROOT}/usr/lib/systemd/system/adsb-bootstrap.service"
cp -a "${SRC_ROOT}/usr/lib/systemd/system/"* "/usr/lib/systemd/system/"
rm -rf "${GIT_PARENT_DIR}/adsb-feeder"

# set the 'image name' and version that are shown in the footer of the Web UI
cd "$APP_DIR" || exit_message "can't cd to $APP_DIR"
if [[ -d /boot/dietpi ]] ; then
    if [[ -f /boot/dietpi/.version ]] ; then
        # shellcheck disable=SC1091
        source /boot/dietpi/.version
        OS="DietPi ${G_DIETPI_VERSION_CORE}.${G_DIETPI_VERSION_SUB}"
    else
        OS="DietPi"
    fi
elif [[ -f /etc/dist_variant ]] ; then
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
echo "ADS-B Feeder app running on ${OS}" > feeder-image.name
echo "$ADSB_IM_VERSION" > adsb.im.version
touch ${APP_DIR}/app.adsb.feeder.image

cd ${APP_DIR}/config || exit_message "can't find ${APP_DIR}/config"
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
 } >> .env

# run the final steps of the setup and then enable the services
systemctl daemon-reload
systemctl enable --now adsb-docker
systemctl enable --now adsb-setup

# while the user is getting ready, let's try to pull the key docker
# containers in the background -- that way startup will feel quicker
systemd-run -u adsb-docker-pull bash ${APP_DIR}/docker-pull.sh

echo "done installing"
echo "you can uninstall this software by running"
echo "sudo bash ${APP_DIR}/app-uninstall"
echo ""
local_ip=$(ip route get 1 | grep -oP 'src \K\S+')
echo "you can access the web interface at http://localhost:${WEB_PORT} or http://${local_ip}:${WEB_PORT}"
