# This bash library contains functions for installing and uninstalling the
# application. It is meant to be sourced from other scripts.


get_distro() {
    local distro="unknown"
    grep -i fedora /etc/os-release &> /dev/null && distro="fedora"
    grep -i centos /etc/os-release &> /dev/null && distro="fedora"
    grep -i suse /etc/os-release &> /dev/null && distro="suse"
    grep -i debian /etc/os-release &> /dev/null && distro="debian"
    grep -i postmarketos /etc/os-release &> /dev/null && distro="postmarketos"
    echo $distro
}

# Return a space-separated string of all packages that have to be installed.
# This is sensitive to the distro, which must be the first argument.
find_missing_packages() {
    local distro=$1
    local PKG_NAME_PYTHON3="python3"
    local PKG_NAME_PYTHON3_FLASK="python3-flask"
    local PKG_NAME_PYTHON3_REQUESTS="python3-requests"
    local PKG_NAME_CURL="curl"
    local PKG_NAME_GIT="git"
    local PKG_NAME_DOCKER="docker"
    local PKG_NAME_DOCKER_COMPOSE="docker-compose"
    local PKG_NAME_USBUTILS="usbutils"
    local PKG_NAME_JQ="jq"
    local PKG_NAME_IW="iw"
    local PKG_NAME_HOSTAPD="hostapd"
    local PKG_NAME_KEA="kea"
    local PKG_NAME_PROMETHEUS_NODE_EXPORTER="prometheus-node-exporter"
    local PKG_NAME_ZSTD="zstd"
    local PKG_NAME_AVAHI="avahi"
    local PKG_NAME_AVAHI_TOOLS="avahi-tools"
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
    local missing=""

    if which python3 &> /dev/null ; then
        python3 -c "import sys; sys.exit(1) if sys.version_info.major != 3 or sys.version_info.minor < 6" &> /dev/null && missing+="${PKG_NAME_PYTHON3} "
        python3 -c "import requests" &>/dev/null || missing+="${PKG_NAME_PYTHON3_REQUESTS} "
        python3 -c "import flask" &>/dev/null || missing+="${PKG_NAME_PYTHON3_FLASK} "
        python3 -c "import sys; import flask; sys.exit(1) if flask.__version__ < '2.0' else sys.exit(0)" &> /dev/null || missing+="${PKG_NAME_PYTHON3_FLASK} "
    else
        missing+="${PKG_NAME_PYTHON3} ${PKG_NAME_PYTHON3_FLASK} ${PKG_NAME_PYTHON3_REQUESTS} "
    fi

    which curl &> /dev/null || missing+="${PKG_NAME_CURL} "
    which git &> /dev/null || missing+="${PKG_NAME_GIT} "

    if which docker &> /dev/null ; then
        ! docker compose version &> /dev/null && ! docker-compose version &> /dev/null && missing+="${PKG_NAME_DOCKER_COMPOSE} "
    else
        missing+="${PKG_NAME_DOCKER} ${PKG_NAME_DOCKER_COMPOSE} "
    fi

    which lsusb &> /dev/null || missing+="${PKG_NAME_USBUTILS} "
    which jq &> /dev/null || missing+="${PKG_NAME_JQ} "
    which iw &> /dev/null || missing+="${PKG_NAME_IW} "
    which hostapd &> /dev/null || missing+="${PKG_NAME_HOSTAPD} "
    which kea-dhcp4 &> /dev/null || missing+="${PKG_NAME_KEA} "
    which node_exporter &> /dev/null || missing+="${PKG_NAME_PROMETHEUS_NODE_EXPORTER} "
    which zstd &> /dev/null || missing+="${PKG_NAME_ZSTD} "
    which avahi-daemon &> /dev/null || missing+="${PKG_NAME_AVAHI} "
    which avahi-publish &> /dev/null || missing+="${PKG_NAME_AVAHI_TOOLS} "

    if [ "$distro" == "postmarketos" ]; then
        # PostmarketOS is based on Alpine, which is missing some tools and uses
        # busybox instead of full-featured versions that we need.

        # busybox' lsusb doesn't have a real -v option (just doesn't show
        # details).
        if lsusb --help 2>&1 | grep BusyBox &> /dev/null ; then
            missing+="${PKG_NAME_USBUTILS} "
        fi

        # busybox' grep is missing the -P option.
        if grep --help 2>&1 | grep BusyBox &> /dev/null ; then
            missing+="grep "
        fi

        # busybox' ps is missing the -q option.
        if ps --help 2>&1 | grep BusyBox &> /dev/null ; then
            missing+="procps "
        fi

        # busybox' ip is missing the -json option.
        if ip --help 2>&1 | grep BusyBox &> /dev/null ; then
            missing+="iproute2 "
        fi

        which bash &> /dev/null || missing+="bash "
    fi
    echo "${missing}"
}
