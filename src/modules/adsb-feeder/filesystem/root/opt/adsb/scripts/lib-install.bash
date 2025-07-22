# This bash library contains functions for installing and uninstalling the
# application. It is meant to be sourced from other scripts.

APP_DIR="/opt/adsb"
METADATA_DIR="${APP_DIR}/porttracker_feeder_install_metadata"
REPO_URL="https://gitlab.navisense.de/navisense-public/adsb-feeder-image.git"
REPO_API_BASE_URL="https://gitlab.navisense.de/api/v4/projects/96"

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
        python3 -c "import sys; sys.exit(1) if sys.version_info.major != 3 or sys.version_info.minor < 9" &> /dev/null && missing+="${PKG_NAME_PYTHON3} "
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

# Generate a command to install the given packages, based on distro.
#
# install_command <distro> <packages>
install_command () {
    local distro=$1
    local packages=$2
    inst=""
    if [ "$distro" == "fedora" ] ; then
        inst="dnf install -y"
    elif [ "$distro" == "suse" ] ; then
        inst="zypper install -y"
    elif [ "$distro" == "debian" ] ; then
        inst="apt-get install -y"
    elif [ "$distro" == "postmarketos" ] ; then
        inst="apk add"
    else
        return 1
    fi
    echo "$inst ${missing_packages}"
}

# Clone the repo at the specified ref to a temporary staging directory. Returns
# the directory.
#
# clone_staging_dir <ref>
clone_staging_dir() {
    local ref=$1
    local clone_dir=$(mktemp -d)

    git clone --branch ${ref} --depth 1 ${REPO_URL} ${clone_dir} > /dev/null 2>&1
    if [ $? -ne 0 ] ; then
        return $?
    fi
    echo ${clone_dir}
}

# Install stuff that is dependent on distro.
#
# install_distro_specific_quirks <staging_root> <distro>
install_distro_specific_quirks() {
    local staging_root=$1
    local distro=$2
    if [ "$distro" == "postmarketos" ]; then
        # Quirks for Alpine-based PostmarketOS.

        # We don't have a /etc/timezone (which is a glibc thing), but we need it
        # to mount into containers. Parse the timezone out of timedatectl.
        if [ ! -f /etc/timezone ] ; then
            timedatectl show | grep Timezone | cut -d= -f2 > /etc/timezone
        fi

        # We have hostapd, kea, and prometheus-node-exporter available, but
        # since these are (OpenRC-based) Alpine packages, no systemd unit files
        # are installed. We have to copy our own.
        cp -a ${staging_root}${APP_DIR}/quirks_postmarketos/*.service \
            /usr/lib/systemd/system/
        systemctl daemon-reload
    fi
}

# Write metadata files about the install.
#
# write_install_metadata <ref> <previous_version>
write_install_metadata() {
    local ref=$1
    local previous_version=$2
    local version=$(cat ${APP_DIR}/version.txt)
    if [[ "${version}" != "${ref}" ]] ; then
        # The ref that was installed wasn't a tag (or it would match exactly the
        # version file). Include the ref in the friendly version.
        version="${ref} building on ${version}"
    fi

    local os="unrecognized OS"
    if [[ -f /etc/dist_variant ]] ; then
        os=$(</etc/dist_variant)
    elif [[ -f /etc/os-release ]] ; then
        source /etc/os-release
        if [[ $PRETTY_NAME != '' ]] ; then
            os="$PRETTY_NAME"
        elif [[ $NAME != '' ]] ; then
            os="$NAME"
        fi
    fi

    mkdir -p ${METADATA_DIR}
    echo "${previous_version}" > ${METADATA_DIR}/previous_version.txt
    echo "Porttracker Feeder running on ${os}" > ${METADATA_DIR}/friendly_name.txt
    echo "${version}" > ${METADATA_DIR}/version.txt
}

# Install application files from a staging directory, for a specific distro.
#
# install_files <staging_dir> <distro>
install_files() {
    local staging_dir=$1
    local distro=$2
    local staging_root="${staging_dir}/src/modules/adsb-feeder/filesystem/root"
    cp -a "${staging_root}${APP_DIR}/"* "${APP_DIR}/"
    cp -a "${staging_root}/usr/lib/systemd/system/"* "/usr/lib/systemd/system/"
    install_distro_specific_quirks ${staging_root} ${distro}
}

# Find the latest stable version that can be installed.
find_latest_stable_version() {
    curl -s "${REPO_API_BASE_URL}/repository/tags" \
    | jq --raw-output '.[].name' \
    | grep '^v[0-9]\.[0-9]\.[0-9]$' \
    | sort -r \
    | head -n 1
}
