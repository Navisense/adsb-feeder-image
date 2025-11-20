#!/bin/bash

# Build and upload device images.
#
# Usage: build-and-upload-image.bash <version> <device> <variant>
#
# <version>: Version of the feeder that should be checked out (i.e. the tag).
# <device>: The name of the device as in pmbootstrap, e.g. raspberry-pi4.
# <variant>: Variant of the image. Can be the special value "headless", in which
#     case the "console" UI is chosen, and the hotspot is disabled. Other values
#     must be valid names of UIs in postmarketOS, e.g. "plasma-mobile" or
#     "phosh".
#
# This script uses pmbootstrap and the app-install.bash script to create a
# postmarketOS image with default username and password for the specified feeder
# version and device (as specified for pmbootstrap). pmbootstrap uses losetup to
# create a loop device from an image file, so if this script should run in a
# container, /dev needs to be mounted into it and it must be started with
# --privileged. pmbootstrap is also not terribly careful about mutexing access
# to loop devices, so it's probably best not to let more than one instance of
# this run in parallel.
#
# Once the image has been created, it is zipped up and uploaded to S3 with the
# file name porttracker-sdr-feeder_${version}_${device}_${variant}.img.

PMBOOTSTRAP_VERSION="3.6.0"
PMAPORTS_BRANCH="v25.06"
HOSTNAME="porttracker-sdr-feeder"
USERNAME="user"
PASSWORD="123"
S3_BUCKET="s3://navisense-api-files-production/public/device_images"

version="${1}"
device="${2}"
variant="${3}"

if [ -z "${version}" ] || [ -z "${device}" ] || [ -z "${variant}" ] ; then
    echo "Missing parameter."
    exit 1
fi

echo "Building image ${version} for device ${device}."

# pmbootstrap wants to modprobe some things. Of course this fails in the
# container, but the functionality is there, so we can just provide a fake
# executable.
echo '#!/bin/sh' > /sbin/modprobe
chmod +x /sbin/modprobe

echo "Creating venv for pmbootstrap."
mkdir /root/pmbootstrap_venv
python3 -m venv /root/pmbootstrap_venv
. /root/pmbootstrap_venv/bin/activate

echo "Installing pmbootstrap ${PMBOOTSTRAP_VERSION}."
git clone --branch ${PMBOOTSTRAP_VERSION} --depth 1 https://gitlab.postmarketos.org/postmarketOS/pmbootstrap.git
pip install ./pmbootstrap

echo "Initializing pmbootstrap."
yes "" | pmbootstrap --as-root init --shallow-initial-clone

echo "Configuring pmbootstrap for device."
pmbootstrap --as-root config build_pkgs_on_install True
pmbootstrap --as-root config device ${device}
pmbootstrap --as-root config hostname ${HOSTNAME}
pmbootstrap --as-root config locale en_US.UTF-8
pmbootstrap --as-root config ssh_keys False
pmbootstrap --as-root config systemd always
pmbootstrap --as-root config timezone GMT
pmbootstrap --as-root config ui_extras True
pmbootstrap --as-root config user ${USERNAME}
if [ "${variant}" = "headless" ] ; then
    pmbootstrap --as-root config ui console
    pmbootstrap --as-root config extra_packages bash,curl,jq
else
    pmbootstrap --as-root config ui "${variant}"
    pmbootstrap --as-root config extra_packages bash,curl,firefox,jq
fi

echo "Checking out pmaports branch ${PMAPORTS_BRANCH}."
cd $(pmbootstrap --as-root config aports) \
    && git fetch --depth 1 \
        origin refs/heads/${PMAPORTS_BRANCH}:refs/heads/${PMAPORTS_BRANCH} \
    && git checkout ${PMAPORTS_BRANCH}
cd ~

echo "Installing base system."
pmbootstrap --as-root install --password "${PASSWORD}" --no-image

feeder_install_args="--ref ${version} --web-port 80 --enable-mdns \
    --expand-rootfs --auto-install-dependencies"
if [ "${variant}" = "headless" ] ; then
    feeder_install_args="${feeder_install_args} --enable-hotspot"
fi
echo "Installing porttracker-sdr-feeder with args ${feeder_install_args}."
pmbootstrap --as-root chroot -r -- bash -c \
    "curl -L -sS 'https://gitlab.navisense.de/navisense-public/adsb-feeder-image/builds/artifacts/main/raw/app-install.bash?job=build-install-script' \
    | bash -s -- ${feeder_install_args}"
# We need to shutdown the chroot now and do the install again to generate the
# image with the feeder installed.
pmbootstrap --as-root shutdown
echo "Creating final image."
pmbootstrap --as-root install --password "${PASSWORD}"
pmbootstrap --as-root shutdown

# Rename and move the image.
pmbootstrap_work=$(pmbootstrap --as-root config work)
device_file="${pmbootstrap_work}/chroot_native/home/pmos/rootfs/${device}.img"
image_file="porttracker-sdr-feeder_${version}_${device}_${variant}.img"
mv ${device_file} ${image_file}

echo "Checking image for successful feeder installation."
mount_dir=$(mktemp -d)
loop_device=$(losetup -P --show -f ${image_file})
mount -o ro ${loop_device}p2 ${mount_dir}
version_in_image=$(cat ${mount_dir}/opt/adsb/porttracker_sdr_feeder_install_metadata/version.txt)
umount ${mount_dir}
losetup -d ${loop_device}
if [ "${version_in_image}" != "${version}" ] ; then
    echo "Didn't fint the correct version file in the created image. Got \
        ${version_in_image}, expected ${version}."
    exit 1
fi

echo "Zipping ${image_file}."
zip --junk-paths ${image_file}.zip ${image_file}
echo "Uploading ${image_file}.zip to S3."
aws --profile cli s3 cp ${image_file}.zip ${S3_BUCKET}/${image_file}.zip
