#!/bin/bash


# this needs to run as root
if [ "$(id -u)" != "0" ] ; then
    echo "this command requires superuser privileges - please run as sudo bash $0"
    exit 1
fi

systemctl stop adsb-setup

TMP="$(mktemp config.json.XXXX)"
JSON="/etc/adsb/config.json"
jq < "$JSON" '."AF_IS_SECURE_IMAGE" = false' > "$TMP" && mv "$TMP" "$JSON"
sed -i '/_ADSBIM_STATE_IS_SECURE_IMAGE=True/d' /etc/adsb/.env
rm /opt/adsb/adsb.im.secure_image

systemctl restart adsb-setup

echo "----------------------"
echo "Secure Image DISABLED!"
echo "----------------------"
