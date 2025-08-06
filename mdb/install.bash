#!/usr/bin/env bash

set -e

docker build -t sass-builder .
docker run --rm -v ./:/mdb/ sass-builder bash -c "\
    sass --source-map --style=compressed \
        /mdb/mdb-ui-kit/src/scss/mdb.free.scss /mdb/mdb.min.css \
    && chown $(id -u):$(id -g) /mdb/mdb.min.css* \
    "

mv -f mdb.min.css* ../src/modules/adsb-feeder/filesystem/root/opt/adsb/adsb-setup/static/css/
