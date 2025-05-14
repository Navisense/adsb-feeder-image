#!/bin/bash

if grep 'FEEDER_SERIAL_AIS=.*' /opt/adsb/config/.env > /dev/null 2>&1 ; then
    # We want to run AIS-catcher with an SDR device, but it doesn't allow us to
    # specify the serial via an environment variable, so grep it from the env
    # file and munge it into the config JSON.
    export $(grep FEEDER_SERIAL_AIS /opt/adsb/config/.env | xargs)
    jq ".serial |= \"$FEEDER_SERIAL_AIS\"" /opt/adsb/ais-catcher/config.json > /tmp/ais-catcher.config
    mv /tmp/ais-catcher.config /opt/adsb/ais-catcher/config.json
fi
