# Porttracker SDR Feeder

This application can be used to easily set up stations receiving AIS ship
positions and/or ADS-B airplane positions on devices running
[postmarketOS](https://postmarketos.org). postmarketOS is a mobile Linux that
runs on some phones, but also on single-board computers like the Raspberry Pi.
The data can be shared with [porttracker.co](https://porttracker.co) by
[Navisense](https://navisense.de), as well as a number of other aggregators.

The application is based on [ADS-B Feeder Image](https://adsb.im) by Dirk
Hohndel.

Development takes place on the [Navisense
Github](https://gitlab.navisense.de/navisense-public/adsb-feeder-image/), but
updates are also regularly pushed to the fork on
[Github](https://github.com/Navisense/adsb-feeder-image).

## Track nearby ships and aircraft with your own hardware and share with others

Track ships and aircraft around you that are broadcasting AIS/ADS-B messages
(ADS-B on 1090 MHz and, in the US, UAT messages on 978 MHz) and view them on
a map. For ships, this includes data like recent tracks, ship name, and size,
for aircraft recent tracks, altitude, speed, and in case of many commercial
flights even the route that they are on.

To receive the data, you need an SDR (software defined radio) USB stick and a
suitable antenna. Note that you need separate SDR sticks and antennas for each
of the 3 frequencies (AIS, ADS-B, UAT), since each can only listen to one
frequency.

## Share the data

You can configure these aggregators and share data with them:

### AIS

- [Porttracker](https://porttracker.co)
- [AIS-catcher](https://www.aiscatcher.org)
- [AISHub](https://www.aishub.net)

### ADS-B

These aggregators have a commitment to open data ([daily release of the
data](https://github.com/adsblol/globe_history)); they also share with each
other the data fed to them (in order to improve mlat coverage, it still makes
sense to feed all of them):
- [adsb.lol](https://adsb.lol)
- [Fly Italy Adsb](https://flyitalyadsb.com)
- [TheAirTraffic](http://theairtraffic.com)

These aggregators are also supported:
- [adsb.fi](https://adsb.fi)
- [ADS-B Exchange](https://adsbexchange.com)
- [ADSBHub](https://adsbhub.org)
- [airplanes.live](https://airplanes.live)
- [AVDelphi](https://www.avdelphi.com)
- [FlightAware](https://flightaware.com)
- [FlightRadar24](https://www.flightradar24.com)
- [hpradar](https://skylink.hpradar.com/)
- [OpenSky Network](https://opensky-network.org)
- [Plane.watch](https://plane.watch)
- [Plane Finder](https://planefinder.net)
- [Planespotters.net](http://planespotters.net)
- [AirNav Radar](https://www.airnavradar.com)
- [Radar Virtuel](https://www.radarvirtuel.com)

## Required hardware

- Get one of the supported devices. That's anything that you can install
  postmarketOS on, see [their wiki](https://wiki.postmarketos.org/wiki/Devices).
- Invest in a decent power supply - we strongly recommend against attempting to
  power these boards from a powered hub or a cheap 'charger' plug, not having a
  stable 5V power source tends to be the biggest cause of issues with these SBC.
- Get an SDR and suitable antenna for each of the frequencies you want to use
  (AIS, ADS-B, UAT). There are many many choices. Availability may differ
  depending on where you are. But often a generic SDR and appropriate antenna is
  all you need.

## Installation using the install script

You can install the whole software stack as an app on an existing postmarketOS
system. Run a small [install
script](https://gitlab.navisense.de/navisense-public/adsb-feeder-image/builds/artifacts/main/raw/app-install.bash?job=build-install-script),
which is generated as a build artifact by the CI pipeline. For the trusting kind
of people, all you need to do is open a root shell and execute

```
curl -L -sS 'https://gitlab.navisense.de/navisense-public/adsb-feeder-image/builds/artifacts/main/raw/app-install.bash?job=build-install-script' \
    | bash -s -- --web-port 80 --enable-mdns --auto-install-dependencies
```

This requires `bash`, `curl`, and `jq` to be installed already. All other
dependencies are checked for (and also installed if you specify
`--auto-install-dependencies`).

The script allows a few options, which are appended to the bash command after
`-s --`. They are

- `--ref`: The ref of the git repo to download, e.g. a tag with a specific
  version. If not specified, the `main` branch is used, which contains the
  latest stable version.
- `--web-port`: The port on which the web interface should be started (default
  1099).
- `--enable-mdns`: Whether an mDNS service should be started, which makes it
  easier to access the machine from the outside as
  `xxxxxxxx-porttracker-sdr.local`.
- `--expand-rootfs`: Whether a service should be started that automatically
  expands the root filesystem. This really only makes sense for generating
  images and shouldn't be used on existing systems.
- `--auto-install-dependencies`: Whether missing dependencies should be
  installed automatically. By default, the script will only tell you which
  dependencies are missing and exit with an error.

Once the script has run through successfully, the web interface should be
available on localhost at the port you specified via `--web-port`, or 1099 by
default.


## For developers

The sources of the adsb-setup app are at
[src/modules/adsb-feeder/filesystem/root/opt/adsb/adsb-setup](src/modules/adsb-feeder/filesystem/root/opt/adsb/adsb-setup).

To develop the application, there is a handy Makefile at the top level of the
repository, which copies the current state of the repo to a device and restarts
the application. You need root SSH access to the devices. You can specify the
host using the `HOST` environment variable, e.g.

```
HOST=xxxxxxxx-porttracker-sdr.local make sync-and-update
```

### Checkboxes in form data

Normally, when an HTML form is submitted, any checkboxes that are unchecked are
simply omitted. In this application, there is a small Javascript hook executed
on every sumbit that ensures each checkbox is contained, with the value "0" for
unchecked ones and "1" for checked ones.

### Logging setup

To save on unnecessary disk writes, all parts of the application log to
`/run/porttracker-sdr-feeder.log` (`/run` is a tmpfs in memory). This file is
regularly spilled over to the permanent log file
`/var/log/porttracker-sdr-feeder.log`, which then gets rotated by logrotate.
