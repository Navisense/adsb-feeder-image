# Porttracker SDR Feeder

This application can be used to easily set up stations receiving AIS ship
positions and/or ADS-B airplane positions on devices running
[postmarketOS](https://postmarketos.org). postmarketOS is a mobile Linux that
runs on some phones, but also on single-board computers like the Raspberry Pi.
The data can be shared with [porttracker.co](https://porttracker.co) by
[Navisense](https://navisense.de), as well as a number of other aggregators.

The application is based on [ADS-B Feeder Image](https://adsb.im) by Dirk
Hohndel.

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

The application has a web-based interface that allows you to configure data
aggregators with which you can share the data you receive. These aggregators are
supported:

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
  depending on where you are. But often a generic SDR USB stick and appropriate
  antenna is all you need. The RTL-SDR with the RTL2832U chipset is a popular
  choice.
- Special hardware receivers and decoders for AIS that connect via a serial port
  are also supported. E.g., these could connect to the GPIO pins of a Raspberry
  Pi.

## Installation

### Installation as an image

We're automatically building images for Raspberry Pis (3, 4, and 5) for every
release. You can simply download them and flash them to an SD card. The images
are available at URLs like

```
https://porttracker-api.porttracker.co/api/v1/file/public/device_images/porttracker-sdr-feeder_<version>_<device>_<variant>.img.zip
```

where

- `<version>` is the version of the image (see
  [tags](https://github.com/maritime-datasystems/adsb-feeder-image/tags))
- `<device>` is the device type, one of `raspberry-pi3`, `raspberry-pi4`,
  `raspberry-pi5`
- `<variant>` is the variant of the image, either `headless` or `plasma-mobile`

For example, the URL for the image for version `v3.12.6` for a Raspberry Pi 4
running in headless mode is

```
https://porttracker-api.porttracker.co/api/v1/file/public/device_images/porttracker-sdr-feeder_v3.12.6_raspberry-pi4_headless.img.zip
```

To flash the image, you can use the [Raspberry Pi
Imager](https://www.raspberrypi.org/software/) and select "Custom Image".

All of these images have a default user named "user" with password "123". You
will need that password in the `plasma-mobile` variants when you log in. On all
devices, the management web interface will prompt you to change that password.

#### Image variants

The difference between the `headless` and `plasma-mobile` variants is that the
`plasma-mobile` variant includes a graphical user interface and is meant for
devices with a touchscreen that you can use like a small stationary tablet. For
these, it is assumed that you can do the basic system setup (e.g. setting up
Wi-Fi) via the graphical user interface. You can access the Porttracker SDR
management interface by opening a browser (firefox comes preinstalled) and
typing `localhost` into the address bar.

The `headless` variant on the other hand is meant for devices without any sort
of display or mouse and keyboard attached. Since you can't do any system
setup directly, these images will always start a WiFi hotspot after they start
up for the first time. Look for a WiFi network called
`xxxxxxxx-porttracker-sdr.local`, where `xxxxxxxx` are 8 characters that
uniquely identify the device (these are randomly generated when the device
starts up and there is no way to know them in advance).

If you want to connect the device via network cable (ethernet), just plug in the
cable, and the device will configure itself automatically (you'll need a DHCP
server on that network, home routers should have that). You can then access the
management interface at `http://xxxxxxxx-porttracker-sdr.local` (replace the
`xxxxxxxx` with the characters from the hotspot name).

If you want the device to connect to a WiFi network, connect to the hotspot,
and your computer or phone should offer an option like "tap here to sign in to
network" or "this network requires sign in" or something similar (captive
portal). Follow that option, and you should see a page on which you can choose a
WiFi network for the device. There is more information on that page, but the
gist of it is: choose a network, enter the password, and wait for the device to
connect. You can then access the management interface at
`http://xxxxxxxx-porttracker-sdr.local`.

In case the "tap here to sign in to network" option doesn't show up, you can try
the following:

- Make sure you are not connected to the internet in any way (e.g. unplug a
  network cable, disable mobile data on your phone).
- Enter `http://porttracker-sdr` into your browser (without a `.local`; the
  device starts a small DNS server that redirects all domains to itself, so you
  can type in almost anything here). You should see the page to select a WiFi
  network. In some browsers, it takes a little while before they show you that
  page, though.
- If that doesn't work either, try entering `http://192.168.199.1` into your
  browser.

### Using the install script

You can install the whole software stack as an app on an existing postmarketOS
system. Run a small [install
script](https://github.com/maritime-datasystems/adsb-feeder-image/releases/latest/download/app-install.bash),
which is generated as a build artifact by the CI pipeline. For the trusting kind
of people, all you need to do is open a root shell and execute

```
curl -L -sS 'https://github.com/maritime-datasystems/adsb-feeder-image/releases/latest/download/app-install.bash' \
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

### Finding the device on the network

Each Porttracker SDR has a unique name, which is displayed in the hotspot name
when it starts up for the first time. The name contains a random string of 8
characters, e.g. `xxxxxxxx-porttracker-sdr.local`. The hotspot is kept open most
of the time so that you can always find the device name. It advertises itself
via mDNS (also known as Bonjour, Avahi, or Zeroconf), so you can access the web
interface at `http://xxxxxxxx-porttracker-sdr.local`.

Each device also publishes an mDNS service named
`xxxxxxxx-porttracker-sdr._http._tcp`.

For the more tech-savvy, you can also find the device's IP address by checking
your router's DHCP lease table (i.e. which IP address is assigned to the device)
after the device is connected to the network. Or you can use `nmap` to scan for
port 22: `nmap -p 22 <your_subnet>`, where <your_subnet> is the subnet from
which your router assigns IP addresses, often `192.168.0.0/24` or
`192.168.1.0/24`.

## Uninstallation

To uninstall the feeder, SSH into the device and run the uninstall script at
`/opt/adsb/uninstall.bash` as root.

Note that the uninstall script doesn't remove system packages that were
installed as dependencies during the installation, nor does it remove Docker
images that were pulled during its operation.

## Extra information for developers

This section contains information about the internal workings of the software.
You don't need to know this if you just want to use it, but you'll find it
helpful if you want to develop the software.

### Directories and files belonging to the feeder

The directory structure of the feeder is a leftover from the adsb-feeder-image
this software is based on (directories and files still have "adsb" in their
names) and should not be changed without careful consideration. The update
process expects these names and this structure, and changing it means updates
become incompatible with the old version.

The following directories and files belong to the feeder:

- `/opt/adsb`
- `/etc/adsb`
- `/usr/lib/systemd/system/adsb*`
- `/etc/logrotate.d/porttracker-sdr-feeder`
- `/var/log/porttracker-sdr-feeder*`

The `adsb-setup` is a Python app as well as a Systemd system service that
contains the main logic. There are additional system services that get started
during operation, as well as Docker compose files.

The sources of the adsb-setup app are at
[src/modules/adsb-feeder/filesystem/root/opt/adsb/adsb-setup](src/modules/adsb-feeder/filesystem/root/opt/adsb/adsb-setup).

### Updating a running device

To develop the application, there is a handy Makefile at the top level of the
repository, which copies the current state of the repo to a device and restarts
the application. You need root SSH access to the devices. You can specify the
host using the `HOST` environment variable, e.g.

```
HOST=xxxxxxxx-porttracker-sdr.local make sync-and-update
```

Note that `rsync` needs to be installed on the device for this to work.

### Checkboxes in form data

Normally, when an HTML form is submitted, any checkboxes that are unchecked are
simply omitted. In this application, there is a small Javascript hook executed
on every submit that ensures each checkbox is contained, with the value "0" for
unchecked ones and "1" for checked ones.

### Cache busting

To prevent browsers from serving stale static assets (CSS, JS) after an update,
we implement a cache busting mechanism:

1. Hash Computation: On startup, the application computes (shortened) MD5 hashes
   for all files in the `static/` directory.
2. URL Generation: We wrap `flask.url_for` to automatically inject these hashes
   into the filenames of static assets (e.g. `style.css` becomes
   `style.<hash>.css`).
3. Request Handling: A custom view handler intercepts requests for static files
   (this replaces the one that comes with Flask). It detects hashed filenames,
   strips the hash, verifies it against the computed hash, and serves the
   original file from disk.

This ensures that whenever a static file changes, its URL changes, forcing the
browser to fetch the new version.

### Logging setup

The default log level is `INFO`. You can change this by creating a file at
`/etc/adsb/log_level` and writing your desired log level into it, which must be
one of `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL`.

To save on unnecessary disk writes, all parts of the application log to
`/run/porttracker-sdr-feeder.log` (`/run` is a tmpfs in memory). This file is
regularly spilled over to the permanent log file
`/var/log/porttracker-sdr-feeder.log`, which then gets rotated by logrotate.
