# Device specific post install scripts

This directory contains device specific post install scripts that are run when
the image is being created, right after the Porttracker SDR Feeder install
script has run.

Each device may have a script named `<device>.bash`, e.g. `raspberry-pi4.bash`.
The script may be missing and nothing gets executed.
