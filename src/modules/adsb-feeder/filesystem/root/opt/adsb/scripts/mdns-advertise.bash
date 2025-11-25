#!/bin/bash

# Advertise this machine with an mDNS service and address.
#
# The hostname to advertise must be given as the only argument, the .local
# suffix will be added for the address. The advertised service will be
# <hostname>._http._tcp on the port given by the envrionment variable
# AF_WEBPORT, or 80 by default if that is unset.
#
# Advertising automatically stops after 60 seconds, at which point this script
# has to be restarted. This is just a low-tech way of ensuring that the correct
# IP is advertised eventually in case it changes.

mdns_hostname="${1}"

# avahi-publish-service will publish a service, and also publish the address as
# <service_name>.local.
timeout 60 avahi-publish-service "${mdns_hostname}" _http._tcp ${AF_WEBPORT:-80}
