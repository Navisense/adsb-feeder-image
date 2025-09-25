#!/bin/bash

# Pull Docker images we need and prune those that are outdated.

if [ ! -f /opt/adsb/scripts/lib-common.bash ] ; then
    echo "Missing /opt/adsb/scripts/lib-common.bash, unable to continue."
    exit 1
else
    source /opt/adsb/scripts/lib-common.bash
    rootcheck
fi

docker ps >/dev/null 2>&1
if [ $? -ne 0 ] ; then
    log_and_exit_sync 1 $0 "The Docker daemon isn't running, can't do anything."
fi

log $0 "Pulling new container images."
# Let the wrapper script figure out which compose files should be activated and
# pull all necessary images.
bash /opt/adsb/docker-compose-adsb pull --ignore-pull-failures &>> ${LOG_FILE}

# Prune images and files we no longer use.
# https://docs.docker.com/config/pruning/ says: A dangling image is one that
# isn't tagged, and isn't referenced by any container. Pretty much all old
# images we have are tagged so they wouldn't be removed without -a but -a also
# removes current images of for example deactived feed containers, thus we
# manually create a list of images that are neither running nor specified in the
# config.
needed_images=$(/opt/adsb/adsb-setup/config.py as_json 2>/dev/null \
    | jq -r '.images[]')
prune_images=""
for existing_image in $(docker images -a --format "{{.Repository}}:{{.Tag}}") ; do
    existing_base_image=$(echo $existing_image | cut -d: -f1)
    existing_tag=$(echo $existing_image | cut -d: -f2)
    for needed_image in $needed_images ; do
        needed_base_image=$(echo $needed_image | cut -d: -f1)
        needed_tag=$(echo $needed_image | cut -d: -f2)
        if [ $existing_base_image = $needed_base_image ] && [ $existing_tag != $needed_tag ] ; then
            prune_images+="${existing_image} "
        fi
    done
done

if [[ -z "$prune_images" ]]; then
    log $0 "No unused images to prune."
else
    log $0 "Pruning unused images ${prune_images}"
    docker image rm $prune_images # unquoted expansion required
fi
log $0 "Pruning done."
