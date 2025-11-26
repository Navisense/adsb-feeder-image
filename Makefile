HOST ?= xxxxxxxx-porttracker-sdr.local
SSH_CONTROL=/tmp/adsb-setup-ssh-control-${HOST}

ssh-control:
# to avoid having to SSH every time,
# we make a SSH control port to use with rsync.
	ssh -M -S "${SSH_CONTROL}" -fnNT root@$(HOST)

sync-and-update-nocontainer:
# sync relevant files and update
	ssh -O check -S "${SSH_CONTROL}" root@$(HOST) || make ssh-control

	# sync over changes from local repo
	make sync-py-control

	# restart webinterface
	ssh -S "${SSH_CONTROL}" root@$(HOST) systemctl restart adsb-setup

sync-and-update:
# sync relevant files and update
	ssh -O check -S "${SSH_CONTROL}" root@$(HOST) || make ssh-control

	# stop webinterface
	ssh -S "${SSH_CONTROL}" root@$(HOST) systemctl stop adsb-setup
	# sync over changes from local repo
	make sync-py-control

	# start webinterface back up
	ssh -S "${SSH_CONTROL}" root@$(HOST) systemctl restart adsb-setup

sync-py-control:
# check if the SSH control port is open, if not, open it.
	ssh -O check -S "${SSH_CONTROL}" root@$(HOST) || make ssh-control

	rsync -av \
	--delete --exclude="*.pyc" --progress \
	-e "ssh -S ${SSH_CONTROL}" \
	src/modules/adsb-feeder/filesystem/root/opt/adsb/ \
	root@$(HOST):/opt/adsb/

	rsync -av --progress \
	-e "ssh -S ${SSH_CONTROL}" \
	src/modules/adsb-feeder/filesystem/root/usr/lib/systemd/system/ \
	root@$(HOST):/usr/lib/systemd/system/

	rsync -av \
	--exclude="*.pyc" --progress \
	-e "ssh -S ${SSH_CONTROL}" \
	src/modules/adsb-feeder/filesystem/root/etc/ \
	root@$(HOST):/etc/

# For good measure, copy this Makefile, run cachebust, set metadata, and do a
# daemon-reload.
	rsync -av \
	-e "ssh -S ${SSH_CONTROL}" \
	Makefile \
	root@$(HOST):/opt/adsb/adsb-setup/Makefile

	ssh -S "${SSH_CONTROL}" root@$(HOST) '\
		rm -f /opt/adsb/.cachebust_done; \
		bash /opt/adsb/scripts/cachebust.sh Makefile; \
		mkdir -p /opt/adsb/porttracker_sdr_feeder_install_metadata; \
		echo "Makefile-sync install" > /opt/adsb/porttracker_sdr_feeder_install_metadata/previous_version.txt; \
		echo "Porttracker Feeder from Makefile-sync" > /opt/adsb/porttracker_sdr_feeder_install_metadata/friendly_name.txt; \
		echo "`cat /opt/adsb/version.txt`-makefile-sync" > /opt/adsb/porttracker_sdr_feeder_install_metadata/version.txt; \
		systemctl daemon-reload; \
	'

run-loop:
# python3 app.py in a loop
	while true; do \
		python3 app.py; \
		sleep 1; \
	done
