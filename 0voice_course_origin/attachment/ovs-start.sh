#!/bin/sh

ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock \
	--remote=db:Open_vSwitch,Open_vSwitch,manager_options \
	--private-key=db:Open_vSwitch,SSL,private_key \
	--certificate=db:Open_vSwitch,SSL,certificate \
	--bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert \
	--pidfile --detach

ovs-vsctl --no-wait init

ovs-vswitchd --pidfile --detach


