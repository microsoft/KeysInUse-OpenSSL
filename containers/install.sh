#!/bin/sh -e

# Helper script to install keysinuse inside containers. Mostly
# recycled from the deb/rpm postinstall script

# Create a directory for keys in use logs
mkdir /var/log/keysinuse
chown root:root /var/log/keysinuse
chmod 1733 /var/log/keysinuse

cp /keysinuse/keysinuse.so $(/usr/bin/openssl version -e | awk '{gsub(/"/, "", $2); print $2}')
/keysinuse/keysinuseutil -update-default install || echo "Configuring engine failed"