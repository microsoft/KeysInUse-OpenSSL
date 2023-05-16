#!/bin/sh -e

# Helper script to install keysinuse inside containers. Mostly
# recycled from the deb/rpm postinstall script

# Create a directory for keys in use logs
mkdir /var/log/keysinuse
chown root:root /var/log/keysinuse
chmod 1733 /var/log/keysinuse

mkdir /usr/lib/keysinuse
mv /keysinuse/keysinuse.so /usr/lib/keysinuse
/keysinuse/keysinuseutil -update-default -install-library install || echo "Configuring engine failed"