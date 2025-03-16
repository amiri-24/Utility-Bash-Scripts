#!/bin/bash

# Disable SELinux temporarily
setenforce 0

# Install required dependencies
yum install -y policycoreutils-python-utils
yum install -y perl gcc kernel-headers kernel-devel make
yum install gcc kernel-devel

# Mount VMware tools CD
mount /dev/cdrom /mnt/

# Copy VMware tools tarball to root directory
cp /mnt/VMware* /root/

# Extract VMware tools tarball
cd /root/
tar -xvf VMware*

# Navigate to VMware tools directory
cd vmware-tools-distrib

# Install VMware tools
./vmware-install.pl
