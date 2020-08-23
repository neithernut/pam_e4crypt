#!/bin/sh

set -e

cd /tmp


echo "Performing basic system setup..." 1>&2
mount -t proc none /proc
mount -t sysfs none /sys
ip link set eth0 up
udhcpc -nq


echo "Installing test prequisites..." 1>&2
apk add gcc cmake make git \
    e2fsprogs-extra \
    linux-pam-dev keyutils-dev openssl-dev linux-headers libc-dev
source /etc/profile

echo "Installing pam test utils..." 1>&2
wget https://github.com/okirch/pam-test-utils/archive/master.zip -O - | unzip -
make -C pam-test-utils-master
mv pam-test-utils-master/pam-test /usr/local/bin/


# The existing `halt` and `poweroff` won't work in our environment. Hence, we
# supply a simple version which calls `reboot(2)` directly.
echo "Installing special halt and poweroff..." 1>&2
gcc -o /sbin/halt -x c - <<EOF
#include <unistd.h>

#include <linux/reboot.h>
#include <sys/reboot.h>

int main() {
    return reboot(LINUX_REBOOT_CMD_POWER_OFF);
}
EOF
ln -fs /sbin/halt /sbin/poweroff


echo "Clearing /tmp..." 1>&2
rm -rf /tmp/*

echo "Setup finalyzed, powering off..." 1>&2
exec poweroff
