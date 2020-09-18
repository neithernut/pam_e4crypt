#!/bin/bash

set -e

function die() {
    echo "$@" 1>&2
    exit 1
}

[[ -n "$ROOTFS_DIR" ]] || die "Need to specify ROOTFS_DIR to use"
[[ -n "$ROOTFS_TARBALL" ]] || die "Need to specify ROOTFS_TARBALL to use"

if [[ -z "$CRYPTPW_IMPL" ]]; then
    CRYPTPW_IMPL="cryptpw"
fi
$CRYPTPW_IMPL foo >> /dev/null || die "$CRYPTPW_IMPL does not work"


echo "Preparing base image..." 1>&2
qemu-img create -f raw pam_e4test_image 1G
mke2fs -O encrypt,^has_journal,uninit_bg pam_e4test_image

mkdir -p "$ROOTFS_DIR"
mount pam_e4test_image "$ROOTFS_DIR"
tar -xpz -C "$ROOTFS_DIR" -f "$ROOTFS_TARBALL"


echo "Adding test users..." 1>&2
cat >> "$ROOTFS_DIR/etc/passwd" <<EOF
test1:`$CRYPTPW_IMPL foo`:1000:100:PAM test user 1,,,:/home/test1:/sbin/nologin
test2:`$CRYPTPW_IMPL bar`:1001:100:PAM test user 2,,,:/home/test2:/sbin/nologin
EOF
mkdir "$ROOTFS_DIR/home/test"{1,2}
mkdir "$ROOTFS_DIR/home/test"{1,2}/secrets
chown -R 1000:100 "$ROOTFS_DIR/home/test1"
chown -R 1001:100 "$ROOTFS_DIR/home/test2"


echo "Adding test files..." 1>&2
mkdir "$ROOTFS_DIR/etc/pam.d"
cp pam.d/test "$ROOTFS_DIR/etc/pam.d"

cp scripts/test_secret.sh "$ROOTFS_DIR/usr/local/bin"
chmod +x "$ROOTFS_DIR/usr/local/bin/test_secret.sh"

mkdir "$ROOTFS_DIR/etc/pam_e4crypt"
head -c 16 /dev/urandom > "$ROOTFS_DIR/etc/pam_e4crypt/testsalt"


echo "Adding completion script..." 1>&2
cp scripts/complete_setup.sh "$ROOTFS_DIR"

umount "$ROOTFS_DIR"
echo "Test image preparation complete. Please spin up VM and run" 1>&2
echo "/complete_setup.sh inside the guest for completion. Observe the" 1>&2
echo "output to make sure the finalization is sucessful." 1>&2
