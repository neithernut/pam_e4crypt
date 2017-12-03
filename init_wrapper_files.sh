#!/bin/bash
set -e

SALTPATH="/home/.e4crypt/salt"
WRAPPATH="/home/.e4crypt/wrap"

# This is actually 1024 but we can't make it that big due to a bug in the e4crypt utility
EXT4_MAX_PASSPHRASE_SIZE=512
EXT4_MAX_SALT_SIZE=256

if sudo [ -f "$SALTPATH/$USER" ]
then
    yn=
    while [ "$yn" != "n" -a "$yn" != "Y" ]
    do
        echo "This script will overwrite your existing salt and wrap."
        echo -n "Do you want to continue? (Y/n) "
        read yn
        if [ "$yn" == "n" ]
        then
            exit 1
        fi
    done
fi

sudo mkdir -p $SALTPATH
sudo rm -f $SALTPATH/$USER
sudo rm -rf $WRAPPATH/$USER
sudo touch $SALTPATH/$USER
sudo mkdir -p $WRAPPATH/$USER
head -c $EXT4_MAX_SALT_SIZE /dev/urandom | sudo tee $SALTPATH/$USER > /dev/null
echo -n "Enter passphrase (echo disabled): "
e4crypt_out=$(e4crypt add_key -S 0x$(sudo xxd -c 9999 -p $SALTPATH/$USER))
echo ""
echo "$e4crypt_out" | tail +2
outerkeyhash=$(echo "$e4crypt_out" | grep -oP '(?<=\[)[0-9a-f]+(?=\])')
sudo e4crypt set_policy $outerkeyhash $WRAPPATH/$USER
head -c $EXT4_MAX_SALT_SIZE /dev/urandom | sudo tee $WRAPPATH/$USER/salt > /dev/null
echo -n `head -c $((EXT4_MAX_PASSPHRASE_SIZE / 2)) /dev/urandom | xxd -c 99999 -p` | sudo tee $WRAPPATH/$USER/auth > /dev/null
sudo chmod -R 700 $SALTPATH
sudo chmod -R 700 $WRAPPATH
sudo chgrp $USER $SALTPATH/$USER
sudo chgrp $USER $WRAPPATH/$USER

yn=
while [ "$yn" != "n" -a "$yn" != "Y" ]
do
    echo -n "Do you want to load the encryption key? (Y/n) "
    read yn
    if [ "$yn" == "Y" ]
    then
        sudo cat $WRAPPATH/$USER/auth | e4crypt add_key -S 0x$(sudo xxd -c 9999 -p $WRAPPATH/$USER/salt) | tail +2
    fi
done
