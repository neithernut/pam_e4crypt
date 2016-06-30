= pam_e4crypt

This is a PAM module for unlocking transparently encrypted directories on ext4.

Since version 4.1, the Linux kernel supports transparent encryption in ext4.  The
mechanism relies on the keyrings facility of the kernel.

This module will create keys for (de)ciphering files and file-names in encrypted
directories during the authentication phase. During the session setup phase,
those keys are added to the session keyring, giving the user (instant) access
to directories for which she previously set a "policy" matching her passphrase
(e.g. using e4crypt from the e2fsprogs).

Note that the only encryption mode currently supported is aes256-xts.


== Using this module

Invoke this module during the authentication phase after the passphrase is
set, so the keys can be generated, and during the session phase right after
pam_keyinit, so the keys are added to the session keyring.


== Dependencies

At runtime, the module requires:
 * Linux-Kernel>=4.1
 * PAM
 * keyutils
 * OpenSSL (or some compatible replacement like libressl)
 * libuuid (util-linux)

At build time, the developer-packages for all the runtime-dependencies are
required in addition to:
 * CMake>=3.5
 * A C-compiler (e.g. gcc or clang)


== Installation

The module is built using CMake. Run

```
cmake <path-to-source>
make
make install
```
in the directory in which you indent to build the module. In-tree builds are
supported (supply `.` as the source directory).

Additional cflags and ldflags can be supplied via the `CMAKE_C_FLAGS` and
`CMAKE_MODULE_LINKER_FLAGS` when generating the build system, e.g.:
```
cmake -DCMAKE_C_FLAGS="-O2 -fstack-protector=strong" <path-to-source>
```


== About passwords, mounts and policies

"policies" are actually keys generated from a passphrase and a salt. This PAM
module will generate keys from the user's passphrase and add them as policies,
just like `e4crypt add_key`. If you view you session keyring, e.g. using
`keyctl show @s`, those keys will be visible as "logon" keys with a descriptor
prefixed with "ext4:". The hexadecimal string following the prefix is the actual
policy descriptor which you can pass to `e4crypt set_policy`.

Please note that the salt is, apparently, parsed from the mtab in some way. This
indicates that policies are actually specific to mounts to some extend. Sadly,
there is no (good) way of telling which policy matches a specific mount.
This module could, in theory, print or log some information about that, but
currently, it doesn't. This may, however, change in the future.


== Licensing

The module is currently licensed under the GPLv2. Have a look at the LICENSE
file for more information. Also, you might want to consult a lawyer if you
intend to ship this module together which a BSD-licensed version of PAM.

The license was chosen because some code was cargo-culted from the e2fsprogs,
which is licensed under the GPLv2. Maybe, one day, if all the affected functions
are rewritten to a degree where they are legally re-implementations, none of the
eventual co-authors object and none of the dependencies switched to GPL-only,
I'll re-release the thing under the LGPL or a BSD-license.

