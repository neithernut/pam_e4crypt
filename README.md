# pam_e4crypt

This is a PAM module for unlocking transparently encrypted directories on ext4.

Since version 4.1, the Linux kernel supports transparent encryption in ext4.  The
mechanism relies on the keyrings facility of the kernel.

This module will create keys for (de)ciphering files and file-names in encrypted
directories during the authentication phase. During the session setup phase,
those keys are added to the session keyring, giving the user (instant) access
to directories for which she previously set a "policy" matching her passphrase
(e.g. using e4crypt from the e2fsprogs).

Note that the only encryption mode currently supported is aes256-xts.

Google's [fscrypt](https://github.com/google/fscrypt) has the same purpose but
is not restricted to ext4's transparent encryption feature and far better
maintained. Thus, fscrypt is probably better suited for production machines.


## Pitfalls

Users should be aware of the following when using (or thinking about using) this
module:

 * Files and directories are usually cached by the kernel for performance
   reasons. When using ext4 transparent encryption, decrypted content ends up
   in those caches and may thus (still) be visible to users with sufficient
   access rights (e.g. `root`) during or even after a session (until the caches
   are cleared).
 * Obviously, this module will only unlock files and directories if it will be
   invoked, e.g. if PAM is used for login. Thus, background services can not
   access encrypted files directories if the files are not unlocked (that's the
   whole point of this module -- duh). TL;DR: don't complain about cronjobs
   failing while trying to access encrypted files.
 * Changing the password used for login does (currently) not change the
   encryption key of affected directories. Hence, those directories will not be
   unlocked after a password-change.


## Using this module

This module should be invoked late during the authentication phase as well as
early during the session phase, after an invocation of the `pam_keyinit` module.
The module should be marked as `required` for the authentication phase and
either `required` or `optional` for the session phase, e.g.:

```
auth ...
auth        required        pam_e4crypt.so

account ...
password ...

session     required        pam_keyinit.so
session     required        pam_e4crypt.so
session ...
```

During the authentication phase, keys are generated from the user password.
Hence, the module should be invoked late, at a point where the password is
available.

During the session phase, the generated keys are added to the session keyring.
Obviously, the keyring has to be initialized. Hence, `pam_keyinit` or an
equivalent module has to invoked prior to `pam_e4crypt`. Since other session
modules may access encrypted directories, it is highly recommended to have
`pam_e4crypt` invoked early.

As this module is considered experimental, users also may want to specify
`onerr=succeed`. Furthermore, it has been reported that having the module
`required` for the session phase may break some setups. Hence, new users are
encouraged making the module `optional` for that phase, at least initially.


### Salt

User can have a specific salt stored in `$HOME/.ext4_encryption_salt`.
You can generate this salt with one of the following commands :

``` echo -n `uuidgen` > ~/.ext4_encryption_salt ```

``` echo -n s:`head -c 16 /dev/urandom | xxd -p` > ~/.ext4_encryption_salt ```

You can also store the salt outside your home directory in your pam config:

```
auth        required        pam_e4crypt.so  saltpath=/home/.e4crypt
```

The module will then look for the salt in `/home/.e4crypt/$USER`

### Keyring

By default, keys are added to the session keyring. Using the `keyring` argument
in the PAM config, it is possible to specify an alternative keyring to which the
keys should be added. Use like:

```
session     required        pam_e4crypt.so  keyring=<desc>
```

As `<desc>`, one may specify either a keyring's description or one of the
"special values" understood by `keyctl` (1.5), e.g. `@u` for the user specific
keyring.


## Dependencies

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


## Installation

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
cmake -DCMAKE_C_FLAGS="-O2 -fstack-protector-strong" <path-to-source>
```

The module is automatically installed in a directory `security` which resides in
the same folder as the PAM library. If those directories are symlinks on the
target platform, the actual installation path may differ from the installation
path originally used by PAM due to the default search order used by CMake.

Albeit the module should still be found by PAM, users may choose to specify the
library base path used for installation manually by setting the
`CMAKE_INSTALL_LIBDIR` variable.

For example, run
```
cmake -DCMAKE_INSTALL_LIBDIR=<lib-base-path> <path-to-source>
```
to prepare the module for installation to `<lib-base-path>/security/`.


## About passwords, mounts and policies

"policies" are actually keys generated from a passphrase and a salt. This PAM
module will generate keys from the user's passphrase and add them as policies,
just like `e4crypt add_key`. If you view you session keyring, e.g. using
`keyctl show @s`, those keys will be visible as "logon" keys with a descriptor
prefixed with "ext4:". The hexadecimal string following the prefix is the actual
policy descriptor which you can pass to `e4crypt set_policy`.

The correct process for encrypting a folder once logged in with pam_e4crypt is:

```
$ keyctl show
Session Keyring
 111111111 --alswrv      0     0  keyring: _ses
 222222222 ----s-rv      0     0   \_ user: invocation_id
 333333333 --als-rv   1000  1000   \_ logon: ext4:abcdef012345678
$ mkdir crypted
$ e4crypt set_policy abcdef012345678 crypted
```

## Licensing

The module is currently licensed under the GPLv2. Have a look at the LICENSE
file for more information. Also, you might want to consult a lawyer if you
intend to ship this module together which a BSD-licensed version of PAM.

The license was chosen because some code was cargo-culted from the e2fsprogs,
which was authored by Michael Halcrow and Ildar Muslukhov, copyrighted by Google
and licensed under the GPLv2. Maybe, one day, if all the affected functions are
rewritten to a degree where they are legally re-implementations, none of the
eventual co-authors object and none of the dependencies switched to GPL-only,
I'll re-release the thing under the LGPL or a BSD-license.

