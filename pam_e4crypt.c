/*
 * pam_e4crypt
 * Copyright Julian Ganz <neither@nut.email>
 *
 * This file is part of pam_mount; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 */


// this is a PAM module implementing authentication (kinda) and session setup
#define PAM_SM_AUTH
#define PAM_SM_SESSION

// std and system includes
#include <fcntl.h>
#include <mntent.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <syslog.h>
#include <limits.h>

#include <keyutils.h>

// ext4 specific includes
#include <ext2fs/ext2_fs.h>
#include <ext2fs/ext2fs.h>

// library includes
#include <openssl/sha.h>
#include <uuid/uuid.h>

// PAM includes
#include <security/pam_modules.h>
#include <security/pam_modutil.h>


// misc definitions -- originally ripped from e4crypt
#define EXT4_KEY_REF_STR_BUF_SIZE ((EXT4_KEY_DESCRIPTOR_SIZE * 2) + 1)
#define EXT2FS_KEY_TYPE_LOGON "logon"
#define EXT2FS_KEY_DESC_PREFIX "ext4:"
#define EXT2FS_KEY_DESC_PREFIX_SIZE 5
#define SHA512_LENGTH 64
#define PAM_E4CRYPT_KEY_DATA "pam_e4crypt_key_data"


#ifndef EXT4_IOC_GET_ENCRYPTION_PWSALT
#define EXT4_IOC_GET_ENCRYPTION_PWSALT	_IOW('f', 20, __u8[16])
#endif


/**
 * Log honoring the silent flag
 *
 * Use like syslog, but only if the variable `flags` is around.
 */
#define pam_log(level, ...) do { if (~flags & PAM_SILENT) \
        syslog(level, "pam_e4crypt: " __VA_ARGS__); } while (0)




/**
 * Hexadecimal characters
 */
static const unsigned char *hexchars = (const unsigned char *) "0123456789abcdef";
static const size_t hexchars_size = 16;




// utility functions


/**
 * Retrieve the value of an argument
 *
 * @returns the value of the option or NULL if the argument doesn't match the
 *          name supplied
 */
static
char const*
get_modarg_value(
    char const* modarg_name, ///< name of the argument
    char const* modarg ///< the argument
) {
    // match the name
    const size_t name_length = strlen(modarg_name);
    if (strncmp(modarg, modarg_name, name_length) != 0)
        return NULL;

    // an option either has a value concanated to the name via `=` or it is
    // empty (e.g. the argument only contains the name)
    if (modarg[name_length] != '=') {
        if (modarg[name_length] == '\0')
            return "";
    }

    // whatever comes after the `=` is a value
    return modarg + name_length + 1;
}




/**
 * Encryption key list
 *
 * This struct implements a simple stack containing encryptoin keys.
 */
struct key_list {
    struct ext4_encryption_key* data; ///< pointer to the array of keys held
    size_t count; ///< number of keys in the list
};


/**
 * Initialize a key list
 */
static
void
key_list_init(
        struct key_list* list ///< key list to initialize
) {
    list->data = NULL;
    list->count = 0;
}


/**
 * Free all resources associated with a key list
 *
 * The key list is reset (e.g. re-initialized)
 */
static
void
key_list_destroy(
        struct key_list* list ///< key list to destroy
) {
    memset(list->data, 0, sizeof(*(list->data)) * list->count);
    free(list->data);
    key_list_init(list);
}


/**
 * Allocate room for one more key
 *
 * @returns a pointer to the key allocated or `NULL`, if the allocation failed.
 */
static
struct ext4_encryption_key*
key_list_alloc_key(
        struct key_list* list ///< key list in which to allocate a key
) {
    size_t current_pos = list->count;
    ++(list->count);

    // we resize whenever we hit a power of 2
    int need_resize = 1;
    for (size_t size = list->count; size > 1; size >>= 1)
        if (size & 1) {
            need_resize = 0;
            break;
        }

    if (need_resize) {
        // reallocate manually so we can clear the memory
        size_t old_size = sizeof(struct ext4_encryption_key) * list->count;
        struct ext4_encryption_key* tmp = malloc(old_size * 2);
        if (!tmp)
            return NULL;
        if (list->data == NULL) {
            list->data = tmp;
            return list->data + current_pos;
        }
        memcpy(tmp, list->data, old_size);
        memset(list->data, 0, old_size);
        free(list->data);
        list->data = tmp;
    }

    return list->data + current_pos;
}


/**
 * Pop a key from the stack
 */
static
void
key_list_pop(
        struct key_list* list ///< key list from which to pop a key
) {
    if (list->count > 0)
        --list->count;
}


/**
 * Cleanup function for keylists given to PAM
 *
 * This function destroys and frees a key-list.
 * Only use if the key list itself was allocated with `malloc()`
 */
static
void
key_list_pam_cleanup(
    pam_handle_t* pamh,
    void* data,
    int error_status
) {
    if (!data)
        return;
    key_list_destroy((struct key_list*) data);
    free(data);
}




/**
 * Salt to use for cryptographic purposes
 *
 * Salt is considered empty/void if `salt` or `salt_len` is 0.
 */
struct salt {
    unsigned char *salt; ///< pointer to the actual salt
    size_t salt_len; ///< length of the salt in bytes
};


/**
 * Parse a salt string
 *
 * @returns a salt parsed from the salt string
 *
 * Originally ripped from e4crypt
 */
static
struct salt
salt_parse(
    char *salt_str ///< salt string to parse
) {
    struct salt retval = {NULL, 0};

    // TODO: clean up! (e.g. by throwing out PARSE_FLAGS_FORCE_FN)
    unsigned char buf[EXT4_MAX_SALT_SIZE];
    char *cp = salt_str;
    int fd, ret, salt_len = 0;

    if (strncmp(cp, "s:", 2) == 0) {
        cp += 2;
        salt_len = strlen(cp);
        if (salt_len >= EXT4_MAX_SALT_SIZE)
            return retval;
        strncpy((char *) buf, cp, sizeof(buf));
    } else if (cp[0] == '/') {
    salt_from_filename:
        fd = open(cp, O_RDONLY | O_DIRECTORY);
        if (fd == -1 && errno == ENOTDIR)
            fd = open(cp, O_RDONLY);
        if (fd == -1)
            return retval;
        ret = ioctl(fd, EXT4_IOC_GET_ENCRYPTION_PWSALT, &buf);
        close(fd);
        if (ret < 0)
            return retval;

        salt_len = 16;
    } else if (strncmp(cp, "f:", 2) == 0) {
        cp += 2;
        goto salt_from_filename;
    } else if (strncmp(cp, "0x", 2) == 0) {
        unsigned char *h, *l;

        cp += 2;
        if (strlen(cp) & 1)
            return retval;
        while (*cp) {
            if (salt_len >= EXT4_MAX_SALT_SIZE)
                return retval;
            h = memchr(hexchars, *cp++, hexchars_size);
            l = memchr(hexchars, *cp++, hexchars_size);
            if (!h || !l)
                return retval;
            buf[salt_len++] =
                (((unsigned char)(h - hexchars) << 4) +
                 (unsigned char)(l - hexchars));
        }
    } else if (uuid_parse(cp, buf) == 0) {
        salt_len = 16;
    } else
        return retval;

    retval.salt = malloc(salt_len);
    if (retval.salt) {
        memcpy(retval.salt, buf, salt_len);
        retval.salt_len = salt_len;
    }

    memset(buf, 0, sizeof(buf));

    return retval;
}


/**
 * Free all resources associated with a salt
 */
static
void
salt_destroy(
        struct salt* salt ///< salt to destroy
) {
    memset(salt->salt, 0, salt->salt_len);
    free(salt->salt);
    salt->salt = NULL;
    salt->salt_len = 0;
}




/**
 * Supposed pbkdf2_sha512 implementation
 *
 * Originally ripped from e4crypt
 */
static
int
pbkdf2_sha512(
        const char *passphrase, ///< passphrase to encode
        struct salt *salt, ///< salt to use for encoding
        unsigned int count, ///< count of cycles to perform
        unsigned char derived_key[EXT4_MAX_KEY_SIZE] ///< output
) {
    // TODO: maybe "clean up"?
    size_t passphrase_size = strlen(passphrase);
    unsigned char buf[SHA512_LENGTH + EXT4_MAX_PASSPHRASE_SIZE] = {0};
    unsigned char tempbuf[SHA512_LENGTH] = {0};
    char final[SHA512_LENGTH] = {0};
    unsigned char saltbuf[EXT4_MAX_SALT_SIZE + EXT4_MAX_PASSPHRASE_SIZE] = {0};
    int actual_buf_len = SHA512_LENGTH + passphrase_size;
    int actual_saltbuf_len = EXT4_MAX_SALT_SIZE + passphrase_size;
    unsigned int x, y;
    __u32 *final_u32 = (__u32 *)final;
    __u32 *temp_u32 = (__u32 *)tempbuf;

#if 0
    // TODO: error out properly
    if (passphrase_size > EXT4_MAX_PASSPHRASE_SIZE) {
        printf("Passphrase size is %zd; max is %d.\n", passphrase_size,
               EXT4_MAX_PASSPHRASE_SIZE);
        exit(1);
    }
    if (salt->salt_len > EXT4_MAX_SALT_SIZE) {
        printf("Salt size is %zd; max is %d.\n", salt->salt_len,
               EXT4_MAX_SALT_SIZE);
        exit(1);
    }
    assert(EXT4_MAX_KEY_SIZE <= SHA512_LENGTH);
#endif

    memcpy(saltbuf, salt->salt, salt->salt_len);
    memcpy(&saltbuf[EXT4_MAX_SALT_SIZE], passphrase, passphrase_size);

    memcpy(&buf[SHA512_LENGTH], passphrase, passphrase_size);

    for (x = 0; x < count; ++x) {
        if (x == 0) {
            SHA512(saltbuf, actual_saltbuf_len, tempbuf);
        } else {
            /*
             * buf: [previous hash || passphrase]
             */
            memcpy(buf, tempbuf, SHA512_LENGTH);
            SHA512(buf, actual_buf_len, tempbuf);
        }
        for (y = 0; y < (sizeof(final) / sizeof(*final_u32)); ++y)
            final_u32[y] = final_u32[y] ^ temp_u32[y];
    }

    memcpy(derived_key, final, EXT4_MAX_KEY_SIZE);

    memset(buf, 0, sizeof(buf));
    memset(tempbuf, 0, sizeof(tempbuf));
    memset(final, 0, sizeof(final));
    memset(saltbuf, 0, sizeof(saltbuf));

    return PAM_SUCCESS;
}


/**
 * Generate a ref string from a key
 *
 * Originally ripped from e4crypt
 */
static
void
generate_key_ref_str(
        char* key_ref_str, //!< output pointer
        struct ext4_encryption_key* key //!< key for which to generate the ref
) {
    // TODO: maybe "clean up"?
    unsigned char key_ref1[SHA512_LENGTH];
    unsigned char key_ref2[SHA512_LENGTH];
    unsigned char key_desc[EXT4_KEY_DESCRIPTOR_SIZE];
    int x;

    SHA512(key->raw, EXT4_MAX_KEY_SIZE, key_ref1);
    SHA512(key_ref1, SHA512_LENGTH, key_ref2);
    memcpy(key_desc, key_ref2, EXT4_KEY_DESCRIPTOR_SIZE);
    for (x = 0; x < EXT4_KEY_DESCRIPTOR_SIZE; ++x) {
        sprintf(&key_ref_str[x * 2], "%02x", key_desc[x]);
    }
    key_ref_str[EXT4_KEY_REF_STR_BUF_SIZE - 1] = '\0';

    memset(key_ref1, 0, sizeof(key_ref1));
    memset(key_ref2, 0, sizeof(key_ref2));
    memset(key_desc, 0, sizeof(key_desc));
}

/**
 * Generate a key and store it into the list
 */
static
void
generate_key(
        int pam_flags,
        char* salt_data,
        char* auth_token,
        struct key_list* keys
) {
    int flags = pam_flags;
    int retval = 0;
    struct salt salt = salt_parse(salt_data);
    if (!salt.salt) {
        pam_log(LOG_WARNING, "Invalid salt data '%s'", salt_data);
        return;
    }
    struct ext4_encryption_key* key = key_list_alloc_key(keys);
    if (!key) {
        pam_log(LOG_WARNING, "Could not allocate space for key!");
        goto free_salt;
    }
    key->mode = EXT4_ENCRYPTION_MODE_AES_256_XTS;
    key->size = EXT4_MAX_KEY_SIZE;

    pam_log(LOG_NOTICE, "Generating key for salt_data '%s'", salt_data);
    retval = pbkdf2_sha512(auth_token, &salt, EXT4_PBKDF2_ITERATIONS, key->raw);
    if (retval != PAM_SUCCESS)
        goto free_salt;

    // avoid duplicates in the key list
    {
        struct ext4_encryption_key* current_key = key;
        while (current_key-- > keys->data)
            if (memcmp(current_key, key, sizeof(*key)) == 0) {
                key_list_pop(keys);
                pam_log(LOG_NOTICE, "Found duplicate key");
                goto free_salt;
            }
    }

free_salt:
    salt_destroy(&salt);
}

/**
 * Read salt_data from file.
 */
static
char*
read_salt_data(
        char* path
) {
    char* result = NULL;
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        return result;
    }
    char buf[EXT4_MAX_SALT_SIZE + 2];
    int nb = read(fd, buf, sizeof(buf));
    close(fd);
    if (nb >= 0) {
        result = malloc(nb + 1);
        memcpy(result, buf, nb);
        result[nb] = '\0';
        memset(buf, 0, sizeof(buf));
    }
    return result;
}


// PAM authentication module implementations


/**
 * Implementation `pam_sm_authenticate` for this module
 *
 * This function actually doesn't do any authentication but instead generates
 * keys from the password.
 * Those keys are stored PAM-internally, so they can later be applied during
 * the session setup.
 */
PAM_EXTERN
int
pam_sm_authenticate(
        pam_handle_t* pamh, ///< pam handle
        int flags, ///< flags
        int argc, ///< number of arguments passed to the module
        const char** argv ///< arguments passed to the module
) {
    int retval;

    char* auth_token = NULL;
    retval = pam_get_item(pamh, PAM_AUTHTOK, (const void**) &auth_token);
    if ((retval != PAM_SUCCESS) || !auth_token) {
        pam_log(LOG_ERR, "Failed to get auth token!");
        return PAM_AUTH_ERR;
    }

    // we will use a key list for carrying the keys from the authentication
    // phase to the session setup phase
    struct key_list* keys = malloc(sizeof(*keys));
    if (!keys) {
        pam_log(LOG_ERR, "Failed to allocate memory for the key list!");
        return PAM_AUTH_ERR;
    }
    key_list_init(keys);
    pam_set_data(pamh, PAM_E4CRYPT_KEY_DATA, keys, key_list_pam_cleanup);

    // First read a salt define in a fixed place in the HOME directory
    const char *username;
    retval = pam_get_item(pamh, PAM_USER, (void*) &username);
    if (retval != PAM_SUCCESS)
        return retval;
    struct passwd const* pw = pam_modutil_getpwnam(pamh, username);
    if (!pw) {
        pam_log(LOG_ERR, "error looking up user");
        return PAM_USER_UNKNOWN;
    }
    char path[PATH_MAX];
    snprintf(path, PATH_MAX, "%s/%s", pw->pw_dir, ".ext4_encryption_salt");
    char* salt_data = read_salt_data(path);
    if (salt_data) {
        generate_key(flags, salt_data, auth_token, keys);
        free(salt_data);
    }

    // We have to generate a policy for each ext4 file system availible.
    // Hence, we iterate over all mounted file systems and create a policy for
    // each ext4 fs we find.
    FILE* f = setmntent("/etc/mtab", "r");
    struct mntent *mnt;
    while (f && ((mnt = getmntent(f)) != NULL)) {
        if (strcmp(mnt->mnt_type, "ext4") || access(mnt->mnt_dir, R_OK))
            continue;
       generate_key(flags, mnt->mnt_dir, auth_token, keys);
    }
    endmntent(f);

    return PAM_SUCCESS;
}


/**
 * Implementation `pam_sm_setcred` for this module
 *
 * Dummy to make PAM happy.
 */
PAM_EXTERN
int
pam_sm_setcred(
        pam_handle_t* pamh, ///< pam handle
        int flags, ///< flags
        int argc, ///< number of arguments passed to the module
        const char** argv ///< arguments passed to the module
) {
    return PAM_SUCCESS;
}




// PAM session module implementations


/**
 * Implementation `pam_sm_open_session` for this module
 *
 * Retrieves the keys previously generated in the authentication stage and adds
 * them to the session keyring.
 */
PAM_EXTERN
int
pam_sm_open_session(
        pam_handle_t* pamh, ///< pam handle
        int flags, ///< flags
        int argc, ///< number of arguments passed to the module
        const char** argv ///< arguments passed to the module
) {
    int retval;

    // parse arguments passed to the module on the session line
    for (int i = 0; i < argc; ++i) {
        pam_log(LOG_WARNING, "Unknown option for open_session: %s", argv[i]);
    }

    // get the keys we are about to insert
    struct key_list* keys = NULL;
    retval = pam_get_data(pamh, PAM_E4CRYPT_KEY_DATA, (const void**) &keys);
    if ((retval != PAM_SUCCESS) || !keys) {
        pam_log(LOG_ERR, "Failed to retrieve key list!");
        return PAM_SESSION_ERR;
    }

    const char *username;
    retval = pam_get_item(pamh, PAM_USER, (void*) &username);
    if (retval != PAM_SUCCESS)
        return retval;

    struct passwd const* pw = pam_modutil_getpwnam(pamh, username);
    if (!pw) {
        pam_log(LOG_ERR, "error looking up user");
        return PAM_USER_UNKNOWN;
    }

    // We need to switch the real UID and GID to find the user session keyring.
    // We also need to switch the FS UID and GID so the keys end up with the
    // correct permission.
    uid_t old_uid = getuid();
    uid_t old_gid = getgid();

    if ((old_gid != pw->pw_gid) && (retval = setregid(pw->pw_gid, -1)) < 0) {
        pam_log(LOG_ERR, "Could not set GID: %s", strerror(errno));
        return PAM_SESSION_ERR;
    }

    if ((old_uid != pw->pw_uid) && (retval = setreuid(pw->pw_uid, -1) < 0)) {
        pam_log(LOG_ERR, "Could not set UID: %s", strerror(errno));
        goto reset_gid;
    }

    if ((old_gid != pw->pw_gid) && (retval = setfsgid(pw->pw_gid)) < 0) {
        pam_log(LOG_ERR, "Could not set FS GID: %s", strerror(errno));
        goto reset_uid;
    }

    if ((old_uid != pw->pw_uid) && (retval = setfsuid(pw->pw_uid) < 0)) {
        pam_log(LOG_ERR, "Could not set FS UID: %s", strerror(errno));
        goto reset_fsgid;
    }

    struct ext4_encryption_key* ext4_key = keys->data + keys->count;
    while (ext4_key-- > keys->data) {
        char key_ref_str[EXT2FS_KEY_DESC_PREFIX_SIZE + EXT4_KEY_REF_STR_BUF_SIZE];
        strcpy(key_ref_str, EXT2FS_KEY_DESC_PREFIX);
        generate_key_ref_str(key_ref_str + EXT2FS_KEY_DESC_PREFIX_SIZE,
                ext4_key);
        pam_log(LOG_NOTICE, "Inserting key with reference %s as %d:%d",
                key_ref_str, pw->pw_uid, pw->pw_gid);

        key_serial_t key = add_key(EXT2FS_KEY_TYPE_LOGON, key_ref_str,
                ext4_key, sizeof(*ext4_key), KEY_SPEC_SESSION_KEYRING);
        if (key < 0) {
            pam_log(LOG_ERR, "Could not add key: %s", strerror(errno));
            continue;
        }
    }

    if ((old_uid != pw->pw_uid) && (retval = setfsuid(old_uid) < 0))
        pam_log(LOG_ERR, "Could not set GID: %s", strerror(errno));

reset_fsgid:
    if ((old_gid != pw->pw_gid) && (retval = setfsgid(old_gid)) < 0)
        pam_log(LOG_ERR, "Could not set UID: %s", strerror(errno));

reset_uid:
    if ((old_uid != pw->pw_uid) && (retval = setreuid(old_uid, -1) < 0))
        pam_log(LOG_ERR, "Could not set GID: %s", strerror(errno));

reset_gid:
    if ((old_gid != pw->pw_gid) && (retval = setregid(old_gid, -1)) < 0)
        pam_log(LOG_ERR, "Could not set UID: %s", strerror(errno));

    return retval;
}


/**
 * Implementation `pam_sm_close_session` for this module
 *
 * Dummy to make PAM happy.
 */
PAM_EXTERN
int
pam_sm_close_session(
        pam_handle_t* pamh, ///< pam handle
        int flags, ///< flags
        int argc, ///< number of arguments passed to the module
        const char** argv ///< arguments passed to the module
) {
    return PAM_SUCCESS;
}


