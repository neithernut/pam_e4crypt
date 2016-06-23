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
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <syslog.h>

// ext4 specific includes
#include <ext2fs/ext2_fs.h>
#include <ext2fs/ext2fs.h>

// library includes
#include <uuid/uuid.h>

// PAM includes
#include <security/pam_modules.h>


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
        struct ext4_encryption_key* tmp;
        tmp = realloc(list->data, sizeof(struct ext4_encryption_key) * list->count * 2);
        if (!tmp)
            return NULL;
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
    free(salt->salt);
    salt->salt = NULL;
    salt->salt_len = 0;
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
    // TODO: get the authentication token
    // TODO: create a key for each salt
    // TODO: expose key list

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
    // TODO: get key list
    // TODO: add keys to the session keyring

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


