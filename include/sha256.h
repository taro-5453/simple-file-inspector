#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>

#define SHA256_DIGEST_LEN 32
#define SHA256_HEX_LEN 64  /* hex characters, excluding the NUL */

/* Computes the SHA-256 digest (FIPS 180-4) of data[0..len) in one shot.
 * data may be NULL when len is 0 (the well-defined empty-input digest). */
void sha256(const unsigned char *data, size_t len,
            unsigned char digest[SHA256_DIGEST_LEN]);

/* Formats a digest as 64 lowercase hex characters plus a NUL terminator.
 * out must have room for SHA256_HEX_LEN + 1 bytes. */
void sha256_hex(const unsigned char digest[SHA256_DIGEST_LEN],
                char out[SHA256_HEX_LEN + 1]);

#endif
