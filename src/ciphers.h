#ifndef __CIPHERS_H__
#define __CIPHERS_H__

#include <stdint.h>
#include <stddef.h>

#define MDBC_CIPHERSUITE "Threefish-512:SHA-256:HMAC"
#define MDBC_ENCRYPTION_BLOCK_SIZE 64

#define MDBC_KDF "PBKDF2-HMAC-SHA-256"


/* Size of MAC tag and HASH tag is fixed at 32 bytes.
 * If the ciphersuite uses less, just pad/ignore.
 * If the ciphersuite uses more, why are your tags so big!?
 */


/* 
 * `location` should be the byte position of the data in the database file.  We use it as part of the encryption
 * tweak.
 * Must be able to *crypt in-place.
 * `keys` is a chunk of bytes containing both the encryption and mac keys.  It is up to the ciphersuite
 * implementation to decide how to split them up.  e.g. in Threefish-512:SHA-256:HMAC the first
 * 64 bytes is the encryption key, and the remaining 64 bytes is the mac key. So these functions
 * would only use the first 64 bytes, and the mac function would only use the last 64 bytes of `keys`.
 */
void mdbc_encrypt (void *dst, uint8_t const keys[static 128], void const *src, size_t len, uint64_t location);
void mdbc_decrypt (void *dst, uint8_t const keys[static 128], void const *src, size_t len, uint64_t location);


void mdbc_mac (void *dst, uint8_t const keys[128], void const *src, size_t len);


/* 
 * It's up the ciphersuite implementation to interpret params.  For example, PBKDF2 would only use a few bytes
 * to determine the iteration count, and ignore the rest of the data.
 */
void mdbc_kdf (void *derived_key, void const *password, size_t password_len, void const *salt, size_t salt_len, uint8_t const params[static 32], size_t derived_len);


void mdbc_hash (void *dst, void const *message, size_t message_len);

#endif
