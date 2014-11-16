#include "ciphers.h"
#include <strong-arm/hmac.h>
#include <strong-arm/threefish.h>
#include <strong-arm/pbkdf2.h>
#include <strong-arm/sha256.h>
#include <meagerdb/app.h>
#include "basic_packing.h"


void mdbc_encrypt (void *dst, uint8_t const keys[static 128], void const *src, size_t len, uint64_t location)
{
	uint8_t tweak[16] = {0};
	uint32_t block_num = 0;

	if ((len & 63) != 0)
		mdba_fatal_error ();

	if ((len >> 6) >= 0xFFFFFFFF)
		mdba_fatal_error ();

	// Calculate initial tweak
	pack_uint64_little (tweak, location);

	// Encrypt blocks
	for (size_t remaining = len >> 6; remaining; --remaining)
	{
		pack_uint32_little (tweak+8, block_num);
		threefish512_encrypt_block (dst, keys, tweak, src);

		block_num += 1;
		src = (uint8_t const *)src + 64;
		dst = (uint8_t *)dst + 64;
	}
}


void mdbc_decrypt (void *dst, uint8_t const keys[static 128], void const *src, size_t len, uint64_t location)
{
	uint8_t tweak[16] = {0};
	uint32_t block_num = 0;

	if ((len & 63) != 0)
		mdba_fatal_error ();

	if ((len >> 6) >= 0xFFFFFFFF)
		mdba_fatal_error ();

	// Calculate initial tweak
	pack_uint64_little (tweak, location);

	// Encrypt blocks
	for (uint32_t remaining = len >> 6; remaining; --remaining)
	{
		pack_uint32_little (tweak+8, block_num);
		threefish512_decrypt_block (dst, keys, tweak, src);

		block_num += 1;
		src = (uint8_t const *)src + 64;
		dst = (uint8_t *)dst + 64;
	}
}


void mdbc_mac (void *dst, uint8_t const keys[128], void const *src, size_t len)
{
	if (len > 0xffffffff)
		mdba_fatal_error ();

	HMAC (dst, keys + 64, 64, src, (uint32_t)len);
}


void mdbc_kdf (void *derived_key, void const *password, size_t password_len, void const *salt, size_t salt_len, uint8_t const params[static 32], size_t derived_len)
{
	if (password_len > 0xffffffff || salt_len > 0xffffffff)
		mdba_fatal_error ();

	uint64_t iterations = unpack_uint64_little (params);

	if (iterations > 0xffffffff)
		mdba_fatal_error ();

	PBKDF2 (derived_key, password, (uint32_t)password_len, salt, (uint32_t)salt_len, (uint32_t)iterations, derived_len);
}


void mdbc_hash (void *dst, void const *message, size_t message_len)
{
	if (message_len > 0xffffffff)
		mdba_fatal_error ();

	SHA256 (dst, message, (uint32_t)message_len);
}
