#ifndef __MEAGERDB_KEYVALUE_H__
#define __MEAGERDB_KEYVALUE_H__

#include <stdint.h>


#define MDBK_KEY_LEN 8


typedef struct
{
	uint8_t const *key;
	uint32_t valuelen;
	void const *value;
} MDBK_UPDATE_ENTRY;


/* 
 * Update the currently selected row using a list of key-value updates.
 */
int mdbk_update (MDBK_UPDATE_ENTRY const *updates, size_t update_count);


/* 
 * Read the value associated with 'key' into 'dst'.  Will return an error if 'maxlen' would
 * be violated.
 *
 * 'dst' may be NULL, so that this function can be used to just get the value's length.
 *
 * Returns 0 if the 'key' does not exist.
 *
 * Returns length of data written, or negative on error.
 */
int64_t mdbk_get_value (void *dst, uint8_t const key[static MDBK_KEY_LEN], size_t maxlen);


/*
 * Reads the 'idx'th key from the currently selected row.
 */
int mdbk_read_key (uint8_t dst[static MDBK_KEY_LEN], uint32_t idx);


/* The following are helpful functions that use mdbk_read_value, but parse the result into
 * a type.
 */
int mdbk_get_uint32 (uint32_t *dst, uint8_t const key[static MDBK_KEY_LEN]);

#endif
