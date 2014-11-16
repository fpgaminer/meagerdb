#include <string.h>
#include <meagerdb/meagerdb.h>
#include <meagerdb/keyvalue.h>
#include "basic_packing.h"
#include <meagerdb/app.h>
#include "util.h"


static bool is_empty_key (uint8_t const key[static MDBK_KEY_LEN])
{
	uint8_t const *ptr = key;

	for (size_t i = MDBK_KEY_LEN; i; --i, ++ptr)
	{
		if (ptr[0])
			return false;
	}

	return true;
}


_Static_assert (MDBK_KEY_LEN < (0xFFFFFFFF-4), "MDBK_KEY_LEN too big.");

int mdbk_update (MDB *db, MDBK_UPDATE_ENTRY const *updates, size_t update_count)
{
	int err;
	uint8_t buf[MAX (32, MDBK_KEY_LEN + 4)];
	uint32_t offset = 0;
	uint32_t valuelen;

	/* Calculate total length of updated data */
	uint32_t total_len = (MDBK_KEY_LEN+4) * update_count;

	for (size_t i = 0, count = update_count; count; ++i, --count)
	{
		if (is_empty_key (updates[i].key))
			return MDBE_BAD_ARGUMENT;

		if (total_len + updates[i].valuelen < total_len)
			return MDBE_DATA_TOO_BIG;
		
		total_len += updates[i].valuelen;
	}

	while (1)
	{
		bool updated = false;

		if ((err = mdb_read_value (db, buf, offset, MDBK_KEY_LEN+4)))
			return err;

		if (is_empty_key (buf))
		{
			if ((total_len + MDBK_KEY_LEN + 4) < total_len)
				return MDBE_DATA_TOO_BIG;
			break;
		}

		valuelen = unpack_uint32_little (buf+MDBK_KEY_LEN);

		if ((valuelen + MDBK_KEY_LEN + 4) < valuelen)
			return -1;

		valuelen += MDBK_KEY_LEN + 4;
		
		if ((offset + valuelen) < offset)
			return -1;

		offset += valuelen;

		for (size_t i = 0, count = update_count; count; ++i, --count)
		{
			if (!memcmp (buf, updates[i].key, MDBK_KEY_LEN))
			{
				updated = true;
				break;
			}
		}

		if (!updated)
		{
			if ((total_len + valuelen) < total_len)
				return MDBE_DATA_TOO_BIG;

			total_len += valuelen;
		}
	}

	/* Begin updating row */
	if ((err = mdb_update_begin (db, total_len)))
		return err;

	/* Copy new key-value pairs */
	for (size_t i = 0, count = update_count; count; ++i, --count)
	{
		memmove (buf, updates[i].key, MDBK_KEY_LEN);
		pack_uint32_little (buf+MDBK_KEY_LEN, updates[i].valuelen);

		if ((err = mdb_update_continue (db, buf, MDBK_KEY_LEN + 4)))
			return err;

		if (!updates[i].value)
			continue;

		if ((err = mdb_update_continue (db, updates[i].value, updates[i].valuelen)))
			return err;
	}

	/* Copy existing key-value pairs that aren't overwritten */
	offset = 0;

	while (1)
	{
		bool updated = false;

		if ((err = mdb_read_value (db, buf, offset, MDBK_KEY_LEN+4)))
			return err;

		if (is_empty_key (buf))
		{
			/* Write terminator */
			if ((err = mdb_update_continue (db, buf, MDBK_KEY_LEN+4)))
				return err;
			break;
		}

		valuelen = unpack_uint32_little (buf+MDBK_KEY_LEN);

		if ((valuelen + MDBK_KEY_LEN + 4) < valuelen)
			return -1;

		valuelen += MDBK_KEY_LEN + 4;
		
		if ((offset + valuelen) < offset)
			return -1;

		for (size_t i = 0, count = update_count; count; ++i, --count)
		{
			if (!memcmp (buf, updates[i].key, MDBK_KEY_LEN))
			{
				updated = true;
				break;
			}
		}

		if (updated)
		{
			offset += valuelen;
			continue;
		}
		
		for (uint32_t remaining = valuelen; remaining; )
		{
			uint32_t l = MIN (remaining, sizeof (buf));

			if ((err = mdb_read_value (db, buf, offset, l)))
				return err;

			if ((err = mdb_update_continue (db, buf, l)))
				return err;

			remaining -= l;
			offset += l;
		}
	}

	/* Finalize */
	if ((err = mdb_update_finalize (db)))
		return err;

	return 0;
}


int64_t mdbk_get_value (MDB *db, void *dst, uint8_t const key[static MDBK_KEY_LEN], size_t maxlen)
{
	int err;
	uint32_t offset = 0;
	uint32_t valuelen;
	uint8_t buf[MDBK_KEY_LEN+4];

	while (1)
	{
		if ((err = mdb_read_value (db, buf, offset, MDBK_KEY_LEN+4)))
			return err;

		if (is_empty_key (buf))
			return 0;

		valuelen = unpack_uint32_little (buf+MDBK_KEY_LEN);

		if ((offset + MDBK_KEY_LEN + 4) < offset)
			return -1;

		offset += MDBK_KEY_LEN + 4;

		if (!memcmp (buf, key, MDBK_KEY_LEN))
		{
			if (dst)
			{
				if (valuelen > maxlen)
					return MDBE_DATA_TOO_BIG;

				if ((err = mdb_read_value (db, dst, offset, valuelen)))
					return err;
			}

			return valuelen;
		}

		if ((offset + valuelen) < offset)
			return -1;

		offset += valuelen;
	}
}


int mdbk_read_key (MDB *db, uint8_t dst[static MDBK_KEY_LEN], uint32_t idx)
{
	int err;
	uint32_t offset = 0;
	uint32_t valuelen;
	uint8_t buf[MDBK_KEY_LEN+4];

	for (uint32_t current_idx = 0; ; ++current_idx)
	{
		if ((err = mdb_read_value (db, buf, offset, MDBK_KEY_LEN+4)))
			return err;

		if (is_empty_key (buf))
			return MDBE_NOT_FOUND;

		valuelen = unpack_uint32_little (buf+MDBK_KEY_LEN);

		if ((offset + MDBK_KEY_LEN + 4) < offset)
			return -1;

		offset += MDBK_KEY_LEN + 4;

		if ((offset + valuelen) < offset)
			return -1;

		offset += valuelen;

		if (current_idx == idx)
		{
			memmove (dst, buf, MDBK_KEY_LEN);
			return 0;
		}
	}
}


int mdbk_get_uint32 (MDB *db, uint32_t *dst, uint8_t const key[static MDBK_KEY_LEN])
{
	int64_t err;
	uint8_t buf[4];

	if ((err = mdbk_get_value (db, buf, key, 4)) < 0)
		return (int)err;

	if (err != 4)
		return MDBE_BAD_TYPE;

	*dst = unpack_uint32_little (buf);

	return 0;
}
