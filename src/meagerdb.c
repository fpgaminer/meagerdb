#include <meagerdb/meagerdb.h>
#include <meagerdb/app.h>
#include "ciphers.h"
#include "basic_packing.h"
#include "util.h"
#include <string.h>
#include <sys/unistd.h>
#include <stddef.h>
#include <fcntl.h>


#define JOURNAL0  0
#define JOURNAL1  1
#define FIRST_PAGE 2

#define ERROR_AND_CLOSE_IF(cond,err) if ((cond)) { mdb_close (db); return (err); }
#define CLOSE_AND_ERROR(err) {mdb_close (db); return (err); }


/* mdb_create and mdb_open depend on these structs, so update those if the data structures change. */
typedef struct __attribute__ ((__packed__)) {
	uint8_t magic[8];
	uint8_t version[2];
	uint8_t page_size[4];
	uint8_t db_id[32];
	uint8_t ciphersuite[32];
	uint8_t hash[32];
} RAW_HEADER;

_Static_assert (sizeof (RAW_HEADER) == (8+2+4+32+32+32), "Struct packing failed");

typedef struct __attribute__ ((__packed__)) {
	uint8_t salt[64];
	uint8_t kdf[32];
	uint8_t kdf_params[32];
	uint8_t keys[128];
	uint8_t mac[32];
	uint8_t hash[32];
} RAW_PARAMS;

_Static_assert (sizeof (RAW_PARAMS) == (64+32+32+128+32+32), "Struct packing failed");


/* We consume one buffer of this size.
 */

_Static_assert (MDB_DEFAULT_PAGE_SIZE <= MDB_MAX_PAGE_SIZE, "MDB_DEFAULT_PAGE_SIZE must be smaller than MDB_MAX_PAGE_SIZE.");

/* These are needed for mdb_create and mdb_open */
_Static_assert (MDB_TMP_SIZE >= sizeof (RAW_HEADER), "MDB_MAX_PAGE_SIZE is too small.");
_Static_assert (MDB_TMP_SIZE >= (sizeof (RAW_PARAMS)+32), "MDB_MAX_PAGE_SIZE is too small.");

/* Necessary to encrypt the key material. */
_Static_assert ((128 % MDBC_ENCRYPTION_BLOCK_SIZE) == 0, "128 must be a multiple of MDBC_ENCRYPTION_BLOCK_SIZE.");


/* Private Prototypes */
static int cleanup_journal (MDB *db);
static int set_journal (MDB *db, int journal, uint32_t page_start, uint32_t page_count);
static int write_page (MDB *db, uint32_t page);



int mdb_create (MDB *db, char const *path, uint8_t const *password, size_t password_len, uint64_t iteration_count)
{
	int err;
	const uint32_t page_size = MDB_DEFAULT_PAGE_SIZE;
	uint8_t header_hash[32];
	uint8_t derived_keys[128];
	const uint32_t header_len = roundup_uint32 (sizeof (RAW_HEADER), page_size);
	const uint32_t params_len = roundup_uint32 (sizeof (RAW_PARAMS), page_size);

	if (strlen (MDBC_CIPHERSUITE) > 32 || strlen (MDBC_KDF) > 32)
		mdba_fatal_error ();

	if (db->fd)
		return MDBE_ALREADY_OPEN;

	memset (db, 0, sizeof (MDB));

	/* Open database file */
	if ((db->fd = mdba_open (path, O_RDWR | O_CREAT | O_EXCL)) == -1)
	{
		db->fd = 0;
		return MDBE_OPEN;
	}

	db->page_size = page_size;
	db->page_offset = header_len + 2 * params_len;
	db->real_page_size = (db->page_size - 32) / MDBC_ENCRYPTION_BLOCK_SIZE;
	db->real_page_size *= MDBC_ENCRYPTION_BLOCK_SIZE;

	/* Generate Encryption Keys */
	mdba_read_urandom (db->keys, 128);

	/* Database Header */
	RAW_HEADER *header = (RAW_HEADER *)(db->tmp);

	memset (header, 0, sizeof (RAW_HEADER));
	memmove (header->magic, "MEAGERDB", 8);                                       /* Magic */
	pack_uint16_little (header->version, 0x0100);                                 /* Version */
	pack_uint32_little (header->page_size, db->page_size);                        /* Page Size */
	mdba_read_urandom (header->db_id, 32);                                        /* Unique ID */
	memmove (header->ciphersuite, MDBC_CIPHERSUITE, strlen (MDBC_CIPHERSUITE));   /* Ciphersuite */
	mdbc_hash (header_hash, header, sizeof (RAW_HEADER)-32);

	ERROR_AND_CLOSE_IF (mdba_write (db->fd, header, sizeof (RAW_HEADER)-32), MDBE_IO);
	ERROR_AND_CLOSE_IF (mdba_write (db->fd, header_hash, 32), MDBE_IO);

	/* Header Padding */
	/* This is safe, because tmp is at least big enough to fit a page, and padding will never
	 * be more than one page. */
	memset (db->tmp, 0, header_len - sizeof (RAW_HEADER));
	ERROR_AND_CLOSE_IF (mdba_write (db->fd, db->tmp, header_len - sizeof (RAW_HEADER)), MDBE_IO);

	/* Encryption Parameters */
	RAW_PARAMS *params = (RAW_PARAMS *)(db->tmp + 32);
	memmove (db->tmp, header_hash, 32);   /* Not part of params, but used to calculate MAC */

	memset (params, 0, sizeof (RAW_PARAMS));
	mdba_read_urandom (params->salt, sizeof (params->salt));    /* Password Salt */
	memmove (params->kdf, MDBC_KDF, strlen (MDBC_KDF));         /* Key Derivation Function */
	pack_uint64_little (params->kdf_params, iteration_count);   /* Key Derivation Parameters */
	memmove (params->keys, db->keys, 128);                      /* Keys */
	
	/* Derived Keys */
	mdbc_kdf (derived_keys, password, password_len, params->salt, sizeof (params->salt), params->kdf_params, sizeof (derived_keys));

	/* Encrypt Real Keys */
	mdbc_encrypt (params->keys, derived_keys, params->keys, 128, header_len + offsetof (RAW_PARAMS, keys));

	/* MAC and HASH */
	mdbc_mac (params->mac, derived_keys, db->tmp, 32 + sizeof (RAW_PARAMS) - 64);
	mdbc_hash (params->hash, params, sizeof (RAW_PARAMS) - 32);

	ERROR_AND_CLOSE_IF (mdba_write (db->fd, params, sizeof (RAW_PARAMS)), MDBE_IO);

	/* Pad previous Encryption Parameters block, and write a blank second EP block. */
	/* This is safe, because tmp is at least big enough to fit a page, and padding will never
	 * be more than one page.  EP block will never be larger than tmp either. */
	memset (db->tmp, 0, sizeof (db->tmp));
	ERROR_AND_CLOSE_IF (mdba_write (db->fd, db->tmp, params_len - sizeof (RAW_PARAMS)), MDBE_IO);
	ERROR_AND_CLOSE_IF (mdba_write (db->fd, db->tmp, sizeof (RAW_PARAMS)), MDBE_IO);
	ERROR_AND_CLOSE_IF (mdba_write (db->fd, db->tmp, params_len - sizeof (RAW_PARAMS)), MDBE_IO);

	/* Write Journals (blank) */
	memset (db->tmp, 0, db->page_size);
	ERROR_AND_CLOSE_IF (mdba_write (db->fd, db->tmp, db->page_size), MDBE_IO);
	ERROR_AND_CLOSE_IF (mdba_write (db->fd, db->tmp, db->page_size), MDBE_IO);

	/* Write row terminator */
	memset (db->tmp, 0, db->page_size);
	ERROR_AND_CLOSE_IF (err = write_page (db, 2), err);

	/* Sync and close */
	ERROR_AND_CLOSE_IF (mdba_fsync (db->fd), MDBE_IO);
	mdb_close (db);

	return 0;
}


int mdb_open (MDB *db, char const *path, uint8_t const *password, size_t password_len)
{
	int err;
	uint8_t calculated_mac[32];
	uint8_t derived_keys[128];

	/* Open database file */
	if (db->fd)
		return MDBE_ALREADY_OPEN;
	
	memset (db, 0, sizeof (MDB));

	if ((db->fd = mdba_open (path, O_RDWR)) == -1)
	{
		db->fd = 0;
		return MDBE_OPEN;
	}

	/* Read database header */
	RAW_HEADER *header = (RAW_HEADER *)(db->tmp);

	ERROR_AND_CLOSE_IF (mdba_read (db->fd, header, sizeof (RAW_HEADER)), MDBE_IO);

	/* Check and parse header */
	ERROR_AND_CLOSE_IF (memcmp (header->magic, "MEAGERDB", 8), MDBE_NOT_MDB);
	ERROR_AND_CLOSE_IF (unpack_uint16_little (header->version) != 0x0100, MDBE_BAD_VERSION);
	db->page_size = unpack_uint32_little (header->page_size);
	ERROR_AND_CLOSE_IF (memcmp (header->ciphersuite, MDBC_CIPHERSUITE, strlen (MDBC_CIPHERSUITE)), MDBE_UNSUPPORTED_CIPHER);

	/* Integrity check */
	mdbc_hash (calculated_mac, header, sizeof (RAW_HEADER) - 32);
	ERROR_AND_CLOSE_IF (memcmp (calculated_mac, header->hash, 32), MDBE_CORRUPT);

	/* Check if we can handle this DB */
	ERROR_AND_CLOSE_IF (db->page_size < 256, MDBE_BAD_PAGE_SIZE);
	ERROR_AND_CLOSE_IF ((db->page_size - 32) < MDBC_ENCRYPTION_BLOCK_SIZE, MDBE_BAD_PAGE_SIZE);
	ERROR_AND_CLOSE_IF (db->page_size > MDB_MAX_PAGE_SIZE, MDBE_UNSUPPORTED_PAGE_SIZE);

	db->real_page_size = (db->page_size - 32) / MDBC_ENCRYPTION_BLOCK_SIZE;
	db->real_page_size *= MDBC_ENCRYPTION_BLOCK_SIZE;
	const uint32_t header_len = roundup_uint32 (sizeof (RAW_HEADER), db->page_size);
	const uint32_t params_len = roundup_uint32 (sizeof (RAW_PARAMS), db->page_size);

	/* Look for valid encryption parameters */
	memmove (db->tmp, calculated_mac, 32);   /* Used for MAC below */
	RAW_PARAMS *params = (RAW_PARAMS *)(db->tmp+32);

	ERROR_AND_CLOSE_IF (mdba_lseek (db->fd, header_len - sizeof (RAW_HEADER), SEEK_CUR), MDBE_IO);
	ERROR_AND_CLOSE_IF (mdba_read (db->fd, params, sizeof (RAW_PARAMS)), MDBE_IO);

	mdbc_hash (calculated_mac, params, sizeof (RAW_PARAMS) - 32);

	if (secure_memcmp (params->hash, calculated_mac, 32))
	{
		ERROR_AND_CLOSE_IF (mdba_lseek (db->fd, params_len - sizeof (RAW_PARAMS), SEEK_CUR), MDBE_IO);
		ERROR_AND_CLOSE_IF (mdba_read (db->fd, params, sizeof (RAW_PARAMS)), MDBE_IO);

		mdbc_hash (calculated_mac, params, sizeof (RAW_PARAMS) - 32);

		ERROR_AND_CLOSE_IF (secure_memcmp (params->hash, calculated_mac, 32), MDBE_CORRUPT);
	}

	/* Check encryption parameters */
	ERROR_AND_CLOSE_IF (memcmp (params->kdf, MDBC_KDF, strlen (MDBC_KDF)), MDBE_BAD_KEY_DERIVE);

	/* Derive keys */
	mdbc_kdf (derived_keys, password, password_len, params->salt, sizeof (params->salt), params->kdf_params, sizeof (derived_keys));

	/* Authenticate header */
	mdbc_mac (calculated_mac, derived_keys, db->tmp, 32 + sizeof (RAW_PARAMS) - 64);

	ERROR_AND_CLOSE_IF (secure_memcmp (params->mac, calculated_mac, 32), MDBE_BAD_PASSWORD);

	/* Decrypt real keys */
	mdbc_decrypt (db->keys, derived_keys, params->keys, 128, header_len + offsetof (RAW_PARAMS, keys));

	/* Nuke key material from tmp */
	secure_memset (db->tmp, 0, sizeof (db->tmp));

	/* Additional DB parameters */
	db->page_offset = header_len + 2 * params_len;

	/* Cleanup Journal */
	ERROR_AND_CLOSE_IF (err = cleanup_journal (db), err);

	return 0;
}


/* Read specified page into db->tmp and set db->tmp_page accordingly. */
static int read_page (MDB *db, uint32_t page)
{
	if (!db->fd)
		return MDBE_NOT_OPEN;

	uint8_t calculated_mac[32];
	uint64_t pos = db->page_offset + (uint64_t)page * (uint64_t)(db->page_size);

	if (db->tmp_page == page && db->tmp_page != 0)
		return 0;

	db->tmp_page = 0;

	if (mdba_lseek (db->fd, pos, SEEK_SET))
		return MDBE_IO;
	
	if (mdba_read (db->fd, db->tmp, db->real_page_size + 32))
		return MDBE_IO;

	/* Move MAC so there's room for tweak */
	memmove (db->tmp + db->real_page_size + 8, db->tmp + db->real_page_size, 32);

	/* Concat tweak for MAC */
	pack_uint64_little (db->tmp + db->real_page_size, pos);

	/* Authenticate */
	mdbc_mac (calculated_mac, db->keys, db->tmp, db->real_page_size + 8);

	if (secure_memcmp (calculated_mac, db->tmp + db->real_page_size + 8, 32))
		return MDBE_CORRUPT;

	/* Decrypt */
	mdbc_decrypt (db->tmp, db->keys, db->tmp, db->real_page_size, pos);

	db->tmp_page = page;

	return 0;
}


/* Write db->tmp to the specified page */
static int write_page (MDB *db, uint32_t page)
{
	if (!db->fd)
		return MDBE_NOT_OPEN;

	uint64_t pos = db->page_offset + (uint64_t)page * (uint64_t)(db->page_size);

	db->tmp_page = 0;

	/* Encrypt */
	mdbc_encrypt (db->tmp, db->keys, db->tmp, db->real_page_size, pos);
	
	/* MAC */
	pack_uint64_little (db->tmp + db->real_page_size, pos);
	mdbc_mac (db->tmp + db->real_page_size + 8, db->keys, db->tmp, db->real_page_size + 8);
	memmove (db->tmp + db->real_page_size, db->tmp + db->real_page_size + 8, 32);

	/* Write */
	if (mdba_lseek (db->fd, pos, SEEK_SET))
		return MDBE_IO;

	if (mdba_write (db->fd, db->tmp, db->real_page_size + 32))
		return MDBE_IO;

	/* Padding, if necessary.
 	 * Re-use tmp; blanking tmp would just cost extra cycles, and there is no risk. */
	if (mdba_write (db->fd, db->tmp, db->page_size - db->real_page_size - 32))
		return MDBE_IO;

	if (mdba_fsync (db->fd))
		return MDBE_IO;

	return 0;
}


static int cleanup_journal (MDB *db)
{
	int err;
	uint32_t page_start, page_count;

	/* Check Journal 1 */
	err = read_page (db, 1);
	page_start = unpack_uint32_little (db->tmp);
	page_count = unpack_uint32_little (db->tmp + 4);

	if (err == 0 && page_count != 0)
	{
		/* Must point to a row */
		if (page_start < FIRST_PAGE)
			return -1;

		/* Journal 1 is valid, execute it */
		/* Nuke Journal 0 */
		if ((err = set_journal (db, JOURNAL0, 0, 0)))
			return err;

		/* Nuke target */
		for (uint32_t count = page_count; count; --count)
		{
			/* Empty row */
			memset (db->tmp, 0, db->page_size);
			pack_uint32_little (db->tmp, 1);

			if ((err = write_page (db, page_start + count - 1)))
				return err;
		}

		/* Nuke Journal 1 */
		if ((err = set_journal (db, JOURNAL1, 0, 0)))
			return err;

		return 0;
	}
	else if (err != 0 && err != MDBE_CORRUPT)
		return err;

	/* Check Journal 0 */
	err = read_page (db, 0);
	page_start = unpack_uint32_little (db->tmp);
	page_count = unpack_uint32_little (db->tmp + 4);

	if (err == 0 && page_count != 0)
	{
		/* Must point to a row */
		if (page_start < FIRST_PAGE)
			return -1;

		/* Journal 0 is valid, execute it */
		/* Nuke target */
		for (uint32_t count = page_count; count; --count)
		{
			/* Empty row */
			memset (db->tmp, 0, db->page_size);
			pack_uint32_little (db->tmp, 1);

			if ((err = write_page (db, page_start + count - 1)))
				return err;
		}

		/* Nuke Journal 0 */
		if ((err = set_journal (db, JOURNAL0, 0, 0)))
			return err;

		return 0;
	}
	else if (err != 0 && err != MDBE_CORRUPT)
		return err;

	return 0;
}


void mdb_close (MDB *db)
{
	if (db->fd)
		mdba_close (db->fd);

	secure_memset (db, 0, sizeof (MDB));
}


static int set_journal (MDB *db, int journal, uint32_t page_start, uint32_t page_count)
{
	int err;

	if (!db->fd)
		return MDBE_NOT_OPEN;

	if (journal != 0 && journal != 1)
		return -1;

	memset (db->tmp, 0, db->page_size);
	pack_uint32_little (db->tmp, page_start);
	pack_uint32_little (db->tmp + 4, page_count);

	if ((err = write_page (db, journal)))
		return err;

	return 0;
}


/* Find an empty row of the specified size.
 * Otherwise, creates a new empty row.
 */
static int find_empty_row (MDB *db, uint32_t *page_start, uint32_t requested_page_count)
{
	int err;
	uint32_t potential_start = 2;
	uint32_t potential_count = 0;
	uint32_t page_count;
	uint32_t row_id;

	if (!db->fd)
		return MDBE_NOT_OPEN;

	if (requested_page_count == 0 || requested_page_count == 0xffffffff)
		return -1;

	while (1)
	{
		if ((err = read_page (db, potential_start + potential_count)))
			return err;

		page_count = unpack_uint32_little (db->tmp);
		row_id = unpack_uint32_little (db->tmp + 4);

		/* Terminator Row?*/
		if (page_count == 0)
		{
			potential_start += potential_count;
			break;
		}

		/* Occupied row? */
		if (row_id != 0)
		{
			potential_start += potential_count + page_count;
			potential_count = 0;
			continue;
		}

		if (page_count != 1)
			return MDBE_CORRUPT;

		potential_count += 1;

		if (potential_count == requested_page_count)
		{
			*page_start = potential_start;
			return 0;
		}
	}

	/* No acceptable empty rows found, create a new one at the end */
	if (potential_start + requested_page_count + 1 <= potential_start)
		return MDBE_FULL;

	/* First, fill the space with terminator pages */
	for (uint32_t count = 0; count <= requested_page_count; ++count)
	{
		memset (db->tmp, 0, db->page_size);

		if ((err = write_page (db, potential_start + count)))
			return err;
	}

	/* Open journal on new row */
	if ((err = set_journal (db, JOURNAL0, potential_start, requested_page_count)))
		return err;

	*page_start = potential_start;

	return 0;
}


int mdb_insert_begin (MDB *db, uint8_t table, uint32_t valuelen)
{
	if (!db->fd)
		return MDBE_NOT_OPEN;

	if ((valuelen + 13) <= valuelen)
		return MDBE_DATA_TOO_BIG;

	if (db->insert_page)
		return MDBE_BUSY;

	int err;
	uint32_t page_count = MAX (1, (valuelen + 13) / db->page_size);
	uint32_t page_start;
	uint32_t rowid;

	if ((err = mdb_get_next_rowid (db, table, &rowid)))
		return err;

	/* Find an empty row (leaves journal0 open on that row) */
	if ((err = find_empty_row (db, &page_start, page_count)))
		return err;

	/* Write row header */
	memset (db->tmp, 0, db->page_size);
	pack_uint32_little (db->tmp, page_count);
	pack_uint32_little (db->tmp+4, rowid);
	db->tmp[8] = table;
	pack_uint32_little (db->tmp+9, valuelen);

	if ((err = write_page (db, page_start)))
		return err;

	db->insert_page = page_start;
	db->insert_page_count = page_count;
	db->insert_offset = 13;

	return 0;
}


int mdb_insert_continue (MDB *db, void const *data, size_t len)
{
	int err;

	if (!db->fd)
		return MDBE_NOT_OPEN;

	if (db->insert_page < FIRST_PAGE || db->insert_page_count == 0)
		return MDBE_NO_ROW_SELECTED;

	while (len)
	{
		uint32_t page = db->insert_offset / db->real_page_size;
		uint32_t page_offset = db->insert_offset - page * db->real_page_size;
		uint32_t available = db->real_page_size - page_offset;
		uint32_t l = MIN (len, available);

		if (page >= db->insert_page_count)
			return -1;

		if ((err = read_page (db, db->insert_page + page)))
			return err;

		memmove (db->tmp + page_offset, data, l);
		data = (uint8_t const *)data + l;
		len -= l;

		if ((err = write_page (db, db->insert_page + page)))
			return err;

		db->insert_offset += l;
	}

	return 0;
}


int mdb_insert_finalize (MDB *db)
{
	int err;

	if (!db->fd)
		return MDBE_NOT_OPEN;

	if (db->update_page)
		return -1;

	if (db->insert_page < FIRST_PAGE || db->insert_page_count == 0)
		return -1;
	
	/* Close journal */
	if ((err = set_journal (db, JOURNAL0, 0, 0)))
		return err;

	db->selected_page = db->insert_page;
	db->selected_page_count = db->insert_page_count;
	db->insert_page = 0;
	db->insert_page_count = 0;

	return 0;
}


int mdb_insert (MDB *db, uint8_t table, void const *value, uint32_t valuelen)
{
	int err;

	if ((err = mdb_insert_begin (db, table, valuelen)))
		return err;

	if ((err = mdb_insert_continue (db, value, valuelen)))
		return err;

	if ((err = mdb_insert_finalize (db)))
		return err;

	return 0;
}


int mdb_read_value (MDB *db, void *dst, uint32_t offset, size_t len)
{
	int err;
	uint64_t datalen = db->selected_page_count * db->real_page_size;

	if (!db->fd)
		return MDBE_NOT_OPEN;

	if (db->selected_page < FIRST_PAGE || db->selected_page_count == 0)
		return MDBE_NO_ROW_SELECTED;

	if ((offset + 13) <= offset)
		return -1;

	/* Skip header */
	offset += 13;

	while (len)
	{
		if (offset >= datalen)
			return MDBE_NOT_ENOUGH_DATA;

		uint32_t page = offset / db->real_page_size;
		uint32_t page_offset = offset - (page * db->real_page_size);
		uint32_t maxlen = db->real_page_size - page_offset;
		uint32_t l = MIN (maxlen, len);

		if ((err = read_page (db, db->selected_page + page)))
			return err;

		memmove (dst, db->tmp + page_offset, l);
		dst = (uint8_t *)dst + l;
		offset += l;
		len -= l;
	}

	return 0;
}


int64_t mdb_get_value (MDB *db, void *dst, size_t maxlen)
{
	int err;
	uint32_t valuelen;

	if (!db->fd)
		return MDBE_NOT_OPEN;

	if (db->selected_page < FIRST_PAGE || db->selected_page_count == 0)
		return MDBE_NO_ROW_SELECTED;

	if ((err = read_page (db, db->selected_page)))
		return err;

	valuelen = unpack_uint32_little (db->tmp + 9);

	if (dst)
	{
		if (valuelen > maxlen)
			return MDBE_DATA_TOO_BIG;

		if ((err = mdb_read_value (db, dst, 0, valuelen)))
			return err;
	}

	return (int64_t)valuelen;
}


int mdb_get_rowid (MDB *db, uint32_t *page, uint8_t *table, uint32_t *rowid)
{
	int err;

	if (!db->fd)
		return MDBE_NOT_OPEN;

	if (db->selected_page < FIRST_PAGE || db->selected_page_count == 0)
		return MDBE_NO_ROW_SELECTED;

	if (page)
		*page = db->selected_page;

	if (!table && !rowid)
		return 0;

	if ((err = read_page (db, db->selected_page)))
		return err;

	if (table)
		*table = db->tmp[8];

	if (rowid)
		*rowid = unpack_uint32_little (db->tmp+4);

	return 0;
}


int mdb_select_by_rowid (MDB *db, uint8_t table, uint32_t rowid)
{
	int err;
	uint32_t current_rowid = 0;

	if (!db->fd)
		return MDBE_NOT_OPEN;

	while (1)
	{
		if ((err = mdb_walk (db, table, current_rowid == 0)) < 0)
			return err;

		if (err == 1)
			return MDBE_ROW_NOT_FOUND;

		if ((err = mdb_get_rowid (db, NULL, NULL, &current_rowid)))
			return err;

		if (current_rowid == 0)
			return -1;

		if (current_rowid == rowid)
			return 0;
	}
}


int mdb_select_by_page (MDB *db, uint32_t page)
{
	int err;

	if (!db->fd)
		return -1;

	if (page < FIRST_PAGE)
		return -1;

	db->selected_page = page;

	if ((err = read_page (db, db->selected_page)))
	{
		db->selected_page = 0;
		db->selected_page_count = 0;
		return err;
	}

	db->selected_page_count = unpack_uint32_little (db->tmp);

	if (db->selected_page_count == 0)
	{
		db->selected_page = 0;
		db->selected_page_count = 0;
		return -1;
	}

	return 0;
}


int mdb_walk (MDB *db, uint8_t table, bool restart)
{
	int err;

	if (!db->fd)
		return MDBE_NOT_OPEN;

	if (restart)
		db->selected_page = FIRST_PAGE;
	else
		db->selected_page += db->selected_page_count;

	if (db->selected_page < FIRST_PAGE)
		return -1;

	while (1)
	{
		if ((err = read_page (db, db->selected_page)))
			return err;

		db->selected_page_count = unpack_uint32_little (db->tmp);
		uint32_t rowid = unpack_uint32_little (db->tmp + 4);
		uint32_t tableid = db->tmp[8];

		if (db->selected_page_count == 0)
			return 1; /* End of database */

		if (rowid > 0 && tableid == table)
			return 0; /* Valid row found */

		db->selected_page += db->selected_page_count;
	}
}


int mdb_get_next_rowid (MDB *db, uint8_t table, uint32_t *rowid)
{
	int err;
	uint32_t maxrowid = 0;
	uint32_t selected_page = db->selected_page;
	uint32_t selected_page_count = db->selected_page_count;

	if (!db->fd)
		return MDBE_NOT_OPEN;

	while (1)
	{
		uint32_t current_rowid;

		if ((err = mdb_walk (db, table, maxrowid == 0)) < 0)
			return err;

		if (err == 1)
			break;

		if ((err = mdb_get_rowid (db, NULL, NULL, &current_rowid)))
			return err;

		if (current_rowid == 0)
			return -1;

		maxrowid = MAX (maxrowid, current_rowid);
	}

	db->selected_page = selected_page;
	db->selected_page_count = selected_page_count;

	if (maxrowid == 0xFFFFFFFF)
		return MDBE_FULL;

	*rowid = maxrowid + 1;

	return 0;
}


int mdb_update_begin (MDB *db, uint32_t valuelen)
{
	int err;
	uint8_t table;
	uint32_t rowid;

	if (!db->fd)
		return MDBE_NOT_OPEN;

	/* Also checks if a row is currently selected */
	if ((err = mdb_get_rowid (db, NULL, &table, &rowid)))
		return err;

	db->update_page = db->selected_page;
	db->update_page_count = db->selected_page_count;

	/* Begin creating the replacement row */
	if ((err = mdb_insert_begin (db, table, valuelen)))
		return err;

	/* Overwrite row header to set rowid */
	memset (db->tmp, 0, db->page_size);
	pack_uint32_little (db->tmp, db->insert_page_count);
	pack_uint32_little (db->tmp+4, rowid);
	db->tmp[8] = table;
	pack_uint32_little (db->tmp+9, valuelen);

	if ((err = write_page (db, db->insert_page)))
		return err;

	return 0;
}


int mdb_update_continue (MDB *db, void const *data, size_t len)
{
	return mdb_insert_continue (db, data, len);
}


int mdb_update_finalize (MDB *db)
{
	int err;

	if (!db->fd)
		return MDBE_NOT_OPEN;

	if (db->update_page < FIRST_PAGE || db->update_page_count == 0)
		return -1;

	if (db->insert_page < FIRST_PAGE || db->insert_page_count == 0)
		return -1;

	/* Set journal to nuke old row */
	if ((err = set_journal (db, JOURNAL1, db->update_page, db->update_page_count)))
		return err;

	if ((err = cleanup_journal (db)))
		return err;

	/* Select the new row, if the old row was selected */
	if (db->selected_page == db->update_page)
	{
		db->selected_page = db->insert_page;
		db->selected_page_count = db->insert_page_count;
	}

	db->update_page = 0;
	db->update_page_count = 0;
	db->insert_page = 0;
	db->insert_page_count = 0;

	return 0;
}


int mdb_update (MDB *db, void const *value, uint32_t valuelen)
{
	int err;

	if ((err = mdb_update_begin (db, valuelen)))
		return err;

	if ((err = mdb_update_continue (db, value, valuelen)))
		return err;

	if ((err = mdb_update_finalize (db)))
		return err;

	return 0;
}


int mdb_delete (MDB *db)
{
	int err;

	if (!db->fd)
		return MDBE_NOT_OPEN;

	if (db->insert_page || db->update_page)
		return MDBE_BUSY;

	if (db->selected_page < FIRST_PAGE || db->selected_page_count == 0)
		return MDBE_NO_ROW_SELECTED;

	if ((err = set_journal (db, JOURNAL0, db->selected_page, db->selected_page_count)))
		return err;

	if ((err = cleanup_journal (db)))
		return err;

	db->selected_page = 0;
	db->selected_page_count = 0;

	return 0;
}
