#include <meagerdb/meagerdb.h>
#include <meagerdb/app.h>
#include <strong-arm/hmac.h>
#include <strong-arm/threefish.h>
#include <strong-arm/pbkdf2.h>
#include <strong-arm/sha256.h>
#include "basic_packing.h"
#include "util.h"
#include <string.h>
#include <sys/unistd.h>


#define JOURNAL0  0
#define JOURNAL1  1
#define FIRST_PAGE 2

#define ENCRYPTION_KEY_SIZE 64
#define MAC_KEY_SIZE 64
#define ENCRYPTION_BLOCK_SIZE 64
#define MAC_TAG_SIZE 32       /* Must also match SHA256 hash size */

/* mdb_create and mdb_open depend on these values, so update those if the data structures change. */
#define MDB_HEADER_SIZE (8+2+4+32)
#define MDB_HEADER_PARAMS_SIZE (64+32+32+128+32+32)

/* We consume one global buffer of this size.
 */
#if (MDB_HEADER_SIZE+MDB_HEADER_PARAMS_SIZE) > (MDB_MAX_PAGE_SIZE + MAC_TAG_SIZE + 8)
	#define TMP_SIZE (MDB_HEADER_SIZE+MDB_HEADER_PARAMS_SIZE)
#else
	#define TMP_SIZE (MDB_MAX_PAGE_SIZE + MAC_TAG_SIZE + 8)
#endif

_Static_assert (MDB_DEFAULT_PAGE_SIZE <= MDB_MAX_PAGE_SIZE, "MDB_DEFAULT_PAGE_SIZE must be smaller than MDB_MAX_PAGE_SIZE.");

_Static_assert ((ENCRYPTION_KEY_SIZE+MAC_KEY_SIZE) == 128, "mdb_create/mdb_open expects ENCRYPTION_KEY_SIZE+MAC_KEY_SIZE to be 128 bytes.");



/* Information about the currently open database */
static struct
{
	void *fp;
	uint32_t page_size;
	uint8_t encryption_key[ENCRYPTION_KEY_SIZE];
	uint8_t mac_key[MAC_KEY_SIZE];
	uint64_t page_offset;      /* File position where Pages start */

	/* Selected Page */
	uint32_t selected_page;
	uint32_t selected_page_count;

	/* Row being inserted */
	uint32_t insert_page;
	uint32_t insert_page_count;
	uint32_t insert_offset;

	/* Pointer to old page during an update */
	uint32_t update_page;
	uint32_t update_page_count;

	uint32_t tmp_page;
	uint8_t tmp[TMP_SIZE];
} g_database = {0};


/* Private Prototypes */
static int cleanup_journal (void);
static int set_journal (int journal, uint32_t page_start, uint32_t page_count);
static int write_page (uint32_t page);



/* 
 * (location) should be the byte position of the data in the database file.  We use it as part of the encryption
 * tweak.
 */
static void _encrypt (uint8_t *dst, uint8_t const key[static 64], uint8_t const *src, uint32_t len, uint64_t location)
{
	uint8_t tweak[16] = {0};
	uint32_t block_num = 0;

	if ((len & 63) != 0)
		mdba_fatal_error ();

	// Calculate initial tweak
	pack_uint64_little (tweak, location);

	// Encrypt blocks
	for (uint32_t remaining = len >> 6; remaining; --remaining)
	{
		pack_uint32_little (tweak+8, block_num);
		threefish512_encrypt_block (dst, key, tweak, src);

		block_num += 1;
		src += 64;
		dst += 64;
	}
}


static void _decrypt (uint8_t *dst, uint8_t const key[static 64], uint8_t const *src, uint32_t len, uint64_t location)
{
	uint8_t tweak[16] = {0};
	uint32_t block_num = 0;

	if ((len & 63) != 0)
		mdba_fatal_error ();

	// Calculate initial tweak
	pack_uint64_little (tweak, location);

	// Encrypt blocks
	for (uint32_t remaining = len >> 6; remaining; --remaining)
	{
		pack_uint32_little (tweak+8, block_num);
		threefish512_decrypt_block (dst, key, tweak, src);

		block_num += 1;
		src += 64;
		dst += 64;
	}
}


int mdb_create (char const *path, uint8_t const *password, size_t password_len, uint64_t iteration_count)
{
	int err;
	const uint32_t page_size = MDB_DEFAULT_PAGE_SIZE;
	const uint32_t database_header_len = roundup_uint32 (MDB_HEADER_SIZE+MDB_HEADER_PARAMS_SIZE*2, page_size);
	uint8_t derived_keys[ENCRYPTION_KEY_SIZE+MAC_KEY_SIZE];
	uint8_t *encryption_key = derived_keys;
	uint8_t *mac_key = derived_keys+ENCRYPTION_KEY_SIZE;

	if (g_database.fp)
		return MDBE_ALREADY_OPEN;

	/* Open database file */
	if (!(g_database.fp = mdba_fopen (path, "w+b")))
		return MDBE_FOPEN;

	g_database.page_size = page_size;
	g_database.page_offset = database_header_len;

	/* Generate Encryption Keys */
	mdba_read_urandom (g_database.encryption_key, sizeof (g_database.encryption_key));
	mdba_read_urandom (g_database.mac_key, sizeof (g_database.mac_key));

	/* Database Header */
	memset (g_database.tmp, 0, MDB_HEADER_SIZE + MDB_HEADER_PARAMS_SIZE);
	memmove (g_database.tmp, "MEAGERDB", 8);                        /* Magic */
	memmove (g_database.tmp+8, "\x00\x01", 2);                      /* Version */
	pack_uint32_little (g_database.tmp+10, page_size);              /* Page Size */
	mdba_read_urandom (g_database.tmp+14, 32);                      /* Unique ID */

	/* Encryption Parameters */
	mdba_read_urandom (g_database.tmp+MDB_HEADER_SIZE, 64);         /* Password Salt */
	memmove (g_database.tmp+MDB_HEADER_SIZE+64, "PBKDF2-HMAC-SHA-256", strlen ("PBKDF2-HMAC-SHA-256"));  /* Key Derivation Function */
	pack_uint64_little (g_database.tmp+MDB_HEADER_SIZE+96, iteration_count);  /* Key Derivation Parameters */
	
	/* Derive Keys */
	PBKDF2 (derived_keys, password, (uint32_t)password_len, g_database.tmp+MDB_HEADER_SIZE, 64, iteration_count, (uint32_t)sizeof (derived_keys));

	/* Encrypted Keys */
	memmove (g_database.tmp+MDB_HEADER_SIZE+128, g_database.encryption_key, ENCRYPTION_KEY_SIZE);
	memmove (g_database.tmp+MDB_HEADER_SIZE+192, g_database.mac_key, MAC_KEY_SIZE);
	_encrypt (g_database.tmp+MDB_HEADER_SIZE+128, encryption_key, g_database.tmp+MDB_HEADER_SIZE+128, ENCRYPTION_KEY_SIZE + MAC_KEY_SIZE, MDB_HEADER_SIZE+128);

	/* Header MAC and HASH */
	HMAC (g_database.tmp+MDB_HEADER_SIZE+256, mac_key, MAC_KEY_SIZE, g_database.tmp, MDB_HEADER_SIZE+256);
	SHA256 (g_database.tmp+MDB_HEADER_SIZE+256+MAC_TAG_SIZE, g_database.tmp, MDB_HEADER_SIZE+256+MAC_TAG_SIZE);

	if (mdba_fwrite (g_database.tmp, MDB_HEADER_SIZE+MDB_HEADER_PARAMS_SIZE, 1, g_database.fp) != 1)
	{
		mdb_close ();
		return MDBE_IO;
	}

	/* Fill remaining space to write a second, blank encryption parameters block, and
 	 * pad to page boundary. */
	memset (g_database.tmp, 0, sizeof (g_database.tmp));

	for (uint32_t remaining = database_header_len - MDB_HEADER_SIZE - MDB_HEADER_PARAMS_SIZE; remaining;)
	{
		uint32_t l = MIN (remaining, sizeof (g_database.tmp));

		if (mdba_fwrite (g_database.tmp, l, 1, g_database.fp) != 1)
		{
			mdb_close ();
			return MDBE_IO;
		}

		remaining -= MIN (remaining, sizeof (g_database.tmp));
	}

	/* Write Journals (blank) */
	memset (g_database.tmp, 0, page_size+MAC_TAG_SIZE);

	if (mdba_fwrite (g_database.tmp, page_size+MAC_TAG_SIZE, 1, g_database.fp) != 1)
	{
		mdb_close ();
		return -1;
	}

	if (mdba_fwrite (g_database.tmp, page_size+MAC_TAG_SIZE, 1, g_database.fp) != 1)
	{
		mdb_close ();
		return -1;
	}

	/* Write row terminator */
	memset (g_database.tmp, 0, page_size);

	if ((err = write_page (2)))
	{
		mdb_close ();
		return err;
	}

	mdb_close ();

	return 0;
}


int mdb_open (char const *path, uint8_t const *password, size_t password_len)
{
	int err;
	uint8_t calculated_mac[MAC_TAG_SIZE];
	uint8_t derived_keys[ENCRYPTION_KEY_SIZE+MAC_KEY_SIZE];

	/* Open database file */
	if (g_database.fp)
		return MDBE_ALREADY_OPEN;
	
	memset (&g_database, 0, sizeof (g_database));

	if ((g_database.fp = mdba_fopen (path, "r+b")) == 0)
		return MDBE_FOPEN;

	/* Read database header */
	if (mdba_fread (g_database.tmp, MDB_HEADER_SIZE + MDB_HEADER_PARAMS_SIZE, 1, g_database.fp) != 1)
	{
		mdb_close ();
		return MDBE_IO;
	}

	if (memcmp (g_database.tmp, "MEAGERDB", 8))
	{
		mdb_close ();
		return MDBE_NOT_MDB;
	}

	if (memcmp (g_database.tmp+8, "\x00\x01", 2))
	{
		mdb_close ();
		return MDBE_BAD_VERSION;
	}

	g_database.page_size = unpack_uint32_little (g_database.tmp+10);

	if (g_database.page_size % ENCRYPTION_BLOCK_SIZE != 0)
	{
		mdb_close ();
		return MDBE_BAD_PAGE_SIZE;
	}

	if (g_database.page_size > MDB_MAX_PAGE_SIZE)
	{
		mdb_close ();
		return MDBE_UNSUPPORTED_PAGE_SIZE;
	}

	/* Look for valid encryption parameters */
	SHA256 (calculated_mac, g_database.tmp, 334);

	if (secure_memcmp (g_database.tmp+334, calculated_mac, MAC_TAG_SIZE))
	{
		if (mdba_fread (g_database.tmp+MDB_HEADER_SIZE, MDB_HEADER_PARAMS_SIZE, 1, g_database.fp) != 1)
		{
			mdb_close ();
			return MDBE_IO;
		}

		SHA256 (calculated_mac, g_database.tmp, 334);

		if (secure_memcmp (g_database.tmp+334, calculated_mac, MAC_TAG_SIZE))
		{
			mdb_close ();
			return MDBE_CORRUPT;
		}
	}

	/* Check encryption parameters */
	if (memcmp (g_database.tmp+110, "PBKDF2-HMAC-SHA-256", strlen ("PBKDF2-HMAC-SHA-256")+1))
	{
		mdb_close ();
		return MDBE_BAD_KEY_DERIVE;
	}

	/* Derive keys */
	uint64_t iteration_count = unpack_uint64_little (g_database.tmp+142);

	if (iteration_count > 0xFFFFFFFF)
	{
		mdb_close ();
		return -1;
	}
	
	PBKDF2 (derived_keys, password, (uint32_t)password_len, g_database.tmp+46, 64, (uint32_t)iteration_count, (uint32_t)sizeof (derived_keys));

	memmove (g_database.encryption_key, derived_keys, ENCRYPTION_KEY_SIZE);
	memmove (g_database.mac_key, derived_keys+ENCRYPTION_KEY_SIZE, MAC_KEY_SIZE);

	/* Authenticate header */
	HMAC (calculated_mac, derived_keys+ENCRYPTION_KEY_SIZE, MAC_KEY_SIZE, g_database.tmp, 302);

	if (secure_memcmp (g_database.tmp+302, calculated_mac, MAC_TAG_SIZE))
	{
		mdb_close ();
		return MDBE_BAD_PASSWORD;
	}

	/* Decrypt real keys */
	_decrypt (g_database.tmp, derived_keys, g_database.tmp+174, ENCRYPTION_KEY_SIZE+MAC_KEY_SIZE, 174);

	memmove (g_database.encryption_key, g_database.tmp, ENCRYPTION_KEY_SIZE);
	memmove (g_database.mac_key, g_database.tmp+ENCRYPTION_KEY_SIZE, MAC_KEY_SIZE);
	secure_memset (g_database.tmp, 0, sizeof (g_database.tmp));

	/* Additional DB parameters */
	g_database.page_offset = roundup_uint64 (MDB_HEADER_SIZE + MDB_HEADER_PARAMS_SIZE*2, g_database.page_size);

	/* Cleanup Journal */
	if ((err = cleanup_journal ()))
	{
		mdb_close ();
		return err;
	}

	return 0;
}


/* Read specified page into g_database.tmp and set g_database.tmp_page accordingly. */
static int read_page (uint32_t page)
{
	if (!g_database.fp)
		return -1;

	uint8_t calculated_mac[MAC_TAG_SIZE];
	uint64_t pos = g_database.page_offset + (uint64_t)page * ((uint64_t)g_database.page_size + MAC_TAG_SIZE);

	if (g_database.tmp_page == page && g_database.tmp_page != 0)
		return 0;

	g_database.tmp_page = 0;

	if (mdba_fseek (g_database.fp, pos, SEEK_SET))
		return MDBE_IO;
	
	if (mdba_fread (g_database.tmp, g_database.page_size + MAC_TAG_SIZE, 1, g_database.fp) != 1)
		return MDBE_IO;

	/* Add tweak for HMAC */
	memmove (g_database.tmp+g_database.page_size+8, g_database.tmp+g_database.page_size, MAC_TAG_SIZE);
	pack_uint64_little (g_database.tmp+g_database.page_size, pos);

	/* Authenticate */
	HMAC (calculated_mac, g_database.mac_key, MAC_KEY_SIZE, g_database.tmp, g_database.page_size + 8);

	if (secure_memcmp (calculated_mac, g_database.tmp+g_database.page_size+8, MAC_TAG_SIZE))
		return MDBE_CORRUPT;

	/* Decrypt */
	_decrypt (g_database.tmp, g_database.encryption_key, g_database.tmp, g_database.page_size, pos);

	g_database.tmp_page = page;

	return 0;
}


/* Write g_database.tmp to the specified page */
static int write_page (uint32_t page)
{
	if (!g_database.fp)
		return -1;

	uint64_t pos = g_database.page_offset + (uint64_t)page * ((uint64_t)g_database.page_size + MAC_TAG_SIZE);

	g_database.tmp_page = 0;

	/* Encrypt */
	_encrypt (g_database.tmp, g_database.encryption_key, g_database.tmp, g_database.page_size, pos);
	
	/* HMAC */
	pack_uint64_little (g_database.tmp+g_database.page_size, pos);
	HMAC (g_database.tmp+g_database.page_size+8, g_database.mac_key, MAC_KEY_SIZE, g_database.tmp, g_database.page_size + 8);
	memmove (g_database.tmp+g_database.page_size, g_database.tmp+g_database.page_size+8, MAC_TAG_SIZE);

	/* Write */
	if (mdba_fseek (g_database.fp, pos, SEEK_SET))
		return MDBE_IO;

	if (mdba_fwrite (g_database.tmp, g_database.page_size + MAC_TAG_SIZE, 1, g_database.fp) != 1)
		return MDBE_IO;

	if (mdba_fflush (g_database.fp))
		return MDBE_IO;

	return 0;
}


static int cleanup_journal (void)
{
	int err;
	uint32_t page_start, page_count;

	/* Check Journal 1 */
	err = read_page (1);
	page_start = unpack_uint32_little (g_database.tmp);
	page_count = unpack_uint32_little (g_database.tmp+4);

	if (err == 0 && page_count != 0)
	{
		/* Journal 1 is valid, execute it */
		/* Nuke Journal 0 */
		if ((err = set_journal (JOURNAL0, 0, 0)))
			return err;

		/* Nuke target */
		for (uint32_t count = page_count; count; --count)
		{
			memset (g_database.tmp, 0, g_database.page_size);
			pack_uint32_little (g_database.tmp, 1);

			if ((err = write_page (page_start + count - 1)))
				return err;
		}

		/* Nuke Journal 1 */
		if ((err = set_journal (JOURNAL1, 0, 0)))
			return err;

		return 0;
	}
	else if (err != 0 && err != MDBE_CORRUPT)
		return err;

	/* Check Journal 0 */
	err = read_page (0);
	page_start = unpack_uint32_little (g_database.tmp);
	page_count = unpack_uint32_little (g_database.tmp+4);

	if (err == 0 && page_count != 0)
	{
		/* Journal 0 is valid, execute it */
		/* Nuke target */
		for (uint32_t count = page_count; count; --count)
		{
			memset (g_database.tmp, 0, g_database.page_size);
			pack_uint32_little (g_database.tmp, 1);

			if ((err = write_page (page_start + count - 1)))
				return err;
		}

		/* Nuke Journal 0 */
		if ((err = set_journal (JOURNAL0, 0, 0)))
			return err;

		return 0;
	}
	else if (err != 0 && err != MDBE_CORRUPT)
		return err;

	return 0;
}


void mdb_close (void)
{
	if (!g_database.fp)
		return;

	mdba_fclose (g_database.fp);
	secure_memset (&g_database, 0, sizeof (g_database));
}


static int set_journal (int journal, uint32_t page_start, uint32_t page_count)
{
	int err;

	if (!g_database.fp)
		return -1;

	if (journal != 0 && journal != 1)
		return -1;

	memset (g_database.tmp, 0, g_database.page_size);
	pack_uint32_little (g_database.tmp, page_start);
	pack_uint32_little (g_database.tmp+4, page_count);

	if ((err = write_page (journal)))
		return err;

	return 0;
}


/* Find an empty row of the specified size.
 * Otherwise, creates a new empty row.
 */
static int find_empty_row (uint32_t *page_start, uint32_t requested_page_count)
{
	int err;
	uint32_t potential_start = 2;
	uint32_t potential_count = 0;
	uint32_t page_count;
	uint32_t row_id;

	if (requested_page_count == 0 || !g_database.fp)
		return -1;

	while (1)
	{
		if ((err = read_page (potential_start+potential_count)))
			return err;

		page_count = unpack_uint32_little (g_database.tmp);
		row_id = unpack_uint32_little (g_database.tmp+4);

		if (page_count == 0)
		{
			potential_start += potential_count;
			break;
		}

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
		memset (g_database.tmp, 0, g_database.page_size);

		if ((err = write_page (potential_start + count)))
			return err;
	}

	/* Open journal on new row */
	if ((err = set_journal (JOURNAL0, potential_start, requested_page_count)))
		return err;

	*page_start = potential_start;

	return 0;
}


int mdb_insert_begin (uint8_t table, uint32_t valuelen)
{
	if (!g_database.fp)
		return MDBE_NOT_OPEN;

	if ((valuelen + 13) <= valuelen)
		return MDBE_DATA_TOO_BIG;

	if (g_database.insert_page)
		return MDBE_BUSY;

	int err;
	uint32_t page_count = MAX (1, (valuelen + 13) / g_database.page_size);
	uint32_t page_start;
	uint32_t rowid;

	if ((err = mdb_get_next_rowid (table, &rowid)))
		return err;

	/* Find an empty row (leaves journal0 open on that row) */
	if ((err = find_empty_row (&page_start, page_count)))
		return err;

	/* Write row header */
	memset (g_database.tmp, 0, g_database.page_size);
	pack_uint32_little (g_database.tmp, page_count);
	pack_uint32_little (g_database.tmp+4, rowid);
	g_database.tmp[8] = table;
	pack_uint32_little (g_database.tmp+9, valuelen);

	if ((err = write_page (page_start)))
		return err;

	g_database.insert_page = page_start;
	g_database.insert_page_count = page_count;
	g_database.insert_offset = 13;

	return 0;
}


int mdb_insert_continue (void const *data, size_t len)
{
	int err;

	if (!g_database.fp)
		return MDBE_NOT_OPEN;

	if (g_database.insert_page < FIRST_PAGE || g_database.insert_page_count == 0)
		return MDBE_NO_ROW_SELECTED;

	while (len)
	{
		uint32_t page = g_database.insert_offset / g_database.page_size;
		uint32_t page_offset = g_database.insert_offset - page * g_database.page_size;
		uint32_t available = g_database.page_size - page_offset;
		uint32_t l = MIN (len, available);

		if (page >= g_database.insert_page_count)
			return -1;

		if ((err = read_page (g_database.insert_page + page)))
			return err;

		memmove (g_database.tmp+page_offset, data, l);
		data = (uint8_t const *)data + l;
		len -= l;

		if ((err = write_page (g_database.insert_page + page)))
			return err;

		g_database.insert_offset += l;
	}

	return 0;
}


int mdb_insert_finalize (void)
{
	int err;

	if (g_database.insert_page < FIRST_PAGE || g_database.insert_page_count == 0)
		return -1;
	
	/* Close journal */
	if ((err = set_journal (JOURNAL0, 0, 0)))
		return err;

	g_database.selected_page = g_database.insert_page;
	g_database.selected_page_count = g_database.insert_page_count;
	g_database.insert_page = 0;
	g_database.insert_page_count = 0;

	return 0;
}


int mdb_insert (uint8_t table, void const *value, uint32_t valuelen)
{
	int err;

	if ((err = mdb_insert_begin (table, valuelen)))
		return err;

	if ((err = mdb_insert_continue (value, valuelen)))
		return err;

	if ((err = mdb_insert_finalize ()))
		return err;

	return 0;
}


int mdb_read_value (void *dst, uint32_t offset, size_t len)
{
	int err;
	uint64_t datalen = g_database.selected_page_count * g_database.page_size;
	uint8_t *pdst = (uint8_t *)dst;

	if (!g_database.fp)
		return MDBE_NOT_OPEN;

	if (g_database.selected_page < FIRST_PAGE || g_database.selected_page_count == 0)
		return MDBE_NO_ROW_SELECTED;

	/* Skip header */
	uint64_t real_offset = (uint64_t)offset + 13;

	while (len)
	{
		if (real_offset >= datalen)
			return MDBE_NOT_ENOUGH_DATA;

		uint32_t page = real_offset / g_database.page_size;
		uint32_t page_offset = real_offset - (page * g_database.page_size);
		uint32_t maxlen = g_database.page_size - page_offset;
		uint32_t l = MIN (maxlen, len);

		if ((err = read_page (g_database.selected_page + page)))
			return err;

		memmove (pdst, g_database.tmp + page_offset, l);
		pdst += l;
		real_offset += l;
		len -= l;
	}

	return 0;
}


int64_t mdb_get_value (void *dst, size_t maxlen)
{
	int err;
	uint32_t valuelen;

	if (!g_database.fp)
		return MDBE_NOT_OPEN;

	if (g_database.selected_page < FIRST_PAGE || g_database.selected_page_count == 0)
		return MDBE_NO_ROW_SELECTED;

	if ((err = read_page (g_database.selected_page)))
		return err;

	valuelen = unpack_uint32_little (g_database.tmp + 9);

	if (dst)
	{
		if (valuelen > maxlen)
			return MDBE_DATA_TOO_BIG;

		if ((err = mdb_read_value (dst, 0, valuelen)))
			return err;
	}

	return (int64_t)valuelen;
}


int mdb_get_rowid (uint8_t *table, uint32_t *rowid)
{
	int err;

	if (!g_database.fp)
		return MDBE_NOT_OPEN;

	if (g_database.selected_page < FIRST_PAGE || g_database.selected_page_count == 0)
		return MDBE_NO_ROW_SELECTED;

	if ((err = read_page (g_database.selected_page)))
		return err;

	if (table)
		*table = g_database.tmp[8];

	if (rowid)
		*rowid = unpack_uint32_little (g_database.tmp+4);

	return 0;
}


int mdb_get_page (uint32_t *page)
{
	if (!g_database.fp)
		return MDBE_NOT_OPEN;

	if (g_database.selected_page < FIRST_PAGE || g_database.selected_page_count == 0)
		return MDBE_NO_ROW_SELECTED;

	*page = g_database.selected_page;
	return 0;
}


int mdb_select_by_rowid (uint8_t table, uint32_t rowid)
{
	int err;
	uint32_t current_rowid = 0;

	if (!g_database.fp)
		return MDBE_NOT_OPEN;

	while (1)
	{
		if ((err = mdb_walk (table, current_rowid == 0)) < 0)
			return err;

		if (err == 1)
			return MDBE_ROW_NOT_FOUND;

		if ((err = mdb_get_rowid (NULL, &current_rowid)))
			return err;

		if (current_rowid == 0)
			return -1;

		if (current_rowid == rowid)
			return 0;
	}
}


int mdb_select_by_page (uint32_t page)
{
	int err;

	if (!g_database.fp)
		return -1;

	if (page < FIRST_PAGE)
		return -1;

	g_database.selected_page = page;

	if ((err = read_page (g_database.selected_page)))
	{
		g_database.selected_page = 0;
		g_database.selected_page_count = 0;
		return err;
	}

	g_database.selected_page_count = unpack_uint32_little (g_database.tmp);

	if (g_database.selected_page_count == 0)
	{
		g_database.selected_page = 0;
		g_database.selected_page_count = 0;
		return -1;
	}

	return 0;
}


int mdb_walk (uint8_t table, bool restart)
{
	int err;

	if (!g_database.fp)
		return -1;

	if (restart)
		g_database.selected_page = FIRST_PAGE;
	else
		g_database.selected_page += g_database.selected_page_count;

	if (g_database.selected_page < FIRST_PAGE)
		return -1;

	while (1)
	{
		if ((err = read_page (g_database.selected_page)))
			return err;

		g_database.selected_page_count = unpack_uint32_little (g_database.tmp);
		uint32_t rowid = unpack_uint32_little (g_database.tmp+4);
		uint32_t tableid = g_database.tmp[8];

		if (g_database.selected_page_count == 0)
			return 1;

		if (rowid > 0 && tableid == table)
			return 0;

		g_database.selected_page += g_database.selected_page_count;
	}
}


int mdb_get_next_rowid (uint8_t table, uint32_t *rowid)
{
	int err;
	uint32_t maxrowid = 0;
	uint32_t selected_page = g_database.selected_page;
	uint32_t selected_page_count = g_database.selected_page_count;

	if (!g_database.fp)
		return MDBE_NOT_OPEN;

	while (1)
	{
		uint32_t current_rowid;

		if ((err = mdb_walk (table, maxrowid == 0)) < 0)
			return err;

		if (err == 1)
			break;

		if ((err = mdb_get_rowid (NULL, &current_rowid)))
			return err;

		if (current_rowid == 0)
			return -1;

		maxrowid = MAX (maxrowid, current_rowid);
	}

	g_database.selected_page = selected_page;
	g_database.selected_page_count = selected_page_count;

	if (maxrowid == 0xFFFFFFFF)
		return MDBE_FULL;

	*rowid = maxrowid + 1;

	return 0;
}


int mdb_update_begin (uint32_t valuelen)
{
	int err;
	uint8_t table;
	uint32_t rowid;

	if (!g_database.fp)
		return MDBE_NOT_OPEN;

	/* Also checks if a row is currently selected */
	if ((err = mdb_get_rowid (&table, &rowid)))
		return err;

	g_database.update_page = g_database.selected_page;
	g_database.update_page_count = g_database.selected_page_count;

	/* Begin creating the replacement row */
	if ((err = mdb_insert_begin (table, valuelen)))
		return err;

	/* Overwrite row header to set rowid */
	memset (g_database.tmp, 0, g_database.page_size);
	pack_uint32_little (g_database.tmp, g_database.insert_page_count);
	pack_uint32_little (g_database.tmp+4, rowid);
	g_database.tmp[8] = table;
	pack_uint32_little (g_database.tmp+9, valuelen);

	if ((err = write_page (g_database.insert_page)))
		return err;

	return 0;
}


int mdb_update_continue (void const *data, size_t len)
{
	return mdb_insert_continue (data, len);
}


int mdb_update_finalize (void)
{
	int err;

	if (!g_database.fp)
		return MDBE_NOT_OPEN;

	if (g_database.update_page < FIRST_PAGE || g_database.update_page_count == 0)
		return -1;

	if (g_database.insert_page < FIRST_PAGE || g_database.insert_page_count == 0)
		return -1;

	/* Set journal to nuke old row */
	if ((err = set_journal (JOURNAL1, g_database.update_page, g_database.update_page_count)))
		return err;

	if ((err = cleanup_journal ()))
		return err;

	/* Select the new row, if the old row was selected */
	if (g_database.selected_page == g_database.update_page)
	{
		g_database.selected_page = g_database.insert_page;
		g_database.selected_page_count = g_database.insert_page_count;
	}

	g_database.update_page = 0;
	g_database.update_page_count = 0;
	g_database.insert_page = 0;
	g_database.insert_page_count = 0;

	return 0;
}


int mdb_update (void const *value, uint32_t valuelen)
{
	int err;

	if ((err = mdb_update_begin (valuelen)))
		return err;

	if ((err = mdb_update_continue (value, valuelen)))
		return err;

	if ((err = mdb_update_finalize ()))
		return err;

	return 0;
}


int mdb_delete (void)
{
	int err;

	if (!g_database.fp)
		return MDBE_NOT_OPEN;

	if (g_database.insert_page || g_database.update_page)
		return MDBE_BUSY;

	if (g_database.selected_page < FIRST_PAGE || g_database.selected_page_count == 0)
		return MDBE_NO_ROW_SELECTED;

	if ((err = set_journal (JOURNAL0, g_database.selected_page, g_database.selected_page_count)))
		return err;

	if ((err = cleanup_journal ()))
		return err;

	g_database.selected_page = 0;
	g_database.selected_page_count = 0;

	return 0;
}
