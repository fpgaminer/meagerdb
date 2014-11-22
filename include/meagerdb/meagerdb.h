#ifndef __MEAGER_DATABASE_DATABASE_H__
#define __MEAGER_DATABASE_DATABASE_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <meagerdb/errorcodes.h>


/* 
 * We require limits on some database properties, to fit the implementation into a reasonable amount
 * of RAM.
 * MDB_MAX_PAGE_SIZE will affect the size of the MDB struct.
 */

#define MDB_DEFAULT_PAGE_SIZE 256
#define MDB_MAX_PAGE_SIZE 512


/* Extra 8 bytes so we can append MAC tweak to pages during authentication */
#define MDB_TMP_SIZE (MDB_MAX_PAGE_SIZE+8)

/* Information about the currently open database */
typedef struct
{
	int fd;
	uint32_t page_size;
	uint32_t real_page_size;   /* How much can actually be stored in page */
	uint8_t keys[128];
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
	uint8_t tmp[MDB_TMP_SIZE];
} MDB;



/* Create a MeagerDB at the given 'path', using the given 'password'. */
int mdb_create (MDB *db, char const *path, uint8_t const *password, size_t password_len, uint64_t iteration_count);


int mdb_open (MDB *db, char const *path, uint8_t const *password, size_t password_len);


void mdb_close (MDB *db);


/*
 * Iterate all the rows in the database, for the given table.
 * With `restart` == true, the first row is selected.
 * With `restart` == false, the next row is selected.
 * Return value is less than 0 for error, 0 for success, and 1 if there are no more rows.
 */
int mdb_walk (MDB *db, uint8_t table, bool restart);


/* Make the row specified by `table` and `rowid` the currently selected row. */
int mdb_select_by_rowid (MDB *db, uint8_t table, uint32_t rowid);


/* 
 * Select a row by its Page.  This is faster than selecting by rowid, but
 * doesn't have as many safety checks.  It should be used with caution.  All guarantees
 * are broken if this function is used to select a Page that isn't the beginning of a row.
 *
 * This is O(1), whereas selecting by rowid is O(N); N == number of rows in DB.
 */
int mdb_select_by_page (MDB *db, uint32_t page);


/* 
 * Reads the selected row's value into 'dst' and returns the length.
 * 'dst' may be NULL, to just get the value length.
 * Will not write more than 'maxlen' bytes to 'dst'.
 */
int64_t mdb_get_value (MDB *db, void *dst, size_t maxlen);


/* Read (len) bytes at (offset) from the selected row's value. */
int mdb_read_value (MDB *db, void *dst, uint32_t offset, size_t len);


/*
 * Get selected row's page number, rowid, and tableid.
 * Any may be NULL, if that value is not desired.
 */
int mdb_get_rowid (MDB *db, uint32_t *page, uint8_t *table, uint32_t *rowid);


/* Return the next available (unused) rowid, or 0 on error. */
int mdb_get_next_rowid (MDB *db, uint8_t table, uint32_t *rowid);


/* NOTE: Sets the selected row to the inserted row. */
int mdb_insert (MDB *db, uint8_t table, void const *value, uint32_t valuelen);


/* 
 * Use this to insert a row with lots of data.
 * Call mdb_insert_continue as many times as necessary to provide the row data.
 * When all data has been provided, call mdb_insert_finalize.
 */
int mdb_insert_begin (MDB *db, uint8_t table, uint32_t valuelen);


int mdb_insert_continue (MDB *db, void const *data, size_t len);


/* NOTE: Sets the selected row to the inserted row. */
int mdb_insert_finalize (MDB *db);


/* Update the selected row */
int mdb_update (MDB *db, void const *value, uint32_t valuelen);


int mdb_update_begin (MDB *db, uint32_t valuelen);


int mdb_update_continue (MDB *db, void const *data, size_t len);


int mdb_update_finalize (MDB *db);


/* Delete the selected row */
int mdb_delete (MDB *db);


#endif
