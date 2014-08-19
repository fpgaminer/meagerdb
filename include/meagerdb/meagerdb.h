/*
 * MeagerDB
 *
 *
 * An encrypted database designed for low memory footprint and simplicity of code.
 * Designed for use on RAM-limited systems (microcontrollers).
 * Designed to optimize for code simplicity first, read performance second, and write performance third.
 *
 *
 * Maximum row size is ~2**32 (less due to row header).
 *
 *
 * There is no rigid table structure.  The underlying database only supports a single, unnamed chunk of data
 * per row.  Columns are implemented as key-value stores per row.  That functionality is provided in keyvalue.h.
 * 
 * Of course, the application is welcome to implement its own functionality layered on top of the underlying
 * database.  For example, rigid table structure could be enforced by having a schema table store schema data,
 * and writing a new key-value store that obeys the respective table's schema.
 *
 *
 * Searching the database can be accomplished manually using mdb_walk, or using the included search
 * functionality found in search.h.
 */
#ifndef __MEAGER_DATABASE_DATABASE_H__
#define __MEAGER_DATABASE_DATABASE_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <meagerdb/errorcodes.h>


/* We require limits on some database properties, to fit the implementation into a reasonable amount
 * of RAM. */
#define MDB_DEFAULT_PAGE_SIZE 256
#define MDB_MAX_PAGE_SIZE 256


/* Create a MeagerDB at the given 'path', using the given 'password'. */
int mdb_create (char const *path, uint8_t const *password, size_t password_len);


int mdb_open (char const *path, uint8_t const *password, size_t password_len);


void mdb_close (void);


int mdb_walk (uint8_t table, bool restart);


int mdb_select_by_rowid (uint8_t table, uint32_t rowid);


int mdb_select_by_page (uint32_t page);


/* 
 * Reads the selected row's value into 'dst' and returns the length.
 * 'dst' may be NULL, to just get the value length.
 * Will not write more than 'maxlen' bytes to 'dst'.
 */
int64_t mdb_get_value (void *dst, size_t maxlen);


/* Read (len) bytes at (offset) from the selected row's value. */
int mdb_read_value (void *dst, uint32_t offset, size_t len);


/*
 * Get current row's rowid and tableid.
 */
int mdb_get_rowid (uint8_t *table, uint32_t *rowid);


/*
 * Get current row's page number.
 */
int mdb_get_page (uint32_t *page);


/* Return the next available (unused) rowid, or 0 on error. */
int mdb_get_next_rowid (uint8_t table, uint32_t *rowid);


/* NOTE: Sets the selected row to the inserted row. */
int mdb_insert (uint8_t table, void const *value, uint32_t valuelen);


/* 
 * Use this to insert a row with lots of data.
 * Call mdb_insert_continue as many times as necessary to provide the row data.
 * When all data has been provided, call mdb_insert_finalize.
 */
int mdb_insert_begin (uint8_t table, uint32_t valuelen);


int mdb_insert_continue (void const *data, size_t len);


/* NOTE: Sets the selected row to the inserted row. */
int mdb_insert_finalize (void);


int mdb_update_begin (uint32_t valuelen);


int mdb_update_continue (void const *data, size_t len);


int mdb_update_finalize (void);


/* Must select the row first with mdb_seek_* or mdb_walk */
int mdb_update (void const *value, uint32_t valuelen);


/* Must select the row first with mdb_seek_* or mdb_walk */
int mdb_delete (void);


#endif
