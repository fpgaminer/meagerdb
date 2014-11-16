#ifndef __MEAGERDB_ERRORCODES_H__
#define __MEAGERDB_ERRORCODES_H__

enum {
	/* -1 should never be returned, unless there was an internal error or you've done something
	 * horribly wrong. */
	MDBE_OPEN = -2,                    /* open failed */
	MDBE_IO = -3,                      /* IO error */
	MDBE_NOT_MDB = -4,                 /* File is not a Meager DB */
	MDBE_BAD_VERSION = -5,             /* Incompatible MDB version */
	MDBE_ALREADY_OPEN = -6,            /* A database is already open */
	MDBE_BAD_PAGE_SIZE = -7,           /* Bad database page size */
	MDBE_BAD_KEY_DERIVE = -8,          /* Incompatible key derivation function */
	MDBE_CORRUPT = -9,                 /* Database file is corrupted */
	MDBE_BAD_PASSWORD = -10,           /* Wrong password specified */
	MDBE_UNSUPPORTED_PAGE_SIZE = -11,  /* Page size is not supported */
	MDBE_FULL = -12,                   /* Database is full */
	MDBE_ROW_NOT_FOUND = -13,          /* Row not found */
	MDBE_BUSY = -14,                   /* e.g. calling insert_begin when an insert is in progress */
	MDBE_DATA_TOO_BIG = -15,           /* Requested data won't fit into destination */
	MDBE_NO_ROW_SELECTED = -16,        /* Must select a row before calling this function */
	MDBE_NOT_OPEN = -17,               /* Must open database before calling this function */
	MDBE_NOT_ENOUGH_DATA = -18,        /* Requested data is larger than value's length */
	MDBE_BAD_ARGUMENT = -19,           /* A bad argument was passed to the function */
	MDBE_BAD_TYPE = -20,               /* Key-Value: Value is not of the requested type */
	MDBE_NOT_FOUND = -21,              /* */
	MDBE_UNSUPPORTED_CIPHER = -22,     /* Ciphersuite is not supported */
};

#endif
