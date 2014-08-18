#ifndef __MEAGERDB_ERRORCODES_H__
#define __MEAGERDB_ERRORCODES_H__

enum {
	MDBE_FOPEN = -2,           /* fopen failed */
	MDBE_IO = -3,                      /* IO error */
	MDBE_NOT_MDB = -4,         /* File is not a Meager DB */
	MDBE_BAD_VERSION = -4,     /* Incompatible MDB version */
	MDBE_ALREADY_OPEN = -5,    /* A database is already open */
	MDBE_BAD_PAGE_SIZE = -6,   /* Bad database page size */
	MDBE_BAD_KEY_DERIVE = -7,  /* Incompatible key derivation function */
	MDBE_CORRUPT = -8,         /* Database file is corrupted */
	MDBE_BAD_PASSWORD = -9,    /* Wrong password specified */
	MDBE_UNSUPPORTED_PAGE_SIZE = -10,  /* Page size is not supported */
	MDBE_FULL = -11,                   /* Database is full */
	MDBE_ROW_NOT_FOUND = -12,          /* Row not found */
	MDBE_UNKNOWN_COLUMN = -13,         /* Unknown column specified for current row */
	MDBE_DATA_TOO_BIG = -14,           /* Requested data won't fit into destination */
	MDBE_NO_ROW_SELECTED = -15,        /* Must select a row before calling this function */
	MDBE_NOT_OPEN = -16,               /* Must open database before calling this function */
	MDBE_NOT_ENOUGH_DATA = -17,        /* Requested data is larger than value's length */
};

#endif
