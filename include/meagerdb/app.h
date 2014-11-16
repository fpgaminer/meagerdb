/* These must be provided by the application. */
#ifndef __MEAGER_DB_APP_H__
#define __MEAGER_DB_APP_H__


#include <stdint.h>
#include <stdlib.h>


/* Filesystem */
int mdba_open (char const *path, int flags);

int mdba_close (int fd);

/* Must read count bytes, otherwise consider it a failure.  Return -1 on failure, 0 on success. */
int mdba_read (int fd, void *buf, size_t count);

/* Must write count bytes, otherwise consider it a failure.  Return -1 on failure, 0 on success. */
int mdba_write (int fd, void const *buf, size_t count);

/* Return -1 on failure, 0 on success. */
int mdba_lseek (int fd, uint64_t offset, int whence);

int mdba_fsync (int fd);


/* Misc */
void mdba_read_urandom (void *dst, size_t len);

void mdba_fatal_error (void);


#endif
