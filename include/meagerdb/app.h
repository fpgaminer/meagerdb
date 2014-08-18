/* These must be provided by the application. */
#ifndef __MEAGER_DB_APP_H__
#define __MEAGER_DB_APP_H__


#include <stdint.h>


/* Filesystem */
void *mdba_fopen (char const *path, char const *mode);

int mdba_fclose (void *fp);

size_t mdba_fread (void *dst, size_t size, size_t nmemb, void *stream);

size_t mdba_fwrite (void const *src, size_t size, size_t nmemb, void *stream);

int mdba_fseek (void *stream, int64_t offset, int whence);

int mdba_fflush (void *stream);


/* Misc */
void mdba_read_urandom (void *dst, size_t len);

void mdba_fatal_error (void);


#endif
