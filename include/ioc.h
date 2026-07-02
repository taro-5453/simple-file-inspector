#ifndef IOC_H
#define IOC_H

#include <stddef.h>

#include "strings.h"

/* Kinds of indicators of compromise we can extract. */
typedef enum {
    IOC_IPV4,
    IOC_URL
} ioc_kind_t;

/* One IOC found inside an extracted string. */
typedef struct {
    ioc_kind_t kind;
    char *text;   /* NUL-terminated heap copy of the IOC token */
    long offset;  /* byte offset in the file where the token starts */
} ioc_t;

/* Growable list of IOCs. */
typedef struct {
    ioc_t *items;
    size_t count;
    size_t capacity;
} ioc_list_t;

/* Scans every extracted string for IPv4 addresses (four dot-separated
 * octets, each 0-255) and http/https URLs. Fills *out (caller passes an
 * uninitialized struct). Returns 0 on success, non-zero on allocation
 * failure (in which case *out is left empty and needs no freeing). */
int scan_iocs(const string_list_t *strings, ioc_list_t *out);

/* Frees every IOC in the list and the list's own storage. */
void free_ioc_list(ioc_list_t *list);

/* Returns a short label for an IOC kind, e.g. "IPv4" or "URL". */
const char *ioc_kind_name(ioc_kind_t kind);

#endif
