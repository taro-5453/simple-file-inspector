#ifndef STRINGS_H
#define STRINGS_H

#include <stddef.h>

/* One printable-ASCII run found in the file. */
typedef struct {
    char *text;   /* NUL-terminated heap copy of the run */
    long offset;  /* byte offset in the file where the run starts */
    size_t len;   /* length in characters (excluding the NUL) */
} extracted_string_t;

/* Growable list of extracted strings. */
typedef struct {
    extracted_string_t *items;
    size_t count;
    size_t capacity;
} string_list_t;

/* Walks the buffer and collects every run of printable ASCII characters
 * (0x20..0x7E) of at least min_len characters, including a run that ends
 * exactly at the end of the buffer. Fills *out (caller passes an
 * uninitialized struct). Returns 0 on success, non-zero on allocation
 * failure (in which case *out is left empty and needs no freeing). */
int extract_strings(const unsigned char *buf, long size, size_t min_len,
                    string_list_t *out);

/* Frees every string in the list and the list's own storage. Safe to call
 * on an empty list. */
void free_string_list(string_list_t *list);

#endif
