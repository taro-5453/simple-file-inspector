#include <stdlib.h>
#include <string.h>

#include "strings.h"

/* Printable ASCII: space (0x20) through tilde (0x7E). */
static int is_printable_ascii(unsigned char c) {
    return c >= 0x20 && c <= 0x7E;
}

/* Copies buf[start .. start+len) into the list as a NUL-terminated string.
 * Returns 0 on success, non-zero on allocation failure. */
static int append_string(string_list_t *list, const unsigned char *buf,
                         long start, size_t len) {
    /* Grow the array when full (doubling, starting at 16). */
    if (list->count == list->capacity) {
        size_t new_cap = (list->capacity == 0) ? 16 : list->capacity * 2;
        extracted_string_t *grown =
            realloc(list->items, new_cap * sizeof(extracted_string_t));
        if (grown == NULL) {
            return 1;
        }
        list->items = grown;
        list->capacity = new_cap;
    }

    char *copy = malloc(len + 1);
    if (copy == NULL) {
        return 1;
    }
    memcpy(copy, buf + start, len);
    copy[len] = '\0';

    list->items[list->count].text = copy;
    list->items[list->count].offset = start;
    list->items[list->count].len = len;
    list->count++;
    return 0;
}

int extract_strings(const unsigned char *buf, long size, size_t min_len,
                    string_list_t *out) {
    out->items = NULL;
    out->count = 0;
    out->capacity = 0;

    if (buf == NULL || size <= 0 || min_len == 0) {
        return 0;
    }

    long run_start = -1;  /* -1 means "not currently inside a run" */

    for (long i = 0; i < size; i++) {
        if (is_printable_ascii(buf[i])) {
            if (run_start < 0) {
                run_start = i;  /* a new run begins here */
            }
        } else if (run_start >= 0) {
            /* Run ended at i (exclusive), so its length is i - run_start. */
            size_t len = (size_t)(i - run_start);
            if (len >= min_len) {
                if (append_string(out, buf, run_start, len) != 0) {
                    free_string_list(out);
                    return 1;
                }
            }
            run_start = -1;
        }
    }

    /* Flush a run still open at end-of-buffer: it spans
     * [run_start, size), length size - run_start. */
    if (run_start >= 0) {
        size_t len = (size_t)(size - run_start);
        if (len >= min_len) {
            if (append_string(out, buf, run_start, len) != 0) {
                free_string_list(out);
                return 1;
            }
        }
    }

    return 0;
}

void free_string_list(string_list_t *list) {
    for (size_t i = 0; i < list->count; i++) {
        free(list->items[i].text);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}
