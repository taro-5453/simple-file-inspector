#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "hashlist.h"
#include "sha256.h"

static char to_lower_hex(char c) {
    if (c >= 'A' && c <= 'F') {
        return (char)(c - 'A' + 'a');
    }
    return c;
}

static int is_hex_char(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

int hashlist_contains(const char *list_path, const char *hex_digest) {
    FILE *fp = fopen(list_path, "r");
    if (!fp) {
        fprintf(stderr, "Error: cannot open hash list '%s': %s\n",
                list_path, strerror(errno));
        return -1;
    }

    /* Long enough for a hash plus a comment/label on the same line. */
    char line[1024];
    int found = 0;

    while (found == 0 && fgets(line, sizeof(line), fp) != NULL) {
        /* Skip leading whitespace. */
        size_t i = 0;
        while (line[i] == ' ' || line[i] == '\t') {
            i++;
        }
        /* Skip blank lines and comments. */
        if (line[i] == '\0' || line[i] == '\n' || line[i] == '#') {
            continue;
        }

        /* The hash is the run of hex characters starting here; it must be
         * exactly 64 long to be a SHA-256. */
        size_t start = i;
        while (is_hex_char(line[i])) {
            i++;
        }
        if (i - start != SHA256_HEX_LEN) {
            continue;  /* not a SHA-256; ignore the line */
        }

        int match = 1;
        for (size_t k = 0; k < SHA256_HEX_LEN; k++) {
            if (to_lower_hex(line[start + k]) != hex_digest[k]) {
                match = 0;
                break;
            }
        }
        if (match) {
            found = 1;
        }
    }

    if (ferror(fp)) {
        fprintf(stderr, "Error: failed reading hash list '%s'\n", list_path);
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return found;
}
