#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "entropy.h"
#include "fileinspect.h"
#include "filetype.h"
#include "ioc.h"
#include "strings.h"

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s <path-to-file>\n", prog);
    fprintf(stderr, "       %s --help\n", prog);
}

static void print_help(const char *prog) {
    printf("fileinspect - defensive file triage tool\n\n");
    printf("Usage: %s <path-to-file>\n\n", prog);
    printf("Inspects a single file and prints a security-focused risk summary:\n");
    printf("  - magic-byte file-type detection\n");
    printf("  - extension-vs-content mismatch\n");
    printf("  - Shannon entropy\n");
    printf("  - file size\n");
    printf("  - printable string extraction\n");
    printf("  - IOC (IP/URL) scanning\n");
}

/* Reads the whole file into a heap buffer. On success, *out_buf points to a
 * malloc'd buffer of *out_size bytes (caller must free) and returns 0.
 * On failure, prints an error and returns non-zero. *out_buf is left NULL
 * when the file is empty (size 0). */
static int read_file(const char *path, unsigned char **out_buf, long *out_size) {
    FILE *fp = fopen(path, "rb");
    // Open file failed
    if (!fp) {
        fprintf(stderr, "Error: cannot open '%s': %s\n", path, strerror(errno));
        return 1;
    }

    // Move file pointer to the end of file
    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "Error: cannot seek '%s': %s\n", path, strerror(errno));
        fclose(fp);
        return 1;
    }

    // Get the file size (byte)
    long size = ftell(fp);
    if (size < 0) {
        fprintf(stderr, "Error: cannot determine size of '%s': %s\n", path, strerror(errno));
        fclose(fp);
        return 1;
    }

    // Move file pointer back to the beginning
    rewind(fp);

    // 
    unsigned char *buf = NULL;
    if (size > 0) {
        buf = malloc((size_t)size);
        if (!buf) {
            fprintf(stderr, "Error: out of memory reading '%s' (%ld bytes)\n", path, size);
            fclose(fp);
            return 1;
        }
        size_t read_bytes = fread(buf, 1, (size_t)size, fp);
        if (read_bytes != (size_t)size) {
            fprintf(stderr, "Error: short read on '%s' (expected %ld bytes, got %zu)\n",
                    path, size, read_bytes);
            free(buf);
            fclose(fp);
            return 1;
        }
    }

    fclose(fp);
    *out_buf = buf;
    *out_size = size;
    return 0;
}

int main(int argc, char *argv[]) {
    // Validation
    if (argc != 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_help(argv[0]);
        return 0;
    }

    // Load file into the buffer
    const char *path = argv[1];
    unsigned char *buf = NULL;
    long size = 0;

    if (read_file(path, &buf, &size) != 0) {
        return 1;
    }

    printf("File: %s\n", path);
    printf("Size: %ld bytes\n", size);

    if (size == 0) {
        printf("[!] Empty file (0 bytes) - nothing to inspect.\n");
        return 0;
    }

    // Detect file type and embedded
    filetype_t type = detect_filetype(buf, size);
    printf("Detected type: %s\n", filetype_name(type));

    embedded_scan_t emb;
    scan_embedded_signatures(buf, size, &emb);
    if (emb.total > 0) {
        printf("[!] Embedded signatures found past the header (%ld total):\n", emb.total);
        for (int t = 1; t < FT_COUNT; t++) {
            if (emb.per_type[t].count > 0) {
                printf("      - %s x%ld (first at offset %ld)\n",
                       filetype_name((filetype_t)t),
                       emb.per_type[t].count,
                       emb.per_type[t].first_offset);
            }
        }
        printf("      Note: short 2-byte signatures (MZ, GZIP) can appear by chance;\n");
        printf("      treat these as a hint to look closer, not proof of an embedded file.\n");
    }

    // Extension vs content (Does the file name match what the bytes say?)
    const char *ext = file_extension(path);
    filetype_t expected = filetype_from_extension(ext);
    if (expected != FT_UNKNOWN) {
        if (type == expected) {
            printf("Extension: .%s (matches content)\n", ext);
        } else if (type != FT_UNKNOWN) {
            printf("[!] Extension mismatch: file is named .%s but content is %s.\n",
                   ext, filetype_name(type));
        } else {
            printf("[!] Extension mismatch: file is named .%s but no %s signature was found.\n",
                   ext, filetype_name(expected));
        }
    } else if (ext != NULL) {
        printf("Extension: .%s (no signature to expect)\n", ext);
    } else {
        printf("Extension: none\n");
    }

    // Shannon entropy score
    double entropy = compute_entropy(buf, size);
    printf("Entropy: %.4f bits/byte\n", entropy);
    if (entropy > ENTROPY_HIGH_THRESHOLD) {
        printf("[!] High entropy (> %.1f) - possibly packed, compressed, or encrypted.\n",
               ENTROPY_HIGH_THRESHOLD);
    }

    // Printable strings (runs of ASCII >= STRING_MIN_LEN chars)
    string_list_t strings;
    if (extract_strings(buf, size, STRING_MIN_LEN, &strings) != 0) {
        fprintf(stderr, "Error: out of memory extracting strings from '%s'\n", path);
        free(buf);
        return 1;
    }
    printf("Strings: %zu printable string(s) of length >= %d\n",
           strings.count, STRING_MIN_LEN);
    size_t shown = strings.count;
    if (shown > STRING_PREVIEW_MAX) {
        shown = STRING_PREVIEW_MAX;
    }
    for (size_t i = 0; i < shown; i++) {
        printf("      [offset %6ld] %s\n", strings.items[i].offset,
               strings.items[i].text);
    }
    if (strings.count > shown) {
        printf("      ... and %zu more (showing first %d)\n",
               strings.count - shown, STRING_PREVIEW_MAX);
    }

    // IOC scan (IPv4 addresses and http/https URLs inside the strings)
    ioc_list_t iocs;
    if (scan_iocs(&strings, &iocs) != 0) {
        fprintf(stderr, "Error: out of memory scanning IOCs in '%s'\n", path);
        free_string_list(&strings);
        free(buf);
        return 1;
    }
    size_t n_ip = 0, n_url = 0;
    for (size_t i = 0; i < iocs.count; i++) {
        if (iocs.items[i].kind == IOC_IPV4) {
            n_ip++;
        } else {
            n_url++;
        }
    }
    printf("IOCs: %zu IPv4 address(es), %zu URL(s)\n", n_ip, n_url);
    size_t ioc_shown = iocs.count;
    if (ioc_shown > IOC_PREVIEW_MAX) {
        ioc_shown = IOC_PREVIEW_MAX;
    }
    for (size_t i = 0; i < ioc_shown; i++) {
        printf("      [offset %6ld] %-4s %s\n", iocs.items[i].offset,
               ioc_kind_name(iocs.items[i].kind), iocs.items[i].text);
    }
    if (iocs.count > ioc_shown) {
        printf("      ... and %zu more (showing first %d)\n",
               iocs.count - ioc_shown, IOC_PREVIEW_MAX);
    }

    free_ioc_list(&iocs);
    free_string_list(&strings);
    free(buf);
    return 0;
}
