/* For isatty/fileno with -std=c11 on Linux. */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "entropy.h"
#include "fileinspect.h"
#include "filetype.h"
#include "hashlist.h"
#include "ioc.h"
#include "sha256.h"
#include "strings.h"

#define C_RESET  "\033[0m"
#define C_RED    "\033[31;1m"
#define C_YELLOW "\033[33m"
#define C_GREEN  "\033[32m"

/* Colors are used only when stdout is a terminal, so piped/redirected
 * output stays plain text. */
static int use_color;

static const char *color(const char *code) {
    return use_color ? code : "";
}

/* The "[!]" warning marker, yellow on a terminal. */
static const char *bang(void) {
    return use_color ? C_YELLOW "[!]" C_RESET : "[!]";
}

/* Prints a section header padded with dashes to a fixed width, e.g.
 * "---- Identity ------------------...". */
static void print_rule(const char *title) {
    int len = printf("---- %s ", title);
    while (len++ < 60) {
        putchar('-');
    }
    putchar('\n');
}

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [--hashlist <list-file>] <path-to-file>\n", prog);
    fprintf(stderr, "       %s --help\n", prog);
}

static void print_help(const char *prog) {
    printf("fileinspect - defensive file triage tool\n\n");
    printf("Usage: %s [--hashlist <list-file>] <path-to-file>\n\n", prog);
    printf("Inspects a single file and prints a security-focused risk summary:\n");
    printf("  - magic-byte file-type detection\n");
    printf("  - extension-vs-content mismatch\n");
    printf("  - Shannon entropy\n");
    printf("  - file size\n");
    printf("  - SHA-256 fingerprint\n");
    printf("  - printable string extraction\n");
    printf("  - IOC (IP/URL) scanning\n\n");
    printf("Options:\n");
    printf("  --hashlist <list-file>  compare the file's SHA-256 against a local\n");
    printf("                          list of known-bad hashes (one hex hash per\n");
    printf("                          line; '#' comments and blank lines ignored)\n");
    printf("  -h, --help              show this help\n\n");
    printf("The tool never touches the network; hash lookups are against the\n");
    printf("local list file only.\n");
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

static void print_ascii_art() {
    printf("                                                                                      __\n");
    printf("  ___ _            _       ___ _ _       ___                      _                -=(o '.\n");
    printf(" / __(_)_ __  _ __| |___  | __(_) |___  |_ _|_ _  ____ __  ___ __| |_ ___ _ _         '.-.\\ \n");
    printf(" \\__ \\ | '  \\| '_ \\ / -_) | _|| | / -_)  | || ' \\(_-< '_ \\/ -_) _|  _/ _ \\ '_|        /|  \\\\ \n");
    printf(" |___/_|_|_|_| .__/_\\___| |_| |_|_\\___| |___|_||_/__/ .__/\\___\\__|\\__\\___/_|          '|  || \n");
    printf("             |_|                                    |_|                                _\\_):,_ \n");
    printf("\n\n");

}

int main(int argc, char *argv[]) {
    // Parse arguments: one input file plus optional --hashlist <file>
    const char *path = NULL;
    const char *hashlist_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--hashlist") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --hashlist requires a file argument.\n");
                print_usage(argv[0]);
                return 1;
            }
            hashlist_path = argv[++i];
        } else if (argv[i][0] == '-' && argv[i][1] != '\0') {
            fprintf(stderr, "Error: unknown option '%s'.\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        } else if (path == NULL) {
            path = argv[i];
        } else {
            fprintf(stderr, "Error: only one input file may be given.\n");
            print_usage(argv[0]);
            return 1;
        }
    }

    if (path == NULL) {
        print_usage(argv[0]);
        return 1;
    }

    use_color = isatty(fileno(stdout));

    // Load file into the buffer
    unsigned char *buf = NULL;
    long size = 0;

    if (read_file(path, &buf, &size) != 0) {
        return 1;
    }
    int is_empty = (size == 0);

    print_ascii_art();

    // ---- Run every check first; all printing happens afterwards. ----

    // SHA-256 fingerprint (+ optional lookup in a local known-bad list).
    // Purely offline: the hash identifies the content; renaming the file
    // does not change it.
    unsigned char digest[SHA256_DIGEST_LEN];
    char hex[SHA256_HEX_LEN + 1];
    sha256(buf, (size_t)size, digest);
    sha256_hex(digest, hex);

    int hash_match = 0;
    if (hashlist_path != NULL) {
        int r = hashlist_contains(hashlist_path, hex);
        if (r < 0) {
            free(buf);
            return 1;
        }
        hash_match = (r == 1);
    }

    // Detect file type and embedded signatures
    filetype_t type = detect_filetype(buf, size);

    embedded_scan_t emb;
    scan_embedded_signatures(buf, size, &emb);
    long emb_reliable = 0;  /* embedded hits from signatures >= 3 bytes */
    long emb_weak = 0;      /* embedded hits from 2-byte signatures (MZ/GZIP) */
    for (int t = 1; t < FT_COUNT; t++) {
        if (emb.per_type[t].count > 0) {
            if (filetype_sig_len((filetype_t)t) >= 3) {
                emb_reliable += emb.per_type[t].count;
            } else {
                emb_weak += emb.per_type[t].count;
            }
        }
    }

    // Extension vs content (Does the file name match what the bytes say?)
    const char *ext = file_extension(path);
    filetype_t expected = filetype_from_extension(ext);
    int mismatch_strong = 0;  /* named one known type, content is another */
    int mismatch_soft = 0;    /* named a known type, but its signature is absent */
    if (expected != FT_UNKNOWN && type != expected) {
        if (type != FT_UNKNOWN) {
            mismatch_strong = 1;
        } else {
            mismatch_soft = 1;
        }
    }

    // Shannon entropy score
    double entropy = compute_entropy(buf, size);
    int high_entropy = (!is_empty && entropy > ENTROPY_HIGH_THRESHOLD);

    // Printable strings (runs of ASCII >= STRING_MIN_LEN chars)
    string_list_t strings;
    if (extract_strings(buf, size, STRING_MIN_LEN, &strings) != 0) {
        fprintf(stderr, "Error: out of memory extracting strings from '%s'\n", path);
        free(buf);
        return 1;
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

    // ---- Report ----

    print_rule("Identity");
    printf("%-14s %s\n", "Path", path);
    if (is_empty) {
        printf("%-14s 0 bytes %s empty\n", "Size", bang());
    } else {
        printf("%-14s %ld bytes\n", "Size", size);
    }
    printf("%-14s %s\n", "SHA-256", hex);
    if (hashlist_path != NULL) {
        if (hash_match) {
            printf("%-14s %s %sMATCH - known-bad hash%s (%s)\n", "Hash list",
                   bang(), color(C_RED), color(C_RESET), hashlist_path);
        } else {
            printf("%-14s no match (%s)\n", "Hash list", hashlist_path);
        }
    }
    printf("%-14s %s\n", "Type (magic)", filetype_name(type));
    if (expected != FT_UNKNOWN && type == expected) {
        printf("%-14s .%s (matches content)\n", "Extension", ext);
    } else if (mismatch_strong) {
        printf("%-14s .%s %s content is %s\n", "Extension", ext, bang(),
               filetype_name(type));
    } else if (mismatch_soft) {
        printf("%-14s .%s %s no %s signature present\n", "Extension", ext,
               bang(), filetype_name(expected));
    } else if (ext != NULL) {
        printf("%-14s .%s\n", "Extension", ext);
    } else {
        printf("%-14s none\n", "Extension");
    }

    printf("\n");
    print_rule("Content signals");
    if (is_empty) {
        printf("%-14s n/a (empty file)\n", "Entropy");
    } else if (high_entropy) {
        printf("%-14s %.4f bits/byte %s high (> %.1f) - possibly packed or encrypted\n",
               "Entropy", entropy, bang(), ENTROPY_HIGH_THRESHOLD);
    } else {
        printf("%-14s %.4f bits/byte (normal range)\n", "Entropy", entropy);
    }
    if (emb.total > 0) {
        printf("%-14s %s %ld hit(s) past the header\n", "Embedded sigs",
               bang(), emb.total);
        for (int t = 1; t < FT_COUNT; t++) {
            if (emb.per_type[t].count > 0) {
                printf("               - %-29s x%-4ld first at offset %ld\n",
                       filetype_name((filetype_t)t),
                       emb.per_type[t].count,
                       emb.per_type[t].first_offset);
            }
        }
        if (emb_weak > 0) {
            printf("               note: 2-byte signatures (MZ, GZIP) can match by\n");
            printf("               chance - a hint to look closer, not proof\n");
        }
    } else {
        printf("%-14s none past the header\n", "Embedded sigs");
    }

    printf("\n");
    print_rule("Strings");
    printf("%zu printable string(s) of length >= %d", strings.count, STRING_MIN_LEN);
    size_t shown = strings.count;
    if (shown > STRING_PREVIEW_MAX) {
        shown = STRING_PREVIEW_MAX;
        printf(" (showing first %d)", STRING_PREVIEW_MAX);
    }
    printf("\n");
    for (size_t i = 0; i < shown; i++) {
        printf("  %8ld  %s\n", strings.items[i].offset, strings.items[i].text);
    }
    if (strings.count > shown) {
        printf("  ... and %zu more\n", strings.count - shown);
    }

    printf("\n");
    print_rule("IOCs");
    if (iocs.count == 0) {
        printf("none found\n");
    } else {
        printf("%zu IPv4 address(es), %zu URL(s)\n", n_ip, n_url);
        size_t ioc_shown = iocs.count;
        if (ioc_shown > IOC_PREVIEW_MAX) {
            ioc_shown = IOC_PREVIEW_MAX;
        }
        for (size_t i = 0; i < ioc_shown; i++) {
            printf("  %8ld  %-4s  %s\n", iocs.items[i].offset,
                   ioc_kind_name(iocs.items[i].kind), iocs.items[i].text);
        }
        if (iocs.count > ioc_shown) {
            printf("  ... and %zu more (showing first %d)\n",
                   iocs.count - ioc_shown, IOC_PREVIEW_MAX);
        }
    }

    // Risk summary: weigh the signals the checks above collected.
    // Hash match and strong mismatch count double (direct evidence);
    // everything else is circumstantial and counts once.
    printf("\n");
    print_rule("Risk summary (weight of evidence)");
    int score = 0;
    if (hash_match) {
        printf("  [+2] SHA-256 present in known-bad hash list\n");
        score += 2;
    }
    if (is_empty) {
        printf("  [+1] Empty file: 0 bytes where content was expected\n");
        score += 1;
    }
    if (mismatch_strong) {
        printf("  [+2] Extension mismatch: named .%s but content is %s\n",
               ext, filetype_name(type));
        score += 2;
    } else if (mismatch_soft) {
        printf("  [+1] Extension mismatch: named .%s but no %s signature present\n",
               ext, filetype_name(expected));
        score += 1;
    }
    if (high_entropy) {
        printf("  [+1] High entropy: %.4f bits/byte - possibly packed or encrypted\n",
               entropy);
        score += 1;
    }
    if (emb_reliable > 0) {
        printf("  [+1] Embedded signature(s) past the header (%ld reliable hit(s))\n",
               emb_reliable);
        score += 1;
    }
    if (n_ip + n_url > 0) {
        printf("  [+1] Network IOCs present (%zu IPv4, %zu URL)\n", n_ip, n_url);
        score += 1;
    }
    if (emb_weak > 0 && emb_reliable == 0) {
        printf("  [ 0] 2-byte signature hit(s) past the header (%ld) - possible\n",
               emb_weak);
        printf("       chance matches, not scored\n");
    }
    if (score == 0) {
        printf("  No scored signals fired.\n");
    }

    const char *verdict;
    const char *vcol;
    if (score == 0) {
        verdict = "CLEAN";
        vcol = C_GREEN;
    } else if (score == 1) {
        verdict = "WORTH A LOOK";
        vcol = C_YELLOW;
    } else {
        verdict = "SUSPICIOUS";
        vcol = C_RED;
    }
    printf("\n%sVerdict: %s (score %d)%s\n", color(vcol), verdict, score,
           color(C_RESET));

    free_ioc_list(&iocs);
    free_string_list(&strings);
    free(buf);
    return 0;
}
