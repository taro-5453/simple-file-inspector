#include <stddef.h>
#include <string.h>

#include "filetype.h"

/* One known magic-byte signature. `bytes` holds the fixed leading bytes to
 * match, and `len` is how many of them to compare. */
typedef struct {
    filetype_t type;
    const unsigned char *bytes;
    size_t len;
} signature_t;

/* Signature byte patterns. Kept as explicit byte arrays so non-printable
 * bytes (0x7f, 0x89, 0xFF, ...) are unambiguous. */
static const unsigned char SIG_PE[]   = {0x4D, 0x5A};                          /* "MZ" */
static const unsigned char SIG_ELF[]  = {0x7F, 0x45, 0x4C, 0x46};             /* 0x7f "ELF" */
static const unsigned char SIG_PDF[]  = {0x25, 0x50, 0x44, 0x46};             /* "%PDF" */
static const unsigned char SIG_ZIP[]  = {0x50, 0x4B, 0x03, 0x04};             /* "PK\x03\x04" */
static const unsigned char SIG_JPEG[] = {0xFF, 0xD8, 0xFF};                    /* JPEG SOI + marker */
static const unsigned char SIG_PNG[]  = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
static const unsigned char SIG_GZIP[] = {0x1F, 0x8B};                          /* gzip */

/* Signature table */
static const signature_t SIGNATURES[] = {
    {FT_PNG,  SIG_PNG,  sizeof(SIG_PNG)},   /* longest first, so more-specific */
    {FT_ELF,  SIG_ELF,  sizeof(SIG_ELF)},   /* signatures win over shorter ones */
    {FT_PDF,  SIG_PDF,  sizeof(SIG_PDF)},
    {FT_ZIP,  SIG_ZIP,  sizeof(SIG_ZIP)},
    {FT_JPEG, SIG_JPEG, sizeof(SIG_JPEG)},
    {FT_PE,   SIG_PE,   sizeof(SIG_PE)},
    {FT_GZIP, SIG_GZIP, sizeof(SIG_GZIP)},
};

filetype_t detect_filetype(const unsigned char *buf, long size) {
    if (buf == NULL || size <= 0) {
        return FT_UNKNOWN;
    }

    size_t n = sizeof(SIGNATURES) / sizeof(SIGNATURES[0]);
    for (size_t i = 0; i < n; i++) {
        const signature_t *sig = &SIGNATURES[i];
        /* Only compare if the file is at least as long as the signature. */
        if ((size_t)size >= sig->len &&
            memcmp(buf, sig->bytes, sig->len) == 0) {
            return sig->type;
        }
    }
    return FT_UNKNOWN;
}

void scan_embedded_signatures(const unsigned char *buf, long size, embedded_scan_t *out) {
    /* Start clean: no hits recorded. */
    out->total = 0;
    for (int t = 0; t < FT_COUNT; t++) {
        out->per_type[t].count = 0;
        out->per_type[t].first_offset = -1;
    }

    /* Nothing to scan past the header if the file is 0 or 1 byte. */
    if (buf == NULL || size <= 1) {
        return;
    }

    size_t n = sizeof(SIGNATURES) / sizeof(SIGNATURES[0]);

    /* Walk every offset from 1 onward (offset 0 is the header, already
     * reported by detect_filetype) and test each signature there. */
    for (long off = 1; off < size; off++) {
        for (size_t i = 0; i < n; i++) {
            const signature_t *sig = &SIGNATURES[i];
            /* Skip if the signature would run past the end of the buffer. */
            if ((size_t)(size - off) < sig->len) {
                continue;
            }
            if (memcmp(buf + off, sig->bytes, sig->len) == 0) {
                embedded_type_info_t *info = &out->per_type[sig->type];
                if (info->count == 0) {
                    info->first_offset = off;
                }
                info->count++;
                out->total++;
            }
        }
    }
}

const char *file_extension(const char *path) {
    if (path == NULL) {
        return NULL;
    }

    /* Find the start of the final path component (after the last '/'), so a
     * dot in a directory name like "my.dir/file" is not mistaken for one. */
    const char *base = path;
    for (const char *p = path; *p != '\0'; p++) {
        if (*p == '/') {
            base = p + 1;
        }
    }

    /* Find the last '.' within the basename. */
    const char *dot = NULL;
    for (const char *p = base; *p != '\0'; p++) {
        if (*p == '.') {
            dot = p;
        }
    }

    /* No dot at all; a leading dot (dotfile like ".bashrc"); or a trailing
     * dot ("name.") -> treat as having no usable extension. */
    if (dot == NULL || dot == base || *(dot + 1) == '\0') {
        return NULL;
    }
    return dot + 1;
}

filetype_t filetype_from_extension(const char *ext) {
    if (ext == NULL) {
        return FT_UNKNOWN;
    }

    /* Copy into a small lowercase buffer for case-insensitive comparison.
     * Any extension longer than this buffer is not one we recognize. */
    char low[16];
    size_t i = 0;
    for (; ext[i] != '\0' && i < sizeof(low) - 1; i++) {
        char c = ext[i];
        if (c >= 'A' && c <= 'Z') {
            c = (char)(c - 'A' + 'a');
        }
        low[i] = c;
    }
    low[i] = '\0';
    if (ext[i] != '\0') {
        return FT_UNKNOWN;  /* extension was too long to be one of ours */
    }

    /* Extensions whose name claims a type that has recognizable magic bytes.
     * Plain-text extensions (.txt, .csv, .c, ...) are intentionally absent:
     * they have no signature, so detect_filetype returns FT_UNKNOWN for them
     * and there is nothing to mismatch against. */
    static const struct {
        const char *ext;
        filetype_t type;
    } MAP[] = {
        {"exe", FT_PE}, {"dll", FT_PE}, {"sys", FT_PE}, {"scr", FT_PE},
        {"so", FT_ELF},
        {"pdf", FT_PDF},
        {"zip", FT_ZIP}, {"jar", FT_ZIP}, {"apk", FT_ZIP},
        {"docx", FT_ZIP}, {"xlsx", FT_ZIP}, {"pptx", FT_ZIP},
        {"jpg", FT_JPEG}, {"jpeg", FT_JPEG},
        {"png", FT_PNG},
        {"gz", FT_GZIP}, {"tgz", FT_GZIP},
    };

    size_t n = sizeof(MAP) / sizeof(MAP[0]);
    for (size_t k = 0; k < n; k++) {
        if (strcmp(low, MAP[k].ext) == 0) {
            return MAP[k].type;
        }
    }
    return FT_UNKNOWN;
}

const char *filetype_name(filetype_t type) {
    switch (type) {
        case FT_PE:   return "PE executable (MZ)";
        case FT_ELF:  return "ELF executable";
        case FT_PDF:  return "PDF document";
        case FT_ZIP:  return "ZIP archive / Office document";
        case FT_JPEG: return "JPEG image";
        case FT_PNG:  return "PNG image";
        case FT_GZIP: return "GZIP archive";
        case FT_UNKNOWN:
        default:      return "unknown";
    }
}
