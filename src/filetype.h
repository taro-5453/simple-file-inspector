#ifndef FILETYPE_H
#define FILETYPE_H

/* Detected file type, based on leading "magic" bytes. */
typedef enum {
    FT_UNKNOWN = 0,
    FT_PE,      /* MZ - DOS/Windows executable (PE) */
    FT_ELF,     /* \x7fELF - Linux/Unix executable */
    FT_PDF,     /* %PDF */
    FT_ZIP,     /* PK\x03\x04 - zip / Office / jar / apk */
    FT_JPEG,    /* FF D8 FF */
    FT_PNG,     /* \x89PNG\r\n\x1a\n */
    FT_GZIP,    /* \x1f\x8b */
    FT_COUNT    /* number of file types; keep last */
} filetype_t;

/* Per-type summary of embedded-signature matches (offset >= 1). */
typedef struct {
    long count;         /* how many times this signature appears past the header */
    long first_offset;  /* offset of the first occurrence, or -1 if none */
} embedded_type_info_t;

/* Result of scanning the whole buffer for signatures beyond the header. */
typedef struct {
    embedded_type_info_t per_type[FT_COUNT]; /* indexed by filetype_t */
    long total;                              /* total occurrences across all types */
} embedded_scan_t;

/* Inspects the leading bytes of buf and returns the detected file type,
 * or FT_UNKNOWN if no signature matches. Safe for short buffers. */
filetype_t detect_filetype(const unsigned char *buf, long size);

/* Returns a human-readable name for a file type, e.g. "PE executable". */
const char *filetype_name(filetype_t type);

/* Scans the entire buffer for known signatures appearing at offset >= 1
 * (i.e. beyond the header) and fills *out with per-type counts and offsets.
 * These are a hint at embedded/appended content (polyglots, hidden payloads);
 * short 2-byte signatures (MZ, GZIP) can match by chance, so treat with care. */
void scan_embedded_signatures(const unsigned char *buf, long size, embedded_scan_t *out);

/* Returns a pointer to the extension (the characters after the last '.' of
 * the final path component), or NULL if the file has no extension. Correctly
 * ignores dots in directory names and treats dotfiles like ".bashrc" and
 * names ending in '.' as having no extension. The returned pointer is into
 * `path`; do not free it. */
const char *file_extension(const char *path);

/* Maps a file extension (without the leading dot, case-insensitive) to the
 * file type its name claims to be, or FT_UNKNOWN for extensions we do not
 * map (including plain-text types that have no magic bytes). */
filetype_t filetype_from_extension(const char *ext);

#endif
