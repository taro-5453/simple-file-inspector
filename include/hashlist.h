#ifndef HASHLIST_H
#define HASHLIST_H

/* Looks for hex_digest (64 lowercase hex chars) in a local hash-list file.
 * The list format is one SHA-256 hash per line; blank lines and lines
 * starting with '#' are ignored, hashes may be upper or lower case, and
 * anything after the hash on a line (e.g. a malware family name) is
 * ignored. Returns 1 if found, 0 if not found, -1 if the list file cannot
 * be opened or read (an error message is printed). */
int hashlist_contains(const char *list_path, const char *hex_digest);

#endif
