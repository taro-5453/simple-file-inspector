#ifndef FILEINSPECT_H
#define FILEINSPECT_H

/* Shannon entropy above this (bits/byte, max 8) is flagged as possibly
 * packed/encrypted/compressed data. */
#define ENTROPY_HIGH_THRESHOLD 7.2

/* Minimum run of printable ASCII characters to count as a string. */
#define STRING_MIN_LEN 4

/* How many extracted strings to show before truncating the listing. */
#define STRING_PREVIEW_MAX 10

#endif
