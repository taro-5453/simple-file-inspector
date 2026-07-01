#ifndef ENTROPY_H
#define ENTROPY_H

/* Computes the Shannon entropy of buf, in bits per byte (0.0-8.0).
 * Returns 0.0 for a NULL buffer or non-positive size. */
double compute_entropy(const unsigned char *buf, long size);

#endif
