#include <math.h>
#include <stddef.h>

#include "entropy.h"

double compute_entropy(const unsigned char *buf, long size) {
    // Validation
    if (buf == NULL || size <= 0) {
        return 0.0;
    }

    // Count byte freqeuncy
    long counts[256] = {0};
    for (long i = 0; i < size; i++) {
        counts[buf[i]]++;
    }

    // Apply Shannon entropy formula
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] == 0) {
            continue;
        }
        double p = (double)counts[i] / (double)size;
        entropy -= p * log2(p);
    }
    return entropy;
}
