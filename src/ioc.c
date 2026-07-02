#include <stdlib.h>
#include <string.h>

#include "ioc.h"

static int is_digit(char c) {
    return c >= '0' && c <= '9';
}

static int is_alnum(char c) {
    return is_digit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

/* Copies token[0..len) into the list as a NUL-terminated IOC. Returns 0 on
 * success, non-zero on allocation failure. */
static int append_ioc(ioc_list_t *list, ioc_kind_t kind, const char *token,
                      size_t len, long offset) {
    if (list->count == list->capacity) {
        size_t new_cap = (list->capacity == 0) ? 8 : list->capacity * 2;
        ioc_t *grown = realloc(list->items, new_cap * sizeof(ioc_t));
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
    memcpy(copy, token, len);
    copy[len] = '\0';

    list->items[list->count].kind = kind;
    list->items[list->count].text = copy;
    list->items[list->count].offset = offset;
    list->count++;
    return 0;
}

/* Strict IPv4 check on s[0..len): exactly four octets separated by single
 * dots, each 1-3 digits with value 0-255. Leading zeros ("010") are
 * accepted since they appear in real logs. */
static int is_valid_ipv4(const char *s, size_t len) {
    size_t pos = 0;

    for (int octet = 0; octet < 4; octet++) {
        if (octet > 0) {
            if (pos >= len || s[pos] != '.') {
                return 0;
            }
            pos++;  /* skip the separating dot */
        }

        /* Read 1-3 digits and accumulate the value. */
        int digits = 0;
        int value = 0;
        while (pos < len && is_digit(s[pos]) && digits < 3) {
            value = value * 10 + (s[pos] - '0');
            pos++;
            digits++;
        }
        if (digits == 0 || value > 255) {
            return 0;
        }
        /* A 4th consecutive digit ("1234.x.x.x") makes the octet invalid. */
        if (pos < len && is_digit(s[pos])) {
            return 0;
        }
    }

    return pos == len;  /* the whole candidate must be consumed */
}

/* Scans one extracted string for IPv4 addresses. A candidate is a maximal
 * run of digits and dots that does not start mid-number (the previous
 * character must not be a digit or a dot). Trailing dots are stripped so
 * "see 10.0.0.1." at the end of a sentence still matches. */
static int scan_string_for_ips(ioc_list_t *list, const char *s, long base_offset) {
    size_t i = 0;
    while (s[i] != '\0') {
        if (is_digit(s[i]) && (i == 0 || (!is_digit(s[i - 1]) && s[i - 1] != '.'))) {
            /* Walk to the end of the digits-and-dots run. */
            size_t j = i;
            while (s[j] == '.' || is_digit(s[j])) {
                j++;
            }
            /* Strip trailing dots ("10.0.0.1." -> "10.0.0.1"). */
            size_t k = j;
            while (k > i && s[k - 1] == '.') {
                k--;
            }
            if (is_valid_ipv4(s + i, k - i)) {
                if (append_ioc(list, IOC_IPV4, s + i, k - i, base_offset + (long)i) != 0) {
                    return 1;
                }
            }
            i = j;  /* skip the whole run, valid or not */
        } else {
            i++;
        }
    }
    return 0;
}

/* Case-insensitive check that s starts with lower_prefix (which must be
 * given in lowercase). Returns the prefix length on match, 0 otherwise. */
static size_t ci_prefix(const char *s, const char *lower_prefix) {
    size_t i = 0;
    for (; lower_prefix[i] != '\0'; i++) {
        char c = s[i];
        if (c >= 'A' && c <= 'Z') {
            c = (char)(c - 'A' + 'a');
        }
        if (c != lower_prefix[i]) {
            return 0;
        }
    }
    return i;
}

/* Characters that end a URL token. Extracted strings are printable ASCII,
 * so control characters never appear here. */
static int is_url_stop(char c) {
    return c == ' ' || c == '"' || c == '\'' || c == '<' || c == '>';
}

/* Punctuation that is more likely sentence/markup context than part of the
 * URL when it appears at the very end ("(see http://x.y)." etc.). */
static int is_trailing_punct(char c) {
    return c == '.' || c == ',' || c == ';' || c == ':' || c == '!' ||
           c == '?' || c == ')' || c == ']' || c == '}';
}

/* Scans one extracted string for http:// and https:// URLs. */
static int scan_string_for_urls(ioc_list_t *list, const char *s, long base_offset) {
    size_t i = 0;
    while (s[i] != '\0') {
        /* Candidate must not start mid-word ("shttp://..." is not a URL). */
        if ((s[i] == 'h' || s[i] == 'H') && (i == 0 || !is_alnum(s[i - 1]))) {
            size_t plen = ci_prefix(s + i, "https://");
            if (plen == 0) {
                plen = ci_prefix(s + i, "http://");
            }
            if (plen > 0) {
                /* Capture until a stop character or end of string. */
                size_t j = i + plen;
                while (s[j] != '\0' && !is_url_stop(s[j])) {
                    j++;
                }
                /* Trim trailing sentence punctuation. */
                size_t k = j;
                while (k > i + plen && is_trailing_punct(s[k - 1])) {
                    k--;
                }
                /* Require at least one character of host after "://". */
                if (k > i + plen) {
                    if (append_ioc(list, IOC_URL, s + i, k - i, base_offset + (long)i) != 0) {
                        return 1;
                    }
                }
                i = j;
                continue;
            }
        }
        i++;
    }
    return 0;
}

int scan_iocs(const string_list_t *strings, ioc_list_t *out) {
    out->items = NULL;
    out->count = 0;
    out->capacity = 0;

    for (size_t i = 0; i < strings->count; i++) {
        const extracted_string_t *es = &strings->items[i];
        if (scan_string_for_ips(out, es->text, es->offset) != 0 ||
            scan_string_for_urls(out, es->text, es->offset) != 0) {
            free_ioc_list(out);
            return 1;
        }
    }
    return 0;
}

void free_ioc_list(ioc_list_t *list) {
    for (size_t i = 0; i < list->count; i++) {
        free(list->items[i].text);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

const char *ioc_kind_name(ioc_kind_t kind) {
    switch (kind) {
        case IOC_IPV4: return "IPv4";
        case IOC_URL:  return "URL";
        default:       return "unknown";
    }
}
