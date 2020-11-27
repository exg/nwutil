#include "nwutil.h"

#include <fsdyn/charstr.h>

struct nwutil_uri {
    char *scheme;
    char *userinfo;
    char *host;
    char *path;
    char *query;
    char *fragment;
    int port;
};

static bool is_unreserved(const char *s)
{
    char c = *s;
    return (charstr_char_class(c) & CHARSTR_ALNUM) || c == '-' || c == '.' ||
        c == '_' || c == '~';
}

static bool is_pct_encoded(const char *s)
{
    return s[0] == '%' && (charstr_char_class(s[1]) & CHARSTR_HEX) &&
        (charstr_char_class(s[2]) & CHARSTR_HEX);
}

static bool is_sub_delim(const char *s)
{
    switch (*s) {
        case '!':
        case '$':
        case '&':
        case '\'':
        case '(':
        case ')':
        case '*':
        case '+':
        case ',':
        case ';':
        case '=':
            return true;
        default:
            return false;
    }
}

static const char *parse_pchar(const char *s)
{
    if (is_unreserved(s) || is_sub_delim(s) || *s == ':' || *s == '@')
        return s + 1;
    if (is_pct_encoded(s))
        return s + 3;
    return NULL;
}

static const char *parse_scheme(const char *s, char **scheme)
{
    const char *p = s;
    if (!(charstr_char_class(*p++) & CHARSTR_ALPHA))
        return NULL;
    while ((charstr_char_class(*p) & CHARSTR_ALNUM) || *p == '+' || *p == '-' ||
           *p == '.')
        p++;
    if (*p != ':')
        return NULL;
    *scheme = charstr_dupsubstr(s, p);
    return p + 1;
}

static const char *parse_userinfo(const char *s, char **userinfo)
{
    const char *p = s;
    for (;;) {
        if (is_unreserved(p) || is_sub_delim(p) || *p == ':')
            p++;
        else if (is_pct_encoded(p))
            p += 3;
        else
            break;
    }
    if (*p == '@') {
        *userinfo = charstr_dupsubstr(s, p);
        return p + 1;
    }
    *userinfo = NULL;
    return s;
}

static const char *parse_dec_octet(const char *s)
{
    char *end;
    long v = strtol(s, &end, 10);
    if (end == s || v < 0 || v > 255 || (end > s + 1 && *s == '0'))
        return NULL;
    return end;
}

static const char *parse_ipv4(const char *s)
{
    const char *p = parse_dec_octet(s);
    if (!p || *p != '.')
        return NULL;
    p = parse_dec_octet(p + 1);
    if (!p || *p != '.')
        return NULL;
    p = parse_dec_octet(p + 1);
    if (!p || *p != '.')
        return NULL;
    p = parse_dec_octet(p + 1);
    if (!p)
        return NULL;
    return p;
}

static const char *parse_h16(const char *s)
{
    int i = 0;
    while (i < 4 && (charstr_char_class(s[i]) & CHARSTR_HEX))
        i++;
    if (i == 0)
        return NULL;
    return s + i;
}

static const char *parse_h16_sequence(const char *s, unsigned *count)
{
    const char *p = s;
    unsigned i = 0;
    for (;;) {
        const char *next = parse_h16(p);
        if (!next || *next != ':')
            break;
        p = next + 1;
        i++;
    }
    *count = i;
    return p;
}

/*
 * This parser is based on the observation that the RFC 3986
 * IPv6address grammar can be written as follows:
 *
 * IPv6address = 7( h16 ":" ) h16
 *             / 6( h16 ":" ) IPV4address
 *             / ( m( h16 ":" ) / ":" ) ":" n( h16 ":" ) IPv4address ; m + n ≤ 5
 *             / ( m( h16 ":" ) / ":" ) ":" n( h16 ":" ) h16         ; m + n ≤ 6
 *             / 1*7( h16 ":" ) ":"
 */
static const char *parse_ipv6(const char *s)
{
    const char *next;
    unsigned m;
    const char *p = parse_h16_sequence(s, &m);
    if (m > 7)
        return NULL;
    switch (m) {
        case 7:
            next = parse_h16(p);
            if (next)
                return next;
            break;
        case 6:
            next = parse_ipv4(p);
            if (next)
                return next;
            break;
        case 0:
            if (*p != ':')
                return NULL;
            p++;
            break;
        default:
            break;
    }
    if (*p != ':')
        return NULL;
    unsigned n;
    p = parse_h16_sequence(p + 1, &n);
    if (m + n <= 5) {
        next = parse_ipv4(p);
        if (next)
            return next;
    }
    if (m + n <= 6) {
        next = parse_h16(p);
        if (next)
            return next;
    }
    if (m <= 7 && n == 0)
        return p;
    return NULL;
}

static const char *parse_zoneid(const char *s)
{
    const char *p = s;
    for (;;) {
        if (is_unreserved(p))
            p++;
        else if (is_pct_encoded(p))
            p += 3;
        else
            break;
    }
    if (p == s)
        return NULL;
    return p;
}

static const char *parse_host(const char *s, char **host)
{
    const char *p = parse_ipv4(s);
    if (p) {
        *host = charstr_dupsubstr(s, p);
        return p;
    }
    p = s;
    if (*p == '[') {
        p = parse_ipv6(p + 1);
        if (!p)
            return NULL;
        if (*p == '%' && p[1] == '2' && p[2] == '5') {
            p = parse_zoneid(p + 3);
            if (!p)
                return NULL;
        }
        if (*p != ']')
            return NULL;
        *host = charstr_dupsubstr(s + 1, p);
        return p + 1;
    }
    for (;;) {
        if (is_unreserved(p) || is_sub_delim(p))
            p++;
        else if (is_pct_encoded(p))
            p += 3;
        else
            break;
    }
    *host = charstr_dupsubstr(s, p);
    return p;
}

static const char *parse_port(const char *s, int *port)
{
    char *end;
    long _port = strtol(s, &end, 10);
    if (_port < 0 || _port > 65535)
        return NULL;
    *port = _port;
    return end;
}

static const char *parse_path(const char *s, char **path)
{
    const char *p = s;
    for (;;) {
        const char *next = parse_pchar(p);
        if (next)
            p = next;
        else if (*p == '/')
            p++;
        else
            break;
    }
    *path = charstr_dupsubstr(s, p);
    return p;
}

static const char *parse_query(const char *s, char **query)
{
    const char *p = s;
    for (;;) {
        const char *next = parse_pchar(p);
        if (next)
            p = next;
        else if (*p == '/' || *p == '?')
            p++;
        else
            break;
    }
    *query = charstr_dupsubstr(s, p);
    return p;
}

nwutil_uri_t *nwutil_parse_uri(const char *str)
{
    nwutil_uri_t *uri = fscalloc(1, sizeof *uri);
    uri->port = -1;
    const char *next = parse_scheme(str, &uri->scheme);
    if (!next)
        goto error;
    if (next[0] == '/' && next[1] == '/') {
        next = parse_userinfo(&next[2], &uri->userinfo);
        next = parse_host(next, &uri->host);
        if (!next)
            goto error;
        if (*next == ':') {
            next = parse_port(next + 1, &uri->port);
            if (!next)
                goto error;
        }
        next = parse_path(next, &uri->path);
        if (*uri->path && *uri->path != '/')
            goto error;
    } else
        next = parse_path(next, &uri->path);
    if (*next == '?')
        next = parse_query(next + 1, &uri->query);
    if (*next == '#')
        next = parse_query(next + 1, &uri->fragment);
    if (*next)
        goto error;

    return uri;

error:
    if (uri->scheme)
        fsfree(uri->scheme);
    if (uri->userinfo)
        fsfree(uri->userinfo);
    if (uri->host)
        fsfree(uri->host);
    if (uri->path)
        fsfree(uri->path);
    if (uri->query)
        fsfree(uri->query);
    if (uri->fragment)
        fsfree(uri->fragment);
    fsfree(uri);
    return NULL;
}

void nwutil_uri_destroy(nwutil_uri_t *uri)
{
    fsfree(uri->scheme);
    if (uri->userinfo)
        fsfree(uri->userinfo);
    if (uri->host)
        fsfree(uri->host);
    fsfree(uri->path);
    if (uri->query)
        fsfree(uri->query);
    if (uri->fragment)
        fsfree(uri->fragment);
    fsfree(uri);
}

const char *nwutil_uri_get_scheme(nwutil_uri_t *uri)
{
    return uri->scheme;
}

const char *nwutil_uri_get_userinfo(nwutil_uri_t *uri)
{
    return uri->userinfo;
}

const char *nwutil_uri_get_host(nwutil_uri_t *uri)
{
    return uri->host;
}

const char *nwutil_uri_get_path(nwutil_uri_t *uri)
{
    return uri->path;
}

const char *nwutil_uri_get_query(nwutil_uri_t *uri)
{
    return uri->query;
}

const char *nwutil_uri_get_fragment(nwutil_uri_t *uri)
{
    return uri->fragment;
}

bool nwutil_uri_get_port(nwutil_uri_t *uri, unsigned *port)
{
    if (uri->port != -1) {
        *port = uri->port;
        return true;
    }
    if (!charstr_case_cmp(uri->scheme, "http")) {
        *port = 80;
        return true;
    }
    if (!charstr_case_cmp(uri->scheme, "https")) {
        *port = 443;
        return true;
    }
    return false;
}
