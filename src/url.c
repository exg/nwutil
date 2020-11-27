#include "nwutil.h"

#include <fsdyn/bytearray.h>
#include <fsdyn/charstr.h>

#include <string.h>

typedef enum {
    SCHEME_FILE,
    SCHEME_FTP,
    SCHEME_HTTP,
    SCHEME_HTTPS,
    SCHEME_WS,
    SCHEME_WSS,
    SCHEME_NOT_SPECIAL,
} scheme_type_t;

static scheme_type_t get_scheme_type(const char *scheme)
{
    if (!strcmp(scheme, "file"))
        return SCHEME_FILE;
    if (!strcmp(scheme, "ftp"))
        return SCHEME_FTP;
    if (!strcmp(scheme, "http"))
        return SCHEME_HTTP;
    if (!strcmp(scheme, "https"))
        return SCHEME_HTTPS;
    if (!strcmp(scheme, "ws"))
        return SCHEME_WS;
    if (!strcmp(scheme, "wss"))
        return SCHEME_WSS;
    return SCHEME_NOT_SPECIAL;
}

static int get_scheme_default_port(scheme_type_t scheme_type)
{
    switch (scheme_type) {
        case SCHEME_FTP:
            return 21;
        case SCHEME_HTTP:
        case SCHEME_WS:
            return 80;
        case SCHEME_HTTPS:
        case SCHEME_WSS:
            return 443;
        default:
            return -1;
    }
}

struct nwutil_url {
    bool base;
    scheme_type_t scheme_type;
    char *scheme;
    char *username;
    char *password;
    char *host;
    char *path;
    char *query;
    char *fragment;
    int port;
};

typedef enum {
    PARSER_SCHEME_START,
    PARSER_SCHEME,
    PARSER_SPECIAL,
    PARSER_NOT_SPECIAL,
    PARSER_NO_SCHEME,
    PARSER_SPECIAL_REL_OR_AUTH,
    PARSER_PATH_OR_AUTH,
    PARSER_REL,
    PARSER_REL_SLASH,
    PARSER_SPECIAL_AUTH,
    PARSER_AUTH,
    PARSER_HOST,
    PARSER_PORT,
    PARSER_FILE,
    PARSER_FILE_SLASH,
    PARSER_FILE_HOST,
    PARSER_PATH_START,
    PARSER_PATH,
    PARSER_NON_BASE_PATH,
    PARSER_QUERY,
    PARSER_FRAGMENT,
} url_parser_state_t;

typedef enum {
    PATH_REL_NONE,
    PATH_REL_BASE,
    PATH_REL_BASE_DRIVE,
} path_type_t;

typedef struct {
    url_parser_state_t state;
    const char *input;
    nwutil_url_t *base;
    bool error;
    size_t cursor;
    const void *state_data;
    byte_array_t *buffer;
    path_type_t path_type;
    list_t *path;
    nwutil_url_t *url;
} url_parser_t;

static const int EOS = -1;

static bool parse_ipv4_pass1(const char *str, long long fields[4], size_t *size)
{
    const char *p;
    *size = 0;
    for (p = str;; p++) {
        char *end;
        int base = 10;
        if (p[0] == '0') {
            if (charstr_lcase_char(p[1]) == 'x') {
                base = 16;
                p += 2;
            } else if (p[1]) {
                base = 8;
                p++;
            }
        }
        long long value = strtoll(p, &end, base);
        if (value < 0)
            return false;
        if (end == p && base == 10)
            break;
        p = end;
        fields[(*size)++] = value;
        if (*size == 4 || *p == '\0')
            break;
        if (*p != '.')
            return false;
    }
    if (*size == 0 || *p)
        return false;
    return true;
}

static bool parse_ipv4_pass2(long long *fields, size_t size, uint32_t *address)
{
    if (fields[size - 1] >= (1ULL << (8 * (5 - size))))
        return false;
    *address = fields[size - 1];
    for (int i = 0; i < size - 1; i++) {
        if (fields[i] > 255)
            return false;
        *address += fields[i] << (8 * (3 - i));
    }
    return true;
}

static const char *parse_dec_octet(const char *str, uint8_t *value)
{
    char *end;
    long v = strtol(str, &end, 10);
    if (end == str || (end > str + 1 && *str == '0') || v < 0 || v > 255)
        return NULL;
    *value = v;
    return end;
}

static const char *parse_ipv6_ipv4(const char *str, uint8_t address[4])
{
    const char *p = parse_dec_octet(str, &address[0]);
    if (!p || *p != '.')
        return NULL;
    p = parse_dec_octet(p + 1, &address[1]);
    if (!p || *p != '.')
        return NULL;
    p = parse_dec_octet(p + 1, &address[2]);
    if (!p || *p != '.')
        return NULL;
    p = parse_dec_octet(p + 1, &address[3]);
    if (!p)
        return NULL;
    return p;
}

static const char *parse_h16(const char *str, uint16_t *value)
{
    char *end;
    long v = strtol(str, &end, 16);
    if (end == str || end > str + 4 || v < 0 || v > 65535)
        return NULL;
    *value = v;
    return end;
}

static const char *parse_h16_sequence(const char *str,
                                      uint16_t address[8],
                                      unsigned *count)
{
    const char *p = str;
    unsigned i = 0;
    for (;;) {
        const char *next = parse_h16(p, &address[i]);
        if (!next || *next != ':')
            break;
        p = next + 1;
        if (++i == 8)
            break;
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
static const char *parse_ipv6(const char *str, uint16_t address[8])
{
    const char *next;
    unsigned m;
    const char *p = parse_h16_sequence(str, address, &m);
    if (m > 7)
        return NULL;
    switch (m) {
        case 7:
            next = parse_h16(p, &address[7]);
            if (next)
                return next;
            break;
        case 6: {
            uint8_t tail[4];
            next = parse_ipv6_ipv4(p, tail);
            if (next) {
                address[6] = (tail[0] << 8) | tail[1];
                address[7] = (tail[2] << 8) | tail[3];
                return next;
            }
            break;
        }
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
    uint16_t remainder[8];
    unsigned n;
    p = parse_h16_sequence(p + 1, remainder, &n);
    for (int i = m; i < 8; i++)
        address[i] = 0;
    if (m + n <= 5) {
        uint8_t tail[4];
        next = parse_ipv6_ipv4(p, tail);
        if (next) {
            for (int i = 0; i < n; i++)
                address[6 - n + i] = remainder[i];
            address[6] = (tail[0] << 8) | tail[1];
            address[7] = (tail[2] << 8) | tail[3];
            return next;
        }
    }
    if (m + n <= 6) {
        next = parse_h16(p, &address[7]);
        if (next) {
            for (int i = 0; i < n; i++)
                address[7 - n + i] = remainder[i];
            return next;
        }
    }
    if (m <= 7 && n == 0)
        return p;
    return NULL;
}

static bool is_forbidden(char c)
{
    switch (c) {
        case '\0':
        case '\t':
        case '\n':
        case '\r':
        case ' ':
        case '#':
        case '%':
        case '/':
        case ':':
        case '<':
        case '>':
        case '?':
        case '@':
        case '[':
        case '\\':
        case ']':
        case '^':
            return true;
        default:
            return false;
    }
}

static char *parse_host_string(scheme_type_t scheme_type, byte_array_t *buffer)
{
    const char *data = byte_array_data(buffer);
    size_t size = byte_array_size(buffer);
    if (*data == '[') {
        if (data[size - 1] != ']')
            return NULL;
        uint16_t address[8];
        const char *end = parse_ipv6(data + 1, address);
        if (!end || end[0] != ']' || end[1])
            return NULL;
        return charstr_printf("%.4x:%.4x:%.4x:%.4x:%.4x:%.4x:%.4x:%.4x",
                              address[0],
                              address[1],
                              address[2],
                              address[3],
                              address[4],
                              address[5],
                              address[6],
                              address[7]);
    }

    if (scheme_type == SCHEME_NOT_SPECIAL) {
        for (int i = 0; i < size; i++)
            if (data[i] != '%' && is_forbidden(data[i]))
                return NULL;
        charstr_url_encoder_t *encoder =
            charstr_create_url_encoder("", " !#$%&'()*+,:;=?@[]");
        char *host = charstr_url_custom_encode(encoder, data);
        charstr_destroy_url_encoder(encoder);
        return host;
    }

    char *host = charstr_url_decode(data, false, &size);
    if (!host)
        return NULL;
    if (!charstr_valid_utf8_bounded(host, host + size)) {
        fsfree(host);
        return NULL;
    }
    for (int i = 0; i < size; i++)
        if (is_forbidden(host[i])) {
            fsfree(host);
            return NULL;
        }
    long long fields[4];
    if (!parse_ipv4_pass1(host, fields, &size))
        return host;
    free(host);
    uint32_t address;
    if (!parse_ipv4_pass2(fields, size, &address))
        return NULL;
    return charstr_printf("%u.%u.%u.%u",
                          (address >> 24) & 0xff,
                          (address >> 16) & 0xff,
                          (address >> 8) & 0xff,
                          (address >> 0) & 0xff);
}

static bool is_single_dot(const char *str)
{
    return !charstr_case_cmp(str, ".") || !charstr_case_cmp(str, "%2e");
}

static bool is_double_dot(const char *str)
{
    return !charstr_case_cmp(str, "..") || !charstr_case_cmp(str, ".%2e") ||
        !charstr_case_cmp(str, "%2e.") || !charstr_case_cmp(str, "%2e%2e");
}

static bool is_drive_letter(const char *str)
{
    return (charstr_char_class(str[0]) & CHARSTR_ALPHA) &&
        (str[1] == ':' || str[1] == '|') && !str[2];
}

static bool starts_with_normalized_drive_letter(list_t *path)
{
    list_elem_t *el = list_get_first(path);
    char *component = (char *) list_elem_get_value(el);
    return (charstr_char_class(component[0]) & CHARSTR_ALPHA) &&
        component[1] == ':' && !component[2];
}

static void shorten_path(scheme_type_t scheme_type, list_t *path)
{
    size_t size = list_size(path);
    if (size == 0)
        return;
    if (scheme_type == SCHEME_FILE && size == 1 &&
        starts_with_normalized_drive_letter(path))
        return;
    fsfree((char *) list_pop_last(path));
}

static void resolve_path(url_parser_t *parser)
{
    list_t *path = parser->path;
    if (!list_empty(path)) {
        list_elem_t *el = list_get_first(path);
        char *component = (char *) list_elem_get_value(el);
        if (parser->url->scheme_type == SCHEME_FILE &&
            is_drive_letter(component)) {
            parser->path_type = PATH_REL_NONE;
            component[1] = ':';
        }
    }
    switch (parser->path_type) {
        case PATH_REL_BASE: {
            const char *base_path = parser->base->path;
            if (*base_path == '/')
                base_path++;
            parser->path = charstr_split(base_path, '/', -1);
            fsfree((char *) list_pop_last(parser->path));
            break;
        }
        case PATH_REL_BASE_DRIVE: {
            const char *base_path = parser->base->path;
            if (*base_path == '/')
                base_path++;
            parser->path = charstr_split(base_path, '/', 1);
            if (list_size(parser->path) == 2)
                fsfree((char *) list_pop_last(parser->path));
            if (list_size(parser->path) == 1 &&
                !starts_with_normalized_drive_letter(parser->path))
                fsfree((char *) list_pop_last(parser->path));
            break;
        }
        default:
            parser->path = make_list();
            break;
    }
    while (!list_empty(path)) {
        char *component = (char *) list_pop_first(path);
        if (is_double_dot(component)) {
            shorten_path(parser->url->scheme_type, parser->path);
            fsfree(component);
            if (list_empty(path))
                list_append(parser->path, charstr_dupstr(""));
        } else if (is_single_dot(component)) {
            fsfree(component);
            if (list_empty(path))
                list_append(parser->path, charstr_dupstr(""));
        } else {
            list_append(parser->path, component);
        }
    }
    destroy_list(path);
}

static const char *prefix_iterator_next(url_parser_t *parser, const char *ptr)
{
    if (ptr)
        ptr++;
    else
        ptr = parser->input;
    const char *end = parser->input + parser->cursor;
    for (; ptr < end; ptr++) {
        switch (*ptr) {
            case '\t':
            case '\n':
            case '\r':
                break;
            default:
                return ptr;
        }
    }
    return NULL;
}

static char *url_encode_prefix(url_parser_t *parser,
                               const char *reserve,
                               const char *unreserve)
{
    charstr_url_encoder_t *encoder =
        charstr_create_url_encoder(reserve, unreserve);
    for (const char *p = prefix_iterator_next(parser, NULL); p != NULL;
         p = prefix_iterator_next(parser, p)) {
        const char *encoding = charstr_url_custom_encode_byte(encoder, *p);
        byte_array_append_string(parser->buffer, encoding);
    }
    charstr_destroy_url_encoder(encoder);
    char *str = charstr_dupstr(byte_array_data(parser->buffer));
    byte_array_clear(parser->buffer);
    return str;
}

static void parse_scheme_start(url_parser_t *parser, int c)
{
    if (charstr_char_class(c) & CHARSTR_ALPHA) {
        parser->input++;
        byte_array_append(parser->buffer, &c, 1);
        parser->state = PARSER_SCHEME;
    } else {
        parser->state = PARSER_NO_SCHEME;
    }
}

static void parse_scheme(url_parser_t *parser, int c)
{
    if ((charstr_char_class(c) & CHARSTR_ALNUM) || c == '+' || c == '-' ||
        c == '.') {
        parser->input++;
        byte_array_append(parser->buffer, &c, 1);
        return;
    }
    if (c != ':') {
        parser->input -= byte_array_size(parser->buffer);
        byte_array_clear(parser->buffer);
        parser->state = PARSER_NO_SCHEME;
        return;
    }
    parser->input++;
    parser->url->scheme = charstr_dupstr(byte_array_data(parser->buffer));
    byte_array_clear(parser->buffer);
    charstr_lcase_str(parser->url->scheme);
    parser->url->scheme_type = get_scheme_type(parser->url->scheme);
    switch (parser->url->scheme_type) {
        case SCHEME_FILE:
            parser->state = PARSER_FILE;
            break;
        case SCHEME_NOT_SPECIAL:
            parser->state = PARSER_NOT_SPECIAL;
            break;
        default:
            parser->state = PARSER_SPECIAL;
            break;
    }
}

static void parse_special(url_parser_t *parser, int c)
{
    nwutil_url_t *base = parser->base;
    if (base && base->base && !strcmp(parser->url->scheme, base->scheme)) {
        if (c == '/') {
            parser->input++;
            parser->state = PARSER_SPECIAL_REL_OR_AUTH;
        } else {
            parser->state = PARSER_REL;
        }
    } else {
        parser->state = PARSER_SPECIAL_AUTH;
    }
}

static void parse_not_special(url_parser_t *parser, int c)
{
    if (c == '/') {
        parser->input++;
        parser->state = PARSER_PATH_OR_AUTH;
    } else {
        parser->state = PARSER_NON_BASE_PATH;
    }
}

static void parse_no_scheme(url_parser_t *parser, int c)
{
    nwutil_url_t *base = parser->base;
    if (base && base->base) {
        parser->url->scheme_type = base->scheme_type;
        parser->url->scheme = charstr_dupstr(base->scheme);
        if (base->scheme_type == SCHEME_FILE)
            parser->state = PARSER_FILE;
        else
            parser->state = PARSER_REL;
    } else if (base && c == '#') {
        parser->url->scheme_type = base->scheme_type;
        parser->url->scheme = charstr_dupstr(base->scheme);
        parser->url->path = charstr_dupstr(base->path);
        parser->url->query = charstr_dupstr(base->query);
        parser->input++;
        parser->state = PARSER_FRAGMENT;
    } else {
        parser->error = true;
    }
}

static void parse_special_relative_or_auth(url_parser_t *parser, int c)
{
    if (c == '/') {
        parser->input++;
        parser->state = PARSER_SPECIAL_AUTH;
    } else {
        parser->state = PARSER_REL_SLASH;
    }
}

static void parse_path_or_auth(url_parser_t *parser, int c)
{
    if (c == '/') {
        parser->input++;
        parser->state = PARSER_AUTH;
    } else {
        parser->state = PARSER_PATH;
    }
}

static void parse_relative(url_parser_t *parser, int c)
{
    parser->input++;
    if (c == '/') {
        parser->state = PARSER_REL_SLASH;
    } else {
        nwutil_url_t *base = parser->base;
        parser->url->username = charstr_dupstr(base->username);
        parser->url->password = charstr_dupstr(base->password);
        parser->url->host = charstr_dupstr(base->host);
        parser->url->port = base->port;
        parser->url->path = charstr_dupstr(base->path);
        parser->url->query = charstr_dupstr(base->query);
        switch (c) {
            case '?':
                parser->state = PARSER_QUERY;
                break;
            case '#':
                parser->state = PARSER_FRAGMENT;
                break;
            case EOS:
                break;
            default:
                parser->path_type = PATH_REL_BASE;
                parser->input--;
                parser->state = PARSER_PATH;
                break;
        }
    }
}

static void parse_relative_slash(url_parser_t *parser, int c)
{
    parser->input++;
    if (c == '/') {
        if (parser->url->scheme_type != SCHEME_NOT_SPECIAL)
            parser->state = PARSER_SPECIAL_AUTH;
        else
            parser->state = PARSER_AUTH;
    } else {
        nwutil_url_t *base = parser->base;
        parser->url->username = charstr_dupstr(base->username);
        parser->url->password = charstr_dupstr(base->password);
        parser->url->host = charstr_dupstr(base->host);
        parser->url->port = base->port;
        parser->input--;
        parser->state = PARSER_PATH;
    }
}

static void parse_special_authority(url_parser_t *parser, int c)
{
    if (c == '/')
        parser->input++;
    else
        parser->state = PARSER_AUTH;
}

static void parse_authority(url_parser_t *parser, int c)
{
    scheme_type_t scheme_type = parser->url->scheme_type;
    switch (c) {
        case '/':
        case '?':
        case '#':
        case EOS: {
            const char *at = parser->state_data;
            if (at) {
                const char *next = prefix_iterator_next(parser, at);
                if (!next || next == parser->input + parser->cursor) {
                    parser->error = true;
                    return;
                }
                charstr_url_encoder_t *encoder =
                    charstr_create_url_encoder(" \"#<>?`{}/:;=@[\\]^|",
                                               "!$%&'()*+,");
                for (const char *p = prefix_iterator_next(parser, NULL);
                     p != at;
                     p = prefix_iterator_next(parser, p)) {
                    if (*p == ':' && !parser->url->username) {
                        parser->url->username =
                            charstr_dupstr(byte_array_data(parser->buffer));
                        byte_array_clear(parser->buffer);
                    } else {
                        const char *encoding =
                            charstr_url_custom_encode_byte(encoder, *p);
                        byte_array_append_string(parser->buffer, encoding);
                    }
                }
                charstr_destroy_url_encoder(encoder);
                if (!parser->url->username)
                    parser->url->username =
                        charstr_dupstr(byte_array_data(parser->buffer));
                else
                    parser->url->password =
                        charstr_dupstr(byte_array_data(parser->buffer));
                byte_array_clear(parser->buffer);
                parser->input = next;
                parser->state_data = NULL;
            }
            parser->cursor = 0;
            parser->state = PARSER_HOST;
            break;
        }
        case '@':
            parser->state_data = parser->input + parser->cursor;
            parser->cursor++;
            break;
        default:
            parser->cursor++;
            break;
    }
}

static void parse_host(url_parser_t *parser, int c)
{
    scheme_type_t scheme_type = parser->url->scheme_type;
    if (c == ':' && parser->state_data) {
        parser->input++;
        byte_array_append(parser->buffer, &c, 1);
        return;
    }
    switch (c) {
        case ':':
        case '/':
        case '?':
        case '#':
        case EOS:
            if (byte_array_size(parser->buffer) == 0 &&
                (c == ':' || scheme_type != SCHEME_NOT_SPECIAL)) {
                parser->error = true;
                return;
            }
            parser->url->host =
                parse_host_string(parser->url->scheme_type, parser->buffer);
            byte_array_clear(parser->buffer);
            if (!parser->url->host) {
                parser->error = true;
                return;
            }
            if (c == ':') {
                parser->input++;
                parser->state = PARSER_PORT;
            } else {
                parser->state = PARSER_PATH_START;
            }
            break;
        case '[':
            parser->state_data = parser->input;
            parser->input++;
            byte_array_append(parser->buffer, &c, 1);
            break;
        case ']':
            parser->state_data = NULL;
            parser->input++;
            byte_array_append(parser->buffer, &c, 1);
            break;
        case '\0':
            parser->error = true;
            break;
        default:
            parser->input++;
            byte_array_append(parser->buffer, &c, 1);
            break;
    }
}

static void parse_port(url_parser_t *parser, int c)
{
    scheme_type_t scheme_type = parser->url->scheme_type;
    if (charstr_char_class(c) & CHARSTR_DIGIT) {
        parser->input++;
        byte_array_append(parser->buffer, &c, 1);
        return;
    }
    switch (c) {
        case '/':
        case '?':
        case '#':
        case EOS:
            break;
        default:
            parser->error = true;
            return;
    }
    const char *data = byte_array_data(parser->buffer);
    char *end;
    long _port = strtol(data, &end, 10);
    byte_array_clear(parser->buffer);
    if (_port < 0 || _port > 65535) {
        parser->error = true;
        return;
    }
    if (data != end && _port != get_scheme_default_port(scheme_type))
        parser->url->port = _port;
    parser->state = PARSER_PATH_START;
}

static void parse_file(url_parser_t *parser, int c)
{
    nwutil_url_t *base = parser->base;
    parser->input++;
    if (c == '/') {
        parser->state = PARSER_FILE_SLASH;
    } else if (base && base->scheme_type == SCHEME_FILE) {
        parser->url->host = charstr_dupstr(base->host);
        parser->url->path = charstr_dupstr(base->path);
        parser->url->query = charstr_dupstr(base->query);
        switch (c) {
            case '?':
                parser->state = PARSER_QUERY;
                break;
            case '#':
                parser->state = PARSER_FRAGMENT;
                break;
            case EOS:
                break;
            default:
                parser->path_type = PATH_REL_BASE;
                parser->input--;
                parser->state = PARSER_PATH;
                break;
        }
    } else {
        parser->input--;
        parser->state = PARSER_PATH;
    }
}

static void parse_file_slash(url_parser_t *parser, int c)
{
    parser->input++;
    if (c == '/') {
        parser->state = PARSER_FILE_HOST;
    } else {
        nwutil_url_t *base = parser->base;
        if (base && base->scheme_type == SCHEME_FILE) {
            parser->url->host = charstr_dupstr(base->host);
            parser->path_type = PATH_REL_BASE_DRIVE;
        }
        parser->input--;
        parser->state = PARSER_PATH;
    }
}

static void parse_file_host(url_parser_t *parser, int c)
{
    switch (c) {
        case '/':
        case '?':
        case '#':
        case EOS:
            if (is_drive_letter(byte_array_data(parser->buffer))) {
                parser->input -= byte_array_size(parser->buffer);
                byte_array_clear(parser->buffer);
                parser->state = PARSER_PATH;
            } else {
                parser->url->host =
                    parse_host_string(parser->url->scheme_type, parser->buffer);
                byte_array_clear(parser->buffer);
                if (!parser->url->host) {
                    parser->error = true;
                    return;
                }
                if (!strcmp(parser->url->host, "localhost")) {
                    fsfree(parser->url->host);
                    parser->url->host = charstr_dupstr("");
                }
                parser->state = PARSER_PATH_START;
            }
            break;
        case '\0':
            parser->error = true;
            break;
        default:
            parser->input++;
            byte_array_append(parser->buffer, &c, 1);
            break;
    }
}

static void parse_path_start(url_parser_t *parser, int c)
{
    scheme_type_t scheme_type = parser->url->scheme_type;
    parser->input++;
    if (scheme_type == SCHEME_NOT_SPECIAL) {
        switch (c) {
            case '?':
                parser->url->path = charstr_dupstr("");
                parser->state = PARSER_QUERY;
                break;
            case '#':
                parser->url->path = charstr_dupstr("");
                parser->state = PARSER_FRAGMENT;
                break;
            case EOS:
                parser->url->path = charstr_dupstr("");
                break;
            default:
                break;
        }
    }
    if (!parser->url->path) {
        if (c != '/')
            parser->input--;
        parser->state = PARSER_PATH;
    }
}

static void parse_path(url_parser_t *parser, int c)
{
    if (!parser->path)
        parser->path = make_list();
    switch (c) {
        case '/':
        case '?':
        case '#':
        case EOS: {
            list_append(parser->path,
                        url_encode_prefix(parser,
                                          " \"#<>?`{}",
                                          "!$%&'()*+,:;=@[]"));
            parser->input += parser->cursor + 1;
            parser->cursor = 0;
            if (c != '/') {
                byte_array_t *buffer = parser->buffer;
                resolve_path(parser);
                while (!list_empty(parser->path)) {
                    char *component = (char *) list_pop_first(parser->path);
                    byte_array_append_string(buffer, "/");
                    byte_array_append_string(buffer, component);
                    fsfree(component);
                }
                destroy_list(parser->path);
                if (parser->url->path)
                    fsfree(parser->url->path);
                parser->url->path = charstr_dupstr(byte_array_data(buffer));
                byte_array_clear(buffer);

                switch (c) {
                    case '?':
                        parser->state = PARSER_QUERY;
                        break;
                    case '#':
                        parser->state = PARSER_FRAGMENT;
                        break;
                    default:
                        break;
                }
            }
            break;
        }
        default:
            parser->cursor++;
            break;
    }
}

static void parse_non_base_path(url_parser_t *parser, int c)
{
    switch (c) {
        case '?':
        case '#':
        case EOS:
            parser->url->base = false;
            parser->url->path =
                url_encode_prefix(parser, "", " !#$%&'()*+,:;=?@[]");
            parser->input += parser->cursor + 1;
            parser->cursor = 0;
            switch (c) {
                case '?':
                    parser->state = PARSER_QUERY;
                    break;
                case '#':
                    parser->state = PARSER_FRAGMENT;
                    break;
                default:
                    break;
            }
            break;
        default:
            parser->cursor++;
            break;
    }
}

static void parse_query(url_parser_t *parser, int c)
{
    switch (c) {
        case '#':
        case EOS:
            if (parser->url->query)
                fsfree(parser->url->query);
            if (parser->url->scheme_type == SCHEME_NOT_SPECIAL)
                parser->url->query =
                    url_encode_prefix(parser, " \"#<>", "!$%&'()*+,:;=?@[]");
            else
                parser->url->query =
                    url_encode_prefix(parser, " \"#<>'", "!$%&()*+,:;=?@[]");
            parser->input += parser->cursor + 1;
            parser->cursor = 0;
            if (c == '#')
                parser->state = PARSER_FRAGMENT;
            break;
        default:
            parser->cursor++;
            break;
    }
}

static void parse_fragment(url_parser_t *parser, int c)
{
    switch (c) {
        case EOS:
            if (parser->url->fragment)
                fsfree(parser->url->fragment);
            parser->url->fragment =
                url_encode_prefix(parser, " \"<>`", "!#$%&'()*+,:;=?@[]");
            parser->input += parser->cursor + 1;
            parser->cursor = 0;
        default:
            parser->cursor++;
            break;
    }
}

static void parse(url_parser_t *parser, int c)
{
    switch (c) {
        case '\t':
        case '\n':
        case '\r':
            if (parser->cursor)
                parser->cursor++;
            else
                parser->input++;
            return;
        case '\\':
            if (parser->url->scheme_type != SCHEME_NOT_SPECIAL)
                c = '/';
            break;
        default:
            break;
    }
    switch (parser->state) {
        case PARSER_SCHEME_START:
            parse_scheme_start(parser, c);
            break;
        case PARSER_SCHEME:
            parse_scheme(parser, c);
            break;
        case PARSER_SPECIAL:
            parse_special(parser, c);
            break;
        case PARSER_NOT_SPECIAL:
            parse_not_special(parser, c);
            break;
        case PARSER_NO_SCHEME:
            parse_no_scheme(parser, c);
            break;
        case PARSER_SPECIAL_REL_OR_AUTH:
            parse_special_relative_or_auth(parser, c);
            break;
        case PARSER_PATH_OR_AUTH:
            parse_path_or_auth(parser, c);
            break;
        case PARSER_REL:
            parse_relative(parser, c);
            break;
        case PARSER_REL_SLASH:
            parse_relative_slash(parser, c);
            break;
        case PARSER_SPECIAL_AUTH:
            parse_special_authority(parser, c);
            break;
        case PARSER_AUTH:
            parse_authority(parser, c);
            break;
        case PARSER_HOST:
            parse_host(parser, c);
            break;
        case PARSER_PORT:
            parse_port(parser, c);
            break;
        case PARSER_FILE:
            parse_file(parser, c);
            break;
        case PARSER_FILE_SLASH:
            parse_file_slash(parser, c);
            break;
        case PARSER_FILE_HOST:
            parse_file_host(parser, c);
            break;
        case PARSER_PATH_START:
            parse_path_start(parser, c);
            break;
        case PARSER_PATH:
            parse_path(parser, c);
            break;
        case PARSER_NON_BASE_PATH:
            parse_non_base_path(parser, c);
            break;
        case PARSER_QUERY:
            parse_query(parser, c);
            break;
        case PARSER_FRAGMENT:
            parse_fragment(parser, c);
            break;
    }
}

nwutil_url_t *nwutil_parse_url(const void *buffer,
                               size_t size,
                               nwutil_url_t *base)
{
    const char *p = buffer;
    while (size > 0 &&
           ((charstr_char_class(p[0]) & CHARSTR_CONTROL) ||
            p[0] == ' ')) {
        p++;
        size--;
    }
    while (size > 0 &&
           ((charstr_char_class(p[size - 1]) & CHARSTR_CONTROL) ||
            p[size - 1] == ' '))
        size--;

    nwutil_url_t *url = fscalloc(1, sizeof *url);
    url->base = true;
    url->port = -1;
    url_parser_t parser = {
        .state = PARSER_SCHEME_START,
        .input = p,
        .base = base,
        .buffer = make_byte_array(-1),
        .path_type = PATH_REL_NONE,
        .url = url,
    };
    const char *end = p + size;
    while (parser.input + parser.cursor <= end && !parser.error) {
        int c;
        if (parser.input < end - parser.cursor)
            c = parser.input[parser.cursor];
        else
            c = EOS;
        parse(&parser, c);
    }

    destroy_byte_array(parser.buffer);
    if (!parser.error)
        return parser.url;

    if (url->scheme)
        fsfree(url->scheme);
    if (url->username)
        fsfree(url->username);
    if (url->password)
        fsfree(url->password);
    if (url->host)
        fsfree(url->host);
    if (url->path)
        fsfree(url->path);
    if (url->query)
        fsfree(url->query);
    if (url->fragment)
        fsfree(url->fragment);
    fsfree(url);
    return NULL;
}

void nwutil_url_destroy(nwutil_url_t *url)
{
    fsfree(url->scheme);
    if (url->username)
        fsfree(url->username);
    if (url->password)
        fsfree(url->password);
    if (url->host)
        fsfree(url->host);
    fsfree(url->path);
    if (url->query)
        fsfree(url->query);
    if (url->fragment)
        fsfree(url->fragment);
    fsfree(url);
}

const char *nwutil_url_get_scheme(nwutil_url_t *url)
{
    return url->scheme;
}

const char *nwutil_url_get_username(nwutil_url_t *url)
{
    return url->username;
}

const char *nwutil_url_get_password(nwutil_url_t *url)
{
    return url->password;
}

const char *nwutil_url_get_host(nwutil_url_t *url)
{
    return url->host;
}

const char *nwutil_url_get_path(nwutil_url_t *url)
{
    return url->path;
}

const char *nwutil_url_get_query(nwutil_url_t *url)
{
    return url->query;
}

const char *nwutil_url_get_fragment(nwutil_url_t *url)
{
    return url->fragment;
}

bool nwutil_url_get_port(nwutil_url_t *url, unsigned *port)
{
    if (url->port != -1) {
        *port = url->port;
        return true;
    }
    return false;
}
