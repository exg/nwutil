#ifndef __NWUTIL__
#define __NWUTIL__

#include <stdbool.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nwutil_http_proxy_settings nwutil_http_proxy_settings_t;

/* Consult the operating system's global network settings and return the
 * HTTP proxy settings to be used for a given URI.
 *
 * If NULL is returned, consult errno. In particular, EAFNOSUPPORT
 * indicates that the function does not support the necessary proxy
 * settings. */
nwutil_http_proxy_settings_t *
nwutil_get_global_http_proxy_settings_1(const char *uri);

/* Return true if a proxy must be used. */
bool nwutil_use_http_proxy(nwutil_http_proxy_settings_t *settings);

/* Return the hostname, IPv4 or IPv6 address of the HTTP proxy. The
 * return value is accessible as long as settings is. */
const char *nwutil_http_proxy_host(nwutil_http_proxy_settings_t *settings);

/* Return the TCP port the HTTP proxy. The return
 * value is accessible as long as settings is. */
unsigned nwutil_http_proxy_port(nwutil_http_proxy_settings_t *settings);

/* Return the username of the HTTP proxy or NULL if basic proxy
 * authentication is not specified. The return value is accessible as
 * long as settings is. */
const char *nwutil_http_proxy_user(nwutil_http_proxy_settings_t *settings);

/* Return the password of the HTTP proxy or NULL if basic proxy
 * authentication is not specified. The return value is accessible as
 * long as settings is. */
const char *nwutil_http_proxy_password(nwutil_http_proxy_settings_t *settings);

/* Deallocate the data structure holding the HTTP proxy settings. */
void nwutil_release_http_proxy_settings(nwutil_http_proxy_settings_t *settings);

typedef struct nwutil_url nwutil_url_t;

/*
 * Implementation of the basic URL parser from the WHATWG URL
 * Standard. Limitations:
 *
 * - no support for the encoding override, url and state override
 *   arguments
 */
nwutil_url_t *nwutil_parse_url(const void *buffer,
                               size_t size,
                               nwutil_url_t *base);
void nwutil_url_destroy(nwutil_url_t *url);
/* Return the URL scheme with all characters lowercase. */
const char *nwutil_url_get_scheme(nwutil_url_t *url);
/* Return the URL username in percent encoding, if present, and
 * NULL otherwise. */
const char *nwutil_url_get_username(nwutil_url_t *url);
/* Return the URL password in percent encoding, if present, and
 * NULL otherwise. */
const char *nwutil_url_get_password(nwutil_url_t *url);
/* Return the URL host, if present, and NULL otherwise. If the scheme
 * is "file" or a web scheme ("http", "https", "ws", "wss", "ftp") the
 * host is returned in IDNA encoding. Otherwise, it is returned in
 * percent encoding. If the scheme is a web scheme the host is
 * guaranteed to exist. */
const char *nwutil_url_get_host(nwutil_url_t *url);
/* Return the URL path in percent encoding. */
const char *nwutil_url_get_path(nwutil_url_t *url);
/* Return the URL query in percent encoding, if present, and NULL
 * otherwise. The value does not include a leading '?'. */
const char *nwutil_url_get_query(nwutil_url_t *url);
/* Return the URL fragment in percent encoding, if present, and NULL
 * otherwise. The value does not include a leading '#'. */
const char *nwutil_url_get_fragment(nwutil_url_t *url);
bool nwutil_url_get_port(nwutil_url_t *url, unsigned *port);

const char *nwutil_url_get_host_header(nwutil_url_t *url);

#ifdef __cplusplus
}
#endif

#endif
