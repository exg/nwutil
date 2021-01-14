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
 *
 * - missing IDNA to ASCII validation and encoding of the host string
 */
nwutil_url_t *nwutil_parse_url(const void *buffer,
                               size_t size,
                               nwutil_url_t *base);
void nwutil_url_destroy(nwutil_url_t *url);
const char *nwutil_url_get_scheme(nwutil_url_t *url);
const char *nwutil_url_get_username(nwutil_url_t *url);
const char *nwutil_url_get_password(nwutil_url_t *url);
const char *nwutil_url_get_host(nwutil_url_t *url);
const char *nwutil_url_get_path(nwutil_url_t *url);
const char *nwutil_url_get_query(nwutil_url_t *url);
const char *nwutil_url_get_fragment(nwutil_url_t *url);
bool nwutil_url_get_port(nwutil_url_t *url, unsigned *port);

#ifdef __cplusplus
}
#endif

#endif
