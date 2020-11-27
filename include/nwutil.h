#ifndef __NWUTIL__
#define __NWUTIL__

#include <stdbool.h>

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

/* Deallocate the data structure holding the HTTP proxy settings. */
void nwutil_release_http_proxy_settings(nwutil_http_proxy_settings_t *settings);

typedef struct nwutil_uri nwutil_uri_t;

nwutil_uri_t *nwutil_parse_uri(const char *str);
void nwutil_uri_destroy(nwutil_uri_t *uri);
const char *nwutil_uri_get_scheme(nwutil_uri_t *uri);
const char *nwutil_uri_get_userinfo(nwutil_uri_t *uri);
const char *nwutil_uri_get_host(nwutil_uri_t *uri);
const char *nwutil_uri_get_path(nwutil_uri_t *uri);
const char *nwutil_uri_get_query(nwutil_uri_t *uri);
const char *nwutil_uri_get_fragment(nwutil_uri_t *uri);
bool nwutil_uri_get_port(nwutil_uri_t *uri, unsigned *port);

#ifdef __cplusplus
}
#endif

#endif
