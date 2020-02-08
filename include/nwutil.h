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

#ifdef __cplusplus
}
#endif

#endif
