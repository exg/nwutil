#include <stdlib.h>
#include <errno.h>
#include "nwutil.h"

struct nwutil_http_proxy_settings {
    bool use_proxy;
    char *proxy_host;
    unsigned proxy_port;
};

static nwutil_http_proxy_settings_t *no_http_proxy()
{
    nwutil_http_proxy_settings_t *settings = malloc(sizeof *settings);
    settings->use_proxy = false;
    settings->proxy_host = NULL;
    settings->proxy_port = 0;
    return settings;
}

#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#include <CoreServices/CoreServices.h>

nwutil_http_proxy_settings_t *parse_proxy(CFDictionaryRef proxy)
{
    CFStringRef proxyType;
    if (!CFDictionaryGetValueIfPresent(proxy, kCFProxyTypeKey,
                                       (CFTypeRef *) &proxyType))
        return NULL;
    if (proxyType != kCFProxyTypeHTTP &&
        proxyType != kCFProxyTypeHTTPS)
        return NULL;

    CFNumberRef cf_port;
    unsigned port;
    if (!CFDictionaryGetValueIfPresent(proxy, kCFProxyPortNumberKey,
                                       (CFTypeRef *) &cf_port) ||
        !CFNumberGetValue(cf_port, kCFNumberIntType, &port))
        return NULL;

    CFStringRef cf_host;
    if (!CFDictionaryGetValueIfPresent(proxy, kCFProxyHostNameKey,
                                       (CFTypeRef *) &cf_host))
        return NULL;

    CFIndex length = CFStringGetLength(cf_host);
    CFIndex size =
        CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;

    char *host = malloc(size);
    if (!CFStringGetCString(cf_host, host, size, kCFStringEncodingUTF8)) {
        free(host);
        return NULL;
    }
    nwutil_http_proxy_settings_t *settings = malloc(sizeof *settings);
    settings->use_proxy = true;
    settings->proxy_host = host;
    settings->proxy_port = port;
    return settings;
}

nwutil_http_proxy_settings_t *http_proxy_settings(const char *url)
{
    CFDictionaryRef proxySettings;
    CFArrayRef proxies;
    CFURLRef cf_url;
    CFIndex i;
    nwutil_http_proxy_settings_t *settings = NULL;
    cf_url = CFURLCreateWithBytes(NULL, (const UInt8 *)url, strlen(url),
                                  kCFStringEncodingUTF8, NULL);
    proxySettings = CFNetworkCopySystemProxySettings();
    proxies = CFNetworkCopyProxiesForURL(cf_url, proxySettings);
    CFRelease(cf_url);
    CFRelease(proxySettings);
    for (i = 0; !settings && i < CFArrayGetCount(proxies); i++)
        settings = parse_proxy(CFArrayGetValueAtIndex(proxies, i));
    CFRelease(proxies);
    if (!settings)
        return no_http_proxy();
    return settings;
}
#endif

nwutil_http_proxy_settings_t *
nwutil_get_global_http_proxy_settings_1(const char *uri)
{
#ifdef __APPLE__
    return http_proxy_settings(uri);
#else
    return no_http_proxy();
#endif
}

bool nwutil_use_http_proxy(nwutil_http_proxy_settings_t *settings)
{
    return settings->use_proxy;
}

const char *nwutil_http_proxy_host(nwutil_http_proxy_settings_t *settings)
{
    return settings->proxy_host;
}

unsigned nwutil_http_proxy_port(nwutil_http_proxy_settings_t *settings)
{
    return settings->proxy_port;
}

void nwutil_release_http_proxy_settings(nwutil_http_proxy_settings_t *settings)
{
    free(settings->proxy_host);
    free(settings);
}

